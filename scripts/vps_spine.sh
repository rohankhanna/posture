#!/usr/bin/env bash
set -euo pipefail
umask 022

# Lightweight posture spine runner for a single small VPS.
# This is the data-plane job GitHub Actions used to own. It keeps the catalog
# fresh on a daily cadence, exports a local spine, and leaves signing/serving
# to the surrounding systemd and nginx deployment.
#
# Bounded growth: the catalog only ever grows, and the host's disk does not,
# so this job bounds itself in three places. A disk-space guard refuses to
# start a build that would fill the disk. A bounded-growth purge forgets
# ancient defects that are no longer relevant (never a known-exploited
# defect, never a highly-exploitable one, never a defect with an outstanding
# fix on a tracked distribution). A weekly git maintenance pass reclaims the
# pack-file bloat the advisory and CVE clones accumulate.
#
# Every degradation is loud: a step that cannot do its job prints a warning
# and marks the run degraded, and the job exits non-zero at the end so the
# failure is visible in the journal instead of being swallowed.

STATE_DIR="${POSTURE_STATE_DIR:-/var/lib/posture}"
EXPORT_DIR="${POSTURE_EXPORT_DIR:-/var/lib/posture}"
CVELIST_DIR="${POSTURE_CVELIST_DIR:-$STATE_DIR/cvelist}"
GHSA_DIR="${POSTURE_GHSA_DIR:-$STATE_DIR/ghsa}"
DB_PATH="${POSTURE_DB_PATH:-$STATE_DIR/posture.db}"
BACKFILL_CAP="${POSTURE_BACKFILL_CAP:-5000}"
OSV_CAP="${POSTURE_OSV_CAP:-5000}"
REFRESH_CAP="${POSTURE_REFRESH_CAP:-200}"
PURGE_AGE_DAYS="${POSTURE_PURGE_AGE_DAYS:-3650}"
KEEP_EPSS_PERCENTILE="${POSTURE_KEEP_EPSS_PERCENTILE:-0.90}"
DISK_WARN_GB="${POSTURE_DISK_WARN_GB:-5}"
DISK_CRIT_GB="${POSTURE_DISK_CRIT_GB:-2}"
# Run the git clone maintenance every N days (tracked by a stamp file).
GC_INTERVAL_DAYS="${POSTURE_GC_INTERVAL_DAYS:-7}"

mkdir -p "$STATE_DIR" "$EXPORT_DIR" "$CVELIST_DIR" "$GHSA_DIR"
export POSTURE_CVELIST_DIR="$CVELIST_DIR"
export POSTURE_GHSA_DIR="$GHSA_DIR"
export POSTURE_DB_PATH="$DB_PATH"

# Free space on the state filesystem, in whole gigabytes.
_free_gb() {
  df -BG --output=avail "$STATE_DIR" | tail -1 | tr -dc '0-9'
}

# A degraded run still publishes a map, but it says so loudly and exits
# non-zero so the failure is visible in the journal.
DEGRADED=0
degrade() {
  echo "posture-spine: DEGRADED — $1"
  DEGRADED=1
}

echo "posture-spine: starting daily spine update ($(date -u +%Y-%m-%dT%H:%M:%SZ))"

# 0) Disk-space guard. A build that would fill the disk is worse than no
#    build: the previously published map keeps serving, so stop before the
#    catalog grows further. An aggressive purge (1-year retention) is tried
#    first, and the run still stops if that does not free enough.
FREE_GB="$(_free_gb)"
echo "posture-spine: ${FREE_GB} GB free on ${STATE_DIR}"
if [ "$FREE_GB" -lt "$DISK_CRIT_GB" ]; then
  echo "posture-spine: CRITICAL disk space — running aggressive purge (365-day retention, keep EPSS >= ${KEEP_EPSS_PERCENTILE})"
  # The emergency purge applies the host's own exploitability protection
  # floor (POSTURE_KEEP_EPSS_PERCENTILE), not a hardcoded one. A hardcoded
  # floor protects a different set of defects than the operator configured:
  # a floor above the configured one keeps defects the host's policy says
  # to forget (so the emergency purge frees less than the policy allows and
  # may not save the host), and a floor below it forgets defects the policy
  # says to keep (so the emergency purge discards rows the host is meant to
  # carry, with no record that it did). Either way the emergency purge must
  # apply the same policy the daily purge applies.
  if ! posture purge \
      --max-age-days 365 \
      --keep-epss-percentile "$KEEP_EPSS_PERCENTILE" \
      --db "$DB_PATH"; then
    # Every degradation is loud: a failed emergency purge means the disk
    # was not reclaimed, so the run is marked DEGRADED and exits non-zero.
    # The build continues so the map is still published; the free-space
    # re-check below aborts the run if the host is still out of space.
    degrade "aggressive purge failed; the emergency disk purge did not run and the catalog is still growing"
  fi
  FREE_GB="$(_free_gb)"
  if [ "$FREE_GB" -lt "$DISK_CRIT_GB" ]; then
    echo "posture-spine: ABORT — disk space still critical after purge (${FREE_GB} GB free)"
    exit 1
  fi
fi
if [ "$FREE_GB" -lt "$DISK_WARN_GB" ]; then
  echo "posture-spine: warning — only ${FREE_GB} GB free; the growth guard is the only thing keeping this host alive"
fi

# 1) Forward stream: pick up newly published skeletons.
#    Best-effort: a transient MITRE cvelistV5 outage must NOT block the daily
#    spine build; the no-wipe stream retains last-known-good and the run is
#    marked degraded so the failure is visible in the journal without aborting
#    the export.
posture stream --db "$DB_PATH" || \
  degrade "stream incomplete; last-known-good retained, spine continues"

# 2) Backfill historical skeletons once, then no-op on later runs.
#    Best-effort: a transient MITRE cvelistV5 outage must NOT block the daily
#    spine build; the no-wipe backfill retains last-known-good and the run is
#    marked degraded so the failure is visible in the journal without aborting
#    the export.
posture backfill --cap "$BACKFILL_CAP" --db "$DB_PATH" || \
  degrade "backfill incomplete; last-known-good retained, spine continues"

# 3) Peer overlays. Caps keep the small VPS bounded; each source is
#    incremental from the persistent database. Best-effort: a transient
#    outage in any source must NOT block the daily spine build; the no-wipe
#    ingest retains last-known-good and the run is marked degraded so the
#    failure is visible in the journal without aborting the export.
posture ingest ghsa --cap "$OSV_CAP" --db "$DB_PATH" || \
  degrade "ghsa ingest incomplete; last-known-good retained, spine continues"

# 3a) Seed the exact NVD CPE heads the operator's host matchers use. The
#     per-CVE refresh cannot guarantee that a specific CPE head is present in
#     the spine; this direct CPE-head query closes that gap before the heavy
#     OSV backfill runs. Best-effort: a transient NVD outage must NOT block the
#     daily spine build; the no-wipe ingest retains last-known-good.
posture ingest nvd-cpe \
  --cpe 'cpe:2.3:a:nvidia:gpu_driver' \
  --cpe 'cpe:2.3:a:nvidia:cuda_toolkit' \
  --cpe 'cpe:2.3:o:canonical:ubuntu_linux' \
  --cpe 'cpe:2.3:o:linux:linux_kernel' \
  --cpe 'cpe:2.3:h:nvidia:gb10' \
  --cpe 'cpe:2.3:h:mediatek:mt7925' \
  --cpe 'cpe:2.3:h:realtek:rtl8127' \
  --db "$DB_PATH" || \
  degrade "nvd-cpe ingest incomplete; last-known-good retained, spine continues"
posture ingest osv --cap "$OSV_CAP" --db "$DB_PATH" || \
  degrade "osv ingest incomplete; last-known-good retained, spine continues"
posture ingest kev --db "$DB_PATH" || \
  degrade "kev ingest incomplete; last-known-good retained, spine continues"
posture ingest apple --db "$DB_PATH" || \
  degrade "apple ingest incomplete; last-known-good retained, spine continues"

# 3b) Distro security-tracker status overlays (ubuntu_fixes, debian_fixes).
#     These carry the per-release status words (released/needed/not-affected/...)
#     that the OSV mirror drops — they clear NVD's unknown-fix false positives
#     on a fully-updated host. Best-effort: a transient tracker outage must NOT
#     block the daily spine build; the no-wipe ingest retains last-known-good.
#     Scope: active Ubuntu LTS + current (resolute/noble/jammy/focal) x
#     linux + linux-nvidia; Debian trixie/bookworm x linux. The operator owns
#     the public-spine editorial choice.
set +e
posture ingest ubuntu \
  --release resolute --release noble --release jammy --release focal \
  --package linux --package linux-nvidia --db "$DB_PATH"
if [ $? -ne 0 ]; then
  degrade "ubuntu ingest failed; last-known-good retained, spine continues"
fi
posture ingest debian --release trixie --release bookworm \
  --package linux --db "$DB_PATH"
if [ $? -ne 0 ]; then
  degrade "debian ingest failed; last-known-good retained, spine continues"
fi
set -e

# 4) Refresh the catalog with a small per-run cap. The persistent DB means
#    later runs continue rather than restart. Best-effort: a transient NVD
#    outage must NOT block the daily spine build; the no-wipe refresh retains
#    last-known-good and the run is marked degraded so the failure is visible
#    in the journal without aborting the export.
posture refresh --no-devices --cap "$REFRESH_CAP" --db "$DB_PATH" || \
  degrade "refresh incomplete; last-known-good retained, spine continues"

# 5) Keep the map honest without touching devices. These three maintenance
#    passes only SURFACE things for human review (vocabulary candidates,
#    drift proposals, new source candidates); none of them writes the map,
#    the verdicts, or the trust. A failure in one of them must therefore not
#    abort the daily build: the purge and the publish still have to run so
#    the host serves a fresh map. Each failure is marked degraded, so the run
#    exits non-zero at the end and the failure is visible in the journal
#    instead of being swallowed. These passes depend on the local database
#    and on the host's own state, so a transient fault in one of them (a
#    locked database, a temporary filesystem condition) is exactly the case
#    the script's stated principle covers: it must NOT block the daily
#    build.
#    A failure of one of these three is also not a reason to withhold the
#    map: the publish step exports and verifies the map from the SAME
#    database, so a database that makes these commands raise (a locked
#    file, a schema the running code no longer understands) fails the
#    publish too and leaves the previously published map serving. A
#    database that is quietly wrong produces quietly wrong rows rather
#    than a raised error, and no command in this script can detect that.
posture monitor run --db "$DB_PATH" || \
  degrade "vocabulary monitor scan failed; no vocabulary candidates were surfaced and the spine continues"
posture repair reconcile --db "$DB_PATH" || \
  degrade "repair reconcile failed; no drift proposals were raised and the spine continues"
posture discover --db "$DB_PATH" || \
  degrade "horizon scan failed; no new source candidates were surfaced and the spine continues"

# 6) Bounded-growth purge. Remove ancient defects that are no longer
#    relevant: older than PURGE_AGE_DAYS, not in KEV, not highly exploitable
#    per EPSS, and with no outstanding fix on a tracked distribution. The
#    purge runs BEFORE the export, so the published map is the purged map in a
#    single atomic publish and the export never has to carry rows that are
#    about to be forgotten. A failed purge is a degraded run, not a silent
#    one: the catalog keeps growing and the disk guard will act on it.
echo "posture-spine: running bounded-growth purge (age=${PURGE_AGE_DAYS}d, keep EPSS>=${KEEP_EPSS_PERCENTILE})"
if ! posture purge \
  --max-age-days "$PURGE_AGE_DAYS" \
  --keep-epss-percentile "$KEEP_EPSS_PERCENTILE" \
  --db "$DB_PATH"; then
  degrade "bounded-growth purge failed; the catalog is still growing"
fi

# 7) Publish the spine to a stable directory. A downstream web server can
#    serve this directory directly; clients can pull only the shards they need
#    from the manifest. If a signing key is configured, sign the manifest so
#    clients can cryptographically verify the spine before importing.
#
#    'publish' is export + verify + one atomic swap: the new map is written to
#    a staging directory, checked against its own manifest (every shard's
#    sha256 and row count), and only then moved into the served directory. A
#    failed build therefore leaves the previously published map serving, instead
#    of a half-written map that clients cannot import. The staging directory is
#    a hidden sibling of the served directory (same filesystem, so the swap is a
#    rename, not a copy) and is removed once the map is published.
SIGN_KEY="${POSTURE_SIGN_KEY:-}"
posture spine publish --db "$DB_PATH" --out "$EXPORT_DIR" ${SIGN_KEY:+--sign-key "$SIGN_KEY"}

# 7b) The published map must still carry the vendor fix-status overlay rows.
#     The publish is atomic, so a build that produced a map without those
#     rows leaves the previously published map serving: intact, consistent
#     with its own manifest, correctly signed and fresh. Every check on it
#     still passes, and the only thing that shows the rows are gone is the
#     map's own row counts. Those rows are what clear NVD's unknown-fix
#     false positives on a fully-updated host, so their absence is a
#     degradation the operator must see, not a quiet success.
#     The per-table check above cannot see a release that is missing while
#     the table still holds the other releases' rows: the per-(release,
#     package) refresh deletes the rows it replaces, so a release whose
#     tracker feed returned nothing ends up empty while the table as a whole
#     is still populated. The per-release requirement says which releases
#     the host needs and how many rows each must carry, and the freshness
#     allowance catches the other silent direction — a release the nightly
#     job stopped ingesting keeps its last-known-good rows, so only their
#     age shows that they stopped being refreshed. The per-package
#     requirement goes one level narrower: the per-(release, package)
#     refresh deletes the rows it replaces, so a source package whose
#     tracker feed returned nothing leaves that (release, package) pair
#     empty while the release still looks populated and passes the
#     per-release floor, so the missing package's fix-status rows are
#     gone and a patched package of that source is reported as unpatched.
#     The known-exploited set is checked in the same command: CISA's Known
#     Exploited Vulnerabilities catalog is the map's statement about what
#     is being exploited in the wild, and it is what the threat axis
#     reads. The KEV ingest is a no-wipe full refresh of a static file, so
#     a fetch that fails leaves the last-known-good rows in place: the
#     served map stays intact, signed and fresh, every other check on it
#     still passes, and only the age of the known-exploited rows shows
#     that the set stopped being refreshed. The row floor catches a map
#     that carries too few known-exploited entries; the freshness
#     allowance catches a set that is present but no longer refreshed.
#     The Apple fix overlay is checked per product as well as per table:
#     the apple_fixes ingest is a per-product full refresh, so a product
#     whose advisory feed returned nothing loses its rows entirely while
#     the other products keep theirs and the table-level row floor still
#     passes. Each product is refreshed on its own, so the per-product
#     freshness allowance is honest: it is that product's own fetch time.
#     The EPSS overlay is checked per score band as well as per table:
#     the EPSS ingest scores every CVE with a percentile, so a map that
#     holds 270k rows passes the table-level floor while quietly losing
#     every CVE in the top percentile bands if the model distribution
#     shifted or a partial fetch narrowed the set; the per-band counts
#     make that loss loud.
posture spine verify --from "$EXPORT_DIR" \
  --require-overlay ubuntu_fixes --require-overlay debian_fixes \
  --require-overlay-release ubuntu_fixes:resolute:1 \
  --require-overlay-release ubuntu_fixes:noble:1 \
  --require-overlay-release ubuntu_fixes:jammy:1 \
  --require-overlay-release ubuntu_fixes:focal:1 \
  --require-overlay-release debian_fixes:trixie:1 \
  --require-overlay-release debian_fixes:bookworm:1 \
  --require-overlay-package ubuntu_fixes:resolute:linux:1 \
  --require-overlay-package ubuntu_fixes:resolute:linux-nvidia:1 \
  --require-overlay-package ubuntu_fixes:noble:linux:1 \
  --require-overlay-package ubuntu_fixes:noble:linux-nvidia:1 \
  --require-overlay-package ubuntu_fixes:jammy:linux:1 \
  --require-overlay-package ubuntu_fixes:jammy:linux-nvidia:1 \
  --require-overlay-package ubuntu_fixes:focal:linux:1 \
  --require-overlay-package ubuntu_fixes:focal:linux-nvidia:1 \
  --require-overlay-package debian_fixes:trixie:linux:1 \
  --require-overlay-package debian_fixes:bookworm:linux:1 \
  --require-overlay-max-age-days 2 \
  --require-kev 1000 \
  --require-kev-max-age-days 3 \
  --require-apple-fixes 1 \
  --require-apple-fixes-max-age-days 7 \
  --require-apple-fixes-product iphone_os:1 \
  --require-apple-fixes-product ipados:1 \
  --require-apple-fixes-product macos:1 \
  --require-apple-fixes-product-max-age-days 7 \
  --require-epss 100000 \
  --require-epss-max-age-days 3 \
  --require-epss-score-band 0.9:100 \
  --require-epss-score-band 0.95:100 \
  --require-epss-score-band 0.99:100 \
  || degrade "the published map does not carry the coverage the host contract requires (the vendor fix-status overlay rows, a fresh known-exploited set, the Apple fix overlay or one of its products, the EPSS exploitability-probability overlay, or its high-severity percentile bands)"

# 8) Periodic git clone maintenance. The advisory-database and cvelistV5
#    clones accumulate pack objects from every fetch; a weekly gc + remote
#    prune reclaims that bloat. The ghsa clone in particular carries thousands
#    of stale remote-tracking refs (one per advisory-improvement PR).
GC_STAMP="$STATE_DIR/.gc_last_run"
RUN_GC=0
if [ ! -f "$GC_STAMP" ]; then
  RUN_GC=1
else
  GC_AGE=$(( ($(date +%s) - $(stat -c %Y "$GC_STAMP")) / 86400 ))
  if [ "$GC_AGE" -ge "$GC_INTERVAL_DAYS" ]; then
    RUN_GC=1
  fi
fi
# Re-compute free space here: the value from step 0 is stale after the
# ingest, refresh, purge, and publish steps (steps 1-7) may have consumed
# or freed significant disk. Using the pre-build value would miss a
# disk-space drop that happened during the build — the GC would not fire
# when it should, the clone bloat would not be reclaimed, and the operator
# would see no warning. The every-degradation-is-loud principle requires
# the disk-space trigger to read the current state, not a stale snapshot.
FREE_GB="$(_free_gb)"
echo "posture-spine: ${FREE_GB} GB free (post-build, before git maintenance)"
if [ "$FREE_GB" -lt "$DISK_WARN_GB" ]; then
  RUN_GC=1
fi
if [ "$RUN_GC" -eq 1 ]; then
  echo "posture-spine: running git clone maintenance (gc + prune)"
  # Every degradation is loud: a failed gc or prune must mark the run
  # DEGRADED (a non-zero exit at the end, visible in the journal) instead of
  # being swallowed by `|| true`. The clones keep their last-known-good
  # state on a failed gc, so the daily build still publishes a fresh map;
  # the loud failure tells the operator the clone bloat is not being
  # reclaimed before the disk guard has to act on it.
  GC_RAN=0
  GC_OK=1
  for repo in "$CVELIST_DIR/cvelistV5" "$GHSA_DIR/advisory-database"; do
    if [ -d "$repo/.git" ]; then
      GC_RAN=1
      # Capture stderr so the degrade message includes the actual error
      # (disk full, corrupt pack file, permission denied) instead of just
      # "git gc failed".  On a successful gc the captured stderr (progress
      # noise) is simply discarded because the || branch does not run.
      gc_err=$(git -C "$repo" remote prune origin 2>&1 1>/dev/null) || \
        { degrade "git remote prune failed for $repo: ${gc_err}; clone bloat not reclaimed, spine continues"; GC_OK=0; }
      gc_err=$(git -C "$repo" gc 2>&1 1>/dev/null) || \
        { degrade "git gc failed for $repo: ${gc_err}; clone bloat not reclaimed, spine continues"; GC_OK=0; }
    fi
  done
  # Only stamp a maintenance pass that actually ran and did not fail. A
  # failed gc must not push the next run out by GC_INTERVAL_DAYS -- the
  # clones are still bloated, so the next daily build retries maintenance
  # instead of waiting a week. When no clone directory exists yet, no
  # maintenance ran and no stamp is written either, so the next run retries
  # once the clones appear.
  if [ "$GC_RAN" -ne 0 ] && [ "$GC_OK" -ne 0 ]; then
    date -u +%Y-%m-%dT%H:%M:%SZ > "$GC_STAMP"
  fi
fi

if [ "$DEGRADED" -ne 0 ]; then
  echo "posture-spine: update finished DEGRADED ($(date -u +%Y-%m-%dT%H:%M:%SZ))"
  exit 1
fi

echo "posture-spine: update complete ($(date -u +%Y-%m-%dT%H:%M:%SZ))"
