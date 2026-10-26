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
  echo "posture-spine: CRITICAL disk space — running aggressive purge (365-day retention)"
  if ! posture purge --max-age-days 365 --keep-epss-percentile 0.90 --db "$DB_PATH"; then
    echo "posture-spine: aggressive purge failed"
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
posture stream --db "$DB_PATH"

# 2) Backfill historical skeletons once, then no-op on later runs.
posture backfill --cap "$BACKFILL_CAP" --db "$DB_PATH"

# 3) Peer overlays. Caps keep the small VPS bounded; each source is
#    incremental from the persistent database.
posture ingest ghsa --cap "$OSV_CAP" --db "$DB_PATH"

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
  echo "posture-spine: warning: nvd-cpe ingest incomplete; last-known-good retained, spine continues"
posture ingest osv --cap "$OSV_CAP" --db "$DB_PATH"
posture ingest kev --db "$DB_PATH"
posture ingest apple --db "$DB_PATH"

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
  echo "::warning::ubuntu ingest failed; last-known-good retained, spine continues"
fi
posture ingest debian --release trixie --release bookworm \
  --package linux --db "$DB_PATH"
if [ $? -ne 0 ]; then
  echo "::warning::debian ingest failed; last-known-good retained, spine continues"
fi
set -e

# 4) Refresh the catalog with a small per-run cap. The persistent DB means
#    later runs continue rather than restart.
posture refresh --no-devices --cap "$REFRESH_CAP" --db "$DB_PATH"

# 5) Keep the map honest without touching devices.
posture monitor run --db "$DB_PATH"
posture repair reconcile --db "$DB_PATH"
posture discover --db "$DB_PATH"

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
posture spine verify --from "$EXPORT_DIR" \
  --require-overlay ubuntu_fixes --require-overlay debian_fixes \
  || degrade "the published map does not carry the vendor fix-status overlay rows"

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
if [ "$FREE_GB" -lt "$DISK_WARN_GB" ]; then
  RUN_GC=1
fi
if [ "$RUN_GC" -eq 1 ]; then
  echo "posture-spine: running git clone maintenance (gc + prune)"
  for repo in "$CVELIST_DIR/cvelistV5" "$GHSA_DIR/advisory-database"; do
    if [ -d "$repo/.git" ]; then
      git -C "$repo" remote prune origin 2>/dev/null || true
      git -C "$repo" gc 2>/dev/null || true
    fi
  done
  date -u +%Y-%m-%dT%H:%M:%SZ > "$GC_STAMP"
fi

if [ "$DEGRADED" -ne 0 ]; then
  echo "posture-spine: update finished DEGRADED ($(date -u +%Y-%m-%dT%H:%M:%SZ))"
  exit 1
fi

echo "posture-spine: update complete ($(date -u +%Y-%m-%dT%H:%M:%SZ))"
