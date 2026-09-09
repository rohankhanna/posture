#!/usr/bin/env bash
set -euo pipefail
umask 022

# Lightweight posture spine runner for a single small VPS.
# This is the data-plane job GitHub Actions used to own. It keeps the catalog
# fresh on a daily cadence, exports a local spine, and leaves signing/serving
# to the surrounding systemd and nginx deployment.
#
# Bounded-growth: a purge step (step 8) removes ancient defects that are no
# longer relevant, and a disk-space guard (step 0) triggers an aggressive purge
# if free space drops below a threshold. Git clones are periodically gc'd to
# reclaim pack-file bloat. The system is designed to stay within the VPS disk.

STATE_DIR="${POSTURE_STATE_DIR:-/var/lib/posture}"
EXPORT_DIR="${POSTURE_EXPORT_DIR:-/var/lib/posture}"
CVELIST_DIR="${POSTURE_CVELIST_DIR:-$STATE_DIR/cvelist}"
GHSA_DIR="${POSTURE_GHSA_DIR:-$STATE_DIR/ghsa}"
DB_PATH="${POSTURE_DB_PATH:-$STATE_DIR/posture.db}"
BACKFILL_CAP="${POSTURE_BACKFILL_CAP:-50000}"
OSV_CAP="${POSTURE_OSV_CAP:-5000}"
REFRESH_CAP="${POSTURE_REFRESH_CAP:-2000}"
PURGE_AGE_DAYS="${POSTURE_PURGE_AGE_DAYS:-3650}"
KEEP_EPSS_PERCENTILE="${POSTURE_KEEP_EPSS_PERCENTILE:-0.90}"
DISK_WARN_GB="${POSTURE_DISK_WARN_GB:-5}"
DISK_CRIT_GB="${POSTURE_DISK_CRIT_GB:-2}"
# Run git gc every N days (tracked in the state DB as a timestamp).
GC_INTERVAL_DAYS="${POSTURE_GC_INTERVAL_DAYS:-7}"

mkdir -p "$STATE_DIR" "$EXPORT_DIR" "$CVELIST_DIR" "$GHSA_DIR"
export POSTURE_CVELIST_DIR="$CVELIST_DIR"
export POSTURE_GHSA_DIR="$GHSA_DIR"
export POSTURE_DB_PATH="$DB_PATH"

_free_gb() {
  df -BG --output=avail "$STATE_DIR" | tail -1 | tr -dc '0-9'
}

echo "posture-spine: starting daily spine update ($(date -u +%Y-%m-%dT%H:%M:%SZ))"

# 0) Disk-space guard. If free space is critically low, run an aggressive
#    purge (1-year retention instead of 10-year) before anything else so the
#    pipeline does not fill the disk. If still critical after purge, abort.
FREE_GB=$(_free_gb)
echo "posture-spine: ${FREE_GB} GB free on ${STATE_DIR}"
if [ "$FREE_GB" -lt "$DISK_CRIT_GB" ]; then
  echo "posture-spine: CRITICAL disk space — running aggressive purge (365-day retention)"
  posture purge --max-age-days 365 --keep-epss-percentile 0.90 --db "$DB_PATH" || \
    echo "posture-spine: warning: aggressive purge failed"
  FREE_GB=$(_free_gb)
  if [ "$FREE_GB" -lt "$DISK_CRIT_GB" ]; then
    echo "posture-spine: ABORT — disk space still critical after purge (${FREE_GB} GB free)"
    exit 1
  fi
fi

# 1) Forward stream: pick up newly published skeletons.
posture stream --db "$DB_PATH"

# 2) Backfill historical skeletons once, then no-op on later runs.
posture backfill --cap "$BACKFILL_CAP" --db "$DB_PATH"

# 3) Peer overlays. Caps keep the small VPS bounded; each source is
#    incremental from the persistent database.
posture ingest ghsa --cap "$OSV_CAP" --db "$DB_PATH"
posture ingest osv --cap "$OSV_CAP" --db "$DB_PATH"
posture ingest kev --db "$DB_PATH"
posture ingest apple --db "$DB_PATH"

# 4) Distro fix overlays (Debian/Ubuntu) and EPSS exploitability overlay.
#    Best-effort: a transient source outage must not block the spine export.
posture ingest debian --release trixie --release bookworm \
  --package linux --db "$DB_PATH" || \
  echo "posture-spine: warning: debian ingest failed; last-known-good retained, spine continues"
posture ingest ubuntu --release noble --release jammy --release focal \
  --package linux --db "$DB_PATH" || \
  echo "posture-spine: warning: ubuntu ingest failed; last-known-good retained, spine continues"
posture ingest epss --db "$DB_PATH" || \
  echo "posture-spine: warning: epss ingest failed; last-known-good retained, spine continues"

# 5) Refresh the catalog with a per-run cap. The persistent DB means
#    later runs continue rather than restart.
posture refresh --no-devices --cap "$REFRESH_CAP" --db "$DB_PATH"

# 6) Keep the map honest without touching devices.
posture monitor run --db "$DB_PATH"
posture repair reconcile --db "$DB_PATH"
posture discover --db "$DB_PATH"

# 7) Export the spine to a stable directory. A downstream web server can
#    publish this directory directly; clients can pull only the shards they
#    need from the manifest.
posture spine export --db "$DB_PATH" --out "$EXPORT_DIR"

# 8) Bounded-growth purge. Remove ancient defects that are no longer relevant:
#    older than PURGE_AGE_DAYS, not in KEV, not high EPSS, not open on a
#    tracked distro, not in Apple fixes. Orphaned overlay rows are cleaned too.
#    Run AFTER export so the served spine reflects the purge immediately.
echo "posture-spine: running bounded-growth purge (age=${PURGE_AGE_DAYS}d, keep EPSS>=${KEEP_EPSS_PERCENTILE})"
posture purge \
  --max-age-days "$PURGE_AGE_DAYS" \
  --keep-epss-percentile "$KEEP_EPSS_PERCENTILE" \
  --db "$DB_PATH" || \
  echo "posture-spine: warning: purge failed; spine continues with current catalog"

# Re-export after purge so the served spine reflects the purged catalog.
if [ "${PURGE_AGE_DAYS:-0}" != "0" ]; then
  posture spine export --db "$DB_PATH" --out "$EXPORT_DIR"
fi

# 9) Periodic git clone maintenance. The advisory-database and cvelistV5
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
FREE_GB=$(_free_gb)
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

echo "posture-spine: update complete ($(date -u +%Y-%m-%dT%H:%M:%SZ))"
