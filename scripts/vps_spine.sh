#!/usr/bin/env bash
set -euo pipefail
umask 022

# Lightweight posture spine runner for a single small VPS.
# This is the data-plane job GitHub Actions used to own. It keeps the catalog
# fresh on a daily cadence, exports a local spine, and leaves signing/serving
# to the surrounding systemd and nginx deployment.

STATE_DIR="${POSTURE_STATE_DIR:-/var/lib/posture}"
EXPORT_DIR="${POSTURE_EXPORT_DIR:-/var/lib/posture}"
CVELIST_DIR="${POSTURE_CVELIST_DIR:-$STATE_DIR/cvelist}"
GHSA_DIR="${POSTURE_GHSA_DIR:-$STATE_DIR/ghsa}"
DB_PATH="${POSTURE_DB_PATH:-$STATE_DIR/posture.db}"
BACKFILL_CAP="${POSTURE_BACKFILL_CAP:-50000}"
OSV_CAP="${POSTURE_OSV_CAP:-5000}"
REFRESH_CAP="${POSTURE_REFRESH_CAP:-2000}"

mkdir -p "$STATE_DIR" "$EXPORT_DIR" "$CVELIST_DIR" "$GHSA_DIR"
export POSTURE_CVELIST_DIR="$CVELIST_DIR"
export POSTURE_GHSA_DIR="$GHSA_DIR"
export POSTURE_DB_PATH="$DB_PATH"

echo "posture-spine: starting daily spine update"

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

echo "posture-spine: update complete"
