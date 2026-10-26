#!/usr/bin/env bash
# check_spine_size — the pre-push size guard for the committed spine.
#
# The repository host refuses a push that contains a file above its hard
# per-file limit, so an oversize spine file is a map that cannot be published.
# The export already caps every shard it writes (see posture/export.py), but
# the committed spine/ tree is the artifact that gets pushed, so the guard
# checks the bytes that are actually on disk.
#
# Usage: check_spine_size.sh [DIR ...]   (default: spine)
# Exits 0 when every file is within the limit, 1 otherwise.
set -euo pipefail

LIMIT_BYTES="${POSTURE_MAX_FILE_BYTES:-104857600}"   # 100 MiB
DIRS=("$@")
if [ "${#DIRS[@]}" -eq 0 ]; then
  DIRS=("spine")
fi

status=0
for dir in "${DIRS[@]}"; do
  if [ ! -d "$dir" ]; then
    echo "check_spine_size: no such directory: $dir (skipped)"
    continue
  fi
  offenders="$(find "$dir" -type f -size +"${LIMIT_BYTES}"c -printf '%s %p\n' | sort -rn)"
  if [ -n "$offenders" ]; then
    echo "check_spine_size: FAIL — files above the ${LIMIT_BYTES}-byte limit in $dir:"
    echo "$offenders" | while read -r size path; do
      echo "  ${path} (${size} bytes)"
    done
    status=1
  else
    echo "check_spine_size: OK — every file in $dir is within ${LIMIT_BYTES} bytes"
  fi
done

exit "$status"
