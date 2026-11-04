#!/usr/bin/env bash
# Cancel a Kev-4B job started from this machine.
#
#   kev-down.sh          the most recent Kev-4B job
#   kev-down.sh <jobid>  that job, if it was started by kev-up.sh
source "$(dirname "$0")/lib.sh"

active=${1:-$(last_kev_job)}

[[ -n "$active" ]] || { echo "no Kev-4B job recorded; nothing cancelled"; exit 0; }
if ! { [[ -f "$KEV_JOBS" ]] && awk -v id="$active" '$2 == id { found = 1 } END { exit !found }' "$KEV_JOBS"; }; then
  echo "job $active is not a recorded Kev-4B job; nothing cancelled"
  exit 0
fi
remote "scancel $active"
echo "cancelled: $active"
