#!/usr/bin/env bash
# Cancel jobs started from this machine.
#
#   down.sh          the most recent serve job
#   down.sh <jobid>  that job (also works for a mynotebook session)
#   down.sh all      every recorded job that is still queued or running
source "$(dirname "$0")/lib.sh"

case "${1:-}" in
  all)
    [[ -f "$STATE_DIR/jobs" ]] || die "no jobs recorded"
    ids=$(awk '{ print $3 }' "$STATE_DIR/jobs" | sort -u | tr '\n' ',')
    active=$(remote "squeue -h --me -j ${ids%,} -o %i 2>/dev/null" | tr -d '\r' | tr '\n' ' ')
    ;;
  "") active=$(last_job serve) ;;
  *) active=$1 ;;
esac

[[ -n "${active// /}" ]] || { echo "nothing to cancel"; exit 0; }
remote "scancel $active"
echo "cancelled: $active"
