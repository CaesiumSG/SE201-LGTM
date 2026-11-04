#!/usr/bin/env bash
# Ensure a Kev-4B server is running on the cluster, then tunnel to it.
# Usage: kev-up.sh [walltime]   (default: SESSION_TIME from .env)
source "$(dirname "$0")/lib.sh"

live=$(live_kev_endpoint)
if [[ -n "$live" ]]; then
  echo "Kev-4B server $live is already running; connecting"
  exec "$DEPLOY_DIR/kev-connect.sh" "$live"
fi

pending=$(last_kev_job)
if [[ -n "$pending" && -n "$(job_state "$pending")" ]]; then
  echo "Kev-4B job $pending is already queued; connecting once it is ready"
  exec "$DEPLOY_DIR/kev-connect.sh" "$pending"
fi

"$DEPLOY_DIR/sync.sh"
release=$(current_release)

id=$(JOB_TIME="${1:-${SESSION_TIME:-}}" submit_gpu kev-serve "$release")
record_kev_job "$id" "$release"
echo "submitted Kev-4B job $id"

exec "$DEPLOY_DIR/kev-connect.sh" "$id"
