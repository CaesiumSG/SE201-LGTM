#!/usr/bin/env bash
# Submit one job serving DEFAULT_MODEL and Kev-4B on a single GPU; prints the job id.
# Usage: judged-up.sh [walltime]   (default: SESSION_TIME from .env)
# Tunnel with deploy/connect.sh <jobid> and deploy/kev-connect.sh <jobid>; stop with deploy/down.sh <jobid>.
source "$(dirname "$0")/lib.sh"

"$DEPLOY_DIR/sync.sh" >&2
release=$(current_release)

id=$(JOB_TIME="${1:-${SESSION_TIME:-}}" submit judged-serve "$release")
record_job judged-serve "$id" "$release"
record_kev_job "$id" "$release"
echo "$id"
