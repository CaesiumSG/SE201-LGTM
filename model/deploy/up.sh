#!/usr/bin/env bash
# Ensure a model server is running on the cluster, then tunnel to it.
# Usage: up.sh [model] [walltime]   (defaults: DEFAULT_MODEL, SESSION_TIME from .env)
source "$(dirname "$0")/lib.sh"

live=$(live_endpoint)
if [[ -n "$live" ]]; then
  echo "server $live is already running; connecting"
  exec "$DEPLOY_DIR/connect.sh" "$live"
fi

pending=$(last_job serve)
if [[ -n "$pending" && -n "$(job_state "$pending")" ]]; then
  echo "serve job $pending is already queued; connecting once it is ready"
  exec "$DEPLOY_DIR/connect.sh" "$pending"
fi

"$DEPLOY_DIR/sync.sh"
release=$(current_release)

model=${1:-}
id=$(JOB_TIME="${2:-${SESSION_TIME:-}}" submit_gpu serve "$release" ${model:+"$model"})
record_job serve "$id" "$release"
echo "submitted serve job $id (${model:-$DEFAULT_MODEL})"

exec "$DEPLOY_DIR/connect.sh" "$id"
