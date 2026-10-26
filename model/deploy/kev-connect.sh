#!/usr/bin/env bash
# Tunnel localhost:$KEV_LOCAL_PORT to a running Kev-4B server.
# Usage: kev-connect.sh [jobid]   (default: newest running Kev-4B server)
# Ctrl+C closes the tunnel only; the server keeps running until deploy/kev-down.sh or its walltime.
source "$(dirname "$0")/lib.sh"

id=${1:-$(live_kev_endpoint)}
[[ -n "$id" ]] || die "no running Kev-4B server found; start one with deploy/kev-up.sh"

wait_running "$id"

# kev-serve.sbatch writes the endpoint file only after the server answers.
echo "waiting for the Kev-4B server in job $id to become ready"
until info=$(remote "cat ~/$REMOTE_ROOT/run/kev/$id.env 2>/dev/null" | tr -d '\r') && [[ -n "$info" ]]; do
  [[ "$(job_state "$id")" == RUNNING ]] || die "job $id ended before it was ready; see deploy/kev-logs.sh $id"
  sleep 5
done

NODE="" PORT=""
while IFS='=' read -r key value; do
  case "$key" in
    NODE|PORT) printf -v "$key" '%s' "$value" ;;
  esac
done <<< "$info"

trust_node "$NODE"

cat <<EOF

Kev-4B in job $id on $NODE
  System One API: http://127.0.0.1:$KEV_LOCAL_PORT/v1/systemone

Tunnel open. Ctrl+C closes it; the server keeps running (deploy/kev-down.sh $id stops it).
EOF

node_ssh "$NODE" -N \
  -o ExitOnForwardFailure=yes \
  -L "$KEV_LOCAL_PORT:127.0.0.1:$PORT"
