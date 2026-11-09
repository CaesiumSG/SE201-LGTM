#!/usr/bin/env bash
# Tunnel localhost:$LOCAL_OLLAMA_PORT to a running model server.
# Usage: connect.sh [jobid]   (default: newest running server, including mynotebook sessions)
# Ctrl+C closes the tunnel only; the server keeps running until deploy/down.sh or its walltime.
source "$(dirname "$0")/lib.sh"

id=${1:-$(live_endpoint)}
[[ -n "$id" ]] || die "no running server found; start one with deploy/up.sh"

wait_running "$id"

# serve_model.ipynb writes the endpoint file only after the model is loaded and
# answered a test prompt, which takes a while on a cold start.
echo "waiting for the server in job $id to become ready"
until info=$(remote "cat ~/$REMOTE_ROOT/run/$id.env 2>/dev/null" | tr -d '\r') && [[ -n "$info" ]]; do
  [[ "$(job_state "$id")" == RUNNING ]] || die "job $id ended before it was ready; see deploy/logs.sh $id"
  sleep 5
done

NODE="" PORT="" MODEL=""
while IFS='=' read -r key value; do
  case "$key" in
    NODE|PORT|MODEL) printf -v "$key" '%s' "$value" ;;
  esac
done <<< "$info"

trust_node "$NODE"

cat <<EOF

Server in job $id on $NODE, model $MODEL
  Ollama API: http://127.0.0.1:$LOCAL_OLLAMA_PORT

Tunnel open. Ctrl+C closes it; the server keeps running (deploy/down.sh $id stops it).
EOF

node_ssh "$NODE" -N \
  -o ExitOnForwardFailure=yes \
  -L "$LOCAL_OLLAMA_PORT:127.0.0.1:$PORT"
