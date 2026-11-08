#!/bin/bash -l
#SBATCH --job-name=kev-serve
#SBATCH --nodes=1
#SBATCH --cpus-per-task=4
#SBATCH --mem=32G
#SBATCH --gres=gpu:3090:1
#SBATCH --time=08:00:00

# Serves jaredpalmer/kev-4b on a node-chosen loopback port and publishes NODE/PORT for kev-connect.sh.
source "$LLM_SERVE_APP/jobs/lib.sh"

export PATH="$HOME/.local/bin:$PATH" HF_HOME="$SCRATCH_DIR/kev-hf" UV_CACHE_DIR="$SCRATCH_DIR/kev-uv-cache"

PORT=$(python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')
RUN_DIR="$LLM_SERVE_ROOT/run/kev"
mkdir -p "$RUN_DIR"
rm -f "$RUN_DIR/$SLURM_JOB_ID.env"

cd "$LLM_SERVE_ROOT/kev/repo"
uv run --extra serve python -m kev.serve --run jaredpalmer/kev-4b@v1.0 --device cuda --port "$PORT" &
server=$!
trap 'kill $server 2>/dev/null; rm -f "$RUN_DIR/$SLURM_JOB_ID.env"; rm -rf "$TMPDIR"' EXIT

until curl -s --max-time 5 -o /dev/null "http://127.0.0.1:$PORT/v1/models"; do
  kill -0 "$server" 2>/dev/null || { echo "kev.serve exited before it was ready" >&2; exit 1; }
  sleep 5
done

umask 077
printf 'NODE=%s\nPORT=%s\n' "$SLURMD_NODENAME" "$PORT" > "$RUN_DIR/$SLURM_JOB_ID.env"
echo "kev-4b ready on $SLURMD_NODENAME:$PORT"
wait "$server"
