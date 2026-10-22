#!/bin/bash -l
#SBATCH --job-name=judged-serve
#SBATCH --nodes=1
#SBATCH --cpus-per-task=4
#SBATCH --mem=32G
#SBATCH --gres=gpu:a40:1
#SBATCH --time=08:00:00

# Serves DEFAULT_MODEL through Ollama and jaredpalmer/kev-4b on one 48 GB GPU.
# Publishes run/<jobid>.env for connect.sh and run/kev/<jobid>.env for kev-connect.sh.
source "$LLM_SERVE_APP/jobs/lib.sh"

export PATH="$HOME/.local/bin:$PATH" HF_HOME="$SCRATCH_DIR/kev-hf" UV_CACHE_DIR="$SCRATCH_DIR/kev-uv-cache"

KEV_PORT=$(python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')
KEV_RUN_DIR="$LLM_SERVE_ROOT/run/kev"
mkdir -p "$KEV_RUN_DIR"
rm -f "$KEV_RUN_DIR/$SLURM_JOB_ID.env"

(cd "$LLM_SERVE_ROOT/kev/repo" && exec uv run --extra serve python -m kev.serve --run jaredpalmer/kev-4b@v1.0 --device cuda --port "$KEV_PORT") &
kev=$!
trap 'kill $kev 2>/dev/null; rm -f "$KEV_RUN_DIR/$SLURM_JOB_ID.env"; rm -rf "$TMPDIR"' EXIT

# Kev loads first so Ollama sizes its allocation against the memory Kev leaves.
until curl -s -o /dev/null "http://127.0.0.1:$KEV_PORT/v1/models"; do
  kill -0 "$kev" 2>/dev/null || { echo "kev.serve exited before it was ready" >&2; exit 1; }
  sleep 5
done
umask 077
printf 'NODE=%s\nPORT=%s\n' "$SLURMD_NODENAME" "$KEV_PORT" > "$KEV_RUN_DIR/$SLURM_JOB_ID.env"
umask 022
echo "kev-4b ready on $SLURMD_NODENAME:$KEV_PORT"

export SERVE_HEADLESS=1
run_notebook "$LLM_SERVE_APP/src/serve_model.ipynb"
