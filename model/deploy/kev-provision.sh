#!/usr/bin/env bash
# Install the Kev server and download jaredpalmer/kev-4b into cluster scratch, on the login node.
# Idempotent: an existing checkout and cached weights are reused.
source "$(dirname "$0")/lib.sh"

"$DEPLOY_DIR/sync.sh"

remote "set -e
  export PATH=\$HOME/.local/bin:\$PATH HF_HOME=$SCRATCH_DIR/kev-hf UV_CACHE_DIR=$SCRATCH_DIR/kev-uv-cache
  command -v uv >/dev/null || { echo 'uv not found on the login node; install it first' >&2; exit 1; }
  mkdir -p ~/$REMOTE_ROOT/kev && cd ~/$REMOTE_ROOT/kev
  [ -d repo ] || git clone https://github.com/jaredpalmer/kev.git repo
  cd repo
  uv sync --extra serve
  uv run --extra serve python -c 'from huggingface_hub import snapshot_download; print(snapshot_download(\"jaredpalmer/kev-4b\", revision=\"v1.0\"))'
  # kev.serve loads the adapter's base model at start-up.
  uv run --extra serve python -c 'import json, pathlib; from huggingface_hub import snapshot_download; d = pathlib.Path(snapshot_download(\"jaredpalmer/kev-4b\", revision=\"v1.0\")); base = json.loads((d / \"adapter_config.json\").read_text())[\"base_model_name_or_path\"]; rev = json.loads((d / \"training_config.json\").read_text())[\"base_revision\"]; print(snapshot_download(base, revision=rev))'"
echo "Kev-4B provisioned"
