#!/usr/bin/env bash
# Run any notebook in model/ headless as a GPU job against freshly synced code.
# Usage: run.sh <notebook path relative to model/> [walltime]
#   e.g. run.sh src/serve_model.ipynb 02:00:00
source "$(dirname "$0")/lib.sh"

notebook=${1:-}
[[ -n "$notebook" ]] || die "usage: run.sh <notebook path relative to model/> [walltime]"
[[ -f "$MODEL_DIR/$notebook" ]] || die "$MODEL_DIR/$notebook not found"

"$DEPLOY_DIR/sync.sh"
release=$(current_release)

id=$(JOB_TIME="${2:-}" submit notebook "$release" "$notebook")
record_job notebook "$id" "$release"
echo "submitted notebook job $id ($notebook, release $release)"
echo "  progress: deploy/logs.sh $id -f"
