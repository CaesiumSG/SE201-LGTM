#!/usr/bin/env bash
# Pull every model in $MODELS into cluster scratch, in a CPU-only job (runs src/pull_models.ipynb).
# Idempotent: models already present are skipped.
source "$(dirname "$0")/lib.sh"

"$DEPLOY_DIR/sync.sh"
release=$(current_release)

id=$(submit provision "$release")
record_job provision "$id" "$release"
echo "submitted provision job $id"

state=$(wait_finished "$id")
remote "tail -n 25 ~/$REMOTE_ROOT/logs/llm-provision-$id.out"
echo "provision job $id: $state"
[[ "$state" == COMPLETED ]]
