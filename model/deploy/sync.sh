#!/usr/bin/env bash
# Deploy the working copy of model/ (tracked + untracked, minus .gitignore'd files)
# to ~/$REMOTE_ROOT/app/<tree-hash> and point app/current at it. Releases are
# content-addressed: re-syncing unchanged code uploads nothing, and changes
# outside model/ never produce a new release.
source "$(dirname "$0")/lib.sh"
cd "$REPO_DIR"

tmp_index=$(mktemp)
trap 'rm -f "$tmp_index"' EXIT
cp "$(git rev-parse --git-dir)/index" "$tmp_index"
GIT_INDEX_FILE="$tmp_index" git -c core.safecrlf=false add -A model 2>/dev/null
tree=$(GIT_INDEX_FILE="$tmp_index" git write-tree --prefix=model/)
release=${tree:0:12}

label=$(git rev-parse --short HEAD)
[[ "$tree" == "$(git rev-parse 'HEAD:model' 2>/dev/null)" ]] || label="$label+uncommitted"

if remote "test -d ~/$REMOTE_ROOT/app/$release"; then
  echo "release $release ($label) already on the cluster"
else
  echo "uploading release $release ($label)"
  # autocrlf off: ship the LF blobs as stored, not Windows checkout line endings.
  git -c core.autocrlf=false archive --format=tar "$tree" \
    | remote "set -e; d=~/$REMOTE_ROOT/app/$release; rm -rf \$d.partial; mkdir -p \$d.partial; tar -x -C \$d.partial; mv \$d.partial \$d"
fi

tr -d '\r' < "$MODEL_DIR/.env" \
  | remote "set -e; mkdir -p ~/$REMOTE_ROOT; cd ~/$REMOTE_ROOT
            mkdir -p run logs
            chmod 700 run
            ln -sfn $release app/current
            ln -sfn app/current/src notebooks
            cat > cluster.env
            printf '%s %s %s\n' \"\$(date +%FT%T)\" $release '$label' >> releases.log"

echo "$release" > "$STATE_DIR/release"
echo "app/current -> $release"
