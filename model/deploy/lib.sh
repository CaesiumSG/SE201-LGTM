# Sourced by the other deploy scripts.
set -euo pipefail

DEPLOY_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODEL_DIR="$(dirname "$DEPLOY_DIR")"
REPO_DIR="$(dirname "$MODEL_DIR")"
STATE_DIR="$MODEL_DIR/.state"
mkdir -p "$STATE_DIR"

die() { echo "error: $*" >&2; exit 1; }

[[ -f "$MODEL_DIR/.env" ]] || die "$MODEL_DIR/.env not found; copy .env.example and fill it in"
set -a
# shellcheck disable=SC1090
source <(tr -d '\r' < "$MODEL_DIR/.env")
set +a

: "${REMOTE_ROOT:=llm-serve}"
: "${LOCAL_OLLAMA_PORT:=11435}"
: "${FALLBACK_GRES:=gpu:rtx_pro_6000_blackwell_max:1}"

# Only the Windows OpenSSH client can use the Windows ssh-agent service.
if [[ -x /c/Windows/System32/OpenSSH/ssh.exe ]]; then
  SSH_BIN=/c/Windows/System32/OpenSSH/ssh.exe
  native_path() { cygpath -w "$1"; }
else
  SSH_BIN=ssh
  native_path() { printf '%s\n' "$1"; }
fi

LOGIN="$ORIGAMI_USER@$ORIGAMI_HOST"
KNOWN_HOSTS="$STATE_DIR/known_hosts"
SSH_OPTS=(
  -i "$(native_path "${ORIGAMI_SSH_KEY/#\~/$HOME}")"
  -o BatchMode=yes
  -o ServerAliveInterval=30
  -o ServerAliveCountMax=4
)

remote() { "$SSH_BIN" "${SSH_OPTS[@]}" "$LOGIN" "$@"; }

# Compute-node host keys are fetched through the already-trusted login node,
# so the jump hop never relies on an interactive trust-on-first-use prompt.
trust_node() {
  local node=$1 key
  touch "$KNOWN_HOSTS"
  grep -q "^$node " "$KNOWN_HOSTS" && return 0
  key=$(remote "ssh-keyscan -t ed25519 $node 2>/dev/null" | tr -d '\r' | grep -v '^#' || true)
  [[ -n "$key" ]] || die "could not fetch the host key for $node"
  printf '%s\n' "$key" >> "$KNOWN_HOSTS"
}

node_ssh() {
  local node=$1
  shift
  # ssh splits UserKnownHostsFile on whitespace unless the path is quoted.
  "$SSH_BIN" "${SSH_OPTS[@]}" \
    -o StrictHostKeyChecking=yes \
    -o "UserKnownHostsFile=\"$(native_path "$KNOWN_HOSTS")\"" \
    -J "$LOGIN" "$ORIGAMI_USER@$node" "$@"
}

record_job() { printf '%s %s %s %s\n' "$(date +%FT%T)" "$1" "$2" "$3" >> "$STATE_DIR/jobs"; }

last_job() {
  [[ -f "$STATE_DIR/jobs" ]] || return 0
  awk -v kind="${1:-}" 'kind == "" || $2 == kind { id = $3 } END { print id }' "$STATE_DIR/jobs"
}

job_state() { remote "squeue -h -j $1 -o %T 2>/dev/null" | tr -d '\r'; }

final_state() { remote "sacct -n -X -j $1 -o State%20" | tr -d '\r ' | head -n 1; }

# Newest endpoint file whose job is still running. Covers both deploy/up.sh jobs
# and serve_model.ipynb started by hand in a mynotebook session.
live_endpoint() {
  remote "cd ~/$REMOTE_ROOT/run 2>/dev/null || exit 0
    for f in \$(ls -t *.env 2>/dev/null); do
      id=\${f%.env}
      [[ \"\$(squeue -h -j \$id -o %T 2>/dev/null)\" == RUNNING ]] && { echo \$id; break; }
    done
    exit 0" | tr -d '\r'
}

current_release() {
  [[ -f "$STATE_DIR/release" ]] || die "nothing deployed yet; run deploy/sync.sh"
  cat "$STATE_DIR/release"
}

# Usage: submit <job> <release> [job args...]; prints the job id.
# Set JOB_TIME or JOB_GRES to override the walltime or GPU request in the sbatch file.
submit() {
  local job=$1 release=$2
  shift 2
  local time_arg="" gres_arg="" args=""
  [[ -n "${JOB_TIME:-}" ]] && time_arg="--time=$JOB_TIME"
  [[ -n "${JOB_GRES:-}" ]] && gres_arg="--gres=$JOB_GRES"
  (($#)) && args=$(printf '%q ' "$@")
  remote "cd ~/$REMOTE_ROOT && sbatch --parsable \
    --account=$SLURM_ACCOUNT --partition=$SLURM_PARTITION --qos=$SLURM_QOS \
    --mail-user=$NOTIFY_EMAIL --mail-type=END,FAIL $time_arg $gres_arg \
    --output=logs/%x-%j.out \
    --export=ALL,LLM_SERVE_ROOT=\$HOME/$REMOTE_ROOT,LLM_SERVE_APP=\$HOME/$REMOTE_ROOT/app/$release \
    app/$release/jobs/$job.sbatch $args" | tr -d '\r' | cut -d';' -f1
}

# Like submit, but resubmits with FALLBACK_GRES when the sbatch file's GPU type has
# no free card. Jobs held by a QOS limit stay queued.
submit_gpu() {
  local id state reason
  id=$(submit "$@")
  for _ in {1..10}; do
    read -r state reason < <(remote "squeue -h -j $id -o '%T %r'" | tr -d '\r') || true
    [[ "$state" == PENDING && "$reason" =~ ^(None|Resources|Priority)$ ]] || { echo "$id"; return 0; }
    sleep 3
  done
  remote "scancel $id"
  echo "no free GPU for job $id; resubmitting with $FALLBACK_GRES" >&2
  JOB_GRES=$FALLBACK_GRES submit "$@"
}

# Progress goes to stderr so callers can capture the result on stdout.
progress() { printf '\r%s: %s ' "$1" "$2" >&2; }

# Blocks until the job leaves PENDING; fails if it is no longer queued.
wait_running() {
  local id=$1 state
  while :; do
    state=$(job_state "$id")
    case "$state" in
      RUNNING) echo >&2; return 0 ;;
      "") echo >&2; die "job $id is no longer queued ($(final_state "$id")); see deploy/logs.sh $id" ;;
      *) progress "$id" "$state"; sleep 10 ;;
    esac
  done
}

# Blocks until the job leaves the queue; prints its final Slurm state.
wait_finished() {
  local id=$1 state
  while state=$(job_state "$id") && [[ -n "$state" ]]; do
    progress "$id" "$state"
    sleep 15
  done
  echo >&2
  final_state "$id"
}
