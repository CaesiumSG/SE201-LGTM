#!/usr/bin/env bash
# One command to run LGTM on a PR: install it, start the GPU job, open the
# tunnels, index the base branch's docs and run the review.
#
#   ./run-lgtm.sh review --repo PATH --base BRANCH --pr BRANCH [lgtm review options]
#   ./run-lgtm.sh setup            install LGTM into .venv (review does this too)
#   ./run-lgtm.sh up [HH:MM:SS]    start or reattach to the GPU job and open the tunnels
#   ./run-lgtm.sh status           show the tunnels and your cluster jobs
#   ./run-lgtm.sh down             close the tunnels and cancel the job this script started
#
# Needs the SCIS VPN and the one-time setup in model/README.md. Each step is
# skipped when it is already done, so it is safe to run again. The GPU job keeps
# running after a review, until `down` or its walltime.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV="$ROOT/.venv"
WAIT_SECONDS=${LGTM_WAIT_SECONDS:-1800}

die() { echo "error: $*" >&2; exit 1; }
say() { echo "==> $*"; }

usage() { sed -n '2,13p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; }

find_python() {
  local py
  for py in python3.13 python3 python; do
    if command -v "$py" >/dev/null 2>&1 &&
      "$py" -c 'import sys; sys.exit(sys.version_info < (3, 13))' 2>/dev/null; then
      echo "$py"
      return 0
    fi
  done
  die "Python 3.13 or newer not found"
}

# Reinstalls only when pyproject.toml is newer than the last install.
cmd_setup() {
  local stamp="$VENV/.run-lgtm-installed"
  if [[ ! -x "$VENV/bin/python" ]]; then
    say "creating .venv"
    "$(find_python)" -m venv "$VENV"
  fi
  if [[ ! "$stamp" -nt "$ROOT/pyproject.toml" ]]; then
    say "installing LGTM into .venv"
    "$VENV/bin/python" -m pip install --quiet -e "$ROOT[dev]" semgrep
    touch "$stamp"
  fi
  export PATH="$VENV/bin:$PATH" PYTHONUTF8=1
  command -v codegraph >/dev/null 2>&1 ||
    echo "note: codegraph not found; reviews run without the investigate_* tools (see README.md)"
}

load_cluster() {
  local lib="$ROOT/model/deploy/lib.sh"
  # lib.sh's `source <(...)` reads nothing on bash 3.2 until PR #31 is merged.
  if ((BASH_VERSINFO[0] < 4)) && grep -q 'source <(' "$lib"; then
    die "the deploy scripts need bash 4 or newer here (you have $BASH_VERSION); run: brew install bash"
  fi
  # shellcheck disable=SC1090
  source "$lib"
  QWEN_URL="http://127.0.0.1:$LOCAL_OLLAMA_PORT"
  KEV_URL="http://127.0.0.1:$KEV_LOCAL_PORT"
  OWN_JOBS="$STATE_DIR/run-lgtm-jobs"
}

qwen_ok() { curl -fsS --noproxy '*' -m 5 -o /dev/null "$QWEN_URL/api/tags" 2>/dev/null; }
kev_ok() { curl -fsS --noproxy '*' -m 5 -o /dev/null "$KEV_URL/v1/models" 2>/dev/null; }

check_cluster() {
  "$SSH_BIN" "${SSH_OPTS[@]}" -o ConnectTimeout=10 "$LOGIN" true ||
    die "cannot log in to $ORIGAMI_HOST; is the VPN on, and does your SSH key work without a prompt? (model/README.md)"
}

check_provisioned() {
  remote "test -d ~/$REMOTE_ROOT/kev/repo && test -d '$SCRATCH_DIR/ollama-models'" ||
    die "models are not on the cluster yet; run model/deploy/provision.sh and model/deploy/kev-provision.sh once, wait for them to finish, then try again"
}

# Sets QWEN_JOB and KEV_JOB: running servers if there are both, else this script's
# queued or running job, else a new job.
pick_jobs() {
  local walltime=${1:-} qwen kev own=""
  qwen=$(live_endpoint)
  kev=$(live_kev_endpoint)
  if [[ -n "$qwen" && -n "$kev" ]]; then
    say "using running servers (Qwen job $qwen, Kev job $kev)"
    QWEN_JOB=$qwen KEV_JOB=$kev
    return 0
  fi
  [[ -f "$OWN_JOBS" ]] && own=$(tail -n 1 "$OWN_JOBS")
  if [[ -z "$own" || -z "$(job_state "$own")" ]]; then
    check_provisioned
    say "submitting a GPU job for Qwen and Kev"
    own=$("$DEPLOY_DIR/judged-up.sh" ${walltime:+"$walltime"})
    [[ -n "$own" ]] || die "job submission failed"
    echo "$own" >> "$OWN_JOBS"
  fi
  QWEN_JOB=$own KEV_JOB=$own
}

endpoint() { remote "cat ~/$REMOTE_ROOT/run/$1.env 2>/dev/null" | tr -d '\r' || true; }

# The endpoint files appear once each server answers, so this covers queue and model load.
wait_ready() {
  local deadline=$((SECONDS + WAIT_SECONDS)) state
  say "waiting for the servers; Ctrl+C is safe, run this again to reattach"
  while :; do
    QWEN_INFO=$(endpoint "$QWEN_JOB")
    KEV_INFO=$(endpoint "kev/$KEV_JOB")
    [[ -n "$QWEN_INFO" && -n "$KEV_INFO" ]] && { echo >&2; return 0; }
    state=$(job_state "$QWEN_JOB")
    [[ -n "$state" ]] || die "job $QWEN_JOB ended before it was ready; see model/deploy/logs.sh $QWEN_JOB"
    ((SECONDS < deadline)) ||
      die "job $QWEN_JOB not ready after ${WAIT_SECONDS}s (state $state); it is still queued. Run this again to keep waiting, or ./run-lgtm.sh down"
    progress "$QWEN_JOB" "$state"
    sleep 10
  done
}

close_tunnel() {
  local pidfile="$STATE_DIR/tunnel-$1.pid" pid
  [[ -f "$pidfile" ]] || return 0
  pid=$(cat "$pidfile")
  # Check it is still our ssh, in case the pid was reused.
  if ps -p "$pid" -o comm= 2>/dev/null | grep -q ssh; then
    kill "$pid" 2>/dev/null || true
  fi
  rm -f "$pidfile"
}

# Usage: open_tunnel <name> <check function> <local port> <endpoint info>
open_tunnel() {
  local name=$1 check=$2 local_port=$3 info=$4 node port log pid
  "$check" && return 0
  close_tunnel "$name"
  node=$(sed -n 's/^NODE=//p' <<< "$info")
  port=$(sed -n 's/^PORT=//p' <<< "$info")
  [[ -n "$node" && -n "$port" ]] || die "bad endpoint file for $name: $info"
  trust_node "$node"
  log="$STATE_DIR/tunnel-$name.log"
  # Same options as node_ssh. ssh is started directly so that $! is its pid.
  nohup "$SSH_BIN" "${SSH_OPTS[@]}" \
    -o StrictHostKeyChecking=yes \
    -o "UserKnownHostsFile=\"$(native_path "$KNOWN_HOSTS")\"" \
    -J "$LOGIN" "$ORIGAMI_USER@$node" -N \
    -o ExitOnForwardFailure=yes \
    -L "$local_port:127.0.0.1:$port" > "$log" 2>&1 < /dev/null &
  pid=$!
  echo "$pid" > "$STATE_DIR/tunnel-$name.pid"
  for _ in {1..30}; do
    "$check" && { say "$name tunnel open on port $local_port"; return 0; }
    kill -0 "$pid" 2>/dev/null || break
    sleep 1
  done
  cat "$log" >&2
  close_tunnel "$name"
  die "$name tunnel did not come up on port $local_port; is something else using that port?"
}

cmd_up() {
  load_cluster
  if qwen_ok && kev_ok; then
    say "Qwen ($QWEN_URL) and Kev ($KEV_URL) are already reachable"
    return 0
  fi
  check_cluster
  pick_jobs "${1:-}"
  wait_ready
  open_tunnel qwen qwen_ok "$LOCAL_OLLAMA_PORT" "$QWEN_INFO"
  open_tunnel kev kev_ok "$KEV_LOCAL_PORT" "$KEV_INFO"
}

cmd_review() {
  local repo="" base="" pr="" output=lgtm-output name rc=0 args=()
  while (($#)); do
    case "$1" in
      --repo | --base | --pr | --output)
        (($# >= 2)) || die "$1 needs a value"
        printf -v "${1#--}" '%s' "$2"
        args+=("$1" "$2")
        shift
        ;;
      --repo=* | --base=* | --pr=* | --output=*)
        name=${1%%=*}
        printf -v "${name#--}" '%s' "${1#*=}"
        args+=("$1")
        ;;
      *) args+=("$1") ;;
    esac
    shift
  done
  [[ -n "$repo" && -n "$base" && -n "$pr" ]] || die "review needs --repo, --base and --pr; see ./run-lgtm.sh help"

  # Catch typos here, before a GPU job is started for nothing.
  local ref
  git -C "$repo" rev-parse --git-dir >/dev/null 2>&1 || die "$repo is not a git repository"
  for ref in "$base" "$pr"; do
    git -C "$repo" rev-parse --verify --quiet "$ref^{commit}" >/dev/null || die "no branch or commit '$ref' in $repo"
  done

  cmd_setup
  # The review only uses an index built from the base commit, so build it from there.
  say "indexing the docs on $base"
  lgtm index --repo "$repo" --ref "$base"
  cmd_up

  say "reviewing $pr against $base"
  # lgtm exits 2 both when the review needs a person and when it crashes. Only
  # a finished review writes the report, so a report newer than this file
  # tells the two apart.
  local started
  started=$(mktemp "${TMPDIR:-/tmp}/run-lgtm.XXXXXX")
  lgtm review --gpu-model qwen3.8-27b --ollama-url "$QWEN_URL" --judge-endpoint "$KEV_URL" "${args[@]}" || rc=$?
  local wrote=0
  [[ "$output/report.json" -nt "$started" ]] && wrote=1
  rm -f "$started"
  echo
  if ((rc <= 2 && !wrote)); then
    say "lgtm failed before writing a report (exit code $rc); see the error above"
    rc=3
  else
    case "$rc" in
      0) say "no vulnerabilities reported" ;;
      1) say "vulnerabilities reported" ;;
      2) say "nothing confirmed, but something needs a person: a candidate was not judged, an agent failed, or the PR changes policy docs; read the report" ;;
      *) say "lgtm failed with exit code $rc" ;;
    esac
  fi
  ((rc > 2)) || say "report: $output/report.md"
  echo "The GPU job is still running. Run ./run-lgtm.sh down when you are finished."
  return "$rc"
}

cmd_status() {
  load_cluster
  if qwen_ok; then echo "Qwen tunnel: up ($QWEN_URL)"; else echo "Qwen tunnel: down"; fi
  if kev_ok; then echo "Kev tunnel:  up ($KEV_URL)"; else echo "Kev tunnel:  down"; fi
  check_cluster
  echo "Your cluster jobs:"
  remote "squeue --me -o '%.10i %.14j %.9T %.10M %.10l %R'"
}

cmd_down() {
  load_cluster
  close_tunnel qwen
  close_tunnel kev
  say "tunnels closed"
  check_cluster
  local id live kept=""
  if [[ -f "$OWN_JOBS" ]]; then
    for id in $(sort -u "$OWN_JOBS"); do
      if [[ -n "$(job_state "$id")" ]]; then
        remote "scancel $id"
        say "cancelled job $id"
        kept="$kept $id "
      fi
    done
    rm -f "$OWN_JOBS"
  fi
  # Servers started some other way are left alone. `kept` holds the jobs already
  # dealt with, including any just cancelled that are still shutting down.
  for live in "$(live_endpoint)" "$(live_kev_endpoint)"; do
    [[ -n "$live" && "$kept" != *" $live "* ]] || continue
    kept="$kept $live "
    echo "note: job $live was not started by this script, so it is still running; stop it with model/deploy/down.sh $live"
  done
}

case "${1:-help}" in
  setup) cmd_setup ;;
  up) shift; cmd_up "$@" ;;
  review) shift; cmd_review "$@" ;;
  status) cmd_status ;;
  down) cmd_down ;;
  help | -h | --help) usage ;;
  *) usage >&2; exit 64 ;;
esac
