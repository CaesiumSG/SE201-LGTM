#!/usr/bin/env bash
# Start one judged job (qwen3.8 + Kev-4B), run the Kev benchmarks against it, and always cancel the job.
# Usage: judged-bench.sh --export EXPORT --labels LABELS --run-dir RUNDIR --out OUTDIR [--results-dir DIR] [--wait-seconds N]
# Run from the repo root. PYTHON names the interpreter (default: python).
source "$(dirname "$0")/lib.sh"

export_file="" labels="" out="" run_src="" results="" wait_seconds=1800
while (($#)); do
  case "$1" in
    --run-dir) run_src=${2:?--run-dir needs a value}; shift 2 ;;
    --export) export_file=${2:?--export needs a value}; shift 2 ;;
    --labels) labels=${2:?--labels needs a value}; shift 2 ;;
    --out) out=${2:?--out needs a value}; shift 2 ;;
    --results-dir) results=${2:?--results-dir needs a value}; shift 2 ;;
    --wait-seconds) wait_seconds=${2:?--wait-seconds needs a value}; shift 2 ;;
    *) die "unknown argument: $1" ;;
  esac
done
[[ -n "$export_file" && -n "$labels" && -n "$out" && -n "$run_src" ]] || die "--export, --labels, --run-dir and --out are required"

for p in "$export_file" "$labels" "$run_src"; do [[ -e "$p" ]] || die "path not found: $p"; done

export PYTHONUTF8=1
py=${PYTHON:-python}
bench="$REPO_DIR/benchmark"

# evaluate_real reads its clones from the worktree cache.
cache="$bench/real_world/.cache"
missing=()
while IFS= read -r project; do
  [[ -d "$cache/$project/.git" ]] || missing+=("$project")
done < <(grep -o '"repo_url"[[:space:]]*:[[:space:]]*"[^"]*"' "$bench/real_world/cases.json" |
  sed -e 's/.*"\([^"]*\)"$/\1/' -e 's:/*$::' -e 's/\.git$//' -e 's:.*/::' | tr -d '\r' | sort -u)
((${#missing[@]} == 0)) || die "no clone for ${missing[*]} under $cache; run benchmark/real_world/fetch.py --policies first"

id=$("$DEPLOY_DIR/judged-up.sh") || die "job submission failed"
pids=()
cleanup() {
  trap - EXIT
  if ((${#pids[@]})); then kill "${pids[@]}" 2>/dev/null || true; fi
  remote "scancel $id" || echo "warning: could not cancel job $id" >&2
}
trap cleanup EXIT
trap 'exit 130' INT TERM

# The job's endpoint files appear only after each server answers.
ready() {
  [[ "$(job_state "$id")" == RUNNING ]] || return 1
  qwen_info=$(remote "cat ~/$REMOTE_ROOT/run/$id.env 2>/dev/null" | tr -d '\r') && [[ -n "$qwen_info" ]] &&
    kev_info=$(remote "cat ~/$REMOTE_ROOT/run/kev/$id.env 2>/dev/null" | tr -d '\r') && [[ -n "$kev_info" ]]
}
deadline=$((SECONDS + wait_seconds))
until ready; do
  ((SECONDS < deadline)) || die "job $id was not ready within ${wait_seconds}s"
  sleep 5
done

# Usage: tunnel <endpoint info> <local port>
tunnel() {
  local NODE="" PORT="" key value
  while IFS='=' read -r key value; do
    case "$key" in NODE|PORT) printf -v "$key" '%s' "$value" ;; esac
  done <<< "$1"
  trust_node "$NODE"
  node_ssh "$NODE" -N -o ExitOnForwardFailure=yes -L "$2:127.0.0.1:$PORT" &
  pids+=($!)
}
tunnel "$qwen_info" "$LOCAL_OLLAMA_PORT"
tunnel "$kev_info" "$KEV_LOCAL_PORT"
sleep 2
for p in "${pids[@]}"; do kill -0 "$p" 2>/dev/null || die "tunnel exited"; done

step() {
  local name=$1
  shift
  echo "== $name"
  "$@" || { echo "step failed: $name" >&2; exit 1; }
}

run_dir="$out/kev-bench-$(date +%Y%m%dT%H%M%S)"
resume=() resume_real=()
[[ -z "$results" ]] || { resume=(--output "$results/evaluate" --resume); resume_real=(--output "$results/evaluate-real" --resume); }
report="${results:-$run_dir}/judge-eval.json"

step kev-bench "$py" "$bench/kev_support/runner.py" --out "$run_dir"

echo "== judge-eval"
mkdir -p "$(dirname "$report")"
"$py" "$bench/judge_eval.py" "$run_src" "$export_file" "$labels" --live | tee "$report" || { echo "step failed: judge-eval" >&2; exit 1; }
judged_nothing=0
if ! grep -Eq '"judged"[[:space:]]*:[[:space:]]*[1-9]' "$report"; then
  echo "step failed: judge-eval judged no units" >&2
  judged_nothing=1
fi

step evaluate "$py" "$bench/evaluate.py" "${resume[@]}"
step evaluate-real "$py" "$bench/real_world/evaluate_real.py" "${resume_real[@]}"
((judged_nothing == 0)) || exit 1
