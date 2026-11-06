#!/usr/bin/env bash
# Run one stream of the final evaluation and log every run to manifest.jsonl.
#
# Usage: benchmark/final_eval/run_stream.sh <stream-file>
#
# A stream file has one run per line: `<run_id> <command...>`. Blank lines and
# lines starting with # are skipped. The variables GPU_JOB and STREAM are taken
# from the environment and recorded. A run whose id already has an "ok" entry
# in the manifest is skipped, so a stream can be restarted after a dropped
# tunnel; the runners themselves are called with --resume where they support it.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
MANIFEST="$HERE/manifest.jsonl"
LOGS="$HERE/logs"
LEDGER="${HOME}/.lgtm/bedrock-spend.jsonl"
mkdir -p "$LOGS"
cd "$ROOT"

ledger_total() {
  python3 - "$LEDGER" <<'EOF'
import json, sys
total = 0.0
try:
    for line in open(sys.argv[1]):
        try:
            total += float(json.loads(line).get("usd") or 0)
        except (ValueError, AttributeError):
            pass
except FileNotFoundError:
    pass
print(f"{total:.4f}")
EOF
}

done_ok() {
  [[ -f "$MANIFEST" ]] && python3 - "$MANIFEST" "$1" <<'EOF'
import json, sys
for line in open(sys.argv[1]):
    r = json.loads(line)
    if r.get("run_id") == sys.argv[2] and r.get("status") == "ok":
        sys.exit(0)
sys.exit(1)
EOF
}

stream_file="$1"
while IFS= read -r line || [[ -n "$line" ]]; do
  [[ -z "${line// }" || "$line" == \#* ]] && continue
  run_id="${line%% *}"
  cmd="${line#* }"
  if done_ok "$run_id"; then
    echo "skip $run_id (already ok)"
    continue
  fi
  sha="$(git rev-parse HEAD)"
  dirty="$(git status --porcelain --untracked-files=no | wc -l | tr -d ' ')"
  start="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  usd_before="$(ledger_total)"
  echo "[$start] start $run_id: $cmd"
  bash -c "$cmd" >> "$LOGS/$run_id.log" 2>&1
  code=$?
  end="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  usd_after="$(ledger_total)"
  status=ok
  [[ $code -eq 0 ]] || status=failed
  python3 - "$MANIFEST" <<EOF
import json, sys
row = {
    "run_id": "$run_id", "stream": "${STREAM:-}", "gpu_job": "${GPU_JOB:-}",
    "git_commit": "$sha", "tracked_changes": int("$dirty"),
    "command": $(printf '%s' "$cmd" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))'),
    "start": "$start", "end": "$end", "exit_code": $code, "status": "$status",
    "bedrock_usd_before": float("$usd_before"), "bedrock_usd_after": float("$usd_after"),
    "bedrock_usd_run": round(float("$usd_after") - float("$usd_before"), 4),
    "log": "benchmark/final_eval/logs/$run_id.log",
}
with open(sys.argv[1], "a") as f:
    f.write(json.dumps(row) + "\n")
EOF
  echo "[$end] $status $run_id (exit $code, bedrock +\$$(python3 -c "print(round($usd_after-$usd_before,2))"))"
done < "$stream_file"
