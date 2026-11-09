#!/usr/bin/env bash
# Print a job's log (default: the most recent recorded job). -f follows it.
source "$(dirname "$0")/lib.sh"

follow=""
id=""
for arg in "$@"; do
  case "$arg" in
    -f) follow=1 ;;
    *) id=$arg ;;
  esac
done
id=${id:-$(last_job)}
[[ -n "$id" ]] || die "no job recorded; pass a job id"

if [[ -n "$follow" ]]; then
  "$SSH_BIN" "${SSH_OPTS[@]}" -t "$LOGIN" "tail -n 50 -F ~/$REMOTE_ROOT/logs/*-$id.out"
else
  remote "cat ~/$REMOTE_ROOT/logs/*-$id.out"
fi
