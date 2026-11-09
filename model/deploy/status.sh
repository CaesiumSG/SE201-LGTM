#!/usr/bin/env bash
# Show queued/running jobs on the cluster and the jobs recorded from this machine.
source "$(dirname "$0")/lib.sh"

remote "squeue --me -o '%.10i %.22j %.10T %.10M %.10L %.8N %R'"
echo
echo "recorded from this machine (most recent last):"
tail -n 8 "$STATE_DIR/jobs" 2>/dev/null || echo "  none"
