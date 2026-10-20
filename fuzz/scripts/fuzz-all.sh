#!/usr/bin/env bash
# Launch every fuzz target in one detached tmux session, with one window per
# target and the available logical CPUs divided across targets.
#
#   fuzz-all.sh [max_total_time_seconds]   (0 means run until stopped)
#
# Environment:
#   SESSION  tmux session name (default: jose-rs-fuzz)
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
require_tools
command -v tmux >/dev/null || {
  echo "tmux not found; install it or use: just fuzz-one <target> <seconds>"
  exit 1
}

SESSION="${SESSION:-jose-rs-fuzz}"
TIME="${1:-0}"
CORES="$(nproc)"
TARGET_COUNT="${#ALL_TARGETS[@]}"
PER_TARGET=$((CORES / TARGET_COUNT))
[[ "$PER_TARGET" -lt 1 ]] && PER_TARGET=1

if tmux has-session -t "$SESSION" 2>/dev/null; then
  echo "tmux session '$SESSION' already exists."
  echo "Attach: tmux attach -t $SESSION"
  echo "Stop:   tmux kill-session -t $SESSION"
  exit 1
fi

"$(dirname "${BASH_SOURCE[0]}")/build.sh"

echo "cores=$CORES targets=$TARGET_COUNT cores/target=$PER_TARGET time=${TIME}s"
tmux new-session -d -s "$SESSION" -n "${ALL_TARGETS[0]}"
first=1
for target in "${ALL_TARGETS[@]}"; do
  if [[ "$first" -eq 0 ]]; then
    tmux new-window -t "$SESSION" -n "$target"
  fi
  first=0
  tmux send-keys -t "$SESSION:$target" \
    "JOBS=$PER_TARGET '$FUZZ_DIR/scripts/run.sh' '$target' '$TIME'" C-m
done

cat <<EOF
Launched $TARGET_COUNT targets x $PER_TARGET workers in tmux session '$SESSION'.
  Attach:      tmux attach -t $SESSION
  Next window: Ctrl-b n
  Previous:    Ctrl-b p
  Detach:      Ctrl-b d
  Stop all:    tmux kill-session -t $SESSION
  Artifacts:   $FUZZ_DIR/artifacts/<target>/
EOF
