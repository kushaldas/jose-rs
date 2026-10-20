#!/usr/bin/env bash
# Run one fuzz target with multiple workers through libFuzzer fork mode.
#
#   run.sh <target> [max_total_time_seconds] [extra libFuzzer arguments...]
#
# Environment:
#   JOBS     fork workers (default: all logical CPUs)
#   MAX_LEN  maximum input length (default: 131072, large enough for every
#            checked-in seed and the certificate/DER parser boundaries)
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
require_tools

TARGET="${1:?usage: run.sh <target> [seconds] [extra libFuzzer arguments...]}"
TIME="${2:-0}"
shift || true
shift || true
require_target "$TARGET"

JOBS="${JOBS:-$(nproc)}"
MAX_LEN="${MAX_LEN:-131072}"

# Start from the curated corpus without overwriting discoveries from earlier
# runs. Crash artifacts remain separate under fuzz/artifacts/<target>/.
mkdir -p "$FUZZ_DIR/corpus/$TARGET"
if [[ -d "$FUZZ_DIR/seeds/$TARGET" ]]; then
  cp -n "$FUZZ_DIR/seeds/$TARGET/"* "$FUZZ_DIR/corpus/$TARGET/" 2>/dev/null || true
fi

cd "$REPO_ROOT"
echo ">> $TARGET  jobs=$JOBS  max_len=$MAX_LEN  time=${TIME}s"
exec cargo +nightly fuzz run --fuzz-dir "$FUZZ_DIR" "$TARGET" -- \
  -fork="$JOBS" \
  -ignore_crashes=1 \
  -rss_limit_mb=4096 \
  -max_len="$MAX_LEN" \
  -max_total_time="$TIME" \
  "$@"
