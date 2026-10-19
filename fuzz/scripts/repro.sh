#!/usr/bin/env bash
# Re-run one artifact under its target to reproduce the failure and print the
# sanitizer stack trace.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
require_tools

TARGET="${1:?usage: repro.sh <target> <artifact>}"
ARTIFACT="${2:?usage: repro.sh <target> <artifact>}"
require_target "$TARGET"

cd "$REPO_ROOT"
exec cargo +nightly fuzz run --fuzz-dir "$FUZZ_DIR" "$TARGET" "$ARTIFACT"
