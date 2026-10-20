#!/usr/bin/env bash
# Remove corpus inputs that do not add coverage for the selected target.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
require_tools

TARGET="${1:?usage: minimize.sh <target>}"
require_target "$TARGET"

cd "$REPO_ROOT"
exec cargo +nightly fuzz cmin --fuzz-dir "$FUZZ_DIR" "$TARGET"
