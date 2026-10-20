#!/usr/bin/env bash
# Build every fuzz target once so parallel campaigns do not contend on the
# initial cargo build lock.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
require_tools

cd "$REPO_ROOT"
echo "Building all jose-rs fuzz targets..."
cargo +nightly fuzz build --fuzz-dir "$FUZZ_DIR"
echo "Build OK. Binaries are under $FUZZ_DIR/target/."
