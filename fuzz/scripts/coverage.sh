#!/usr/bin/env bash
# Generate an HTML line-coverage report for one target's accumulated corpus.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
require_tools

TARGET="${1:?usage: coverage.sh <target>}"
require_target "$TARGET"
cd "$REPO_ROOT"

cargo +nightly fuzz coverage --fuzz-dir "$FUZZ_DIR" "$TARGET"

TRIPLE="$(rustc +nightly -vV | sed -n 's/host: //p')"
PROFILE="$FUZZ_DIR/coverage/$TARGET/coverage.profdata"
OUTPUT="$FUZZ_DIR/coverage/$TARGET/html"
mkdir -p "$OUTPUT"

# cargo-fuzz's coverage binary layout has changed across releases. Locate the
# instrumented binary instead of depending on one exact target directory.
BINARY="$(find "$REPO_ROOT/target" "$FUZZ_DIR/target" -type f -name "$TARGET" -path '*coverage*release*' 2>/dev/null | head -1 || true)"
if [[ -z "$BINARY" || ! -f "$BINARY" ]]; then
  echo "coverage binary not found for $TARGET" >&2
  exit 1
fi
if [[ ! -f "$PROFILE" ]]; then
  echo "coverage profile not found at $PROFILE" >&2
  exit 1
fi

SYSROOT="$(rustc +nightly --print sysroot)"
LLVM_COV="$SYSROOT/lib/rustlib/$TRIPLE/bin/llvm-cov"
if [[ ! -x "$LLVM_COV" ]]; then
  echo "llvm-cov not found; run: rustup component add llvm-tools-preview --toolchain nightly" >&2
  exit 1
fi

DEMANGLER=()
command -v rustfilt >/dev/null 2>&1 && DEMANGLER=(-Xdemangler=rustfilt)

"$LLVM_COV" show \
  "${DEMANGLER[@]}" \
  "$BINARY" \
  -instr-profile="$PROFILE" \
  -show-line-counts-or-regions \
  -show-instantiations \
  -format=html \
  -output-dir="$OUTPUT" \
  "$REPO_ROOT/src"

echo "Coverage HTML: $OUTPUT/index.html"
