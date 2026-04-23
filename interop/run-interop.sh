#!/usr/bin/env bash
# Top-level entrypoint for the interop matrix.
# Used by both `just interop` and the CI workflow.
#
# Assumes prerequisites are already built (Rust harness binary, JS deps).
# Run `just interop-build` to prepare them.

set -u -o pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

# Silence npm noise even if a wrapping script happens to call npm.
export NPM_CONFIG_FUND=false
export NPM_CONFIG_AUDIT=false

exec ./tests/matrix.sh "$@"
