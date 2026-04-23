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

# Suppress Node's ExperimentalWarning for the ML-DSA Web Crypto API. A
# process.on('warning', ...) listener inside the JS harness does NOT
# replace Node's default stderr printer, so this must be set before Node
# starts. Scoped to ExperimentalWarning so deprecations still surface.
# (Requires Node >=21.3 for --disable-warning; we require >=24.7 anyway.)
export NODE_OPTIONS="--disable-warning=ExperimentalWarning ${NODE_OPTIONS:-}"

exec ./tests/matrix.sh "$@"
