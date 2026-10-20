#!/usr/bin/env bash
# Shared helpers for the jose-rs fuzz scripts. Sourced, not executed.
set -euo pipefail

FUZZ_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_ROOT="$(cd "$FUZZ_DIR/.." && pwd)"

ALL_TARGETS=(
  base64url_decode
  jwk_from_json
  jwk_thumbprint
  jws_decode_header
  jws_verify
  jwe_decrypt
  jwt_decode_unverified
  jws_verify_mldsa
  jws_verify_composite
  jwk_from_pem
  jwk_from_der
  certificate_extract
  encrypted_pkcs8
  jwkset_select
  jwe_json_flattened
  jwe_json_general
  jwt_claims
)

require_tools() {
  command -v cargo >/dev/null || {
    echo "cargo not found (install rustup)"
    exit 1
  }
  cargo +nightly --version >/dev/null 2>&1 || {
    echo "nightly toolchain missing: rustup toolchain install nightly"
    exit 1
  }
  cargo +nightly fuzz --version >/dev/null 2>&1 || {
    echo "cargo-fuzz missing: cargo install --locked cargo-fuzz"
    exit 1
  }
}

require_target() {
  local requested="${1:?target name required}"
  local target
  for target in "${ALL_TARGETS[@]}"; do
    if [[ "$target" == "$requested" ]]; then
      return 0
    fi
  done
  echo "unknown fuzz target: $requested" >&2
  printf 'available targets: %s\n' "${ALL_TARGETS[*]}" >&2
  exit 1
}
