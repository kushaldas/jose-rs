#!/usr/bin/env bash
# Drives every cell of the jose-rs <-> panva/jose interop matrix.
# Runs four directions per (alg, format) cell:
#   1. rust-sign  -> js-verify
#   2. js-sign    -> rust-verify
#   3. rust-keygen -> js-roundtrip (JS signs with Rust-generated key, then verifies)
#   4. js-keygen  -> rust-roundtrip (Rust signs with JS-generated key, then verifies)
#
# Writes interop/interop-results.json with one entry per cell.
# Always exits 0 — run-interop.sh reads the results file to produce CI
# output. The individual-cell invocation `matrix.sh --cell <name>` exits
# non-zero on failure so `just interop-cell` surfaces it.

set -u -o pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "$HERE/.." && pwd)"
RS_BIN="$ROOT/rust-harness/target/release/jose-interop"
JS_SCRIPT="$ROOT/js-harness/index.mjs"
VECTORS="$ROOT/vectors"
RESULTS="$ROOT/interop-results.json"

mkdir -p "$VECTORS"
: > "$RESULTS.tmp"

ALGS_PQ=("ML-DSA-44" "ML-DSA-65" "ML-DSA-87")
ALGS_CLASSICAL=("EdDSA" "ES256")
FORMATS=("compact" "jwt")
DIRECTIONS=(
  "rust-sign-js-verify"
  "js-sign-rust-verify"
  "rust-keygen-js-roundtrip"
  "js-keygen-rust-roundtrip"
)

: "${JQ:=jq}"
: "${NODE:=node}"

if ! command -v "$JQ" >/dev/null 2>&1; then
  echo "matrix.sh: jq is required" >&2
  exit 2
fi
if [ ! -x "$RS_BIN" ]; then
  echo "matrix.sh: Rust harness not built at $RS_BIN; run \`just interop-build\`" >&2
  exit 2
fi
if [ ! -d "$ROOT/js-harness/node_modules" ]; then
  echo "matrix.sh: JS deps not installed; run \`just interop-build\`" >&2
  exit 2
fi

rs() { "$RS_BIN" "$@"; }
js() { "$NODE" "$JS_SCRIPT" "$@"; }

# Canned payloads/claims so every cell sends the same bytes.
PAYLOAD_TEXT="interop payload $(date -u +%FT%TZ)"
# Portable base64url: `base64 -w0` is GNU-only, so strip newlines with tr
# for macOS/BSD parity. (GNU wraps at 76 chars by default; BSD doesn't wrap.)
PAYLOAD_B64U="$(printf '%s' "$PAYLOAD_TEXT" | base64 | tr -d '\n' | tr '+/' '-_' | tr -d '=')"
CLAIMS='{"iss":"interop","sub":"matrix","foo":"bar"}'

record() {
  # record <cell-id> <direction> <alg> <format> <result> <stderr-file>
  local cell="$1" dir="$2" alg="$3" fmt="$4" result="$5" errfile="$6"
  local stderr_txt=""
  if [ -s "$errfile" ]; then
    stderr_txt="$(cat "$errfile")"
  fi
  "$JQ" -cn \
    --arg cell "$cell" \
    --arg direction "$dir" \
    --arg alg "$alg" \
    --arg format "$fmt" \
    --arg result "$result" \
    --arg stderr "$stderr_txt" \
    '{cell:$cell, direction:$direction, alg:$alg, format:$format, result:$result, stderr:$stderr}' \
    >> "$RESULTS.tmp"
}

run_cell() {
  local direction="$1" alg="$2" fmt="$3"
  local cell="${direction}_${alg}_${fmt}"
  local errfile
  errfile="$(mktemp)"
  local pass=0
  # Subshell isolation so `set -e` inside doesn't abort the matrix.
  (
    set -e
    local priv_path="$VECTORS/${cell}.priv.json"
    local pub_path="$VECTORS/${cell}.pub.json"
    local signed_path="$VECTORS/${cell}.signed.json"

    case "$direction" in
      # 1. producer=rust (keygen+sign), consumer=js
      rust-sign-js-verify)
        rs gen-key --alg "$alg" > "$priv_path"
        rs export-pub < "$priv_path" > "$pub_path"
        if [ "$fmt" = "compact" ]; then
          "$JQ" -n --argjson jwk "$(cat "$priv_path")" --arg p "$PAYLOAD_B64U" \
            '{jwk:$jwk, payload_b64u:$p}' \
            | rs sign-compact --alg "$alg" > "$signed_path"
          local jws; jws="$("$JQ" -r .jws "$signed_path")"
          local got; got="$("$JQ" -n --argjson jwk "$(cat "$pub_path")" --arg jws "$jws" '{jwk:$jwk, jws:$jws}' \
            | js verify-compact --alg "$alg" | "$JQ" -r .payload_b64u)"
          [ "$got" = "$PAYLOAD_B64U" ] || { echo "payload mismatch" >&2; exit 1; }
        else
          "$JQ" -n --argjson jwk "$(cat "$priv_path")" --argjson c "$CLAIMS" \
            '{jwk:$jwk, claims:$c}' \
            | rs sign-jwt --alg "$alg" > "$signed_path"
          local jwt; jwt="$("$JQ" -r .jwt "$signed_path")"
          local iss; iss="$("$JQ" -n --argjson jwk "$(cat "$pub_path")" --arg jwt "$jwt" '{jwk:$jwk, jwt:$jwt}' \
            | js verify-jwt --alg "$alg" | "$JQ" -r .claims.iss)"
          [ "$iss" = "interop" ] || { echo "claim mismatch (iss=$iss)" >&2; exit 1; }
        fi
        ;;

      # 2. producer=js (keygen+sign), consumer=rust
      js-sign-rust-verify)
        js gen-key --alg "$alg" > "$priv_path"
        js export-pub < "$priv_path" > "$pub_path"
        if [ "$fmt" = "compact" ]; then
          "$JQ" -n --argjson jwk "$(cat "$priv_path")" --arg p "$PAYLOAD_B64U" \
            '{jwk:$jwk, payload_b64u:$p}' \
            | js sign-compact --alg "$alg" > "$signed_path"
          local jws; jws="$("$JQ" -r .jws "$signed_path")"
          local got; got="$("$JQ" -n --argjson jwk "$(cat "$pub_path")" --arg jws "$jws" '{jwk:$jwk, jws:$jws}' \
            | rs verify-compact --alg "$alg" | "$JQ" -r .payload_b64u)"
          [ "$got" = "$PAYLOAD_B64U" ] || { echo "payload mismatch" >&2; exit 1; }
        else
          "$JQ" -n --argjson jwk "$(cat "$priv_path")" --argjson c "$CLAIMS" \
            '{jwk:$jwk, claims:$c}' \
            | js sign-jwt --alg "$alg" > "$signed_path"
          local jwt; jwt="$("$JQ" -r .jwt "$signed_path")"
          local iss; iss="$("$JQ" -n --argjson jwk "$(cat "$pub_path")" --arg jwt "$jwt" '{jwk:$jwk, jwt:$jwt}' \
            | rs verify-jwt --alg "$alg" | "$JQ" -r .claims.iss)"
          [ "$iss" = "interop" ] || { echo "claim mismatch (iss=$iss)" >&2; exit 1; }
        fi
        ;;

      # 3. Rust mints the key, JS consumes it (signs + self-verifies).
      #    Detects JWK-shape drift on the producer side.
      rust-keygen-js-roundtrip)
        rs gen-key --alg "$alg" > "$priv_path"
        rs export-pub < "$priv_path" > "$pub_path"
        if [ "$fmt" = "compact" ]; then
          "$JQ" -n --argjson jwk "$(cat "$priv_path")" --arg p "$PAYLOAD_B64U" \
            '{jwk:$jwk, payload_b64u:$p}' \
            | js sign-compact --alg "$alg" > "$signed_path"
          local jws; jws="$("$JQ" -r .jws "$signed_path")"
          "$JQ" -n --argjson jwk "$(cat "$pub_path")" --arg jws "$jws" '{jwk:$jwk, jws:$jws}' \
            | js verify-compact --alg "$alg" > /dev/null
        else
          "$JQ" -n --argjson jwk "$(cat "$priv_path")" --argjson c "$CLAIMS" \
            '{jwk:$jwk, claims:$c}' \
            | js sign-jwt --alg "$alg" > "$signed_path"
          local jwt; jwt="$("$JQ" -r .jwt "$signed_path")"
          "$JQ" -n --argjson jwk "$(cat "$pub_path")" --arg jwt "$jwt" '{jwk:$jwk, jwt:$jwt}' \
            | js verify-jwt --alg "$alg" > /dev/null
        fi
        ;;

      # 4. JS mints the key, Rust consumes it (signs + self-verifies).
      js-keygen-rust-roundtrip)
        js gen-key --alg "$alg" > "$priv_path"
        js export-pub < "$priv_path" > "$pub_path"
        if [ "$fmt" = "compact" ]; then
          "$JQ" -n --argjson jwk "$(cat "$priv_path")" --arg p "$PAYLOAD_B64U" \
            '{jwk:$jwk, payload_b64u:$p}' \
            | rs sign-compact --alg "$alg" > "$signed_path"
          local jws; jws="$("$JQ" -r .jws "$signed_path")"
          "$JQ" -n --argjson jwk "$(cat "$pub_path")" --arg jws "$jws" '{jwk:$jwk, jws:$jws}' \
            | rs verify-compact --alg "$alg" > /dev/null
        else
          "$JQ" -n --argjson jwk "$(cat "$priv_path")" --argjson c "$CLAIMS" \
            '{jwk:$jwk, claims:$c}' \
            | rs sign-jwt --alg "$alg" > "$signed_path"
          local jwt; jwt="$("$JQ" -r .jwt "$signed_path")"
          "$JQ" -n --argjson jwk "$(cat "$pub_path")" --arg jwt "$jwt" '{jwk:$jwk, jwt:$jwt}' \
            | rs verify-jwt --alg "$alg" > /dev/null
        fi
        ;;

      *) echo "unknown direction: $direction" >&2; exit 1 ;;
    esac
  ) 2> "$errfile"
  local rc=$?
  if [ $rc -eq 0 ]; then
    record "$cell" "$direction" "$alg" "$fmt" "pass" "$errfile"
    pass=1
  else
    record "$cell" "$direction" "$alg" "$fmt" "fail" "$errfile"
  fi
  rm -f "$errfile"
  return $(( 1 - pass ))
}

# --cell <direction> <alg> <format>  — run one cell, exit non-zero on fail
if [ "${1:-}" = "--cell" ]; then
  shift
  dir="${1:?direction required}"; alg="${2:?alg required}"; fmt="${3:?format required}"
  run_cell "$dir" "$alg" "$fmt"
  rc=$?
  "$JQ" -s '.' "$RESULTS.tmp" > "$RESULTS"
  rm -f "$RESULTS.tmp"
  exit "$rc"
fi

# Full matrix
for alg in "${ALGS_PQ[@]}"; do
  for fmt in "${FORMATS[@]}"; do
    for dir in "${DIRECTIONS[@]}"; do
      run_cell "$dir" "$alg" "$fmt" || true
    done
  done
done

# Classical baseline — compact JWS only; catches generic wire-format
# regressions that might masquerade as a PQ-specific break.
for alg in "${ALGS_CLASSICAL[@]}"; do
  for dir in "${DIRECTIONS[@]}"; do
    run_cell "$dir" "$alg" "compact" || true
  done
done

# Aggregate into a JSON array for downstream tools (jq, gh summary, etc.).
"$JQ" -s '.' "$RESULTS.tmp" > "$RESULTS"
rm -f "$RESULTS.tmp"

echo "Results written to $RESULTS"
"$JQ" -r '
  group_by(.result) | map({(.[0].result): length}) | add
' "$RESULTS"
