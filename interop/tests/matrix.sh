#!/usr/bin/env bash
# Drives every cell of the jose-rs <-> panva/jose interop matrix.
# Runs four directions per (alg, format) cell:
#   1. rust-sign  -> js-verify
#   2. js-sign    -> rust-verify
#   3. rust-keygen -> js-roundtrip (JS signs with Rust-generated key, then verifies)
#   4. js-keygen  -> rust-roundtrip (Rust signs with JS-generated key, then verifies)
#
# Plus three extra families (see the loops at the bottom):
#   - format `hdr`: compact JWS with a custom protected header (kid + a
#     non-registered `tenant` member); the consumer must report both back.
#     Directions rust-sign-js-verify / js-sign-rust-verify.
#   - format `jwe`: compact JWE, alg label `<ALG>:<ENC>` (e.g. `dir:A256GCM`),
#     same custom header. Directions rust-encrypt-js-decrypt /
#     js-encrypt-rust-decrypt; plaintext and header compared.
#   - format `jws-dup`: negative vectors. Rust hand-builds a validly signed
#     compact JWS whose protected header repeats a member (dup-kid, dup-alg,
#     dup-ext). Both sides verify; what each did lands in the cell's
#     `observed` field. dup-kid / dup-alg pass iff jose-rs rejects; dup-ext
#     (a non-registered member, which jose-rs keeps in `extra`) passes iff
#     both sides agree on the value.
#
# Writes interop/interop-results.json with one entry per cell.
# Exit status:
#   - Full matrix run: 0 even when cells fail (the results file is the signal);
#     2 if prerequisites are missing (jq, built Rust harness, JS deps).
#   - --cell invocation: 0 if that cell passed, 1 if it failed, 2 on missing
#     prerequisites. This lets `just interop-cell` surface pass/fail directly.

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

# Custom-protected-header JWS cells.
ALGS_HDR=("ES256" "EdDSA")
DIRECTIONS_HDR=("rust-sign-js-verify" "js-sign-rust-verify")
# JWE cells: "<key-management alg>:<content enc>".
ALGS_JWE=("dir:A256GCM" "dir:A128CBC-HS256" "A256KW:A256GCM" "A256KW:A128CBC-HS256")
DIRECTIONS_JWE=("rust-encrypt-js-decrypt" "js-encrypt-rust-decrypt")
# Duplicate-member negative cells (signature alg is ES256 throughout).
DIRECTIONS_DUP=("dup-kid" "dup-alg" "dup-ext")

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
# Extra protected-header members for the `hdr` / `jwe` cells: one registered
# (kid) and one private, non-registered member (tenant). Consumers must
# report both back unchanged.
HDR_MEMBERS='{"kid":"interop-kid-1","tenant":"interop"}'

# assert_header <json-file-with-.protected_header>
assert_header() {
  "$JQ" -e --argjson want "$HDR_MEMBERS" \
    '.protected_header as $h | $want | to_entries | all(.value == $h[.key])' \
    "$1" > /dev/null \
    || { echo "protected header mismatch: want $HDR_MEMBERS, got $("$JQ" -c .protected_header "$1")" >&2; return 1; }
}

record() {
  # record <cell-id> <direction> <alg> <format> <result> <stderr-file> [observed-json-file]
  local cell="$1" dir="$2" alg="$3" fmt="$4" result="$5" errfile="$6" obsfile="${7:-}"
  local stderr_txt=""
  if [ -s "$errfile" ]; then
    stderr_txt="$(cat "$errfile")"
  fi
  local observed="null"
  if [ -n "$obsfile" ] && [ -s "$obsfile" ]; then
    observed="$(cat "$obsfile")"
  fi
  "$JQ" -cn \
    --arg cell "$cell" \
    --arg direction "$dir" \
    --arg alg "$alg" \
    --arg format "$fmt" \
    --arg result "$result" \
    --arg stderr "$stderr_txt" \
    --argjson observed "$observed" \
    '{cell:$cell, direction:$direction, alg:$alg, format:$format, result:$result, stderr:$stderr}
     + (if $observed == null then {} else {observed:$observed} end)' \
    >> "$RESULTS.tmp"
}

# run_hdr_cell <direction> <alg> — compact JWS with custom protected header.
run_hdr_cell() {
  local direction="$1" alg="$2"
  local priv_path="$VECTORS/${CELL}.priv.json"
  local pub_path="$VECTORS/${CELL}.pub.json"
  local signed_path="$VECTORS/${CELL}.signed.json"
  local out_path="$VECTORS/${CELL}.verified.json"
  local producer consumer
  case "$direction" in
    rust-sign-js-verify) producer=rs; consumer=js ;;
    js-sign-rust-verify) producer=js; consumer=rs ;;
    *) echo "unknown hdr direction: $direction" >&2; return 1 ;;
  esac
  "$producer" gen-key --alg "$alg" > "$priv_path"
  "$producer" export-pub < "$priv_path" > "$pub_path"
  "$JQ" -n --argjson jwk "$(cat "$priv_path")" --arg p "$PAYLOAD_B64U" --argjson h "$HDR_MEMBERS" \
    '{jwk:$jwk, payload_b64u:$p, header:$h}' \
    | "$producer" sign-compact --alg "$alg" > "$signed_path"
  local jws; jws="$("$JQ" -r .jws "$signed_path")"
  "$JQ" -n --argjson jwk "$(cat "$pub_path")" --arg jws "$jws" '{jwk:$jwk, jws:$jws}' \
    | "$consumer" verify-compact --alg "$alg" > "$out_path"
  [ "$("$JQ" -r .payload_b64u "$out_path")" = "$PAYLOAD_B64U" ] || { echo "payload mismatch" >&2; return 1; }
  assert_header "$out_path"
}

# run_jwe_cell <direction> <alg:enc> — compact JWE with custom protected header.
run_jwe_cell() {
  local direction="$1" alg="${2%%:*}" enc="${2#*:}"
  local key_path="$VECTORS/${CELL}.key.json"
  local enc_path="$VECTORS/${CELL}.encrypted.json"
  local out_path="$VECTORS/${CELL}.decrypted.json"
  local producer consumer
  case "$direction" in
    rust-encrypt-js-decrypt) producer=rs; consumer=js ;;
    js-encrypt-rust-decrypt) producer=js; consumer=rs ;;
    *) echo "unknown jwe direction: $direction" >&2; return 1 ;;
  esac
  # Symmetric key: the consumer gets the producer-generated JWK as-is
  # (doubles as a JWK-shape check for `oct` keys in both directions).
  "$producer" gen-key --alg "$alg" --enc "$enc" > "$key_path"
  "$JQ" -n --argjson jwk "$(cat "$key_path")" --arg p "$PAYLOAD_B64U" --argjson h "$HDR_MEMBERS" \
    '{jwk:$jwk, plaintext_b64u:$p, header:$h}' \
    | "$producer" encrypt-compact --alg "$alg" --enc "$enc" > "$enc_path"
  local jwe; jwe="$("$JQ" -r .jwe "$enc_path")"
  "$JQ" -n --argjson jwk "$(cat "$key_path")" --arg jwe "$jwe" '{jwk:$jwk, jwe:$jwe}' \
    | "$consumer" decrypt-compact --alg "$alg" --enc "$enc" > "$out_path"
  [ "$("$JQ" -r .plaintext_b64u "$out_path")" = "$PAYLOAD_B64U" ] || { echo "plaintext mismatch" >&2; return 1; }
  assert_header "$out_path"
}

# try_verify <rs|js> <alg> <pub-jwk-file> <jws> — never fails; prints
# {accepted, protected_header?, error?} describing what that side did.
try_verify() {
  local side="$1" alg="$2" pub="$3" jws="$4" out err rc
  err="$(mktemp)"
  rc=0
  # `|| rc=$?` keeps the cell subshell's `set -e` from aborting on the
  # (expected) rejection.
  out="$("$JQ" -n --argjson jwk "$(cat "$pub")" --arg jws "$jws" '{jwk:$jwk, jws:$jws}' \
    | "$side" verify-compact --alg "$alg" 2> "$err")" || rc=$?
  if [ $rc -eq 0 ]; then
    "$JQ" -c '{accepted:true, protected_header:.protected_header}' <<< "$out"
  else
    # First line only: the JS harness prints a full stack.
    "$JQ" -cn --arg e "$(head -n1 "$err")" '{accepted:false, error:$e}'
  fi
  rm -f "$err"
}

# run_dup_cell <dup-kid|dup-alg|dup-ext> <alg> — negative duplicate-member vector.
run_dup_cell() {
  local direction="$1" alg="$2" header_raw
  local priv_path="$VECTORS/${CELL}.priv.json"
  local pub_path="$VECTORS/${CELL}.pub.json"
  local signed_path="$VECTORS/${CELL}.signed.json"
  case "$direction" in
    dup-kid) header_raw="{\"alg\":\"$alg\",\"kid\":\"first\",\"kid\":\"second\"}" ;;
    # First `alg` names a different algorithm; the signature is $alg.
    dup-alg) header_raw="{\"alg\":\"HS256\",\"alg\":\"$alg\",\"kid\":\"interop-kid-1\"}" ;;
    dup-ext) header_raw="{\"alg\":\"$alg\",\"kid\":\"interop-kid-1\",\"tenant\":\"first\",\"tenant\":\"second\"}" ;;
    *) echo "unknown dup direction: $direction" >&2; return 1 ;;
  esac
  rs gen-key --alg "$alg" > "$priv_path"
  rs export-pub < "$priv_path" > "$pub_path"
  "$JQ" -n --argjson jwk "$(cat "$priv_path")" --arg h "$header_raw" --arg p "$PAYLOAD_B64U" \
    '{jwk:$jwk, header_raw:$h, payload_b64u:$p}' \
    | rs sign-compact-raw --alg "$alg" > "$signed_path"
  local jws; jws="$("$JQ" -r .jws "$signed_path")"
  local rs_obs js_obs
  rs_obs="$(try_verify rs "$alg" "$pub_path" "$jws")"
  js_obs="$(try_verify js "$alg" "$pub_path" "$jws")"
  "$JQ" -n --arg h "$header_raw" --argjson r "$rs_obs" --argjson j "$js_obs" \
    '{header_raw:$h, jose_rs:$r, panva_jose:$j}' > "$OBSFILE"
  # Human-readable summary lands in the recorded `stderr` too.
  echo "header: $header_raw" >&2
  echo "jose-rs: $rs_obs" >&2
  echo "panva/jose: $js_obs" >&2
  case "$direction" in
    dup-kid|dup-alg)
      "$JQ" -e '.accepted == false' <<< "$rs_obs" > /dev/null \
        || { echo "FAIL: jose-rs accepted a header with a duplicated typed member" >&2; return 1; }
      ;;
    dup-ext)
      # jose-rs keeps unregistered members in a flattened map; no rejection
      # is asserted, only that both sides resolve the same value.
      "$JQ" -e -n --argjson r "$rs_obs" --argjson j "$js_obs" \
        '($r.accepted == $j.accepted) and ($r.protected_header.tenant == $j.protected_header.tenant)' > /dev/null \
        || { echo "FAIL: jose-rs and panva/jose disagree on a duplicated extension member" >&2; return 1; }
      ;;
  esac
}

run_cell() {
  local direction="$1" alg="$2" fmt="$3"
  local cell="${direction}_${alg}_${fmt}"
  local errfile obsfile
  errfile="$(mktemp)"
  obsfile="$(mktemp)"
  local pass=0
  # Subshell isolation so `set -e` inside doesn't abort the matrix.
  (
    set -e
    CELL="$cell"
    OBSFILE="$obsfile"
    case "$fmt" in
      hdr) run_hdr_cell "$direction" "$alg"; exit 0 ;;
      jwe) run_jwe_cell "$direction" "$alg"; exit 0 ;;
      jws-dup) run_dup_cell "$direction" "$alg"; exit 0 ;;
    esac
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
    record "$cell" "$direction" "$alg" "$fmt" "pass" "$errfile" "$obsfile"
    pass=1
  else
    record "$cell" "$direction" "$alg" "$fmt" "fail" "$errfile" "$obsfile"
  fi
  rm -f "$errfile" "$obsfile"
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

# Custom protected header (kid + private `tenant` member), compact JWS.
for alg in "${ALGS_HDR[@]}"; do
  for dir in "${DIRECTIONS_HDR[@]}"; do
    run_cell "$dir" "$alg" "hdr" || true
  done
done

# Compact JWE with the same custom protected header.
for alg in "${ALGS_JWE[@]}"; do
  for dir in "${DIRECTIONS_JWE[@]}"; do
    run_cell "$dir" "$alg" "jwe" || true
  done
done

# Duplicate-member negative vectors (L-4): does a last-key-wins JSON parser
# (panva/jose, via JSON.parse) read these differently from jose-rs?
for dir in "${DIRECTIONS_DUP[@]}"; do
  run_cell "$dir" "ES256" "jws-dup" || true
done

# Aggregate into a JSON array for downstream tools (jq, gh summary, etc.).
"$JQ" -s '.' "$RESULTS.tmp" > "$RESULTS"
rm -f "$RESULTS.tmp"

echo "Results written to $RESULTS"
"$JQ" -r '
  group_by(.result) | map({(.[0].result): length}) | add
' "$RESULTS"
