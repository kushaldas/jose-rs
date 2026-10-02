#!/usr/bin/env bash
# The mechanical half of the per-PR definition of done, as one command.
#
#   ./scripts/gate.sh              # full gate (~6 minutes: every CI configuration)
#   ./scripts/gate.sh --quick      # fmt + default-configuration tests + rustdoc
#   ./scripts/gate.sh --with-interop   # gate plus the interop matrix and every peer suite
#
# Why a script and not prose in a CONTRIBUTING file: a checklist that has to be
# remembered is a checklist that gets half-run. The remaining items in
# docs/definition-of-done.md are judgement calls that no script can make (RFC
# review, whether the ADR states a real consequence, whether the tests would fail
# for the right reason), and this script says so in its own closing output rather
# than implying that green means done.
#
# Notes on the exact invocations, each of which is a lesson paid for once:
#   * `--locked` everywhere, so a Cargo.lock change cannot ride along unnoticed.
#   * Clippy's `-D warnings` goes through RUSTFLAGS, not as a cargo-clippy argument.
#   * Five feature configurations, matching .github/workflows/ci.yml; `--pem` is
#     not one of them because `pem` is not a feature.
#   * Tests are run without `--lib`, which would silently skip tests/*.
#   * The capability tables are diffed against their generator, because a table
#     nobody regenerates is a table that quietly lies.

set -u -o pipefail

cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." || exit 1

QUICK=0
WITH_INTEROP=0
for arg in "$@"; do
    case "$arg" in
        --quick) QUICK=1 ;;
        --with-interop) WITH_INTEROP=1 ;;
        *) echo "unknown argument: $arg (try --quick or --with-interop)" >&2; exit 2 ;;
    esac
done

FAILED=0
step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
ok() { printf '  \033[32mok\033[0m     %s\n' "$*"; }
bad() { printf '  \033[31mFAIL\033[0m   %s\n' "$*"; FAILED=1; }

FEATURES=("" "--no-default-features" "--features deprecated" "--features post-quantum" "--all-features")
CONFIG_LABEL="five feature configurations"
if [[ "$QUICK" == 1 ]]; then
    FEATURES=("")
    CONFIG_LABEL="default configuration only (--quick)"
fi

step "format"
if cargo fmt --all -- --check >/dev/null 2>&1; then ok "cargo fmt --check"; else bad "cargo fmt --check (run: cargo fmt --all)"; fi

step "tests ($CONFIG_LABEL)"
for f in "${FEATURES[@]}"; do
    out=$(cargo test --locked $f 2>&1)
    total=$(printf '%s' "$out" | grep -E '^test result: ok' | awk '{s+=$4} END {print s+0}')
    if printf '%s' "$out" | grep -qE '^test result: FAILED|^error'; then
        bad "cargo test --locked $f"
        printf '%s\n' "$out" | grep -E 'panicked|^error' | head -5 | sed 's/^/         /'
    else
        ok "cargo test --locked ${f:-<default>} => $total passed"
    fi
done

step "clippy ($CONFIG_LABEL, -D warnings)"
for f in "${FEATURES[@]}"; do
    if RUSTFLAGS='-D warnings' cargo clippy --locked $f --all-targets >/dev/null 2>&1; then
        ok "cargo clippy --locked ${f:-<default>} --all-targets"
    else
        bad "cargo clippy --locked $f --all-targets"
        RUSTFLAGS='-D warnings' cargo clippy --locked $f --all-targets 2>&1 \
            | grep -E '^error' -A6 | head -12 | sed 's/^/         /'
    fi
done

step "documentation (rustdoc, -D warnings)"
if RUSTDOCFLAGS='-D warnings' cargo doc --locked --all-features --no-deps >/dev/null 2>&1; then
    ok "cargo doc --locked --all-features --no-deps"
else
    bad "cargo doc (broken intra-doc links or missing docs)"
    RUSTDOCFLAGS='-D warnings' cargo doc --locked --all-features --no-deps 2>&1 \
        | grep -E '^(error|warning)' -A6 | head -12 | sed 's/^/         /'
fi

step "capability tables"
generated="$(mktemp)"
if cargo run --locked --quiet --example capabilities >"$generated" 2>/dev/null; then
    if diff -q "$generated" docs/capabilities.md >/dev/null; then
        ok "docs/capabilities.md matches src/capability.rs"
    else
        bad "docs/capabilities.md is stale (run: cargo run --example capabilities > docs/capabilities.md)"
        diff "$generated" docs/capabilities.md | head -10 | sed 's/^/         /'
    fi
else
    bad "examples/capabilities.rs did not run"
fi
rm -f "$generated"

if [[ "$WITH_INTEROP" == 1 ]]; then
    step "interop matrix"
    ./interop/run-interop.sh >/dev/null 2>&1 || true
    # `run-interop.sh` always exits 0 (per-cell results are the contract), so the verdict has to
    # come from the results file rather than the exit code.
    summary=$(python3 - <<'PY' 2>/dev/null
import json, collections
try:
    cells = json.load(open("interop/interop-results.json"))
except Exception as exc:  # noqa: BLE001
    print(f"unreadable:{exc}")
    raise SystemExit
tally = collections.Counter(c["result"] for c in cells)
print(f"{tally.get('pass', 0)}/{len(cells)} cells pass"
      + ("" if len(tally) == 1 else f" [{dict(tally)}]"))
raise SystemExit(0 if tally.get("pass", 0) == len(cells) and cells else 1)
PY
)
    if [[ $? -eq 0 && "$summary" != unreadable:* ]]; then ok "run-interop.sh => $summary"; else bad "run-interop.sh => ${summary:-no results} (see interop/interop-results.json)"; fi

    step "peer suites (jwcrypto / cryptography / panva-jose)"
    HARNESS=interop/rust-harness/target/debug/jose-interop
    PY=interop/.venv/bin/python
    if [[ ! -x "$PY" ]]; then
        bad "missing $PY (see interop/README.md for the venv setup)"
    else
        for suite in ecdh_kdf_vectors jwe_json_jwcrypto jwe_ecdh_es_jwcrypto jwe_gcm_kw_jwcrypto \
                     jwe_pbes2_jwcrypto pem_jwcrypto pkcs8_encrypted_cryptography \
                     cert_cryptography jwt_claims_jwcrypto jws_json_jwcrypto \
                     jwks_selection_jwcrypto numeric_dates_jwcrypto ed25519_jwcrypto; do
            # Exit codes, not message text: every suite exits non-zero on failure, and a
            # substring test on prose once mis-reported two passing suites as failures because
            # one said "0 failures" and the other "0 failed".
            output=$("$PY" "interop/tests/$suite.py" "$HARNESS" 2>&1)
            status=$?
            line=$(printf '%s\n' "$output" | tail -1)
            if [[ "$status" -eq 0 ]]; then
                ok "$suite => $line"
            else
                bad "$suite (exit $status) => $line"
            fi
        done
        if line=$(node interop/js-harness/thumbprint-uri.mjs 2>&1 | tail -1); then
            ok "thumbprint-uri_jose => $line"
        else
            bad "thumbprint-uri_jose => $line (needs npm ci in interop/js-harness)"
        fi
    fi
fi

step "result"
if [[ "$FAILED" == 0 ]]; then
    printf '  \033[32mgate clean\033[0m\n\n'
    cat <<'NOTE'
  Still yours to check (no script can do these):
    - RFC sections and errata re-read against the diff, not from memory
    - an ADR that states a consequence, not just a decision
    - tests in tests/, not only --lib, and each one fails for its stated reason
    - negative and resource-bound cases, not only happy paths
    - CHANGELOG, README, capability tables and migration notes match real support
    - new files staged; no generated artifacts, fixtures with real secrets, or
      scratch files (see the repo's untracked-file policy)
    - human review and merge before any dependent task starts
NOTE
    exit 0
else
    printf '  \033[31mgate failed\033[0m\n'
    exit 1
fi
