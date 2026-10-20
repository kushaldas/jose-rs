# jose-rs task runner
#
#   just            # list recipes
#   just check-all  # mirrors CI
#   just interop    # run the panva/jose interop matrix (needs Node 24.7+)
#
# `just` is only a developer convenience — CI calls scripts directly so the
# pipeline never depends on `just` being installed on runners.

set shell := ["bash", "-uc"]
set dotenv-load := false

interop_dir := justfile_directory() + "/interop"
rust_harness := interop_dir + "/rust-harness"
js_harness := interop_dir + "/js-harness"
fuzz_dir := justfile_directory() + "/fuzz"
fuzz_scripts := fuzz_dir + "/scripts"

_default:
    @just --list

# Full build (all features).
build:
    cargo build --locked --all-features

# Unit, integration and doc tests (all features). Mirrors
# `cargo test (all-features)` in CI. No `--lib`: that would skip tests/.
test:
    cargo test --locked --all-features

# All tests, post-quantum feature only — isolates ML-DSA regressions.
test-pq:
    cargo test --locked --no-default-features --features post-quantum

# Clippy across the whole target graph.
clippy:
    cargo clippy --locked --all-features --all-targets -- -D warnings

# Format (writes).
fmt:
    cargo fmt --all

# Format check (CI parity).
fmt-check:
    cargo fmt --all -- --check

# Doc build with -D warnings, as CI does.
doc:
    RUSTDOCFLAGS="-D warnings" cargo doc --locked --all-features --no-deps

# Optional: cargo audit (not required, run locally).
audit:
    cargo audit

# Everything CI runs on the core Rust crate.
check-all: fmt-check clippy test doc

# --- Definition of done --------------------------------------------------
#
# The mechanical half of `docs/definition-of-done.md`, in one command. The script
# is the implementation (and runs without `just` installed); these recipes are
# aliases so the gate is discoverable from `just --list`.

# Full pre-commit gate: fmt, tests and Clippy in every CI configuration, strict
# rustdoc, and the capability tables' drift check.
gate:
    ./scripts/gate.sh

# Just fmt + default-configuration tests + rustdoc + capability drift.
gate-quick:
    ./scripts/gate.sh --quick

# Gate plus the interop matrix and every peer suite (needs the harness build and
# the interop venv; see interop/README.md).
gate-interop:
    ./scripts/gate.sh --with-interop

# Regenerate the capability tables from the code.
capabilities:
    cargo run --locked --example capabilities > docs/capabilities.md

# --- Fuzzing (fuzz/, cargo-fuzz + libFuzzer) ----------------------------

# Install nightly, llvm-tools and cargo-fuzz; detached campaigns also need tmux.
fuzz-setup:
    rustup toolchain install nightly
    rustup component add llvm-tools-preview --toolchain nightly
    cargo install --locked cargo-fuzz

# Build every fuzz target once before starting a campaign.
fuzz-build:
    {{fuzz_scripts}}/build.sh

# Fuzz every target in tmux; duration is seconds and zero runs until stopped.
fuzz seconds="0":
    {{fuzz_scripts}}/fuzz-all.sh {{seconds}}

# Fuzz one target in foreground fork mode: `just fuzz-one jwk_from_json 3600`.
fuzz-one target seconds="0":
    {{fuzz_scripts}}/run.sh {{target}} {{seconds}}

# Attach to the detached campaign.
fuzz-attach:
    tmux attach -t jose-rs-fuzz

# Stop the detached campaign, if one exists.
fuzz-stop:
    tmux kill-session -t jose-rs-fuzz || true

# List crash, timeout and out-of-memory artifacts found so far.
fuzz-crashes:
    @if [[ -d "{{fuzz_dir}}/artifacts" ]] && find "{{fuzz_dir}}/artifacts" -type f -print -quit | grep -q .; then find "{{fuzz_dir}}/artifacts" -type f | sort; else echo "no artifacts yet"; fi

# Reproduce an artifact: `just fuzz-repro jwk_from_json path/to/crash-abc`.
fuzz-repro target artifact:
    {{fuzz_scripts}}/repro.sh {{target}} {{artifact}}

# Generate an HTML line-coverage report for one target's accumulated corpus.
fuzz-coverage target:
    {{fuzz_scripts}}/coverage.sh {{target}}

# Remove corpus entries that do not add coverage for the selected target.
fuzz-cmin target:
    {{fuzz_scripts}}/minimize.sh {{target}}

# --- Interop (panva/jose) ------------------------------------------------

# Build the Rust harness and install JS deps. Prerequisite for any
# `interop*` recipe. Safe to re-run — both commands are idempotent.
interop-build:
    cargo build --locked --release --manifest-path {{rust_harness}}/Cargo.toml
    cd {{js_harness}} && npm ci --no-audit --no-fund

# Run the full interop matrix. Always exits 0; inspect
# interop/interop-results.json for per-cell pass/fail.
interop: interop-build
    {{interop_dir}}/run-interop.sh

# Run a single interop cell. Exit code reflects that cell only.
# Example:
#   just interop-cell rust-sign-js-verify ML-DSA-65 compact
interop-cell DIRECTION ALG FORMAT: interop-build
    {{interop_dir}}/run-interop.sh --cell {{DIRECTION}} {{ALG}} {{FORMAT}}

# Print Node + OpenSSL versions — ML-DSA needs Node >=24.7 with OpenSSL >=3.5.
interop-node-version:
    @node --version
    @node -e "console.log('openssl', process.versions.openssl)"

# Scrub interop artifacts. `vectors/` is gitignored as a whole and
# `matrix.sh` recreates it with `mkdir -p` on every run.
interop-clean:
    rm -f {{interop_dir}}/interop-results.json
    rm -rf {{interop_dir}}/vectors
    rm -rf {{rust_harness}}/target
    rm -rf {{js_harness}}/node_modules

# `cargo clean` plus interop-clean.
clean: interop-clean
    cargo clean
