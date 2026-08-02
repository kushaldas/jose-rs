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

_default:
    @just --list

# Full build (all features).
build:
    cargo build --locked --all-features

# Unit tests (all features). Mirrors `cargo test (all-features)` in CI.
test:
    cargo test --locked --all-features --lib

# Unit tests, post-quantum feature only — isolates ML-DSA regressions.
test-pq:
    cargo test --locked --no-default-features --features post-quantum --lib

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
