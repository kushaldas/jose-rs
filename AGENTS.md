# AGENTS.md — contributor guidelines for jose-rs

Guidance for humans and coding agents working in this repository. Read
`future_plan.md` for the roadmap and `docs/adr/` for accepted decisions before
changing behaviour.

## 1. What this crate is

A pure-Rust JOSE library: JWS (RFC 7515), JWE (RFC 7516), JWK (RFC 7517),
JWA algorithm bindings (RFC 7518), JWT (RFC 7519) plus RFC 7797 unencoded
payloads, RFC 8037 OKP keys and feature-gated post-quantum signatures.

Primary locations: `src/algorithm.rs`, `src/header.rs`, `src/jws/`,
`src/jwe/`, `src/jwk/`, `src/jwt/`. Evidence lives in `tests/`, `interop/` and
`fuzz/`; decisions live in `docs/adr/`.

Out of scope by design (do not add): OIDC/OAuth token profiles, JWKS or
certificate fetching, issuer trust configuration, caching, HTTP clients, async
runtimes, global algorithm registries, certificate path validation, and any
form of authorization logic.

## 2. Definition of done — CI parity is mandatory

Every change must pass **all** of the following locally before it is
considered ready. CI enforces the same list. One command runs the whole set:

```sh
./scripts/gate.sh            # or: just gate   (--quick while iterating)
./scripts/gate.sh --with-interop   # plus the matrix and every peer suite
```

The script is the implementation of this section's commands; the expanded
checklist, including the judgement calls no script can make (RFC review, ADR
consequences, negative tests that fail for the right reason, migration notes,
human merge), is [`docs/definition-of-done.md`](docs/definition-of-done.md).
`just check-all` mirrors only the core subset. Expanded list, for reference:

```sh
cargo fmt --all -- --check                                  # must be silent
cargo clippy --locked --no-default-features --all-targets -- -D warnings
cargo clippy --locked --all-targets -- -D warnings          # default = pkcs11
cargo clippy --locked --no-default-features --features deprecated --all-targets -- -D warnings
cargo clippy --locked --no-default-features --features post-quantum --all-targets -- -D warnings
cargo clippy --locked --all-features --all-targets -- -D warnings
cargo test --locked --no-default-features
cargo test --locked
cargo test --locked --no-default-features --features deprecated
cargo test --locked --no-default-features --features post-quantum
cargo test --locked --all-features
RUSTDOCFLAGS='-D warnings' cargo doc --locked --all-features --no-deps
```

Hard rules:

- **`cargo fmt --all -- --check` must produce no output and no errors.** Run
  `cargo fmt --all` after every edit round; do not commit unformatted code.
- **`cargo clippy ... -- -D warnings` must report zero warnings and zero
  errors** for *every* feature combination in the list above, not only for the
  default feature set. Conditional `cfg(feature = "...")` blocks bit-rot
  silently if only one combination is checked.
- `cargo fmt` and `cargo clippy --fix` may rewrite other files: always run
  them on the whole workspace (`--all`) and review `git diff` afterwards.
- Never silence a lint with `#[allow(...)]` to make CI green. Fix the finding,
  or leave a comment explaining why the exception is correct and limit it to
  the narrowest scope.
- Never add `--lib` to a test run: it skips `tests/*.rs` and the doctests.
- Rustdoc must build warning-free (`RUSTDOCFLAGS='-D warnings'`). Intra-doc
  links from public items to private items are an error — use a code span for
  crate-private modules.
- Use `--locked` for build/test/clippy so `Cargo.lock` changes are always an
  explicit, reviewable change of their own.

## 3. Rustdoc and comment expectations

- `#![warn(missing_docs)]` is on: every public item needs a doc comment, and it
  must state *why* plus what it refuses, not just what it returns.
- Public `Options` structs are `#[non_exhaustive]` with `new()` plus
  `with_*` builders; document the strict default and what opting in costs.
- Every function that can fail documents its error conditions under
  `# Errors` (which `JoseError` variant, and when).
- Security-relevant behaviour gets a comment naming the attack it blocks and
  the RFC clause it implements (e.g. `RFC 7516 §5.1 step 14`, `RFC 8725 §3.1`).
- Public API examples must compile as doctests; prefer one small realistic
  example over a long one.
- Crate stays `#![forbid(unsafe_code)]`.

## 4. Tests

- Regression/acceptance tests are written **before** the behaviour they pin.
- Unit tests live next to the code; cross-module and wire-format tests live in
  `tests/*.rs`. A feature is not done until its integration file exists —
  `cargo test --lib` passing is never sufficient.
- Independent vectors (RFC text, peer-generated fixtures) are required in
  addition to generated roundtrips. Record the source, algorithm, expected
  output, and how the fixture was produced.
- Negative tests are required for: wrong key types, duplicate/colliding JSON
  members, altered authenticated data, mismatched or wrong keys, policy denial
  (`use`/`key_ops`/`alg` pins, algorithm allow-lists), and limit boundaries.
- Interop: cross-language checks are bidirectional whenever the peer supports
  the feature. See `interop/README.md`; Python/jwcrypto helpers live in
  `interop/tests/*_jwcrypto.py`, the Node/panva matrix in
  `interop/tests/matrix.sh`.
- Fuzz targets in `fuzz/` must be extended when a new parser or envelope
  shape is added; keep any crash as a regression fixture. A new harness also
  needs seeds (`examples/fuzz_seeds.rs`, corpus committed under `fuzz/seeds/`)
  and a mirrored `replay_*` function in `tests/fuzz_regressions.rs`, which is
  what actually executes on stable in CI — the fuzz job only builds (ADR 0034).

## 5. Design constraints that are never relaxed

- Never infer authorization from successful parsing, a thumbprint or a key URL.
- Preserve algorithm pins, key types/curves, `use` and `key_ops` at every new
  entry point. A convenience wrapper may add restrictions, never remove them.
- Strict canonical base64url; reject ambiguous header composition; keep the
  original protected bytes for authentication — never re-serialize a parsed
  header to rebuild an authentication input.
- Keep protected and unprotected metadata distinguishable in APIs and results.
- No plaintext is returned before authentication and configured limits pass.
- Secret material lives in zeroizing owners (`Zeroizing`, `Jwk::Drop`) and is
  redacted in `Debug` and error text.
- Bound allocations, recipient/key trials and KDF work before doing that work.
- Strict defaults stay strict: any compatibility relaxation needs its own
  explicit opt-in, its own ADR, and negative tests.

## 6. Dependencies

- Cryptographic primitives come from the locked `kryptering` backend or from
  jose-rs's already-locked direct dependencies. Verify a primitive against the
  **locked** version (`cargo tree`, `~/.cargo/registry/src/.../kryptering-<v>/`),
  never against a sibling checkout.
- If a primitive is missing in the backend, that is a separate backend change;
  do not hand-roll the primitive in JOSE glue and do not patch a vendored copy.
- Feature flags on already-locked crates are acceptable; new crates need an
  ADR, an MSRV/trait-family compatibility note and a lockfile review.
- Do not vendor anything. Do not commit generated artifacts, secrets,
  `target/`, or interop vectors.

## 7. ADRs and commits

- New behaviour or policy ⇒ new file in `docs/adr/NNNN-<slug>.md` (context,
  decision, security boundaries, consequences) plus a row in
  `docs/adr/README.md`. ADRs are immutable once accepted; supersede rather
  than edit.
- Record breaking changes and choose the release version deliberately; for a
  pre-1.0 crate a source-breaking change is not a routine patch release.
- One small, independently reviewable change per commit: mechanics/formatting
  separately from behaviour, primitive/backend changes separately from JOSE
  integration.
- Commit messages: imperative subject (`feat(jwe): …`, `fix(jwt): …`,
  `docs(adr): …`, `interop: …`), body explaining the threat or requirement the
  change addresses and what was deliberately not changed.
- Leave commits, tags, publishes and merges to the human maintainer unless
  explicitly asked to commit.

## 8. Quick reference

```sh
just                 # list recipes
just fmt-check       # cargo fmt --all -- --check
just clippy          # clippy --all-features --all-targets -D warnings
just test            # cargo test --locked --all-features (incl. tests/ + doctests)
just doc             # rustdoc with -D warnings
just check-all       # fmt + clippy + test + doc
just interop-build   # Rust harness + npm ci
just interop         # panva/jose matrix
```
