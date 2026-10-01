# jose-rs implementation plan — future_plan.md tracks that need no kryptering change

Date: working session plan. Authoritative roadmap: `future_plan.md`.
Backend: kryptering **0.6.0** (the locked version; `~/code/kryptering` matches the
registry copy byte-for-byte, verified with `diff -r`).

## 0. Backend inventory (decides what is implementable here)

kryptering 0.6.0 already provides everything tracks J, K, I and L need:

| Need | kryptering 0.6.0 API | Verdict |
|---|---|---|
| AES-KW, RSA-OAEP | `keywrap::{wrap,unwrap}`, `keytransport::{kt_encrypt,kt_decrypt}` | in use |
| ECDH P-256/384/521 | `software::keyagreement::agree(EcCurve, peer, &SoftwareKey)` | available |
| X25519 | `keyagreement::agree_x25519`, `SoftwareKey::from_x25519` | available |
| ConcatKDF (SP 800-56A) | `kdf::concat_kdf` + `ConcatKdfParams` | available |
| PBKDF2 | `kdf::pbkdf2_derive` + `Pbkdf2Params` (+ min/max bounds) | available |
| AES-GCM (for A*GCMKW) | `aes-gcm` is a **direct jose-rs dep** already used for `enc` | available |

**Not** available in kryptering 0.6.0 → out of scope for this session, recorded
instead as ADR decisions (no kryptering update, no new backend dependency):

- standalone **Ed448** signing (`SignatureAlgorithm` has only `Ed25519`),
- **ES256K / secp256k1** and **Brainpool** (no backend, no curve enum),
- **X448** agreement (`keyagreement` covers P-curves + X25519 only).

Dependency policy for this session: **no new crates, no vendoring**. Only feature
flags on already-locked dependencies. `Cargo.lock` already contains
`pem-rfc7468`, `pkcs1`, `sec1`, `der`, `spki`, `des`, `pbkdf2`, `sha1`, so
`pkcs8`'s `pem` and `encryption` features resolve with no new packages.

## 1. Commit sequence

Each row = one commit, with rustdoc, unit tests, an integration test file under
`tests/`, interop coverage where the peer implements the feature, and an ADR for
new behaviour/policy.

| # | Commit | Plan item | New artefacts |
|---|---|---|---|
| 1 | `refactor(jwe): split envelope internals from compact API` | J0 | `src/jwe/internal.rs`, `src/jwe/content.rs` (behaviour-preserving) |
| 2 | `feat(jwe): flattened JSON serialization` | J1 | `src/jwe/json.rs`, ADR 0012, `tests/jwe_json.rs`, jwcrypto + node interop |
| 3 | `feat(jwe): external AAD for JSON serializations` | J2 | options + ADR 0013, `tests/jwe_aad.rs`, interop |
| 4 | `feat(jwe): shared and per-recipient unprotected headers` | J3 | header-union types, ADR 0014, `tests/jwe_unprotected.rs` |
| 5 | `feat(jwe): general JSON serialization` | J4a | general envelope, ADR 0015, tests |
| 6 | `feat(jwe): multiple recipients with bounded selection` | J4b | budgets, ADR 0016, `tests/jwe_multi_recipient.rs`, interop |
| 7 | `feat(jwe): caller-understood crit extensions` | D1 | JWS-parity opt-in, ADR 0017, tests |
| 8 | `feat(jwk): operation-aware key-agreement boundary` | K0 | `jwk_to_agreement_key`, ADR 0018, RFC 7518/7520 KDF vectors |
| 9 | `feat(jwe): ECDH-ES direct agreement with P-256` | K1a | ADR 0019, `tests/jwe_ecdh_es.rs`, interop |
| 10 | `feat(jwe): ECDH-ES direct agreement with P-384/P-521` | K1b | vectors + interop |
| 11 | `feat(jwe): ECDH-ES + AES key wrapping` | K2 | `tests/jwe_ecdh_es_kw.rs`, interop |
| 12 | `feat(jwe): X25519 agreement keys for ECDH-ES` | K3a | OKP/X25519 JWK + ECDH-ES, ADR 0020, interop |
| 13 | `feat(jwe): AES-GCM key management` | K4 | `A128/192/256GCMKW`, ADR 0021, vectors, interop |
| 14 | `feat(jwe): PBES2 password-based key derivation` | K5 | dedicated password API, ADR 0022, budget tests, interop |
| 15 | `feat(jwk): PEM import and export` | I0 | `jwk::{pem}`, ADR 0023, tests |
| 16 | `feat(jwk): PKCS#1 RSA import` | I1 | `jwk_from_pkcs1_*`, tests |
| 17 | `feat(jwk): SEC1 EC private key import` | I2 | `jwk_from_sec1_der`, tests |
| 18 | `feat(jwk): password-protected PKCS#8` | I3 | `pkcs8/encryption` feature, ADR 0024, tests |
| 19 | `feat(jwk): certificate public-key extraction` | I4 | SPKI extraction, ADR 0025, tests |
| 20 | `feat: executable capability reporting` | L0 | `src/capability.rs`, ADR 0026, tests |
| 21 | `fix(jwt): unambiguous claim parsing` | L1 | duplicate-member rejection, raw-number tests |
| 22 | `feat(jws): JWK-aware JSON serialization APIs` | L2 | wrappers, tests, interop |
| 23 | `feat(jwk): bounded JWKS selection policy` | L3 | limits + diagnostics, tests |
| 24 | `feat: authenticated results and stable error categories` | L4 | result types, `JoseError` kinds, ADR |
| 25 | `feat(jwk): thumbprint URI and typed generation options` | L5 | RFC 9278, tests |
| 26 | `docs(adr): curve/algorithm coverage decisions` | A0-A3 | blocked-on-backend ADR |
| 27 | `docs: roadmap, changelog and capability tables` | Q3 closeout | README/CHANGELOG/plan status |

## 2. Fixed design rules honoured everywhere

- protected bytes kept verbatim; AAD built from original encoded fields;
- `alg`/`enc` pins, `use`/`key_ops`, HMAC minimum strengths never relaxed;
- no plaintext before authentication + configured size limits;
- zeroizing owners for CEK/shared secrets/passwords, redacted `Debug`;
- bounded parse, bounded recipient trials, bounded KDF work;
- strict defaults: every relaxation is an explicit opt-in with its own ADR;
- `#![forbid(unsafe_code)]` retained; no async, no network, no global registry.

## 3. Evidence per commit (Q0/Q3)

```sh
cargo fmt --all -- --check
cargo test --locked --lib
cargo test --locked
cargo test --locked --no-default-features
cargo test --locked --no-default-features --features deprecated
cargo test --locked --all-features
cargo clippy --locked --all-features --all-targets -- -D warnings
RUSTDOCFLAGS='-D warnings' cargo doc --locked --all-features --no-deps
```

Interop: `interop/tests/*_jwcrypto.py` (uv-managed venv with jwcrypto) and the
Node/panva matrix (`interop/tests/matrix.sh`), extended per feature.

## 4. Progress log

| # | Commit | Item | Notes |
|---|--------|------|-------|
| 0 | docs: working plan | — | this file |
| 1 | refactor(jwe): shared internals | J0 | `src/jwe/internal.rs` + `src/jwe/content.rs`; compact API/wire unchanged |
