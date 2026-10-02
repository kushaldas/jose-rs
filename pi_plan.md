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
| 2 | `feat(jwe): flattened JSON serialization` | J1 | `src/jwe/json.rs`, ADR 0011, `tests/jwe_json.rs`, jwcrypto + node interop |

> **ADR numbering.** The numbers in this table were assigned before the
> repository's ADR sequence was checked. Accepted ADRs ran 0001–0010 when the
> plan was written, and each record takes the next free number when it is
> written, so the real numbers are: J1 = 0011, J2 = 0012, J3 = 0013, J4a = 0014
> (J4a and J4b landed as one record — a bounded search would authenticate against
> a header the caller never agreed to, so recipient selection is caller-named
> only), D1 = 0015, K0 = 0016. Later rows still carry their pre-flight numbers and
> must be renumbered when written.
| 3 | `feat(jwe): external AAD for JSON serializations` | J2 | options + ADR 0013, `tests/jwe_aad.rs`, interop |
| 4 | `feat(jwe): shared and per-recipient unprotected headers` | J3 | header-union types, ADR 0014, `tests/jwe_unprotected.rs` |
| 5 | `feat(jwe): general JSON serialization` | J4a | general envelope, ADR 0015, tests |
| 6 | `feat(jwe): multiple recipients with bounded selection` | J4b | folded into J4a: a search authenticates against a header the caller never named, so selection is caller-scoped only (ADR 0014) |
| 7 | `feat(jwe): caller-understood crit extensions` | D1 | JWS-parity opt-in, ADR 0015, `tests/jwe_crit.rs`, `jwe-crit` matrix family |
| 8 | `feat(jwk): operation-aware key-agreement boundary` | K0 | **done** — `jwk::agreement` (`agreement_key`/`peer_key`/`AgreementKey::derive_key`), ADR 0016, RFC 7518 Appendix C vectors in `tests/jwk_agreement.rs` + `interop/tests/ecdh_kdf_vectors.py` |
| 9 | `feat(jwe): direct ECDH key agreement` | K1a + K1b | **done** — all three P-curves and every `enc` landed together (one policy, one set of decisions; splitting by curve would have duplicated ADR 0017 for no safety gain). ADR 0017, `tests/jwe_ecdh_es.rs`, `jwe-ecdh` matrix family, jwcrypto checks |
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
| 2 | docs: RFC texts + contributor guidelines | Q1 | `rfcs/rfc{7515,7516,7517,7518,7519,7797,8037,9278,9864}.txt` (IETF-sourced, checksums recorded), `AGENTS.md` |
| 3 | `feat(jwe): flattened JSON serialization` | J1 | `src/jwe/json.rs`, `src/member_map.rs` (strict duplicate-rejecting JSON objects), ADR 0011, `tests/jwe_json.rs`, `jwe-json` matrix family (8 cells) + `interop/tests/jwe_json_jwcrypto.py` (9 alg/enc combos, both directions, pinned ADR-0011 divergence) |
| 4 | `feat(jwe): external AAD for JSON serializations` | J2 | `Jwe{Encrypt,Decrypt}Options::with_external_aad`, `FlattenedJwe::aad`, ADR 0012, `tests/jwe_aad.rs`, `jwe-json-aad` matrix family (8 cells) + jwcrypto external-AAD checks; compact refuses the option |
| 5 | `feat(jwe): shared and per-recipient unprotected headers` | J3 | `FlattenedJwe::{unprotected,header}`, disjointness + unprotected-position policy, `peek_jose_header`, `ParsedEnvelope::alg_authenticated`, ADR 0013, `tests/jwe_unprotected.rs` (RFC 7516 §A.5 vector), `jwe-json-unprot` matrix family + jwcrypto boundary checks |
| 6 | `feat(jwe): general JSON serialization with caller-named recipients` | J4a + J4b | `jwe::general` (`GeneralJwe`, `RecipientSpec`, `encrypt_general*`, `decrypt_general_with_jwk{,_by_kid,_and_aad}`, `MAX_RECIPIENTS`), `wrap_cek`/`encrypt_core_multi` split, ADR 0014 (bounded array, no searching — J4b's "bounded selection" lands as a documented rejection), `tests/jwe_general.rs` (RFC 7516 §A.4 vector), `jwe-general` matrix family + jwcrypto general checks |
| 7 | `feat(jwe): caller-understood crit extensions` | D1 | `Jwe{Encrypt,Decrypt}Options::with_understood_crit`, shared `validate_crit` (emit = receive), `JweDecryptOptions::pinned_to_jwk`, `{json,general}::decrypt_*_with_jwk_options`, ADR 0015, `tests/jwe_crit.rs`, `jwe-crit` matrix family (8 cells) + jwcrypto crit checks |
| 9 | `feat(jwe): direct ECDH key agreement (ECDH-ES)` | K1a | `KeyMaterial` (bytes vs JWK) through every key-management path, ephemeral key generated per message and published as `epk`, curve taken from the recipient, `epk` read from the protected header only, one recipient only, `apu`/`apv` honoured as KDF inputs, `deriveKey` as the operation; ADR 0017, `tests/jwe_ecdh_es.rs` (21 tests, RFC 7520 §5.5 both serializations), `jwe-ecdh` matrix family (8 cells), `interop/tests/jwe_ecdh_es_jwcrypto.py` (60 checks incl. the jwcrypto unprotected-`epk` divergence). Matrix now 87 cells |
| 8 | `feat(jwk): operation-aware key-agreement boundary` | K0 | `jwk::agreement` (`AgreementCurve`, `AgreementKey`/`PeerKey`, `agreement_key`/`peer_key`, `AgreementKey::derive_key`), one Concat KDF in `jwe::internal` (module made `pub(crate)` for it), ADR 0016, `tests/jwk_agreement.rs` (10 tests, RFC 7518 §C `Z` + derived key), `interop/tests/ecdh_kdf_vectors.py` (19 checks vs OpenSSL ECDH + an independent Python KDF), harness `agree`/`derive-key`. X25519 refused by name until its JWK import + `d`↔`x` check land (K3a) |
