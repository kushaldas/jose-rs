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
| 10 | `feat(jwe): ECDH key agreement with key wrapping` | K2 | **done** — see progress log |
| 9 | `feat(jwe): direct ECDH key agreement` | K1a + K1b | **done** — all three P-curves and every `enc` landed together (one policy, one set of decisions; splitting by curve would have duplicated ADR 0017 for no safety gain). ADR 0017, `tests/jwe_ecdh_es.rs`, `jwe-ecdh` matrix family, jwcrypto checks |
| 11 | `feat(jwe): ECDH-ES + AES key wrapping` | K2 | **done** — landed as `feat(jwe): ECDH key agreement with key wrapping` (see progress log) |
| 12 | `feat(jwe): X25519 agreement keys for ECDH-ES` | K3a | **done** — see progress log (ADR 0019, not 0020) |
| 13 | `feat(jwe): AES-GCM key management` | K4 | **done** — see row 12 |
| 13a | `feat(jwe): PBES2 password-based key management (PBES2-HS256+A128KW / +HS384+A192KW / +HS512+A256KW)` | K5 | `jwe::password` (`Password` held in `Zeroizing`, UTF-8 and octet constructors, no equality, redacted `Debug`) plus three benchmark-backed constants; `KeyMaterial::Password` with `password_key` refusing non-PBES2 and `jwk_to_jwe_key_bytes` refusing a JWK for PBES2; `p2s`/`p2c` generated here, published before serialization, read only from the protected header, typed as base64url string / positive JSON integer; `JweEncryptOptions::with_pbes2_iterations` + `JweDecryptOptions::with_pbes2_max_iterations`, checked **before** deriving; general refused naming `p2s and p2c` (one password accepted); ADR 0021; `tests/jwe_pbes2.rs` (13 tests, RFC 7520 §5.3 end to end) + 7 internal unit tests (RFC 7520 Figure 100 reproduced, salt construction, budget timing); `jwe-pbes2` matrix family (6 cells); `interop/tests/jwe_pbes2_jwcrypto.py` (166 checks, re-deriving in Python, panva/jwcrypto `p2c` ceilings asserted). Emitted default moved 100 000 → 8 192 because panva caps `p2c` at 10 000 and jwcrypto at 16 384. Matrix now 109 cells |
| 14 | `feat(jwe): PBES2 password-based key management` | K5 | **done** — see row 13a |
| 15 | `feat(jwk): PEM (RFC 7468) import and export` | I0 | **done** — `jwk::pem` (`jwk_from_pem` label dispatch, format-explicit `jwk_from_pkcs8_pem`/`jwk_from_spki_pem`, separate `private_pem_from_jwk`/`public_pem_from_jwk`); one block only (refused with a count), no preamble and no trailing text (whitespace around the block is free, re-indented armor is not), canonical base64, CRLF accepted; PKCS#1/SEC1/certificate/`ENCRYPTED PRIVATE KEY` refused **by name** with the entry point that will serve them, legacy `Proc-Type`/`DEK-Info` refused as an encrypted key; DER-level refusals (RSA-PSS, modulus floor) still apply through the armor; X25519 public export refused rather than hand-wrapping raw bytes; Ed25519 private export normalized OneAsymmetricKey(v1) → PrivateKeyInfo(v0) because `cryptography` refuses v1 (measured) while the importer still reads it; `pem-rfc7468` + `pkcs8` were already resolved in the lock (one lock line, no new package). ADR 0022, `tests/jwk_pem.rs` (18 tests, OpenSSL fixtures), `interop/tests/pem_jwcrypto.py` (60 checks, byte-equal against `openssl` re-encoding), harness `import-pem`/`export-pem`/`sign-pem` + RSA generation |
| 16 | `feat(jwk): PKCS#1 RSA import` | I1 | **done** — `jwk_from_pkcs1_der` / `jwk_from_pkcs1_public_der` + PEM labels `RSA PRIVATE KEY`/`RSA PUBLIC KEY`; key is **rebuilt** from n,e,d,p,q (primes must multiply to n, `de ≡ 1 mod p−1`) then normalized to PKCS#8 and run through the existing PKCS#8 import so the modulus floor and backend checks are shared; the file's `dp`/`dq`/`qi` are compared and a mismatch refused naming the member (neither trusted nor silently repaired); multi-prime refused by name (no JWK member for a third factor); thumbprints equal across PKCS#1/PKCS#8/SPKI for one key; PEM armor names RFC 7468 §3's 64-column rule when exceeded. ADR 0023, `tests/jwk_pkcs1.rs` (9 tests, OpenSSL fixtures + single-octet variants), `interop/tests/pem_jwcrypto.py` extended to 62 checks |
| 17 | `feat(jwk): SEC1 EC private key import` | I2 | **done** — `jwk_from_sec1_der` + PEM label `EC PRIVATE KEY` for P-256/P-384/P-521; refuses a scalar with no curve (guessing reads a P-256 secret as P-384), explicit curve parameters (curve asserted by the file, not named) — refused BY NAME via a tag classifier that can only sharpen a refusal, never grant an acceptance — a public point that does not derive from the scalar, and unsupported named curves naming the OID; survivors normalized to PKCS#8 and run through the shared importer, so SEC1/PKCS#8 give the same JWK, thumbprint and **identical signatures**. ADR 0024, `tests/jwk_sec1.rs` (9 tests, OpenSSL fixtures + rebuilt-SEQUENCE variants), `interop/tests/pem_jwcrypto.py` extended to 63 checks |
| 18 | `feat(jwk): password-encrypted PKCS#8 support` | I3 | **done** — RFC 5958 `ENCRYPTED PRIVATE KEY` import/export with an explicit scheme type (`Pkcs8Encryption`) and work budget (`Pkcs8ReadOptions`); the `pkcs5` feature set *is* the allow-list (SHA-1/DES/3DES unreachable, not merely refused), scheme + iteration budget checked **before** deriving, PBES1/scrypt/SHA-1/SHA-224 refused by name, no encrypted↔plain fallback either way, empty password refused on emit (ADR 0021 reused), and the encrypted payload normalized to portable PKCS#8 **before** encryption (the interop suite caught the version-1 Ed25519 case). Floor 2 048 = measured OpenSSL/`cryptography` default; emit 600 000 (175 ms); ceiling 10 000 000 (1.7 s). ADR 0025, `src/jwk/encrypted_pkcs8.rs` (11 lib tests incl. scrypt + OneAsymmetricKey regressions + ignored benchmark), `tests/jwk_encrypted_pkcs8.rs` (9 tests, OpenSSL fixtures + generator README), `interop/tests/pkcs8_encrypted_cryptography.py` (65 checks) |
| 19 | `feat(jwk): certificate public-key extraction` | I4 | **done** — `public_jwk_from_certificate_der`/`_pem` walk `Certificate`/`TBSCertificate` **positionally** (version-presence decided by tag, so the v1/v3 index shift is handled, not guessed) and hand the located SPKI to the existing importer, so there is one SPKI parser and no second key-type policy; DER-only per RFC 5280 A.1 (definite lengths, low tags, minimal lengths, no trailing bytes) — measured stricter than OpenSSL and matching `cryptography`; chains refused with a block count; no invented `kid`/`use`/`alg`; **no validation of any kind**, pinned by a tampered-signature test. No new dependency (ADR 0026 explains why `x509-cert` was not used). `src/jwk/cert.rs` (3 lib tests), `tests/jwk_cert.rs` (11 tests over 25 fixtures incl. decoy-SPKI-in-extension and signature-verification proof), `interop/tests/cert_cryptography.py` (42 checks incl. a Python-side RFC 7638 thumbprint) |
| 20 | `feat: executable capability reporting` | L0 | **done** — `src/capability.rs`: read-only rows (identifier / availability / operations / note) over JWS algs, JWE alg+enc, key formats and key types, with **four** distinct statuses (`Supported`, `RequiresFeature`, `RecognizedNotSupported`, `RefusedByPolicy(reason)`) and `features()` reporting this build's flags; `docs/capabilities.md` generated by `examples/capabilities.rs`; `tests/capability_report.rs` **performs** every advertised operation and **attempts** every advertised refusal across all five feature configs, enumerates the enums with exhaustive matches so a new variant without a row is a compile error, and fails if the committed docs go stale. Two hand-written rows were falsified while building it (an invented `HS1`; `ML-DSA-87-Ed448` wrongly called unsupported — it signs) — see ADR 0028 |
| 21 | `fix(jwt): unambiguous claim parsing` | L1 | duplicate-member rejection, raw-number tests |
| 22 | `feat(jws): JWK-aware JSON serialization APIs` | L2 | **done** — `jws::json` gains 12 JWK-aware entry points + `SignaturePolicy`/`GeneralJwkSigner`/`JwkSignatureResult`/`GeneralVerifyReport`/`MAX_CANDIDATE_KEYS`. The key rule set is shared **by function** (`compact::signer_from_jwk`/`verifier_from_jwk`, now called by both serializations), so `use`/`key_ops`, pinned-`alg` spelling and per-algorithm strength cannot drift — `tests/jws_jwk_json.rs` asserts the parity *observable* (same key+token ⇒ identical refusal text). Multi-signature success is an explicit `Any`/`All` choice; the report separates *rejected* from *not attempted* (reasons tiered: matching-verifier failure > key-rule refusal > alg-mismatch note) and bounds attempts at 64 candidate keys; all signers are built before the first signature is spent. `interop/tests/jws_json_jwcrypto.py` (**30 checks**) pins that **jwcrypto's verify is any-of**, that its JWKSet cannot drive multi-`kid` General JWS, and that it cannot emit detached JSON JWS at all. See ADR 0030 |
| 23 | `feat(jwk): bounded JWKS selection policy` | L3 | **done** — `src/jwk/selection.rs`: `SelectionPolicy` (`max_candidates` as an *error* not a truncation, `Fallback::{Refuse, TryWhenUnaddressable, TryAll}`, `require_kid`), deterministic `select` that refuses an unknown kid in an addressable set (and a kid-less token against one), `SetLimits`/`from_json_with_limits` checked **before** parsing, and three-state diagnostics (`Usable` via the real converter / `Unsupported` / `Invalid`) that keep every entry and its kid. `jwt::decode_with_jwkset_policy` added; **`from_json` and `decode_with_jwkset` left untouched** (pinned by a 70-key legacy test, because a quiet budget in a working path is a breaking change). `tests/jwk_selection.rs` 10 tests + `interop/tests/jwks_selection_jwcrypto.py` **21 checks**. See ADR 0031 |
| 24 | `feat: authenticated results and stable error categories` | L4 | result types, `JoseError` kinds, ADR |
| 25 | `feat(jwk): thumbprint URI and typed generation options` | L5 | **done** — `thumbprint_uri`/`thumbprint_uri_sha256` build RFC 9278 URIs and `JwkThumbprintUri::parse` validates one (prefix, IANA *Hash Name String* — `sha-256` hyphenated, others refused per §4 — unpadded base64url, and decoded length **must** equal the named digest); `matches()` compares under the algorithm the URI named. Reproduced the RFC §6 example byte for byte, and 68 interop checks against `jose`'s `calculateJwkThumbprintUri` across RSA/EC×4/Ed25519/oct × SHA-256/384/512. Typed `KeyGeneration`/`EcCurve`/`generate_key` reuse the existing generators (one statement of the RSA floor and curve set), refuse unsupported options by name, and deliberately have **no** feature-gated post-quantum variant. ADR 0027; 3 lib + 8 integration tests |
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
| 10 | `feat(jwe): ECDH key agreement with key wrapping (ECDH-ES+A128KW/+A192KW/+A256KW)` | K2 | `AgreementSender` with the two RFC 7518 §4.6 modes as separate methods (AlgorithmID `alg` vs `enc`, KEK length from `alg`), CEK carried wrapped under the agreed KEK, RFC 3394 mapping shared with `A*KW`; several recipients still refused because RFC 7516 gives a recipient element no protected header for its own `epk`; ADR 0018 (amends 0017), `tests/jwe_ecdh_kw.rs` (12 tests, RFC 7520 §5.4 both serializations), `jwe-ecdh-kw` matrix family (6 cells), jwcrypto agreement script extended to 84 checks. Matrix now 93 cells |
| 11 | `feat(jwk): X25519 agreement keys (OKP import + d-derives-x check)` | K3a | `AgreementCurve::X25519`, `generate_x25519()`, `jwk_to_x25519` refusing a `d` that does not derive `x` (the backend importer checks lengths only, and agreement multiplies with `d` while the message publishes `x`), curve-specific public encoding (bare u-coordinate vs SEC1 point), X448/Ed25519/Ed448 refused each with its own reason; ADR 0019 (amends 0016), `tests/jwe_ecdh_x25519.rs` (8 tests) + RFC 8037 §A.6 vector in `jwk_agreement.rs`, 4 new matrix cells + jwcrypto X25519 checks. Matrix now 97 cells |
| 12 | `feat(jwe): AES-GCM key management (A128GCMKW/A192GCMKW/A256GCMKW)` | K4 | `Prepared` enum so the key work happens **before** the header is serialized (the wrap's `iv`/`tag` are header members, and that header is the content AAD), `gcm_kw_wrap`/`gcm_kw_unwrap` on the existing `aes-gcm` dependency with sizes checked rather than asserted, `required_header_bytes`, caller-supplied `iv`/`tag` refused twice over (emit validation + the publishing helper), several recipients refused naming `iv and tag`; ADR 0020, `tests/jwe_gcm_kw.rs` (12 tests) + 7 internal unit tests (which also cover the RFC 3394/agreement wrap mapping, untested until now), `jwe-gcmkw` matrix family (6 cells), `interop/tests/jwe_gcm_kw_jwcrypto.py` (135 checks, unwrapping the header's wrap in Python and decrypting the content with it). Matrix now 103 cells |
| 8 | `feat(jwk): operation-aware key-agreement boundary` | K0 | `jwk::agreement` (`AgreementCurve`, `AgreementKey`/`PeerKey`, `agreement_key`/`peer_key`, `AgreementKey::derive_key`), one Concat KDF in `jwe::internal` (module made `pub(crate)` for it), ADR 0016, `tests/jwk_agreement.rs` (10 tests, RFC 7518 §C `Z` + derived key), `interop/tests/ecdh_kdf_vectors.py` (19 checks vs OpenSSL ECDH + an independent Python KDF), harness `agree`/`derive-key`. X25519 refused by name until its JWK import + `d`↔`x` check land (K3a) |
