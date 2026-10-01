# Changelog

All notable changes to `jose-rs` from the `0.5.0` release onward are documented here.

## [Unreleased]

### Fixed

- JWK-based JWS verification now selects symmetric key material using the
  actual signature algorithm and enforces HS256/384/512 minimum key lengths
  even when the JWK omits `alg`. Valid unpinned 256-bit HMAC keys no longer
  get misclassified as AES keys. JWT JWK/JWKSet verification inherits the fix.

### Added

- `jwk::thumbprint::thumbprint` with `ThumbprintHash::{Sha256, Sha384, Sha512}`.
  The existing `thumbprint_sha256` function and SHA-256 default retain their
  outputs and errors. All supported hashes share the same required-member
  canonicalization; legacy hashes are not exposed by this API.

- Explicit `JwsAlgorithm::Ed25519` wire-name support for compact/JSON JWS
  and JWT, using the existing Ed25519 backend. JWK `alg: "Ed25519"` now
  requires OKP/Ed25519 material. `EdDSA` remains supported but is not an
  alias in JWK pins or JWT allowlists. Downstream exhaustive matches on
  `JwsAlgorithm` must handle the new variant. No dependency or feature change.

- `jwk::jwk_to_signature_key(jwk, alg, op)` for bindings and explicit JWS
  operations. It checks algorithm pins, operation permissions, key type/curve,
  HMAC strength, and private material for signing without modifying the JWK.
  Generic material conversion and one-shot signing's required `alg` pin are
  unchanged. Callers remain responsible for selecting an allowed algorithm
  and using the returned key with the same algorithm and operation.

## [0.8.0] - 2026-10-01

`0.7.2` was prepared on the release branch but never published; its changes
ship here. The header-policy changes below reject inputs that `0.7.1`
accepted, hence the minor-version bump.

### Breaking

- Signing (every `jws::compact`, `jws::json` and `jwt::encode*` entry point)
  and JWE encryption with a caller-supplied header now reject protected
  headers that `0.7.1` accepted:
  - a `JoseHeader::extra` entry that repeats a typed member (`alg`, `enc`,
    `kid`, `typ`, `cty`, `jku`, `jwk`, `x5u`, `x5c`, `x5t`, `x5t#S256`,
    `crit`). Previously this emitted a duplicate JSON member; set the typed
    field instead. Other `extra` names (including `b64`) are unaffected.
  - the key-reference members `jku`, `jwk`, `x5u` and `x5c`, unless the new
    `allow_key_reference_headers` opt-in is set. Code signing a header built
    with `jws::x5::bind_cert_to_header` must opt in, e.g.
    `SignOptions::new().with_key_reference_headers(true)` with
    `sign_with_options`, `sign_flattened_opts`, `jwt::encode_with_options`,
    `jwt::encode_nested_with_options`, or a `GeneralSigner`.
  - headers or tokens larger than `MAX_TOKEN_BYTES`, which this crate's
    decoders already refused (`InvalidHeader` for the header,
    `InvalidToken` for the token or a JWS JSON payload or signature
    member; the signature is checked after signing because a custom or HSM
    `Signer` controls its length).
- JWS signing (every `jws::compact`, `jws::json` and `jwt::encode*` entry
  point, including nested JWT) additionally rejects:
  - JWE-only members (`enc`, `zip`, `epk`, `apu`, `apv`, `iv`, `tag`, `p2s`,
    `p2c`) in the protected header, whether set through the typed `enc`
    field or through `extra`. RFC 7516 §9 identifies a JWE header by the
    presence of `enc`, so a signed JWS header carrying it claimed to be a
    JWE; the others describe processing a JWS never performs (IANA JOSE
    header registry, usage location "JWE").
  - a `crit` list naming a header parameter registered by RFC 7515,
    RFC 7516 or RFC 7518 (e.g. `crit: ["kid"]`), even if the caller lists it
    in `SignOptions::understood_crit`, and a `crit` list naming any
    parameter twice. RFC 7515 §4.1.11: producers "MUST NOT include Header
    Parameter names defined by this specification or [JWA] for use with
    JWS, duplicate names, ... in the `crit` list". RFC 7797 `b64` is still
    allowed (and required with `b64: false`). Verification is unchanged: a
    peer's token with a registered name in `crit` still verifies when the
    caller declares it understood, as §4.1.11 only says recipients MAY
    reject it.
- JWS JSON signing (`sign_flattened_opts`, `sign_flattened_detached_opts`,
  `sign_general_full`) now validates the unprotected `header` member: it must
  be a JSON object whose member names are disjoint from the protected header
  (RFC 7515 §7.2.1), must not contain `crit` or `b64` (which must be
  integrity protected) or any JWE-only member (`zip`, `enc`, `epk`, ...), and
  follows the key-reference opt-in.
- `jws::SignOptions` and `jwe::JweEncryptOptions` are now
  `#[non_exhaustive]`, so future policy switches are not breaking changes.
  Outside this crate they can no longer be built with a struct literal,
  including `..SignOptions::new()` update syntax. Start from `new()` and use
  the new builders (`with_b64`, `with_understood_crit`,
  `with_key_reference_headers`), or assign the public fields on a `mut`
  binding. `SignOptions` also has a new public field,
  `allow_key_reference_headers`.

### Added

- Expose `jwe::encrypt_with_header` and `jwe::encrypt_with_jwk_header`, also
  available through `jwe::compact`, so bindings and applications can encrypt
  with authenticated custom protected headers without patching or vendoring
  the backend. Algorithm/header consistency and JWK operation permissions
  remain enforced. The header must not repeat a typed member in `extra`,
  carry `crit`, or carry a registered member this crate does not implement
  for JWE compact (`zip`, `b64`, `epk`, `apu`, `apv`, `p2s`, `p2c`, `iv`,
  `tag`), so these APIs never emit a token that the decrypt side refuses or
  that a peer implementing those members would read differently.
- `jwe::JweEncryptOptions` with `jwe::encrypt_with_header_options` and
  `jwe::encrypt_with_jwk_header_options`, to opt in to key-reference members.
- `jws::compact::sign_with_jwk_options`, `jwt::encode_with_options`,
  `jwt::encode_with_jwk_options`, `jwt::encode_nested_with_options` and
  `jwt::encode_nested_with_jwk_options`, so every JWK and JWT signing path,
  nested JWT included, can take `SignOptions` (e.g. to emit an `x5c` chain
  in the inner JWS header). The options apply to the inner JWS only; the
  outer JWE header is still built by the library.
- Builders `SignOptions::with_b64`, `SignOptions::with_understood_crit`,
  `SignOptions::with_key_reference_headers` and
  `JweEncryptOptions::with_key_reference_headers`.
- `header::KEY_REFERENCE_MEMBERS`, the list of members covered by the opt-in,
  and `header::JWE_ONLY_MEMBERS`, the members JWS signing refuses.
- `rfcs/rfc8725.txt` (JWT Best Current Practices) for reference.
- Interop matrix (`interop/`): custom protected-header JWS cells, JWE compact
  cells (`dir` and `A256KW` with `A256GCM` / `A128CBC-HS256`, both
  directions), and duplicate-member cells. The latter confirm that
  panva/jose accepts a validly signed header with a duplicated `kid` or
  `alg` and uses the last value, while jose-rs rejects it; a duplicated
  extension member resolves to the last value in both.

### Security

- Reject protected headers whose `extra` map repeats a member already
  serialized by a typed `JoseHeader` field. `extra` is flattened into the
  same JSON object, so such a header was signed with a duplicate member,
  e.g. `{"alg":"HS256","alg":"none"}`. The sign-side `alg` and `crit` checks
  only saw the typed field, while last-key-wins parsers (JavaScript
  `JSON.parse`, panva/jose) read the `extra` value. This crate's own
  verifier already rejected such tokens as duplicate fields.
- Every caller-supplied protected header is now serialized through a single
  checked path (`JoseHeader::to_protected_b64`), so a new signing or
  encryption path cannot skip the duplicate-member, key-reference or size
  rules.
- Refuse key-reference members (`jku`, `jwk`, `x5u`, `x5c`) on emit unless
  opted in. This crate never dereferences them, but a peer might (RFC 8725
  §2.9 / §3.10), so an application forwarding caller-controlled data into a
  header could otherwise mint key references under a trusted key.
- Enforce `MAX_TOKEN_BYTES` on emit, before any signing or encryption where
  possible, so the crate never produces a token (for example from a large
  caller-supplied header value) that its own decoders refuse.
- Refuse JWS JSON unprotected headers that contradict or duplicate the
  protected header, or that carry members which must be integrity
  protected, closing the unprotected-header variant of the same ambiguity.
- Refuse JWE-only members in JWS headers (protected and unprotected), so a
  signed JWS header can no longer claim to be a JWE (RFC 7516 §9).
- Enforce the RFC 7515 §4.1.11 producer rules for `crit` (no registered
  names, no duplicates) on every signing path.

### Tests

- Table-driven regression tests across all 18 public JWS/JWT signing entry
  points and all 4 JWE header-encryption entry points: duplicate members,
  key-reference opt-in, header and token size limits, unprotected-header
  rules, JWE-only members in JWS headers, registered and duplicate `crit`
  names, and unimplemented JWE members. Every token the JWE tests emit is
  also decrypted. A nested-JWT round trip checks that an opted-in `x5c`
  chain survives sign, encrypt, decrypt and verify. Each test's rustdoc
  cites the RFC section it enforces.
- `tests/header_parsing.rs` pins the decode-side half of the design: a
  duplicated typed member (including the `\u0061lg` escape) fails to parse,
  and every JWS/JWT verify and JWE decrypt entry point rejects a token with
  such a header even when its signature is valid.
- A unit test keeps the reserved member list in sync with the `JoseHeader`
  fields; unit tests pin the registered-name set used for `crit`, and that
  verification still accepts a peer's registered `crit` name when declared
  understood.

### Changed

- Bumped the crate version to `0.8.0` (from `0.7.1`; `0.7.2` was not
  released).

## [0.7.1] - 2026-09-28

### Security

- Reject RSA-PSS-specific PKCS#8 and SPKI imports instead of silently losing
  their PSS-only and parameter restrictions during JWK conversion. This also
  rejects PSS wrappers with absent parameters. Ordinary `rsaEncryption` DER
  remains supported for RS* and PS* algorithms.
- Add regression coverage for mixed-case, whitespace, and escaped `alg`
  values across JWS and JWT verification APIs.

### Documentation

- Document the RSA-PSS import restriction and the security invariants checked
  by the new test helpers and regression tests.

### Changed

- Bumped the crate version to `0.7.1`.
- Updated `kryptering` from `0.5` to `0.6` in the library, fuzz targets, and
  interop harness, and refreshed the dependency lockfiles.
- Kept transitive `aes` at `0.9.2` in the lockfiles to preserve Rust 1.88
  compatibility (`0.9.3` requires Rust 1.89).
- Updated compatible dependencies, including `rand`, `serde`, `serde_json`,
  `thiserror`, and `cryptoki`.
- Replaced the yanked transitive `spin 0.9.8` dependency with `0.9.9` and
  removed its obsolete CI audit warning exception.


## [0.7.0] - 2026-08-05

### Changed

- Bumped the crate version to `0.7.0`.

### Security

- Changed `jwt::decode_with_jwkset` to return a hard error when the token
  header pins a `kid` that matches no JWK in the set, instead of falling
  through and trying every key. The try-all fallback now applies to kid-less
  tokens, and to kid-pinned tokens against a set in which no JWK carries a
  `kid` at all — such a set cannot be addressed by name, so the pinned `kid`
  selects nothing and no pinning is weakened by trying each key. Sets that
  label at least one JWK with a `kid` are treated as addressable and reject
  an unmatched `kid`.
- Added `jwt::Validation::require_kid()`, which rejects tokens whose protected
  header carries no `kid`. `decode_with_jwkset` enforces it before trying any
  key, closing the path where an attacker holding one key in a JWK Set omits
  `kid` to reach the try-every-key fallback and be accepted under that key.
  Off by default — `kid` is optional in RFC 7515 §4.1.4.
- Rejected JWE tokens whose protected header declares a `zip` member, since
  content compression is not implemented and the compressed bytes would
  previously have been returned as plaintext.
- Rejected empty-but-present `crit` header arrays on JWE decrypt per
  RFC 7515 §4.1.11.

### Documentation

- Added ADRs 0002–0004 under `docs/adr/` covering the three security fixes
  above.

## [0.6.0] - 2026-08-04

### Added

- Added all six composite ML-DSA JWS algorithms from
  `draft-ietf-jose-pq-composite-sigs-03`, including strict AKP aggregate-key
  import/export, key generation, JWS/JWT signing and verification, thumbprints,
  draft Appendix A vectors, and a composite verification fuzz target.

### Changed

- Bumped the crate version to `0.6.0`.
- Updated to kryptering 0.5's opaque software-key API and raised the minimum
  supported Rust version to 1.88.

### Security

- Changed RSA-OAEP CEK recovery to use implicit rejection: failed unwraps and
  incorrectly sized CEKs now continue through content authentication with a
  random zeroizing fallback CEK instead of exposing a distinct early error.

### Documentation

- Completed documentation for the public Rust API and enabled the
  `missing_docs` lint so new exported items remain documented.

## [0.5.1] - 2026-07-07

### Changed

- Bumped the crate version to `0.5.1`.
- Updated `kryptering` from `0.3` to `0.4` and refreshed the dependency lockfile.

## [0.5.0] - 2026-06-24

### Added

- Added expanded JWS JSON Serialization support, including flattened and general serialization helpers, detached payload support, multi-signature verification results, and signer configuration helpers.
- Added compact JWS signing and verification options with `SignOptions`, `VerifyOptions`, and `LIB_UNDERSTOOD_CRIT`.
- Added RFC 7797 unencoded payload support for `b64: false`.
- Added `jws::x5` helpers for certificate thumbprints, x5c leaf extraction, and protected-header certificate binding checks.
- Added JWK import helpers for PKCS#8 and SPKI DER inputs.
- Enabled PKCS#8 support for P-256 and P-384 key handling.

### Security

- Hardened JWS `crit` validation by rejecting empty lists, unsupported extensions, absent critical parameters, and invalid `b64` usage.
- Bounded General JWS signing and verification to 64 signatures and added size checks on JSON serialization inputs.
- Required consistent `b64` policy across General JWS signatures before verifier-specific algorithm matching.
- Strengthened JWT validation with `typ` pinning, signing-algorithm allow-lists, required timestamp claim options, and `with_max_age` enforcement that requires `iat`.
- Required symmetric JWE one-shot JWK APIs to use `kty: "oct"` for `dir` and AES Key Wrap algorithms.
- Rejected sub-2048-bit RSA keys during PKCS#8 and SPKI DER import.

### Fixed

- Avoided exposing a General JWS payload unless at least one signature verifies.
- Preserved payload signing input during verification instead of re-encoding it, including for unencoded payload flows.
