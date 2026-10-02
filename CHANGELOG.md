# Changelog

All notable changes to `jose-rs` from the `0.5.0` release onward are documented here.

## [Unreleased]

### Added

- Flattened JWE JSON Serialization (RFC 7516 §7.2.2) in the new
  `jose_rs::jwe::json` module: `encrypt_flattened*`, `decrypt_flattened*`,
  `FlattenedJwe::from_json`/`to_json`, and `to_compact`/`from_compact` for
  lossless conversion to and from the compact form. Every key-management and
  content algorithm already supported by `jose_rs::jwe` works, and messages
  produced by either serialization are readable by the other.
  `protected` is required (so `alg` is always integrity protected) and
  `unprotected`, `header` and `recipients` are refused by name rather than
  ignored; the parser also rejects duplicate JSON member names, non-string
  member values and non-canonical base64url. See ADR 0011.
- External additional authenticated data for the JSON serializations:
  `JweEncryptOptions::with_external_aad` / `JweDecryptOptions::with_external_aad`
  bind out-of-band bytes to the ciphertext through the `aad` member (RFC 7516
  §7.2.1). The data is authenticated but not encrypted, message/caller
  disagreement is reported by name instead of as a generic authentication
  failure, an empty value is refused, and the compact serialization refuses the
  option because it cannot represent it. See ADR 0012.
- The unprotected header members of the JSON serializations (`unprotected`
  shared, `header` per-recipient) are now read, with the parameter-name
  disjointness RFC 7516 §7.2.1 requires, so RFC 7516 §A.5's own flattened
  example decrypts. An `alg` conveyed there is accepted only when the caller's
  JWK pins the same algorithm; the raw-key APIs refuse it, and `enc`, `zip`,
  `crit` and the unimplemented key-agreement parameters are refused in
  unprotected positions outright. jose-rs never emits unprotected parameters.
  See ADR 0013.
- The **General JWE JSON Serialization** (RFC 7516 §7.2.1, multiple recipients
  sharing one ciphertext) is implemented in `jwe::general`: `GeneralJwe` parses
  and re-serializes it, `encrypt_general*` addresses several recipients with one
  CEK and one content encryption, and decryption is scoped to a recipient the
  caller names — an element index, or the key's own `kid` — because the header
  the content tag is validated under is per-recipient. Recipient arrays are
  bounded at `MAX_RECIPIENTS = 32`, per-recipient header names must be disjoint
  from the shared ones, and `dir` cannot address two recipients. See ADR 0014.
- JWE callers can now declare critical header extensions:
  `Jwe{Encrypt,Decrypt}Options::with_understood_crit`. The default remains "no
  extension is understood", so a message carrying `crit` is still refused unless
  the caller names the parameter; when it does, the RFC 7515 §4.1.11 structure is
  enforced identically on emit and receive, and both `crit` and the parameter it
  names are required to be integrity protected. Added
  `JweDecryptOptions::pinned_to_jwk`,
  `json::decrypt_flattened_with_jwk_options` and
  `general::decrypt_general_with_jwk_options` so the opt-in is reachable on every
  path. See ADR 0015.
- **ECDH key agreement with key wrapping (`ECDH-ES+A128KW`, `+A192KW`,
  `+A256KW`, RFC 7518 §4.6)** in the compact and flattened serializations: the
  agreement output is a key-encryption key of the length the algorithm names, the
  content encryption key is generated normally and carried wrapped under it, the
  Concat KDF's AlgorithmID input is the ASCII `alg` rather than `enc`, and the
  mode's whole key schedule is independent of direct agreement's, so a message
  cannot be read under the other mode's key. One recipient per message for now —
  several recipients need one `epk` each, and RFC 7516 gives a recipient element
  no protected header of its own (ADR 0018). Decrypts RFC 7520 §5.4's message;
  interoperates with panva in both directions and with jwcrypto (whose JSON
  serialization ships `epk` unprotected, as for `ECDH-ES`). See ADR 0018.
- **Direct ECDH key agreement (`ECDH-ES`, RFC 7518 §4.6)** in both JWE
  serializations: the content encryption key is agreed with the recipient rather
  than carried, so nothing is conveyed as the encrypted key, an ephemeral key pair
  is generated per message and published as `epk` in the protected header, and the
  recipient's key is consumed as a peer value with its point validated. It is
  reachable only through the JWK APIs (a `&[u8]` cannot name a curve), its
  operation permission is `deriveKey` rather than `encrypt`/`wrapKey`, it addresses
  exactly one recipient, `epk` is read from the integrity-protected header only,
  and `apu`/`apv` are honoured as Concat KDF inputs. `ECDH-ES+A128KW`/`+A192KW`/
  `+A256KW` remain unimplemented. Decrypts RFC 7520 §5.5's message; interoperates
  with panva in both directions and with jwcrypto (whose JSON serialization ships
  `epk` unprotected, a refusal that is documented and asserted). See ADR 0017.
- The **key-agreement boundary** in the new `jose_rs::jwk::agreement` module:
  `agreement_key()` prepares one's own half (curve support, `use`/`key_ops`
  permitting `deriveKey`, an `alg` pin that names a key-agreement algorithm, and
  the presence of private material are all enforced), `peer_key()` prepares the
  other half (public material only, point validated, no policy read from a
  sender-controlled key), and `AgreementKey::derive_key` performs agreement and
  RFC 7518 §4.6.2's Concat KDF in one step so the raw shared secret never has to
  be handled as a key. Curve mismatches are refused, and agreement is verified
  against RFC 7518 Appendix C. This is infrastructure for the `ECDH-ES*`
  key-management modes, which remain unimplemented. See ADR 0016.

### Internal

- `jose_rs::jwe` is split into `content` (AEAD / AES-CBC-HMAC), `internal`
  (envelope parsing, header policy, key management, encryption core) and the
  `compact` / `json` serialization front ends, so both share one policy
  implementation. No public API change.
- New internal `MemberMap`: strict JSON object parsing that preserves member
  order and rejects duplicate members instead of applying `serde_json`'s
  last-key-wins default.

## [0.9.0] - 2026-10-01

### Breaking

- `Claims::{exp, nbf, iat}` now use `Option<NumericDate>` instead of
  `Option<u64>`. Migrate integer assignments to `Some(seconds.into())`.
  JSON dates retain up to nanosecond precision instead of being floored.
  Nonzero subnanosecond values, negative zero, encodings over 128 bytes,
  and exponents outside the signed 32-bit range are rejected explicitly.
  Integer dates retain the full u64 range. Missing/null optional dates retain
  their existing absence semantics.
- Expiration now rejects at `now == exp + leeway`, as required by RFC 7519.
  The system clock and all time checks retain their fractional component.
  Not-before, future-issued-at, and maximum-age checks no longer floor dates.

### Fixed

- JWT JWK Set decoding rejects multiple entries matching the token's `kid`
  instead of selecting the first. This includes identical or unsupported keys.
  Mixed sets still retain unsupported entries; unknown-kid and unlabelled-set
  fallback rules are unchanged. `JwkSet::find_unique_by_kid` exposes the same
  unambiguous lookup for callers; legacy `find_by_kid` remains first-match.

- JWK-based JWS verification now selects symmetric key material using the
  actual signature algorithm and enforces HS256/384/512 minimum key lengths
  even when the JWK omits `alg`. Valid unpinned 256-bit HMAC keys no longer
  get misclassified as AES keys. JWT JWK/JWKSet verification inherits the fix.

### Added

- `JweDecryptOptions::with_max_plaintext` sets an inclusive plaintext-byte
  limit for option-aware JWE and nested JWT decryption. Oversized messages
  fail without returning plaintext. Existing algorithm policy, token-size
  bounds, and default behavior are unchanged; compression remains unsupported.

- `jwt::NumericDate` provides exact decimal JSON parsing/serialization and
  integer/Duration conversions. `Validation::validate_at` accepts a trusted
  explicit timestamp for deterministic validation and boundary testing.

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
