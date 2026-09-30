# Changelog

All notable changes to `jose-rs` from the `0.5.0` release onward are documented here.

## [Unreleased]

## [0.7.2] - 2026-09-30

### Added

- Expose `jwe::encrypt_with_header` and `jwe::encrypt_with_jwk_header`, also
  available through `jwe::compact`, so bindings and applications can encrypt
  with authenticated custom protected headers without patching or vendoring
  the backend. Algorithm/header consistency and JWK operation permissions
  remain enforced.
- Add public-API regression tests for custom header authentication, mismatched
  algorithms, and JWK operation restrictions.

### Changed

- Bumped the crate version to `0.7.2`.

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
