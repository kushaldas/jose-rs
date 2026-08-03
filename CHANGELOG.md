# Changelog

All notable changes to `jose-rs` from the `0.5.0` release onward are documented here.

## [Unreleased]

## [0.6.0] - 2026-08-03

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
