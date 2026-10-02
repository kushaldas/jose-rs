# Architecture Decision Records

Each ADR captures one significant decision: its context, the decision itself,
the security boundaries it establishes, and the consequences. ADRs are
immutable once accepted; supersede with a new record rather than editing
history.

| # | Title | Status |
|---|-------|--------|
| [0001](0001-jose-security-boundary-hardening.md) | JOSE security boundary hardening | Accepted |
| [0005](0005-operation-aware-jwk-signature-conversion.md) | Validate JWK signature keys against the requested operation | Accepted |
| [0006](0006-explicit-ed25519-wire-identifier.md) | Support the explicit Ed25519 wire identifier | Accepted |
| [0007](0007-configurable-jwk-thumbprint-hashes.md) | Allow explicit SHA-2 JWK thumbprint hashes | Accepted |
| [0008](0008-precise-jwt-numeric-dates.md) | Preserve fractional JWT timestamps | Accepted |
| [0009](0009-unambiguous-jwks-key-selection.md) | Reject ambiguous JWT key identifiers | Accepted |
| [0010](0010-jwe-plaintext-size-limit.md) | Configurable JWE plaintext-size limit | Accepted |
| [0011](0011-jwe-flattened-json-serialization.md) | Flattened JWE JSON Serialization requires a protected header | Accepted |
| [0012](0012-jwe-external-aad.md) | External additional authenticated data is authenticated, never confidential | Accepted |
| [0013](0013-jwe-unprotected-headers.md) | An unauthenticated `alg` is only ever read against a key that pins it | Accepted |
| [0014](0014-jwe-general-serialization.md) | A recipient is named by the caller, never chosen by the library | Accepted |
| [0015](0015-jwe-critical-extensions.md) | `crit` is refused by default and understood only by the caller | Accepted |
| [0016](0016-key-agreement-boundary.md) | The key-agreement boundary enforces operation, material and curve | Accepted, amended by 0019 |
| [0017](0017-direct-ecdh-key-agreement.md) | Direct key agreement agrees the CEK and publishes its own ephemeral key | Accepted, amended by 0018 |
| [0018](0018-ecdh-key-agreement-with-key-wrapping.md) | Agreement with key wrapping agrees a KEK, and waits for a place to put a second `epk` | Accepted |
| [0019](0019-x25519-agreement-keys.md) | X25519 is admitted to agreement only with a `d`-derives-`x` check | Accepted, amends 0016 |
