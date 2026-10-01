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
