# ADR 0004 - Reject empty crit arrays on JWE decrypt

- **Status:** Accepted
- **Date:** 2026-08-05
- **Component:** `src/jwe`
- **Related:** Security audit finding on `jwe::compact::decrypt_with_options`;
  RFC 7515 §4.1.11 / RFC 7516 §4.1.13

## Context

`jwe::compact::decrypt_with_options` rejected non-empty `crit` header arrays
because the library understands no critical extensions, but accepted an
empty-but-present `crit` array. RFC 7515 §4.1.11 (applied to JWE via RFC
7516 §4.1.13) states that when `crit` is present it MUST NOT be empty, so an
empty `crit` is a malformed header that strict parsers must reject; accepting
it diverges from the JWS side of this crate, which already rejects empty
`crit` lists.

## Decision

`jwe::compact::decrypt_with_options` now rejects a present-but-empty `crit`
array with `JoseError::InvalidHeader`
("crit header must not be empty (RFC 7515 §4.1.11)"), alongside the existing
rejection of non-empty `crit` arrays. Since no critical extensions are
supported, a `crit` member of any shape is now always rejected on JWE
decrypt.

## Security boundaries

| Threat | Control | Residual risk |
|--------|---------|---------------|
| Malformed (empty) `crit` accepted, diverging from RFC-mandated validation | Present-but-empty `crit` rejected before any cryptographic operation | Non-empty `crit` already rejected; no extension support is added |

## Consequences

**Positive**

- JWE header validation now matches the RFC and the crate's JWS behaviour.
- Malformed headers fail fast, before key management or content decryption.

**Negative / accepted trade-offs**

- Tokens carrying a superfluous empty `crit` member that previously
  decrypted now fail; producers must omit `crit` entirely.

## References

- `src/jwe/compact.rs` - `decrypt_with_options` header validation.
- `src/jwe/compact.rs` - regression test `empty_crit_rejected_on_decrypt`.
- RFC 7515 §4.1.11 - `crit` Header Parameter.
