# ADR 0005 - Validate JWK signature keys against the requested operation

- **Status:** Accepted
- **Date:** 2026-10-01
- **Component:** `src/jwk`, `src/jws/compact`, JWK-based JWT callers

## Context

Generic JWK material conversion infers AES for unpinned 16/24/32-byte octet
keys and HMAC for other sufficiently long octet keys. This cannot establish
whether a key is suitable for a particular signature algorithm. In particular,
an unpinned 32-byte HMAC key is classified as AES, while HMAC minimum-length
checks depend on optional algorithm metadata instead of the requested operation.

Bindings need a public conversion boundary with both algorithm and operation
context. Changing generic import to always select HMAC would break AES users.

## Decision

Add `jwk::jwk_to_signature_key(&Jwk, JwsAlgorithm, JwkOp)`. It accepts only
signing and verification, checks backend algorithm support, `use`, `key_ops`,
and exact agreement with any pinned algorithm. A temporary JWK copy supplies
operation context to existing key-type, curve, and material validation. The
original key is unchanged, conflicting pins are never replaced, and the
temporary copy's secret fields are wiped by the existing JWK drop implementation.
AKP keys retain their independently required `alg` member.

HMAC conversion consequently enforces the actual algorithm's 32/48/64-byte
minimum for HS256/384/512 regardless of optional metadata. Signing also
requires private or symmetric secret material.

Route compact JWK signing and verification through this helper. JWK-based JWT
and JWKSet verification inherit it. Preserve one-shot signing's existing
required algorithm pin and existing header/pin mismatch error variants.
Generic material conversion, raw signer/verifier APIs, and JWE are unchanged;
JWE already selects symmetric material and validates sizes by operation.

## Security boundaries

| Boundary | Enforcement | Remaining caller responsibility |
|----------|-------------|---------------------------------|
| HMAC strength | Minimum length follows the actual signature algorithm | Supply high-entropy secret material |
| Key authorization | Check use, operations, and exact algorithm pin | Select an allowed algorithm and trusted key |
| Algorithm/key compatibility | Validate type, curve, material, and signing capability | Use the returned key only with the checked algorithm and operation |
| Existing imports | Preserve generic conversion and AKP required metadata | Generic conversion alone does not authorize an operation |

## Consequences

Valid unpinned HMAC keys work with explicit signing context and JWK verification.
Insufficient HMAC keys are rejected even without metadata. Bindings must adopt
the new API to receive these operation checks; returning a software key does
not constrain arbitrary later backend use. No algorithm defaults or token
header rules are relaxed. The temporary clone adds bounded-by-key-size copying
to conversion and is preferred here over duplicating cryptographic validation.

## Validation and references

- `tests/jwk_signature_key.rs`: HMAC length boundaries, valid compact
  roundtrips, pre-authentication key rejection, immutable metadata,
  permissions, asymmetric compatibility, generic AES behavior, and AKP pins.
- `rfcs/rfc8725.txt`, sections 3.1 and 3.5: algorithm verification and
  sufficient key entropy.
- RFC 7518 section 3.2: HMAC key length requirements.
- `src/jwk/convert.rs`, `src/jws/compact.rs`: API documentation and integration.
