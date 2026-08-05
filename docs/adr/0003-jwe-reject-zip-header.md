# ADR 0003 - Reject JWE tokens declaring a zip header

- **Status:** Accepted
- **Date:** 2026-08-05
- **Component:** `src/jwe`
- **Related:** Security audit finding on `jwe::compact::decrypt_with_options`;
  RFC 7516 §4.1.3

## Context

RFC 7516 §4.1.3 defines the optional `zip` header member for JWE content
compression. This library does not implement compression, and its
`JoseHeader` struct has no `zip` field, so a `zip` member parsed into the
`extra` catch-all map and was silently ignored. A JWE produced by another
library with compression enabled would decrypt successfully but return the
still-compressed bytes as "plaintext" — a silent integrity/semantic failure
for the caller.

## Decision

`jwe::compact::decrypt_with_options` — the single choke point behind
`decrypt`, `decrypt_with_jwk`, and nested-JWT decoding — now rejects any
JWE whose protected header contains a `zip` member with
`JoseError::InvalidHeader` before any cryptographic operation. Compression
support is not added; tokens that need it must be handled by a library that
implements RFC 7516 §4.1.3.

## Security boundaries

| Threat | Control | Residual risk |
|--------|---------|---------------|
| Compressed plaintext returned as if decompressed | Hard rejection of any `zip` header member before decryption | Callers requiring compression cannot use this library for those tokens |

## Consequences

**Positive**

- No silent misdelivery of compressed bytes as plaintext.
- The rejection happens before any key management or content decryption,
  so malformed compression declarations cost no cryptographic work.

**Negative / accepted trade-offs**

- JWEs compressed by other libraries that previously "decrypted" (to
  garbage) now fail fast with an explicit error.

## References

- `src/jwe/compact.rs` - `decrypt_with_options` header validation.
- `src/jwe/compact.rs` - regression test `zip_header_rejected_on_decrypt`.
- RFC 7516 §4.1.3 - `zip` Header Parameter.
