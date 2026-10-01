# ADR 0007 - Allow explicit SHA-2 JWK thumbprint hashes

- **Status:** Accepted
- **Date:** 2026-10-01
- **Component:** `src/jwk/thumbprint`

## Context

The existing API computes only SHA-256 thumbprints. Compatibility consumers
also need SHA-384 and SHA-512, without changing stored SHA-256 identifiers
or making legacy hashes available through a broad backend hash selector.
RFC 7638 separates required-member canonicalization from hash selection.

## Decision

Add `thumbprint(&Jwk, ThumbprintHash)` and a dedicated enum containing only
`Sha256`, `Sha384`, and `Sha512`. Its default is `Sha256`. Keep the existing
`thumbprint_sha256` as a compatibility wrapper. All three choices use the
same required-member selection, lexicographic ordering, UTF-8 JSON escaping,
and unpadded base64url output. Reuse the backend's existing digest API;
no dependencies or feature flags change.

Optional metadata and asymmetric private fields remain excluded. AKP `alg`
remains required and contributes to the hash. An octet key's secret `k`
member remains part of its thumbprint. Missing required members and unknown
key types retain the existing errors. No key material is normalized or
mutated, and this operation does not validate mathematical key material.

## Security boundaries

| Boundary | Policy |
|----------|--------|
| Hash selection | Only SHA-256/384/512; legacy builds do not expand the choices |
| Existing identifiers | The SHA-256 wrapper and default preserve existing outputs |
| Canonicalization | One shared implementation with JSON escaping and required fields only |
| Key trust | A thumbprint identifies a supplied representation; it is not authentication or authorization |

Applications must agree on the hash algorithm: a bare digest does not
identify its hash. Thumbprints of low-entropy symmetric secrets can allow
offline guessing; choosing a longer digest does not increase key entropy.

## Consequences

Bindings can expose configurable SHA-2 thumbprints without implementing
hashing or canonicalization themselves. Existing callers need no changes.
Python argument adapters and thumbprint URI formatting remain separate work.

## Validation and references

- `tests/thumbprint_hashes.rs`: jwcrypto 1.6.1 SHA-2 reference values,
  RSA/EC/OKP/oct/AKP required-member handling, missing-field errors,
  escaping, immutable inputs, and generated private/public key equivalence.
- Existing RFC 7638 RSA SHA-256 regression remains unchanged.
- `src/jwk/thumbprint.rs`: runnable rustdoc example and API contracts.
- [RFC 7638 sections 3.2-3.4](https://www.rfc-editor.org/rfc/rfc7638.html):
  required members, canonical representation, and hash selection. This RFC
  is not currently present in the local `rfcs/` collection.
