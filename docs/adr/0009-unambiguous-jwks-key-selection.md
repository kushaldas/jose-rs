# ADR 0009 - Reject ambiguous JWT key identifiers

- **Status:** Accepted
- **Date:** 2026-10-01
- **Component:** `src/jwk`, `src/jwt`
- **Related:** ADR 0002 (unknown kid and fallback rules)

## Context

Mixed federation JWKS may publish supported and unsupported keys together.
The Rust JwkSet parser already retains structurally valid entries without
requiring backend support. The pyjosers eager-import restriction is a separate
binding concern. Removing unsupported entries in Rust would change which
identifiers remain addressable and could enable the entirely-unlabelled
fallback described in ADR 0002.

JWT decoding previously selected the first matching kid. Duplicate identifiers
therefore made the outcome depend on publication order. pyjosers already
rejects ambiguous single-key lookup, and backend selection should be equally
explicit about ambiguity.

## Decision

Add JwkSet::find_unique_by_kid, returning an absent result, one borrowed key,
or a key error for multiple matches. Use it in jwt::decode_with_jwkset.
Reject duplicates before material conversion, algorithm filtering, or signature
verification, including identical keys and unsupported entries. Compare kid
case-sensitively, as before. Errors do not include key material.

Keep find_by_kid as a documented first-match inspection API for compatibility.
Keep parsing and serialization unchanged: unsupported entries and duplicate
identifiers survive import. Do not introduce an implicit skip-invalid policy.
Parsing validates typed structure, not cryptographic material or authorization.

## Preserved boundaries

- A unique supported key still undergoes all operation, algorithm, material,
  signature, and claims checks.
- A unique unsupported key selected by kid fails without fallback.
- Unknown kid in any labelled set still fails, even if the only labelled
  entry is unsupported.
- Kid-less tokens and entirely unlabelled sets retain existing try-all rules.
  require_kid still rejects a token without kid; it does not require labels on
  keys or establish trust in the supplied set.
- No network discovery, trust inference, new algorithms, or weaker validation
  is introduced. Standalone Ed448 remains unsupported.

## Consequences and validation

This intentionally rejects JWTs previously accepted through first-match
selection when their kid is ambiguous. Issuers should publish distinct key
identifiers or callers should explicitly select an authorized key and use
decode_with_jwk. No global ban on duplicate identifiers is imposed on storage.
Only duplicates matching the token's kid affect labelled selection.

tests/jwks_selection.rs covers duplicate order, identical material, mismatched
algorithm metadata, unsupported entries, mixed-set JSON roundtrip, unknown and
unsupported identifiers, preserved fallback rules, required kid, malformed
typed fields, and empty sets. Additional checks retain operation permissions, algorithm,
issuer, type, and required-claim policies and allow unrelated duplicate kids.
Disposable HMAC keys exercise actual JWT signing
and verification without external fixtures. This tests a local selection
policy, not wire-format or cryptographic interoperability.
