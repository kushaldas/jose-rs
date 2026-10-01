# ADR 0006 - Support the explicit Ed25519 wire identifier

- **Status:** Accepted
- **Date:** 2026-10-01
- **Component:** `src/algorithm`, `src/jwk`, JWS and JWT consumers

## Context

The library supports the Ed25519 primitive through `alg: "EdDSA"`, but
cannot read or emit signatures using the fully specified `Ed25519`
identifier defined in RFC 9864 section 2.2. Rewriting the identifier as an
alias would lose the distinction needed by application algorithm policies
and could alter the bytes over which signatures are verified.

## Decision

Add a distinct `JwsAlgorithm::Ed25519` variant with exact parsing and serde
roundtrips. Map it to the existing backend Ed25519 primitive. Retain the
`EdDSA` variant and its existing Ed25519-only implementation.

Require `kty: "OKP"` and `crv: "Ed25519"` for JWK metadata naming the
new algorithm. Continue exact JWK pin comparisons and JWT algorithm
allowlist comparisons. A key pinned to one wire name cannot authorize
the other. Generated keys remain unpinned; callers choose their wire name.

Compact, flattened, general, detached, and RFC 7797 JWS reuse existing
header validation and signing-input construction. Verification authenticates
the received protected-header bytes without renaming or reserializing them.

## Security boundaries

| Boundary | Policy |
|----------|--------|
| JWK key type and curve | Ed25519 metadata requires OKP/Ed25519 material |
| JWK authorization | Existing `use`, `key_ops`, and exact `alg` checks remain |
| JWT allowlists | Ed25519 and EdDSA are separate entries |
| Raw verifier binding | Backend Ed25519 verifiers accept both wire names; applications needing a single name must apply JOSE-level policy |
| Signature integrity | Preserve original protected bytes; header changes invalidate authentication |

Raw backend verifiers do not carry a JOSE identifier and cannot distinguish
these two names at primitive level. This is documented explicitly rather
than implying that primitive matching enforces a wire-name allowlist.
No token parser limits, critical-header rules, or key validation are relaxed.

## Consequences

Applications can use fully specified Ed25519 without backend changes or
additional feature flags. Legacy EdDSA workflows remain valid. Adding an
enum variant requires downstream exhaustive matches to be updated. Ed448,
new curves, and Python binding changes remain separate work items.

## Validation and references

- `tests/ed25519.rs`: exact identifiers, JWK pins and permissions, key
  compatibility, JWT allowlists, JSON/detached serialization, and original
  protected-byte authentication.
- `interop/tests/ed25519_jwcrypto.py`: disposable-key compact interoperability
  in both directions for Ed25519 and legacy EdDSA using jwcrypto 1.6.1.
- `src/jwk/generate.rs`: runnable rustdoc example.
- [RFC 9864 sections 2.2 and 4](https://www.rfc-editor.org/rfc/rfc9864.html):
  fully specified identifiers and unchanged key representations. This RFC
  is not currently present in the local `rfcs/` collection.
- `rfcs/rfc8725.txt`, section 3.1: algorithm verification.
