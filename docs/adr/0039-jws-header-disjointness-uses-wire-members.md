# ADR 0039 — JWS header disjointness uses wire members

## Date

2026-10-16

## Status

Accepted.

## Context

RFC 7515 §7.2 requires the protected and unprotected header parameter-name sets for a
JSON JWS signature to be disjoint. Emit paths enforced that rule, but verify paths did
not. Checking after conversion to `JoseHeader` is insufficient: a protected member such
as `"kid": null` is present on the wire but becomes `None`, and serialization of that
typed value omits the member. An attacker could then supply an unprotected `kid` and
create two readings of the same signature entry.

## Decision

Flattened and General JWS verification reject the whole document when any signature's
unprotected `header` is not an object or shares a member name with its protected header.
The comparison parses the original protected JSON into the duplicate-rejecting ordered
member representation. It never reconstructs the member set from `JoseHeader`.

The same structural preflight is shared by raw-verifier and JWK-aware entry points and
runs before verifier construction or signature attempts.

## Security boundaries

- Unprotected metadata remains reportable but never gains authority from successful
  verification.
- A `null` protected value still occupies its wire-level parameter name.
- A malformed signature entry makes the envelope structurally ambiguous; success from a
  different signature does not make that ambiguity acceptable.

## Consequences

- JSON JWS documents previously accepted with colliding protected/unprotected names are
  now refused.
- Callers that need both values must rename the application-specific unprotected member.
- Protected bytes remain verbatim in the signing input; this decision only inspects their
  member names.

