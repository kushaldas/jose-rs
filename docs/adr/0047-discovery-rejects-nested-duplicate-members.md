# ADR 0047 - Discovery rejects duplicate members before normalization

- Date: 2026-11-17
- Status: Accepted; extends ADR 0044 and preserves ADR 0029 for ordinary claims.

## Context

Discovery exposes nested claims as `serde_json::Value`. Its last-member-wins
normalization silently discards duplicate embedded JWKS `keys` and JWK `alg`,
`use`, or key-material members. The documented selector reserializes the Value
before strict JWK parsing, so that parser can no longer reject the original
ambiguity. Checking a signature over the original payload does not resolve which
reading of those signed duplicate members was intended.

## Decision

`UnverifiedJwt::parse` streams over the decoded payload before constructing any
claim Values and rejects duplicate names in every object, including objects in
arrays. Each object has its own set of decoded member names, so escaped equivalent
names collide and the same name remains valid in separate objects. Detection
returns `InvalidClaims` before the self-signed decoder invokes its selector.

The rule applies to all discovery payload objects rather than only a literal
`jwks` claim: selectors may read keys or policy from arbitrary claim names and
nesting positions. Ordinary JWT/Claims APIs retain ADR 0029's top-level-only
policy. Header processing is unchanged; this decision covers the reported payload
normalization boundary, not unrelated key-reference header handling.

## Security boundaries

This prevents key-policy confusion through JSON parser differentials (RFC 7517
section 4). It does not authorize embedded keys or change the signature input.
The existing token-size bound applies before decoding. The streaming preflight
retains serde_json's recursion limit and EOF checks and uses per-object hash sets.
It does not interpret numeric or string contents or create an intermediate Value
representation; the subsequent Claims parser preserves numeric precision.

## Consequences

Discovery now rejects nested ambiguous metadata that ordinary JWT decoding still
accepts. This stricter boundary costs an additional bounded JSON pass. No API,
dependency, wire encoding, or conventional claims-policy change is needed.

Signed raw-payload regressions cover duplicate JWKS/JWK members, escaped names,
alternative claim names, arrays, and identical duplicate values; they prove the
selector is never called. Controls cover valid embedded-key verification, separate
objects reusing names, JSON-looking strings, exact numbers, and ordinary claims
compatibility. Existing inspection fuzz targets/replays gain a duplicate-key seed.
