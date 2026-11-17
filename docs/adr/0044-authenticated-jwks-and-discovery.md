# ADR 0044 — Discovery reads untrusted claims; verification returns a fresh result

- Date: 2026-11-17
- Status: Accepted; extends ADRs 0031 and 0032.
- Release: 0.12.0

## Context

Applications need the authenticated header when verifying against a JWK Set.
Self-signed documents also require reading embedded candidate keys before checking
the signature. The deprecated unverified decoder makes this legitimate trust
boundary hard to express, and a synchronous selector cannot cover async discovery.

## Decision

Add `decode_with_jwkset_authenticated` and
`decode_with_jwkset_policy_authenticated`. Existing claims-only functions delegate
to these and keep their selection rules, including the legacy unbounded fallback.
`Authenticated::verified_key_index()` reports the successful original set index,
including fallback trials, and survives `map()`. Single-key and JWE results carry
no set index. The index is private metadata, not an issuer identity.

Add `UnverifiedJwt::parse`, `header()`, `claims()`, `verify_with()` and
`verify_with_policy()`. It privately owns the original compact token. Inspection
checks compact shape, canonical base64url, existing token/claims limits and duplicate
members, but confers no authentication. Debug omits the token and claims.
Verification checks the original bytes and parses fresh verified claims.

Add synchronous `decode_self_signed(token, validation, select_keys)`. Its selector
runs once over untrusted claims and returns candidate keys, never trusted identity.
Both this helper and inspection's default verification use bounded
`SelectionPolicy::default()`. Async applications retain the inspection value while
doing their own discovery, then supply keys. Policy-aware verification remains
available for explicit fallback and budget choices.

## Security boundaries

RFC 8725 §3.10: discovery is an attacker-controlled input boundary. No URL fetching,
issuer trust, authorization, federation profile, cache, HTTP client or runtime is
added. A valid self-signature only proves possession of the selected key. Named
sets still require a matching token kid under default bounded selection. Candidate
ceilings and duplicate-kid rejection run before key trials. All key metadata,
critical-header, signature and caller claim-policy checks remain in force.

## Consequences

`Authenticated` gains a private field; external struct construction and exhaustive
struct patterns cease to compile. Its constructor was already intended to be
crate-private in ADR 0032. Read public fields or transform with `map()` instead.
Existing functions retain return types and error/selection behavior. An inspected
JWT keeps both the original token and parsed inspection data until dropped.
The old deprecated decoder remains for compatibility. The existing JWT fuzz target
and stable corpus replay cover the new inspection and bounded verification path.
