# ADR 0002 - Unknown kid in JWT header is a hard error in JWK Set decoding

- **Status:** Accepted
- **Date:** 2026-08-05
- **Component:** `src/jwt`
- **Related:** Security audit finding on `jwt::decode_with_jwkset`

## Context

`jwt::decode_with_jwkset` selects a verification key from a caller-supplied
JWK Set. Previously, when the token header pinned a `kid` that matched no JWK
in the set, the function silently fell through to the kid-less path and tried
every key in the set until one verified. This weakened key-pinning semantics:
a token naming an unknown key could still be accepted under any other key in
the set, and every key in the set was exercised against attacker-controlled
input the token itself never claimed to target.

## Decision

When the token header carries a `kid` and no JWK in the set matches it,
`decode_with_jwkset` now returns `JoseError::Key` immediately
("no JWK in the set matches the token's kid ...") without attempting any
signature verification. The try-every-key fallback is retained only for
tokens whose header carries no `kid` at all, preserving the documented
kid-less behaviour.

## Security boundaries

| Threat | Control | Residual risk |
|--------|---------|---------------|
| Token accepted under a key it did not name (key-pinning bypass) | Unknown `kid` returns a hard error before any verification | Kid-less tokens still try every key; callers wanting strict pinning must require `kid` |

## Consequences

**Positive**

- Key selection is deterministic when `kid` is pinned: exactly one key is
  ever used, or the token is rejected.
- Attacker-controlled tokens can no longer trigger verification attempts
  against unrelated keys in the set.

**Negative / accepted trade-offs**

- Tokens whose `kid` drifted from the deployed JWK Set (e.g. stale caches)
  now fail instead of being rescued by the fallback; issuers must keep
  `kid` values in sync with their published sets.

## References

- `src/jwt/mod.rs` - `decode_with_jwkset` kid selection.
- `src/jwt/mod.rs` - regression test `decode_with_jwkset_unknown_kid_rejected`.
