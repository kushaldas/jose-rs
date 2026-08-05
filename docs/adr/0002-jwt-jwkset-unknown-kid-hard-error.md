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
signature verification.

The rule is scoped to *addressable* sets — those in which at least one JWK
carries a `kid`. A set whose JWKs are all `kid`-less cannot be selected from
by name, so a pinned `kid` there names nothing that exists and the token is in
exactly the position of a kid-less one; those tokens still fall through to
try-all. Publishing a JWK Set without `kid` is common for single-key issuers,
and rejecting such tokens would break them for no security gain: there is no
key the token could have named instead.

The try-every-key fallback therefore applies to tokens with no `kid`, and to
kid-pinned tokens against an entirely unlabelled set.

## Requiring `kid`

The fallback means a token that names no key can still be accepted under any
key in the set — so an attacker holding *one* key in a set can omit `kid`
rather than name the wrong one. `Validation::require_kid()` closes this:
`decode_with_jwkset` rejects a kid-less token before touching any key, and the
same check runs in `Validation::validate_with_header`, so it also applies to
`decode`, `decode_with_jwk` and the nested-JWT paths.

This is opt-in, not the default: requiring `kid` would break issuers that
legitimately omit it, and RFC 7515 §4.1.4 makes `kid` optional.

## Security boundaries

| Threat | Control | Residual risk |
|--------|---------|---------------|
| Token accepted under a key it did not name (key-pinning bypass) | Unknown `kid` returns a hard error before any verification | Kid-less tokens still try every key by default; `Validation::require_kid()` closes this for sets mixing keys of differing trust |
| Attacker holds one key in a multi-trust set and omits `kid` to reach the try-all path | `Validation::require_kid()` rejects before any key is tried | Only if the caller enables it; sets should not mix trust domains in the first place |

## Consequences

**Positive**

- Key selection is deterministic when `kid` is pinned against an addressable
  set: exactly one key is ever used, or the token is rejected.
- Attacker-controlled tokens can no longer trigger verification attempts
  against unrelated keys in the set.
- Callers wanting strict pinning now have an API for it rather than having to
  pre-parse the header themselves.

**Negative / accepted trade-offs**

- Tokens whose `kid` drifted from the deployed JWK Set (e.g. stale caches)
  now fail instead of being rescued by the fallback; issuers must keep
  `kid` values in sync with their published sets.
- A set that labels *some* keys with `kid` is treated as addressable, so a
  kid-pinned token that matches none of them is rejected even if an
  unlabelled key in the same set would have verified it. Mixed labelling is
  ambiguous; failing closed is the safer reading.

## References

- `src/jwt/mod.rs` - `decode_with_jwkset` kid selection.
- `src/jwt/validation.rs` - `Validation::require_kid`.
- `src/jwt/mod.rs` - regression tests `decode_with_jwkset_unknown_kid_rejected`,
  `decode_with_jwkset_kidless_set_accepts_kid_pinned_token`,
  `decode_with_jwkset_partially_labelled_set_still_rejects_unknown_kid`,
  `require_kid_rejects_kidless_token_against_jwkset`,
  `require_kid_applies_to_plain_decode`.
