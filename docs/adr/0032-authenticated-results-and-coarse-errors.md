# ADR 0032 — Authenticated results, and errors coarse enough not to lie

## Date

2026-07-28

## Status

Accepted

## Context

Verification APIs returned a `Vec<u8>`. A caller that also needed the header — `kid` for
rotation, `typ`/`cty` for handling, a private member for routing — had to re-parse it, and the
data structure that made that easy was the problem: a JWS/JWE document can carry the same
member in a protected **and** an unprotected place (`unprotected`, the per-signature
`header`, the general form's shared `unprotected`). Whichever copy the caller's re-parse
happened to reach for decided the answer, and re-parsing the unprotected one after a
successful verification is how "we checked the signature *and then* trusted cleartext"
happens in production JOSE.

The second half of L4 asked whether typed errors should distinguish unsupported capability,
invalid structure, policy rejection, and authentication failure. They should — except for one
split that must not be offered.

## Decision

### `Authenticated<T>`: separate fields, no public constructor

`crate::Authenticated<T>` carries `value`, `protected` (the header the signature or AEAD tag
covered), and `unprotected: Vec<Value>` (verbatim, in document order, one entry per
unauthenticated object). It is returned by:

* `jws::compact::{verify_authenticated, verify_with_jwk_authenticated}`
* `jws::json::verify_flattened_with_jwk_authenticated`
* `jwt::decode_with_jwk_authenticated`
* `jwe::compact::decrypt_with_jwk_authenticated`
* `jwe::json::decrypt_flattened_with_jwk_authenticated`
* `jwe::general::decrypt_general_with_jwk_authenticated`

Three properties, each tested:

1. **No merge.** `protected` never absorbs unprotected members, so `outcome.kid()` and
   `outcome.algorithm()` can only report the authenticated values. A test rewrites the
   unprotected `kid`/`alg` after signing — the on-path attacker's exact move — and asserts the
   authenticated view is unchanged *and* the forgery is still visible for logging.
2. **Not constructible from outside.** `Authenticated::new` is `pub(crate)`; the type's name
   makes a claim ("this came out of a verification") that a public constructor would let
   anyone mint.
3. **Reporting, not filtering.** Unauthenticated metadata is returned, not dropped. A caller
   who wants to alert on "a document tried to tell me something outside the signature" has
   `has_unprotected()`.

`map` transforms the value while keeping the header context, so `Authenticated<Vec<u8>>` can
become `Authenticated<MyType>` without touching headers.

### `ErrorCategory`: additive grouping, and one refusal to distinguish

`JoseError` is an exhaustive enum, so adding variants is breaking for every downstream
`match`; a `#[non_exhaustive] enum ErrorCategory` returned by `JoseError::category()` is not.
It groups: `UnsupportedCapability`, `InvalidStructure`, `PolicyRejection`,
`AuthenticationFailure`, `KeyMaterial`, `Cryptographic`, `Encoding`.

The classification that was *refused*: whether an integrity check failed, versus the backend
refusing input on the way to that check. Concretely, a tampered Ed25519 signature produces
this crate's own "did not verify" verdict (`AuthenticationFailure`), while a garbage ECDSA
scalar produces a backend refusal (`Cryptographic`). Those are not reconciled by sniffing
messages, because a caller who can ask "was the tag wrong, or was it refused earlier?" holds a
probe that distinguishes well-formed ciphertext from junk without ever learning the plaintext
— the oracle class this crate already refuses elsewhere. `JoseError::is_authentication_failure()`
answers the *merged* question (our verdict **or** a backend failure), documented as only
meaningful on a verify/decrypt path, since a `Crypto` error from a key import means something
else entirely.

The constant `SIGNATURE_VERIFICATION_FAILED` exists so the precise bucket is assigned by
equality against what this crate emits, not by substring-matching arbitrary text — a heuristic
would classify any message that *mentions* a verification failure as one.

### Migration notes (the plan asks for them explicitly)

* No existing function changes signature or return type. The authenticated APIs are new names
  alongside the old ones; `verify_with_jwk` still returns `Vec<u8>`.
* No variant is added, removed, or re-typed. `ErrorCategory` is purely additive, and matching
  it requires a wildcard arm because it is `#[non_exhaustive]` — so future categories cannot
  break a caller by construction.
* One emission site changed shape internally: the three places that raised the literal
  "signature verification failed" now use the public constant. The message text is unchanged,
  so string-matching callers are unaffected.

### Not built

No `PlainHeader`/"any header" accessor — a getter that searches protected and unprotected
objects in some precedence order is precisely the ambiguity being removed. No authorization or
identity layer (`aud`/`iss` policy stays in `Validation`); `Authenticated` says what was
verified, not who is allowed to be. No error variant for "authenticated but disallowed" —
`PolicyRejection` covers the class, and the specific variants (`Expired`, `InvalidIssuer`,
`InvalidAudience`, `NotYetValid`) remain the precise ones.

## Consequences

* The comfortable path and the correct path are the same path: read the header off the
  verified result instead of re-parsing whichever copy is nearest.
* Error handling that branches on "sort of problem" is forward-compatible with this crate
  growing categories; error handling that branches on "why the tag failed" is not
  available, by design, and the reason is written where someone will complain about it.
* Verification paths grew a header parse they may already have done internally. That is one
  small base64+JSON parse per call on APIs where the caller was going to do it anyway — and
  the honest alternative (threading the parsed header out through every internal helper)
  would touch the hot paths for a convenience.
