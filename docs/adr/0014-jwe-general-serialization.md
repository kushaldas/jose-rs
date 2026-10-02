# 0014 — A recipient is named by the caller, never chosen by the library

- Status: Accepted
- Date: 2026-07-16
- Applies to: `jose_rs::jwe::general`
- Builds on: ADR 0011 (flattened syntax), ADR 0012 (external AAD), ADR 0013
  (unprotected header members)

## Context

RFC 7516 §7.2.1 allows one JWE to address several recipients. The wire shape is
one `protected` header, one `ciphertext`, one `iv`, one `tag`, an optional shared
`unprotected` header, and a `recipients` array holding one object per recipient:

```json
{
  "protected":   "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
  "unprotected": {"jku":"https://server.example.com/keys.jwks"},
  "recipients": [
    {"header": {"alg":"RSA1_5","kid":"2011-04-29"}, "encrypted_key": "…"},
    {"header": {"alg":"A128KW","kid":"7"},          "encrypted_key": "…"}
  ],
  "iv": "…", "ciphertext": "…", "tag": "…"
}
```

RFC 7516 §A.4 — the RFC's own example — uses exactly this, and its two
recipients use **different key-management algorithms** (`RSA1_5` and `A128KW`),
declared in the per-recipient *unprotected* header.

Two decisions had to be made, and each is a security decision dressed up as an
API question.

**Which recipient am I decrypting for?** The header the content tag is validated
under is `protected ∪ unprotected ∪ recipients[i].header` — *per i*. So
"decrypt this message" is not a complete instruction: the same ciphertext is
authenticated against a *different* string for each element. A library that
searches the array is picking the string the tag will be checked against, on
data nobody authenticated.

**What may the array cost?** Its length is attacker-chosen. Unbounded parsing and
per-element key management turns a 10 000-element array into a free denial of
service, and key unwrapping is the expensive part.

## Decision

**Decryption is always scoped to a recipient the caller names. The library never
searches.**

1. `GeneralJwe::flatten_for(i)` turns the message into the flattened form for
   element `i`, and every decrypt path goes through it. RFC 7516 §7.2.2 already
   defines flattened as the one-recipient case of general, so this is the RFC's
   own equivalence — and it means there is **one** policy implementation
   (`jwe::json`'s decrypt path), not a second one that could drift. `enc` must be
   protected, an unprotected `alg` needs a pinning key, the locations must be
   disjoint: all of ADR 0011/0013 applies to general messages *for free*.

2. Two entry points, no third one:
   - `decrypt_general_with_jwk(jwk, jwe, recipient)` — position, chosen by the
     caller;
   - `decrypt_general_with_jwk_by_kid(jwk, jwe)` — the *key's own* `kid` selects
     the element. `kid` is unauthenticated, so it is used only to narrow, never
     to authorize: zero matches is an error, and **more than one match is an
     error too**. Choosing between two elements that both claim the same kid is
     exactly the decision this ADR refuses to make on the caller's behalf.

3. **No bounded search either.** A `for each recipient: try key` loop with a
   budget would still end in a successful decryption whose authenticated header
   the caller never agreed to, and it would report success identically whichever
   element won. (panva's `generalDecrypt` does search; the interop matrix records
   that as a divergence rather than pretending to parity.) If a deployment
   needs searching, it must say what "authenticated" means afterwards — that is
   a new ADR, not a flag on this one. The `MAX_RECIPIENTS = 32` bound would make
   such a loop affordable, but cost was never the only objection.

4. **`recipients` is bounded at 32** on parse and on emit, with an error naming
   the bound. RFC 8725 §1 offers no number; 32 is generous for real fan-out and
   small enough that worst-case key management stays predictable. Elements must
   be JSON objects; `header` and `encrypted_key` at the *top* level are refused
   ("they belong to an element"), because honouring them would apply one
   recipient's key to all of them.

5. **Disjointness is checked per recipient** (RFC 7516 §7.2.1 "MUST be
   disjoint"), and the error names which recipient — in a three-recipient
   message, "the header locations collide" is not an actionable diagnostic.

6. **Emitting uses one algorithm for all recipients, and `dir` gets one
   recipient.** `encrypt_general*` takes N keys, generates the CEK **once**,
   encrypts the content **once**, and wraps that CEK N times — the shape the RFC
   describes. Per-recipient algorithms would require `alg` in the element's
   unprotected header; ADR 0013 says an unprotected `alg` is tolerable when a
   *key* pins it, but here the library is the one writing the message and would be
   choosing to leave the algorithm unauthenticated for its readers. Refused, with
   an error that says the recipients must pin the same `alg`. `dir` conveys no
   encrypted key at all, so a second recipient is not representable (panva and
   jwcrypto agree).

7. **The library emits what it would accept.** No shared `unprotected` header;
   the only per-recipient parameter it writes is the `kid` the caller supplied for
   their own key. Unknown members — top-level and per-element — are ignored for
   processing but retained, so re-serializing does not delete a peer's data.

## Consequences

- RFC 7516 §A.4 decrypts. Its second recipient is an `A128KW` element whose `alg`
  rides unprotected, so the test exercises ADR 0013 and this ADR at once; the
  first element is `RSA1_5` and is asserted to be *not* ours.
- Callers must handle "which element is mine" themselves, which is where the
  information actually lives: an application knows its own key and its own `kid`.
  The `kid` entry point exists so that knowing them is enough.
- `MAX_RECIPIENTS` is operational policy, not a normative claim. It is a `pub`
  constant, so a deployment that wants a different number can at least find this
  one and argue with it in a review.
- Emitting a per-recipient-algorithm message is not available. A real use case
  would be an ADR of its own, and would have to answer why the reader should
  trust an algorithm it cannot authenticate.
- Interop covers both directions against panva/jose 6 and jwcrypto 1.6
  (`jwe-general` matrix cells, jwcrypto general checks), including that
  jwcrypto/panva *will* search and jose-rs will not.
