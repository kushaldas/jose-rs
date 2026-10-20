# 0012 — External additional authenticated data is authenticated, never confidential

- Status: Accepted
- Date: 2026-07-16
- Applies to: `jose_rs::jwe::json`, `JweEncryptOptions`, `JweDecryptOptions`

## Context

RFC 7516 §2 defines a JWE AAD value: octets supplied out of band, placed in the
JSON serialization's `aad` member, and included in the content authentication
input as `ASCII(Encoded Protected Header || '.' || BASE64URL(JWE AAD))`
(§5.1 step 14). It is the only message member that is authenticated but not
encrypted.

ADR 0011 shipped the flattened JSON serialization and refused `aad` by name,
because the AAD input has to be constructed from the exact encoded bytes and the
decryption path needed a place to receive them. Implementing it means deciding
three things the RFC leaves to the implementation: where the value enters the
API, what happens when the message and the caller disagree, and what the compact
serialization does with an option it cannot represent.

## Decision

1. **One option, two ends.** External AAD is configured through
   `JweEncryptOptions::with_external_aad` and
   `JweDecryptOptions::with_external_aad`, which both serializations already
   take. The field is private: the bytes must reach the AAD input unaltered, so
   only this crate's serializers may position them.

2. **The encoded form is the interface.** The encrypting side base64url-encodes
   the octets **once** and uses that string for both the AAD input and the `aad`
   member, so they cannot disagree. The decrypting side compares the caller's
   bytes against the member by re-encoding them, and feeds the *member* — not a
   fresh encoding — into the AAD input. This mirrors the verbatim-`protected`
   rule from ADR 0011: the RFC authenticates the base64url text, so the text is
   what must be preserved.

3. **Disagreement is a named error, not an authentication failure.** All four
   combinations of "message has an `aad` member" × "caller supplied bytes" are
   distinguishable without any secret:
   - member present, no bytes supplied → error naming the member and the option
     that supplies it;
   - no member, bytes supplied → error saying the message has no `aad` member;
   - both present but different → error saying they do not match;
   - both absent → AAD input is the protected header alone, as before.

   These checks run before key derivation. They leak nothing (the caller already
   holds the message) and they turn the most common integration mistake —
   forgetting the out-of-band data — into an actionable message instead of
   `Crypto("decryption failure")`. The content tag remains the last line of
   defence: if a recipient is fooled into *accepting* a substituted `aad`
   member, the bytes match the member, these checks pass, and the tag still
   fails because it was computed over the original input. Tests assert exactly
   that case.

4. **Empty external AAD is refused.** RFC 7516 §7.2.1 requires the member to be
   absent when the value is empty, but the AAD *input* for an empty member
   (`protected || '.' || ""`) differs from the input with no member. Accepting
   `with_external_aad(b"")` would let a sender and a recipient hold different
   beliefs about the authenticated bytes, so it is a hard error on both ends.

5. **The compact serialization refuses the option.** RFC 7516 §7.1 has no `aad`
   member. Silently ignoring the option would produce a token encrypted under an
   AAD the recipient has no way to reconstruct, so `jwe::compact` encrypt *and*
   decrypt return an error naming the JSON serialization as the required
   serialization. `FlattenedJwe::to_compact` likewise refuses a message with
   external AAD rather than dropping the member (the ADR 0011 rule for
   unrepresentable content).

6. **The member counts against the size limit.** `MAX_TOKEN_BYTES` is applied to
   the emitted text including the encoded AAD, so this crate never produces a
   message it would refuse to parse.

## Consequences

- Callers get external AAD on the JSON path with no new entry points: it rides
  on the options objects they already pass. `decrypt_flattened_with_jwk_and_aad`
  is the one new function, because the JWK path builds its own strict options
  internally and needs a way to receive the bytes.
- External AAD is documented as what it is: integrity protection for data both
  sides already know (routing hints, policy labels, per-tenant context that must
  be bound to a ciphertext). It is *not* a confidentiality feature and the
  rustdocs say so at the point of use.
- Messages that carry external AAD cannot travel as compact JWE. That is a
  property of the wire format, surfaced as a clear error rather than a
  silent downgrade.
- Decrypting a message with an `aad` member through an API that cannot supply
  one (e.g. `decrypt_flattened_with_jwk`) fails with the explanatory error;
  there is no way to accidentally authenticate under the wrong AAD input.
- Interop: panva/jose (`setAAD` / `additionalAuthenticatedData`) and jwcrypto
  round-trip the member with jose-rs in both directions; the matrix gained a
  `jwe-json-aad` family that also asserts the AAD input is what makes the
  ciphertext unreadable when omitted.
