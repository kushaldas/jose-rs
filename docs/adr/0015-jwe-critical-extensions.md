# 0015 — `crit` is refused by default and understood only by the caller

- Status: Accepted
- Date: 2026-07-16
- Applies to: JWE encrypt/decrypt options, all three serializations
- Builds on: ADR 0011 (flattened), ADR 0013 (unprotected members), ADR 0014
  (general serialization); mirrors the long-standing JWS design

## Context

RFC 7515 §4.1.11, adopted for JWE by RFC 7516 §4.1.13, gives JOSE a way to say
"do not accept this if you cannot *process* it":

> Its value is an array listing the Header Parameter names present in the JOSE
> Header that use those extensions. If any of the listed extension Header
> Parameters are not understood and supported by the recipient, then the JWS is
> invalid. … When used, this Header Parameter MUST be integrity protected;
> therefore, it MUST occur only within the JWS Protected Header.

Until now jose-rs refused any JWE carrying `crit`, with a single blunt rule: it
implements no critical extensions, so it understands nothing listed. That is
correct, and it also makes a whole class of deployment impossible to express —
an application that *does* implement an extension (a policy or profile parameter
of its own) cannot read a message that correctly marks it critical, and cannot
emit one either, so it has to drop the marker and silently downgrade an "you
must process this" to a "please ignore this if you like".

The JWS side of this crate already solved the same problem the right way:
`SignOptions::understood_crit` / `VerifyOptions::understood_crit`, a caller-side
list. JWE had no equivalent, which was an asymmetry rather than a decision.

## Decision

**The list of understood extensions belongs to the caller, and everything else
about `crit` stays non-negotiable.**

1. `JweEncryptOptions::with_understood_crit` /
   `JweDecryptOptions::with_understood_crit` carry the caller's list. The
   **default is the empty list**, so the previous behaviour — refuse any message
   carrying `crit` — is what a caller gets unless they say otherwise. This is a
   widening of what can be *expressed*, not a relaxation of a default.
2. jose-rs never *interprets* an extension. It verifies the structure of the
   claim and hands the value over in `JoseHeader::extra`. "Understood" here
   means "the code calling jose-rs processes this", a claim only that code can
   make; a library cannot know it, and pretending otherwise would let jose-rs
   certify processing it did not perform.
3. One `validate_crit` implementation, used on **both** the emit and the receive
   side, enforcing RFC 7515 §4.1.11 in order: non-empty; no duplicate names; no
   registered JWE/JWA member (a registered member is not an extension, so
   declaring it critical asks the recipient to confirm a duty it already has);
   every name in the caller's list; every name actually present in the header.
   Sharing the function means a message jose-rs is willing to write is always one
   it is willing to read — divergent emit/receive checks are how implementations
   end up producing tokens they cannot themselves decrypt.
4. **Criticality must be integrity protected.** `crit` may appear only in the
   protected header (already refused in `unprotected`/`header` by ADR 0013), and
   the *named parameter* must also be in the protected header. The JSON
   serialization has unprotected locations in which a `crit`-named member could
   legally sit per RFC 7515's wording; jose-rs refuses that. An attacker who
   could add the parameter unprotected could manufacture a satisfied criticality
   check the sender never performed. Documented as stricter than the RFC's
   minimum (ADR 0015).
5. The opt-in is available on every path that can carry it. Because the general
   syntax's decryption APIs take a `Jwk` (ADR 0014) and derive their options from
   it, `decrypt_flattened_with_jwk_options` and
   `decrypt_general_with_jwk_options` were added, alongside
   `JweDecryptOptions::pinned_to_jwk` — options *built from* the key, with the
   key's `alg` pin intact. An option that only the raw-key API could express
   would have made the general syntax unusable with `crit`, and the flattened and
   general paths are supposed to be the same message.

## Consequences

- Applications can now mark their own parameters critical in JWE and read
  messages that do the same, in all three serializations, with the extension
  reaching the content-authentication input identically whether it travels
  compact, flattened or general (tested).
- Interop confirms the policy rather than contradicting it: **jwcrypto refuses to
  read** a JWE listing an extension it does not know (`Unknown critical
  header`) and **panva refuses even to emit** one — so the matrix asserts that a
  peer rejects a jose-rs message carrying `crit`, and asserts a control message
  without `crit` is accepted, so the rejection is demonstrably about the
  extension (8 `jwe-crit` cells; jwcrypto checks across 9 combinations).
- Declaring an extension understood is now a caller responsibility with real
  consequences: listing a name jose-rs happens to see in `extra` makes the
  message decryptable, and it is the caller's code that must then act on it.
  Rustdoc says so at the option, not only here.
- A `crit` naming a registered member is refused even with a permissive list, so
  a caller cannot widen the definition of "extension" by accident.
- Emitting `crit` for an extension the caller did not list stays impossible; so
  does an empty list, a duplicate, or a name that is absent from the header.
