# 0013 — An unauthenticated `alg` is only ever read against a key that pins it

- Status: Accepted
- Date: 2026-07-16
- Applies to: `jose_rs::jwe::json`, all JWE decrypt paths
- Partially supersedes: ADR 0011 (which refused the `unprotected` / `header`
  members outright)

## Context

RFC 7516 §7.2.1 gives the JSON serialization three header locations — the
integrity-protected `protected` member, the shared `unprotected` member, and the
per-recipient `header` member — whose parameter **names must be disjoint** and
whose union is the JOSE Header the recipient computes over. "At least one of the
`header`, `protected`, and `unprotected` members MUST be present so that `alg`
and `enc` Header Parameter values are conveyed."

ADR 0011 refused `unprotected` and `header` by name. That made the library
strict, and it also made a family of conformant messages unreadable — including
**RFC 7516 §A.5's own flattened example**, which carries `{"enc":…}` protected
and `{"alg":"A128KW","kid":"7"}` in the per-recipient unprotected header, plus a
`jku` in the shared unprotected one. jwcrypto's default output goes further and
places *everything*, `enc` included, in the unprotected member.

The reason ADR 0011 was right to be nervous is the header's role: `alg` selects
the key-management operation, and an attacker who chooses it unselected can
redirect key material (the classic algorithm-substitution and
key-confusion family). But the RFC does not require `alg` to be protected, and
interoperability is not optional. The question is therefore not *whether* to
read these members but *under what invariant* reading them stays safe.

## Decision

**Read the unprotected header locations, and never let an unauthenticated value
answer a security question — unless something other than the message pins the
answer.**

1. **`enc` must be integrity protected.** It is refused in `unprotected` and in
   `header`, so a message that conveys `enc` only there (jwcrypto's default
   shape) is not read at all. This is not pedantry about placement: `enc`
   decides how the received octets are split into ciphertext and authentication
   tag. An attacker-chosen `enc` makes the same bytes authenticate under one
   reading and mean something else under another — a substitution attack, not a
   trust question. Consequence: the RFC §A.5 shape is readable (it protects
   `enc`), jwcrypto's default is not, and both are asserted in interop.

2. **`alg` may be unprotected only against a key that pins it.** The JWK decrypt
   APIs take the algorithm from `jwk.alg`; the token's claim — protected or not —
   is compared against it, and a mismatch is refused before any key management.
   So the header value is *checked*, not believed: the message cannot steer the
   key anywhere the key disagrees. The raw-key APIs have no pin, so they refuse
   an unprotected `alg` and say why, naming the value and the alternative.
   `ParsedEnvelope` carries `alg_authenticated` to make the distinction visible
   in the code rather than implied by call order.

3. **`zip` and `crit` are also refused in unprotected locations.** RFC 7516
   §4.1.3 requires `zip` to occur only in the protected header; a `crit` marker
   nobody can authenticate is an invitation to force rejection or strip the
   marker. The key-agreement and PBES2 parameters this crate does not implement
   (`epk`, `apu`, `apv`, `p2s`, `p2c`, and the A128GCMKW `iv`/`tag`) are refused
   there too: reading unauthenticated key-agreement inputs is how a peer ends up
   using an attacker's ephemeral key.

4. **The three locations must be disjoint, checked at parse time**
   (RFC 7516 §7.2.1 "MUST be disjoint"). A name in two places has no defined
   meaning; deciding it later, per code path, is how implementations diverge.

5. **`protected` remains required**, so rule 1 is enforceable and the AAD input
   is always well-defined. An absent member now reports *why* (the content
   encryption algorithm must be integrity protected) rather than only that a
   member is missing.

6. **jose-rs never emits unprotected header parameters.** Every message it
   produces keeps its parameters in the protected header; the members exist here
   for reading the ecosystem, not for growing more of them. A test asserts that
   no emitted message carries `unprotected` or `header`.

7. **Unprotected members are retained and reported, never acted on.** They
   survive a parse/emit round trip, `peek_jose_header()` exposes the union for
   display and key-*candidate* selection, and `to_compact()` refuses a message
   carrying them (the compact form has nowhere to put them, and dropping them
   would change the message). `jku`/`x5u`/`jwk` stay exactly what ADR 0001 made
   them: parsed, never fetched, never trusted — the RFC §A.5 test asserts the
   `jku` is reported as a string and nothing more.

## Consequences

- RFC 7516 §A.5 now decrypts. It is an acceptance test, not a story.
- jwcrypto interop improved: the RFC-shaped messages it is configured to produce
  read fine, and its default shape still fails — with an error that names the
  reason, and an interop assertion pinning that boundary.
- The rule is easy to state to users: **if your key pins `alg`, you can read
  these messages; if you hand the library raw bytes, you cannot** — and the
  error tells you to switch APIs rather than leaving you to guess.
- Callers who key-select on an unprotected `kid` are selecting on attacker-
  controlled data. That remains their choice and is documented; the decryption
  itself is still pinned, so a wrong `kid` lands on a key that refuses (tested).
- Emitting unprotected parameters is not available. If a deployment genuinely
  needs it, that is a new ADR, not a flag.
- ADR 0011's other rules are untouched: `protected` verbatim as the AAD input,
  duplicate JSON member names refused, unknown private members retained but
  ignored, and no general-syntax support yet (`recipients` — ADR 0014).
