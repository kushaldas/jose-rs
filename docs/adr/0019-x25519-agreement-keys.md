# ADR 0019 — X25519 joins agreement, and this crate owns the `d`-derives-`x` check

Date: 2026-07-28
Status: Accepted
Implements: RFC 8037 §2 (OKP key type, X25519), §5 (algorithm profiles);
RFC 7748 §5 (X25519); RFC 7518 §4.6 (unchanged KDF); RFC 7517 §4.1/§4.2
Depends on: ADR 0016 (agreement boundary — amends it), ADR 0017, ADR 0018
Amends: ADR 0016 (which excluded X25519 for the reason this record closes)

## Context

ADR 0016 listed the curves agreement could run on as P-256, P-384 and P-521, and
refused X25519 by name — not because the backend cannot do X25519 (it can), but
because the import path could not yet prove that a JWK's two halves belong to the
same key. That refusal was written down as the condition for lifting it:

> a JWK whose `d` is an X25519 scalar cannot be imported yet, and importing it
> without checking that `d` really derives `x` would let a JWK publish one identity
> and agree with another.

This record is that check, and the curve that comes with it.

The mismatch is not a thought experiment. An X25519 JWK is

```json
{"kty":"OKP","crv":"X25519","x":"…32 octets…","d":"…32 octets…"}
```

two base64url strings that any producer, cache, provisioning script or copy-paste
may have paired wrongly. The backend's importer, `SoftwareKey::from_x25519`, stores
whatever pair it is handed — it checks the lengths and nothing else. And the two
halves are then consumed by different code paths: agreement multiplies with `d`,
while a JWE publishes `x` as `epk`. So a JWK with an inconsistent pair does not
fail; it produces a message whose sender believes it addressed one identity while
the arithmetic used another, and a recipient that cannot tell the difference from a
correct message. Ed25519 import in this crate has always refused it. The same rule
belongs here.

Two further facts shape the implementation rather than the argument:

* an X25519 public value is a **bare u-coordinate** — 32 octets, no SEC1 `0x04`
  prefix, no `y` — so the encoding the sender publishes and the encoding the
  recipient hands to the primitive are both a different shape from the P-curves';
* `OKP` is a key type shared by signing curves (Ed25519, Ed448) and agreement
  curves (X25519, X448). Only one of those four is available here, so a caller
  holding the wrong one needs an error that says which one they have and why it
  cannot work, or they will conclude that OKP is broken and replace a key that was
  fine for its own purpose.

## Decision

### Agreement accepts X25519, with the consistency check this crate computes

`AgreementCurve` gains `X25519`. Import of an OKP/X25519 JWK that carries `d`
computes `X25519(d, G)` and compares it to `x`, refusing the key when they differ
(`jwk_to_x25519`). The check is performed **in this crate**, because the backend
importer does not and cannot be made to from here, and because agreement is the
consumer that makes the mismatch dangerous.

It is computed with the backend's own scalar multiplication against the base point
(`kryptering::software::keyagreement::ecdh_x25519`) rather than with a second
implementation of the curve: this crate gains no Curve25519 arithmetic, and the
check cannot drift from the primitive that later consumes the same pair. The same
constant — the RFC 7748 §5 base point — is `pub(crate)` and shared with key
generation, so "derive the public value" has exactly one implementation.

Self-consistency is also why `generate_x25519()` returns a key that always passes
the check: it derives `x` from the scalar it generated instead of treating the two
as independent choices.

### Public values are encoded per curve, not per key type

`encode_public` returns the raw 32-octet u-coordinate for X25519 and the
uncompressed SEC1 point (`0x04 || X || Y`) for the P-curves. Getting this wrong is
not silently exploitable — the primitive rejects a wrong-length value — but it
would surface as "malformed key" for a key that is perfectly formed, which is the
kind of failure that teaches a caller to distrust the error.

The same split appears in the `epk` a sender publishes: an X25519 `epk` is
`{"kty":"OKP","crv":"X25519","x":…}` with exactly those three members, no `y`, no
`d` — asserted in the tests, since RFC 7518 §4.6.1.1 makes "public parameters only"
absolute for `epk`.

### Every OKP curve that is not X25519 is refused, each with its own reason

Ed25519 and Ed448: signing curves, not agreement curves. X448: a genuine agreement
curve which this backend cannot perform — saying "signing curve" about it would be
false, and the two remedies differ (use a different key versus use a different
backend). A generic "unsupported OKP curve" would send a caller with an Ed25519 key
looking for a bug that does not exist.

### Everything else about agreement is unchanged, deliberately

The KDF, AlgorithmID, `keydatalen`, `epk` placement, the authenticated-position rule
(ADR 0013/0017), the one-recipient rule for direct mode and the general-serialization
refusal (ADR 0018) all apply to X25519 exactly as they do to the P-curves. The
tests assert that rather than assuming it: `apu`/`apv` validation, the KEK-from-`alg`
wrapping length, curve mixing in both directions, and a public-only X25519 key being
a peer rather than an own key are all checked on the X25519 path, so the curve
cannot quietly skip a policy step that the P-curves pass.

Low-order peer values need no new code: the backend's X25519 primitive refuses a
peer whose multiplication yields the identity element, which is the case an
all-zero `x` produces. A test pins that this arrives as a refusal rather than a
derived key — an attacker-chosen `epk` should never be able to hand a recipient a
shared secret the attacker already knows.

## Consequences

* Agreement now covers four curves and four algorithms, and one JWK key type
  (`OKP`) is split across purposes by its `crv`, which the boundary now enforces
  rather than any caller having to remember.
* Every X25519 private JWK import now performs one scalar multiplication. That is
  the price of the check; it happens on paths that were already doing a key import,
  and agreement itself does two more multiplications, so it is not a new order of
  cost.
* A JWK that previously round-tripped through `to_public_jwk()` and back is now
  checked for internal consistency at import. A caller who was, unknowingly, holding
  an inconsistent X25519 JWK will now get an error — which is the point, and the
  error names the mismatch.
* RFC 8037 Appendix A.6 gives the shared secret but no ciphertext, so the
  crypto-level vector lives in `jwk_agreement.rs` (Z against the RFC's numbers) and
  the wire-level proof is the interop suite, where both peers implement X25519.

## Alternatives considered

**Import X25519 without the consistency check and rely on the backend.** Rejected:
the backend checks lengths, not correspondence, and the failure it permits is
silent. It is also the asymmetry that makes the key type dangerous — `x` is what
the world sees, `d` is what the math uses.

**Derive `x` from `d` and ignore the published `x` entirely.** Tempting and nearly
free: it guarantees the pair is consistent. Rejected because it silently rewrites a
key the caller supplied — if `x` and `d` disagree, one of them is wrong and the
caller needs to know which key they are holding, not receive a third one. (On the
*encrypt* path the public half really is all that matters, and there the mismatch is
not an error; the test asserts exactly that split.)

**Refuse `OKP` entirely at the agreement boundary, as before.** Rejected now for the
reason ADR 0016 anticipated: the obstacle was the check, not the curve, and the
check is cheap, local, and shared with generation.

**Implement the d↔x check with a self-contained Curve25519 scalar multiplication.**
Rejected: a second implementation of the same primitive in this crate is a second
thing to audit, and any drift between it and the backend is a bug that only shows
up as a mismatched key.

## Verification

* `tests/jwk_agreement.rs` — X25519 additions: RFC 8037 §A.6's shared secret
  reproduced from the RFC's own ephemeral secret and recipient key (both directions
  of the RFC's printed value); the public value is the bare 32-octet u-coordinate; a
  JWK whose `d` does not derive `x` is refused; round-trip symmetry on a generated
  pair; an all-zero (small-order) peer value refused; a public-only X25519 key is a
  peer, not an own key; X448 refused with the agreement-curve wording and Ed25519
  with the signing-curve wording.
* `tests/jwe_ecdh_x25519.rs` — 8 tests: all four agreement algorithms round-trip
  over X25519 with four content algorithms in both serializations; the `epk` is
  OKP-shaped and carries nothing extra; encryption to an inconsistent JWK succeeds
  while recovery with it is refused (the deliberate split); a private `epk` refused;
  curve mixing refused in both directions and for both modes; `EdDSA`-pinned and
  `use: sig` X25519 keys refused; `apu`/`apv` and the KEK-length rule enforced on
  this path too.
* Interop: `jwe-ecdh` and `jwe-ecdh-kw` families each gain an X25519 cell, both
  directions (4 cells; the `epk` shape assertion is curve-aware — OKP and no `y` for
  X25519, EC with both coordinates otherwise); `gen-key --crv X25519` in the Rust
  harness; the jwcrypto agreement suite extended to 104 checks including X25519 in
  both modes. Matrix 97/97.
