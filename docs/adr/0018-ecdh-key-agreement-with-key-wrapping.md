# ADR 0018 — agreement with key wrapping agrees a KEK, and waits for a place to put a second `epk`

Date: 2026-07-28
Status: Accepted
Implements: RFC 7518 §4.6 / §4.6.1.1 / §4.6.2 (ECDH-ES with key wrapping),
RFC 3394 (AES-KW); RFC 7516 §5.1 step 5, §7.2.1–§7.2.2; amends ADR 0017
Depends on: ADR 0013 (unprotected-header policy), ADR 0016 (agreement boundary),
ADR 0017 (direct agreement)

## Context

`ECDH-ES+A128KW`, `ECDH-ES+A192KW` and `ECDH-ES+A256KW` look like `ECDH-ES` with a
suffix. They are a different key-management mode in RFC 7518 §4.6's own terms, and
the difference is not cosmetic:

* the Concat KDF output is **not** the content encryption key — it is a
  key-encryption key, which then wraps a normally generated CEK with RFC 3394
  AES-KW, so the message *carries* a key;
* the KDF's AlgorithmID input is the ASCII `alg` value (`"ECDH-ES+A128KW"`)
  instead of the ASCII `enc` value, and `keydatalen` is the KEK's bit length
  (128/192/256, named by `alg`) instead of the CEK's (named by `enc`);
* because the CEK is no longer the agreed value, one ciphertext **can** address
  several recipients: generate one CEK, run one agreement per recipient, wrap the
  same CEK once per agreed KEK. This is the mode RFC 7518 offers for
  multi-recipient key agreement;
* and that last point creates the problem this record exists to settle, because
  each recipient's agreement has its own ephemeral key, and RFC 7516 §7.2.1 gives
  a recipient element exactly two members: `header` (unprotected) and
  `encrypted_key`. There is no per-recipient protected header.

That is not a hypothetical shape. RFC 7520 §5.13 — the cookbook's own three
recipient message, whose second recipient is `ECDH-ES+A256KW` — publishes each
recipient's `epk` in that recipient's **unprotected** `header` member (Figure 209).
panva's Node implementation emits the same shape. So "support agreement for
several recipients" and "do not derive a key from an unauthenticated peer value"
(ADR 0013, ADR 0017) are in direct conflict, and something has to give.

## Decision

### The mode is its own key schedule, not `ECDH-ES` with a suffix

`AgreementSender` (crate-internal) holds the agreement handles and offers the two
RFC 7518 §4.6 modes as two methods: `derive_cek()` for direct agreement
(AlgorithmID `enc`, keydatalen `enc.cek_size()`) and `wrap()` for the wrapping
modes (AlgorithmID `alg`, keydatalen from `agreement_kek_len(alg)`). Nothing
computes a KDF input by inference from the other mode; the parameters are named at
the call site that the RFC names them in.

The consequence is deliberate and asserted: the same recipient key, the same
sender key and the same `enc` derive **different** material in the two modes, so a
message produced for one mode cannot be read under the other. The recipient's
pinned `alg` fixes which mode runs, so the mismatch surfaces as an algorithm
refusal rather than a silently wrong key.

### The KEK's length comes from `alg`; the CEK's from `enc`

`agreement_kek_len` is the only place that answers "how long is the agreed key",
and it answers from the algorithm. `ECDH-ES+A128KW` with `A256GCM` therefore
derives a 128-bit KEK that wraps a 256-bit CEK — the pairing that catches an
implementation keying off the wrong half of the header. The wrapped key's length
is asserted in the tests (RFC 3394 adds one 64-bit integrity block), which reports
which length was used for what without trusting either implementation's own
account of it.

The three wrapping algorithms reuse the existing `A*KW` AES-KW mapping rather than
adding a third spelling of "128-bit AES-KW": the wrap itself is identical, and
only the origin of the key differs. This does not make the raw-byte path reachable
for agreement — agreement is dispatched away from the byte-oriented match before
this mapping is consulted, and `&[u8]` still cannot name a curve or carry an `epk`.

### The encrypted key is required, and its absence is a refusal

Direct mode refuses a message that conveys an encrypted key (ADR 0017); the
wrapping modes refuse a message that omits one. Both directions are explicit
because the failure mode of getting it wrong is silent: a recipient that read a
missing key as "then agree the CEK instead" would decrypt a message whose
key-management mode it had misread, and would report success.

### Several recipients stay refused, with the reason named

`encrypt_core_multi` and the general-serialization entry points refuse any
agreement algorithm for more than one recipient, and the message says why: one
`epk` per recipient, and no protected place to put it. Emitting into the element's
unprotected `header` is what RFC 7520 §5.13 and panva do, and it is not done here
until that trade-off is decided on its own merits (see *Alternatives considered*).
A general message that *arrives* with an agreement recipient is likewise refused —
the rule is one function used on both sides, so the crate cannot emit what it is
unwilling to read.

Single-recipient general messages are refused too, rather than quietly flattened
into the shared protected header: a general JWE whose one element carries no
`epk` of its own is a shape no other implementation produces, and inventing it
would buy a serialization no peer reads in exchange for an API surprise.

### `epk` placement per serialization, unchanged from ADR 0017

Compact and flattened forms put `epk` in the shared protected header — which is
what RFC 7520 §5.4 does and what panva does in both forms — so those two forms
interoperate with everyone and need no exception to ADR 0013. jwcrypto's JSON form
ships `epk` in the unprotected `header` member in *both* agreement modes, so
jwcrypto → jose-rs in JSON is refused by name in both; its compact form puts `epk`
where compact has to put it, and does interoperate.

## Consequences

* Agreement now covers all four RFC 7518 §4.6 algorithms for P-256/P-384/P-521,
  in compact and flattened form. The multi-recipient gap is narrow and named: it
  is exactly the general serialization, and the refusal text explains the shape
  problem rather than saying "unsupported".
* The multi-recipient path is *not* blocked on this crate's crypto — the CEK/KEK
  split already scales. It is blocked on a header-policy decision, which makes it
  a small follow-up with a documented argument rather than an open-ended one.
* Callers get one visible asymmetry: `dir`/`A*KW`/`RSA-OAEP` accept several
  recipients in a general JWE, agreement algorithms do not. That asymmetry is
  reported by name at the API boundary, and it is the RFC's own asymmetry.
* A mode-confusion attack is closed by construction rather than by a check: the
  KDF inputs differ, and each side's mode comes from a pinned `alg`.

## Alternatives considered

**Publish `epk` in the recipient element's unprotected `header`, as RFC 7520 §5.13
and panva do.** Tempting — it is the ecosystem's shape, and it would open the
general serialization immediately. The security argument for it is real: an
attacker who substitutes `epk` changes the KEK the recipient derives, so the wrap
unwraps to garbage and the content tag fails; they cannot compute the KEK without
the recipient's private scalar, so nothing leaks and nothing is forged. But that
argument is *about this algorithm's arithmetic*, not about the header rule, and the
rule exists to keep callers from having to re-derive that argument per algorithm.
The one place a peer value's position is decided should not have an exception that
holds "because ECDH happens to fail loudly". Deferred rather than rejected: if
general-agreement interop becomes a requirement, the honest version of this is a
separate decision that also pins the invalid-curve and unknown-key-share reasoning
in one place — not a rule exception buried in a feature commit.

**Accept an unprotected `epk` when the recipient's key pins the agreement `alg`.**
This mirrors ADR 0013's rule for `alg` itself, and is the strongest version of the
alternative above — the pin constrains the mode, so the unauthenticated value
cannot switch it. It still lets an attacker pick *which* sender value the
recipient agrees with, and ADR 0013's premise is that the caller should not have to
reason about what that enables per algorithm. Kept as the likely shape of the
follow-up if the refusal proves too costly in practice.

**Reuse one `epk` for all recipients and put it in the shared protected header.**
Cheap, and cryptographically not obviously broken (each recipient still derives a
different KEK from a different static key). Rejected: RFC 7518 §4.6's new-ephemeral
-per-operation requirement is generally read per recipient, no other
implementation emits this shape, and a receiver must not have to guess which
private reading of the RFC a sender used.

**Treat the wrapping modes as `ECDH-ES` plus a post-processing step, reusing the
direct-mode KDF output.** Rejected: it would derive the CEK and then re-derive, or
worse, derive once with the wrong AlgorithmID — the kind of bug that is invisible
until two implementations disagree.

## Verification

* `tests/jwe_ecdh_kw.rs` — 12 tests: RFC 7520 §5.4's message decrypts in compact
  and flattened form (with `epk` asserted public-only and on the recipient's
  curve); 3 algorithms × 3 curves × 4 content algorithms round-trip in both
  serializations with the encrypted key present; a sender holding only the public
  half; the KEK-from-`alg`/CEK-from-`enc` pairing checked through the wrapped
  key's length (40 octets for a 256-bit CEK under a 128-bit KEK, 24 for a 128-bit
  CEK under a 256-bit KEK); an absent encrypted key refused; a sender key on
  another curve refused; a swapped `epk` fails authentication; the ephemeral key
  fresh, minimal, recipient-curve, and not caller-supplied; `apu`/`apv` emitted,
  honoured, and validated (equal or non-base64url refused); several recipients
  refused with the reason named; the raw-key API cannot reach the mode.
* `tests/jwe_ecdh_es.rs` — direct agreement's suite gains the counterpart tests:
  the wrapping modes convey an encrypted key, and the two modes derive different
  keys from the same pair.
* Interop: `jwe-ecdh-kw` matrix family, 6 cells (one wrapping algorithm per curve,
  both directions; each cell asserts the encrypted-key segment is non-empty, the
  converse of the `jwe-ecdh` family's assertion, so a cell cannot silently change
  mode); `interop/tests/jwe_ecdh_es_jwcrypto.py`, 84 checks, covering the wrapping
  modes in both directions plus the wrapped length asserted independently of both
  implementations; both harnesses' `gen-key` accept the `ECDH-ES+A*KW` names.
  Matrix 93/93.
