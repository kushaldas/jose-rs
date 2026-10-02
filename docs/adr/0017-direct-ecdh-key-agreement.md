# ADR 0017 — direct key agreement agrees the CEK and publishes its own ephemeral key

Date: 2026-07-28
Status: Accepted
Implements: RFC 7518 §4.6 / §4.6.1.1 / §4.6.2 (ECDH-ES direct mode);
RFC 7516 §4.1.5, §7.1, §7.2.1–§7.2.2; RFC 7517 §4.2/§4.3; builds on ADR 0016
Depends on: ADR 0011 (protected header required), ADR 0013 (unprotected-header
policy), ADR 0014 (recipient selection), ADR 0016 (agreement boundary)

## Context

`ECDH-ES` is the first key-management mode this crate supports in which **no key
is carried**. For `dir`, `AxxxKW` and `RSA-OAEP*` the sender either already shares
the CEK or transports one, and the shape of the operation is the same from the
library's side: hand me key bytes, and a `&[u8]` is enough to describe the input.
In direct key agreement the CEK is computed as `ConcatKDF(ECDH(ephemeral,
recipient))`, which means:

* the library needs the recipient's key *as a key* — curve, coordinates,
  whether the private scalar is present, and its `use`/`key_ops`/`alg` statements;
* the sender has to **create** something per message (an ephemeral key pair) and
  publish half of it in the protected header (`epk`) *before* that header is
  serialized, because the serialized header is also the AEAD AAD input;
* the peer value on the receiving side arrives from the message, so the same
  header location question ADR 0013 settled for `enc` comes back in a sharper
  form: `epk` decides which key the content is authenticated under;
* one recipient is all direct mode can address, because the agreed key is the
  CEK — two recipients would need two CEKs and one ciphertext cannot be
  encrypted under two.

Each of those has an obvious wrong answer: accepting a caller-supplied `epk`
(ephemeral-key reuse is exactly the failure RFC 7518 §4.6's "MUST generate a new
ephemeral key" exists to prevent); letting the caller choose the curve
(invali/cross-curve territory); reading `epk` from wherever it is found; letting a
raw `&[u8]` API "support" `ECDH-ES` by inventing a curve.

## Decision

### Key management takes key material, not bytes

An internal `KeyMaterial` enum carries either zeroized bytes (`dir`, `AxxxKW`,
`RSA-OAEP*`) or a `Jwk` (the agreement family), and every key-management entry
point — `produce_cek`/`wrap_cek` on the emit side, `recover_cek` on the receive
side — takes that instead of `&[u8]`. Agreement is dispatched **before** the
byte-oriented match, on both sides, so a caller who hands bytes to an agreement
algorithm is told the truth:

> `ECDH-ES` requires a JWK: key agreement needs the curve and coordinates of a
> key, and the peer key is read from the message's `epk` header member, so the
> raw-key API cannot express it

That is not a missing feature that could be filled in later; a byte string cannot
name a curve, and there is no `epk` in a `&[u8]`. The public raw-key APIs
therefore cannot reach key agreement **by construction**, which is the same
reasoning ADR 0013 applied to an unauthenticated `alg`.

### The library generates the ephemeral key, on the recipient's curve

`epk` is not an input anywhere in this crate. On emit, the recipient's public
value is made a [`PeerKey`](../../src/jwk/agreement.rs) first, and the ephemeral
pair is generated on **that** curve — so a P-521 recipient cannot be talked into a
P-256 sender key, and neither party's curve comes from an attacker. A caller that
supplies `epk` in a header is refused with a message naming the RFC requirement,
which keeps ephemeral-key reuse unrepresentable rather than merely discouraged.

The published `epk` is minimal and public-only (`kty`/`crv`/`x`/`y`), per RFC 7518
§4.6.1.1. A sender legitimately holding the recipient's *private* JWK is accepted
on the encrypt path — `d` is dropped before anything is emitted, not required to
be absent — because that is how the RFC's own examples are written.

### `epk` is read from the authenticated protected header, only

The JSON serializations already refuse `epk` in an `unprotected`/`header` member
(ADR 0013 put it in the forbidden list), so a recipient never derives a key from
an unauthenticated value.

**Consequence, recorded and asserted in the interop suite:** jwcrypto 1.6.1 ships
`epk` in the unprotected `header` member of its JWE JSON Serialization, so
jwcrypto → jose-rs ECDH-ES in JSON form is refused (by name, before any crypto).
Its compact form puts `epk` in the protected header — where it has to go, compact
has nowhere else — and that direction interoperates. jose-rs → jwcrypto works in
both serializations. panva puts `epk` in the protected header in both and
interoperates in both directions. The divergence is therefore jwcrypto's,
one-directional, and confined to one serialization; this crate does not loosen the
rule to accommodate it, because "the key you authenticate under was chosen by
whoever wrote the bytes" is not a policy worth having for the sake of one peer.

### Conveys nothing, in both directions

`encrypted_key` is the empty octet sequence: the compact form's second segment is
empty, the flattened form omits the member (RFC 7516 §7.2.1), and a message that
does convey one under `ECDH-ES` is refused rather than ignored — a message
describing two key-management schemes at once should not have a defined
decryption outcome.

### One recipient

`ECDH-ES` is accepted by the single-recipient paths (compact and flattened JSON)
and refused by the general-serialization emit path, with the reason and the
alternative named. A *received* general message whose recipient array has one
element still decrypts, because general decryption flattens to the ADR 0014 path.

### KDF parameters are the RFC's, not the caller's

AlgorithmID is the ASCII `enc` value and `keydatalen` is the CEK size that `enc`
needs (so `A128CBC-HS256` derives 256 bits, which is the case that catches an
implementation keying off the "A128" prefix). RFC 7520 §5.5 — a message produced
by another implementation, with the recipient's private key and the CEK printed —
pins this.

`apu`/`apv` are honoured as KDF inputs and travel in the protected header, which
makes them AAD as well as derivation material: editing them after the fact breaks
the tag. They are untyped members, so they must be strings (`"apu": 5` is refused
rather than stringified), must differ when both are present, and must be valid
base64url.

### Emit policy is now algorithm-aware

`apu`/`apv` are emittable exactly when the algorithm runs the Concat KDF; every
other unimplemented member (`zip`, `b64`, `p2s`, `p2c`, `iv`, `tag`) stays
refused for every algorithm, and `epk` stays refused for all of them because it is
ours to generate. The alternative — a static list — would have had to either
forbid `apu`/`apv` forever or allow them where they mean nothing.

A JWK's operation permission for `ECDH-ES` is `deriveKey` on **both** sides (RFC
7517 §4.3), not `encrypt`/`wrapKey`: an agreement neither encrypts nor wraps. A
key pinned to `sign`, or with `use: "sig"`, cannot be a recipient.

> **Amended by [ADR 0018](0018-ecdh-key-agreement-with-key-wrapping.md):** the
> wrapping modes described below as unimplemented are now implemented for a
> single recipient. Everything this record decided about *direct* agreement —
> ephemeral key generation, `epk` placement, the empty encrypted key, refusing
> more than one recipient — still stands, unchanged.

`ECDH-ES+A128KW`/`+A192KW`/`+A256KW` remain unimplemented; a test asserts the
refusal by name so the gap is a decision rather than an accident.

## Consequences

**Good**

* RFC 7520 §5.5 — a message produced elsewhere with the RFC's own keys — decrypts
  in both serializations, so agreement, KDF parameters, header placement and the
  empty-key shape are all checked against another implementation's output.
* Three independent implementations agree on the wire: panva (8 matrix cells over
  P-256/P-384/P-521 × GCM and CBC-HMAC, both directions, asserting `epk` shape and
  the empty encrypted key) and jwcrypto (60 checks, both directions plus the
  documented divergence).
* The dangerous shapes are unrepresentable, not merely unchecked: no caller
  ephemeral key, no caller-chosen curve, no unauthenticated peer key, no
  agreement through a raw-key API, no two-recipient direct agreement.
* A swapped `epk` yields an authentication failure rather than plaintext under an
  attacker-influenced key, and that is asserted.

**Bad**

* **`ECDH-ES` provides no origin authentication.** Anyone holding the recipient's
  public key can produce a message that this recipient will successfully decrypt,
  because the sender half is ephemeral and unauthenticated. That is inherent to
  direct ECDH-ES (it is the mode's point) and not something this crate can fix;
  it must never be described as authenticated key exchange. Callers who need
  origin authentication need a signed envelope, or a mode whose key is bound to an
  authenticated identity.
* The ephemeral key is generated before the emitted-size pre-flight, so a message
  that is going to be refused for size still pays for one scalar multiplication.
  Deliberate: doing it afterwards would mean the header used for the size check is
  not the header that gets serialized.
* `epk` lives in `JoseHeader::extra` as untyped JSON rather than as a typed
  member, so the agreement code reads and validates it explicitly. Making it
  typed (`Option<Jwk>`) is the cleaner long-term shape and is left for a header
  refactor rather than smuggled into this commit.
* jwcrypto's JSON output is refused (documented above). Users who need that peer
  must ask it for the compact form or accept the message with a peer library and
  hand the bytes over separately.

## Alternatives considered

* **Accept a caller-supplied `epk`** (for deterministic tests, or to let a caller
  reuse a pre-agreed key). Rejected: ephemeral-key reuse across two recipients
  reveals both agreed keys to anyone who sees both messages, and RFC 7518 §4.6
  makes a new value mandatory. The RFC 7520 vectors need only the decrypt side.
* **Read `epk` from the unprotected member when the caller opts in.** Rejected:
  unlike an unauthenticated `alg` (ADR 0013), which at least gets checked against
  a key that pins it, there is nothing to check an ephemeral public key against —
  an opt-in would be a switch labelled "let the sender choose the key".
* **Convert every key-management path to JWKs only.** Rejected as unnecessarily
  large: the byte paths are what the raw-key APIs and `RecipientSpec` already
  expose, and `KeyMaterial` keeps both honest without touching the public surface.
* **Refuse `apu`/`apv` outright** until PBES2 needs them too. Rejected: RFC 7518
  §4.6.1 says they MUST be understood and processed when these algorithms are
  used, and refusing them would make some conformant producers' messages
  undecryptable.
* **Support `ECDH-ES+AxxxKW` in the same commit.** Rejected: the wrapping modes
  need their own decisions (AlgorithmID becomes the ASCII `alg`, the wrapped CEK
  is random while the agreement key becomes a KEK, and multi-recipient emit
  becomes possible), which deserve a separate record.

## Verification

* `tests/jwe_ecdh_es.rs` (21 tests): RFC 7520 §5.5 in compact and flattened form
  (asserting the plaintext, the `epk` member and its public-only shape); a message
  conveying an `encrypted_key` is refused; round trips over 3 curves × 6 content
  algorithms, including a sender holding only the public half; fresh-and-minimal
  `epk`; empty/absent `encrypted_key` in both serializations; caller-supplied
  `epk` refused; `apu`/`apv` emitted, honoured and bound; equal, non-base64url and
  non-string party values refused; direct agreement refused for general
  serialization; peer key with `d`, peer on another curve, missing `epk`, garbage
  `epk` each refused; a swapped `epk` failing authentication; `epk` unprotected
  refused at parse; raw-key APIs unable to reach agreement; signing-pinned and
  `use: sig` recipients refused; public-only recipient cannot decrypt;
  `ECDH-ES+AxxxKW` refusal asserted by name.
* Interop: `jwe-ecdh` matrix family (8 cells: P-256/P-384/P-521 × GCM and
  CBC-HMAC, both directions, with `epk` shape and empty-encrypted-key assertions
  on the consuming side); `interop/tests/jwe_ecdh_es_jwcrypto.py` (60 checks).
  Full matrix 87/87.
* Existing suites unchanged and green (317 lib tests; RFC 7520, JWS, JSON, AAD,
  `crit`, general and unprotected suites all passing), confirming that routing key
  management through `KeyMaterial` did not alter `dir`/`AxxxKW`/`RSA-OAEP*`.
