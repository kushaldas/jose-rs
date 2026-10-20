# ADR 0021 — PBES2 password-based key management

- Status: Accepted
- Date: 2026-07-30
- RFCs: RFC 7518 §4.8, §4.8.1.1 (`p2s`), §4.8.1.2 (`p2c`); RFC 2898 §6.2 / RFC 8018
  (PBES2, PBKDF2); RFC 3394 (the wrap); RFC 7520 §5.3 (worked example)
- Relates to: [ADR 0013](0013-jwe-unprotected-headers.md) (which members may appear
  unprotected), [ADR 0018](0018-ecdh-key-agreement-with-key-wrapping.md) and
  [ADR 0020](0020-aes-gcm-key-management.md) (per-recipient header members),
  [ADR 0020](0020-aes-gcm-key-management.md) (the library-generated member category)

## Context

PBES2 (`PBES2-HS256+A128KW`, `+HS384+A192KW`, `+HS512+A256KW`) is the last key-management
family in RFC 7518. PBKDF2 and AES-KW are both already in the dependency tree; nothing
cryptographic is missing. What is different is the input.

A password is not a key. It is low-entropy, supplied by a human, and is *never* used
directly — it is one input to a key derivation whose other inputs (`p2s`, `p2c`) travel in
the message. Three consequences had to be decided:

1. **How a password enters the API.** The existing entry points take `&[u8]` or
   `Jwk`, and both would work mechanically. `jwcrypto` in fact ships
   `JWK.from_password` — a JWK standing in for a password.
2. **Who chooses the work, and who pays for it.** `p2c` is chosen by the sender and
   computed by the recipient. An unbounded accepted count is a one-message denial of
   service; an unbounded emitted count produces messages nobody will read. Both ceilings
   turned out to be empirical: panva's default `maxPBES2Count` is 10 000 and jwcrypto's
   `default_max_pbkdf2_iterations` is 16 384, so a cost-optimal default of 100 000 —
   roughly a tenth of a second of recipient work — makes messages that **both** peers
   refuse to open.
3. **Where `p2s` and `p2c` may be read from.** They are the derivation's inputs, so a
   peer that positions them unauthenticated chooses the salt the password is mixed with.
   And for several recipients, each password derives a different key, so each recipient
   needs its own pair — the same structural problem `epk` (ADR 0018) and the AES-GCM
   wrap's `iv`/`tag` (ADR 0020) have, only sharper, because here the unauthenticated
   values are KDF inputs rather than a public key the attacker already knows.

## Decision

**1. A password is its own type, and only the PBES2 paths accept it.**

`jose_rs::jwe::Password` owns its octets in `Zeroizing`, has two constructors
(`from_utf8`, `from_bytes` — RFC 7518 §4.8 permits an octet sequence and mandates UTF-8
for text, so the encoding decision is made visible at the call site), redacts itself in
`Debug`, and offers no equality and no `Deref<[u8]>`. It is not a `Jwk` and not a
`&[u8]`:

* an `oct` JWK whose `k` holds a passphrase would *also* be accepted by `A128KW` and
  `dir`, giving one secret two incompatible security arguments; and
* raw password bytes on a `&[u8]` path would be used **as** a key-encryption key by the
  wrapping algorithms, which is exactly the mistake PBES2's parameters exist to prevent.

The refusal runs both ways and is asserted in both: `password_key` refuses a non-PBES2
algorithm by name, `jwk_to_jwe_key_bytes` refuses to build PBES2 key material from a JWK,
and `recover_cek` accepts a password only for PBES2. A `KeyMaterial::Password` reaching
any byte-oriented path is a third, internal refusal.

Because a password carries no `alg`, it cannot pin the key-management algorithm the way a
JWK does. That pin is replaced by a family gate: the password entry points accept only
`alg` values from the PBES2 family, so a message claiming `dir`, `A128KW`, `RSA-OAEP-256`
or an agreement mode never gets the password offered to it.

**2. `p2s` and `p2c` are generated here, published in the protected header, and read from
nowhere else.** They join `epk` and the AES-GCM wrap's `iv`/`tag` in the category ADR 0020
named: members whose bytes the library produces because a caller getting them wrong is not
a typo. `p2s` is a nonce (sixteen fresh octets; §4.8.1.1 requires eight or more and a new
value per operation), `p2c` is a work budget the recipient pays. Both are refused from a
caller on the emit path — twice, in header validation and in the function that publishes
them — and read only from the integrity-protected header on receipt, which ADR 0013's
parse-time refusal of unprotected `p2s`/`p2c` is what makes reachable. `p2c` must be a
positive JSON **integer** (§4.8.1.2): a string, float or negative is refused rather than
coerced, and the salt must encode at least eight octets.

**3. The work budget is enforced on both ends, with numbers from measurements — and one of
them from the ecosystem, not from us.**

| constant | value | why |
|---|---|---|
| `PBES2_MIN_ITERATIONS` | 1 000 | RFC 7518 §4.8.1.2's own recommended minimum, so refusing below it costs nothing in interop. Both peers emit 2 048 and 8 192. |
| `PBES2_DEFAULT_ITERATIONS` | 8 192 | Inside panva's `maxPBES2Count` (10 000) **and** jwcrypto's `default_max_pbkdf2_iterations` (16 384); four times panva's default, equal to jwcrypto's, eight times the floor. Measured cost to the recipient: 2.9 ms / 7.9 ms / 16.6 ms for the three algorithms. |
| `PBES2_DEFAULT_MAX_ITERATIONS` | 1 000 000 | A per-message receive budget of about a second (163 ms / 983 ms / 909 ms), overridable downward; raising it is a decision about how much CPU a stranger may bill this process. |

The benchmark is a test, not a comment
(`jwe::internal::tests::pbes2_work_budget_benchmark`, `#[ignore]`d, run in release mode),
and it measured, on the decision machine: 1 000 iterations ≈ 0.4 ms / 1.0 ms / 2.0 ms;
8 192 ≈ 2.8 ms / 7.9 ms / 16.6 ms; 100 000 ≈ 31 ms / 105 ms / 155 ms; 1 000 000 ≈ 163 ms /
983 ms / 909 ms (HS256+A128KW / HS384+A192KW / HS512+A256KW).

The **asymmetry between the two defaults is deliberate and is the interesting part**: what
this crate *emits* is bounded by what other implementations are willing to compute, while
what it *accepts* is bounded only by its own patience. A cost-based rule alone would have
picked 100 000 and produced messages both peers reject with `p2c out of acceptable bounds`
— an interop failure that would have looked like the peer being fussy, and was in fact
checked rather than assumed.

Refusal is always before the derivation, which is what makes it free: checking the count
after deriving would be the bug, not the fix, and both the unit test and the interop suite
assert the timing.

**4. Several recipients stay refused, naming `p2s and p2c`.** The rule from ADR 0018/0020
applies verbatim — RFC 7516 §7.2.1 gives a recipient element `header` (unprotected) and
`encrypted_key`, nothing protected — and PBES2 is where the argument is strongest, because
the unauthenticated values would be KDF inputs. RFC 7520 §5.3 states the multi-recipient
expectation ("each recipient use different values for the PBES2 parameters") without
publishing a multi-recipient message, and both peers tested here offer only the
single-recipient form. Exactly one password through the general entry point is accepted:
then both members live in the shared protected header, which *is* authenticated.

## Consequences

* Every key-management family registered in RFC 7518 §3 is now implemented by this crate:
  `dir`, RFC 3394 AES-KW, RSA-OAEP(-256), AES-GCM key management, ECDH-ES with and without
  wrapping, and PBES2 — with the general (multi-recipient) serialization available for the
  families whose per-recipient values have an authenticated home.
* "Library-generated protected-header members" now covers `epk`, `iv`, `tag`, `p2s` and
  `p2c`, one emit-side refusal, one receive-side rule.
* The iteration-count defaults are documented as **ecosystem-derived**, with the two
  peer ceilings named and a check asserting them (interop). If a peer raises its cap, the
  check notices; the default does not silently drift above it.
* The password/key boundary is asserted in four places, so the confusion needs more than
  one mistake to occur.
* PBES2's failure mode is a password oracle for anyone who can send a message and observe
  the result. This is inherent to password-based encryption and is not hidden: RFC 3394's
  wrap authenticates, so a wrong password fails loudly rather than implicitly (unlike
  RSA-OAEP), and the error names it. The iteration count is the mitigation, and this ADR
  records how large that mitigation actually is — which is not large, for a low-entropy
  passphrase, and should not be mistaken for one.

## Alternatives rejected

* **`JWK.from_password`, i.e. an `oct` JWK as the password carrier.** Rejected: the same
  JWK is valid input to `A128KW`, so one secret would serve two incompatible security
  arguments, and the JWK's policy members (`alg`, `use`, `key_ops`) would either sit empty
  — switching off the pinning every other path relies on — or pretend to be key policy.
* **A `&[u8]` password parameter on the existing key APIs.** Rejected: the wrapping
  algorithms take `&[u8]` as a key, so the same call would use a passphrase as a KEK
  wherever the header named a non-PBES2 algorithm.
* **A cost-based emit default (100 000 iterations).** Rejected on measurement: panva
  refuses above 10 000 and jwcrypto above 16 384, so every emitted message would be
  unreadable by both peers. The rejected value and the refusals are recorded rather than
  dropped, since the reason is the point.
* **A single iteration constant for emit and receive.** Rejected: the sender's limit and
  the recipient's limit answer different questions and are set by different parties.
* **Accepting `p2s`/`p2c` from an unprotected header for the general form.** Rejected:
  those are the derivation's inputs, so an editor picks the salt the password is mixed
  with; this is the primitive of an offline dictionary attack that has to beat a
  precomputed table, not a public value an eavesdropper already has.
* **Trusting the caller's count on receive "since they asked for it".** Rejected: the
  count comes from the message, not the caller. The caller's knob is a ceiling.
* **Refusing the empty password when reading.** Rejected: a peer's message is not refused
  for the shape of its secret; the wrap's integrity check decides that. Emitting with one
  *is* refused, because an unset secret and an empty one are indistinguishable.
* **Deriving, then checking the count.** Rejected: refusal must be free.
