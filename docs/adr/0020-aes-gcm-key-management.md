# ADR 0020 — AES-GCM key management (`A128GCMKW`, `A192GCMKW`, `A256GCMKW`)

- Status: Accepted
- Date: 2026-07-30
- RFCs: RFC 7518 §4.7; RFC 7516 §4.1.2/§7.2 (the envelope's own `iv`/`tag`);
  RFC 7515 §5.2 (what the authenticated data is)
- Relates to: [ADR 0013](0013-jwe-unprotected-headers.md) (which members may appear
  unprotected), [ADR 0018](0018-ecdh-key-agreement-with-key-wrapping.md) (the
  per-recipient header-member rule this extends), [ADR 0019](0019-x25519-agreement-keys.md)

## Context

RFC 7518 §4.7 defines the third key-management family: the CEK is carried in the
message (as with `A128KW`/`A192KW`/`A256KW`), but instead of RFC 3394 it is protected
with AES-GCM under a symmetric key whose length follows `alg`. It needs no asymmetric
key, no password, and no HSM, and both interop peers implement it.

The algorithm has one structural peculiarity, and it is the whole decision. AES-GCM
needs an IV and produces a tag, and §4.7.1 says both travel as **header members**
named `iv` and `tag` — the same names RFC 7516 §4.1.2/§7.2 gives to the *envelope's*
own members, which belong to the content encryption. So:

* the same two names appear in two places in one message, meaning two different
  things;
* the key wrap's IV and tag must be inside the protected header to be authenticated,
  which means they must exist **before** the header is serialized — and the serialized
  header is the content encryption's additional authenticated data. That inverts the
  usual order of operations, where the CEK is produced and wrapped after the header is
  fixed;
* and for multiple recipients each wrap would need its own `iv`/`tag`, which — exactly
  as with a per-recipient `epk` in ADR 0018 — RFC 7516 gives no authenticated home.

The backend offers no AES-GCM key wrap (`kryptering::keywrap` is RFC 3394 and Triple
DES only), so the primitive comes from `aes-gcm`, which the crate already depends on
for content encryption — no new dependency, and the same construction as the content
path.

## Decision

**Accept the family on three rules.**

**1. `iv` and `tag` are generated here, and are protected-header members — for every
algorithm.** They join `epk` in the class of members whose bytes the library produces
because a caller getting them wrong is not a typo but a break: a reused IV under a
fixed key destroys AES-GCM's confidentiality *and* authenticity of the wrapped CEK,
and a caller-supplied tag would let a message assert its own verification. The emit
path refuses a caller-supplied `iv`/`tag` for every algorithm (it already refused
`epk`) — and so does the function that publishes them, which is the one that would
otherwise overwrite a supplied value in silence — and the receive path only ever reads
them from the integrity-protected header
— the parse-time refusal of unprotected `epk`/`iv`/`tag` from ADR 0013 is what makes
that safe rather than merely convenient. Both members are mandatory on receipt, with
the RFC's exact sizes (12 and 16 octets) and the RFC's exact type (base64url string):
there is no default for either, and defaulting a zero IV would turn a malformed
message into a decryption attempt under a key nobody intended.

**2. The key work happens before serialization, and the code says so.** The encrypt
path dispatches on the algorithm into a `Prepared` enum — agreed CEK, agreement-with-
wrapping sender, already-wrapped GCM CEK, or plain byte key — precisely because three
of the four shapes have to publish something in the header first. Silently wrapping
*after* the header bytes were fixed would either drop the members or emit a header
whose bytes no longer match what was authenticated.

**3. Multiple recipients stay refused, with the reason named.** The rule stated in
ADR 0018 for `epk` generalizes verbatim: RFC 7516 gives a recipient element no
protected header, so per-recipient `iv`/`tag` could only travel unprotected — and
those two values *are* the wrap's nonce and authenticity, not a public key an
eavesdropper happens to already know. Emit and receive share one refusal
(`per_recipient_member_unsupported`), so the crate cannot write what it will not read.
Unlike `epk`, there is no serious argument for relaxing this: RFC 7520 §5.13 does not
ship a multi-recipient GCMKW example, and nothing needs to be conceded to keep
interoperating on the messages that exist.

**Key sizes.** The KEK length comes from `alg` (16/24/32), the CEK length from `enc`.
The wrap's AAD is empty, as RFC 7518 §4.7 requires — the protected header is not
folded in, which is why the header's integrity must come from the content tag covering
those bytes. GCM does not expand, so the conveyed encrypted key is *exactly* `enc`'s
CEK length: unlike RFC 3394's +8 octets, the message says for itself which CEK it
carries.

## Consequences

* The last key-management family in RFC 7518 that needs no asymmetric key, no
  password, and no backend extension is now implemented. What remains in RFC 7518 is
  PBES2 (a password API, ADR 0022's subject) and `ECDH-ES`+`ECDH-1PU` variants beyond
  the direct and wrapping modes.
* "Library-generated protected-header members" is now a named category with three
  members (`epk`, `iv`, `tag`) and one refusal on the emit path, rather than three
  ad-hoc decisions. A future `p2s` (PBES2 salt) joins the same set.
* The name collision is asserted rather than assumed: tests and interop checks require
  the header's `iv`/`tag` *and* the envelope's to exist simultaneously with different
  values, because a message that reused them would be readable by nobody.
* The interop evidence is unusually direct: the suite unwraps the header wrap **in
  Python** with the RFC's own parameters, checks the recovered key is `enc`'s CEK
  length, and then decrypts the content with it — so "the header protects the key the
  content needs" is verified end to end rather than trusted to either implementation.
* Multi-recipient AES-GCM key management remains an explicit gap, and the reason is
  one decision record, not two.

## Alternatives rejected

* **Accept a caller-supplied `iv`/`tag`.** Rejected: a key-wrap nonce is not a
  caller's to choose, and accepting a tag means accepting a message that vouches for
  itself.
* **Put the wrap's `iv`/`tag` in the unprotected header, as RFC 7516's recipient
  element would require for several recipients.** Rejected: an attacker who can edit
  them chooses the nonce and forges or destroys the wrap's authenticity, and the
  failure is not detected. Both peers put them in the protected header, so refusing
  costs nothing in interoperability today.
* **Wrap after serializing the header, then append the members.** Rejected: the header
  is the content AAD, so the emitted bytes would not be the bytes that were
  authenticated.
* **Fold the protected header into the wrap's AAD** (defense in depth against a header
  edit). Rejected: RFC 7518 §4.7 says the AAD is empty, and a deviation would break
  every peer to defend against an edit the content tag already catches.
* **Default a missing `iv` to zeros / accept a shorter tag.** Rejected: both turn a
  malformed message into an attempt.
* **Trust the AEAD primitives to reject wrong lengths.** They assert rather than
  report: `Nonce::from_slice` panics on anything but 12 octets. The wrap and unwrap
  check the sizes themselves, so the panic is unreachable rather than merely
  unreached-by-today's-callers.
* **Use `kryptering::keywrap` for this.** Not available — it implements RFC 3394 only
  — and adding a GCM wrap to the backend would be a backend change this feature does
  not need, since the crate already has `aes-gcm`.
