# ADR 0016 — the key-agreement boundary enforces operation, material and curve

Date: 2026-07-28
Status: Accepted
Implements: RFC 7518 §4.6 (ECDH key agreement), §4.6.1 (`epk`/`apu`/`apv`),
§4.6.2 (Concat KDF); RFC 7517 §4.2/§4.3 (`use`, `key_ops`); RFC 8037 §2 (`crv`)

## Context

Every key-management mode this crate lacks and most of the ones it plans to add
— `ECDH-ES`, `ECDH-ES+AxxxKW`, the X25519 variants, and any future
HPKE-based mode — start from the same primitive: an ephemeral-static
Diffie-Hellman agreement, followed by NIST SP 800-56A's Concat KDF. The backend
already exports both (`kryptering::software::keyagreement::agree`,
`kryptering::kdf::concat_kdf`), so the missing part is not cryptography but the
boundary that decides *which JWK may be used how*.

That boundary matters more for agreement than for signing or wrapping, for
reasons specific to it:

* Agreement is the only operation that **needs a private scalar and proves
  nothing**. Signing keys and wrapping keys both act on data someone can check;
  an agreement's output is 32 bytes whose correctness is only revealed later,
  when decryption fails. Errors are therefore invisible by construction.
* One of the two inputs is **attacker-chosen**. In direct key agreement the peer
  key arrives as `epk`, a header member of a message somebody else wrote, and
  RFC 7518 §4.6.1.1 places no restriction on it at all.
* The curve is part of the operation's identity. A P-256 scalar multiplied
  against a P-384 point is not "a slightly different key"; in a permissive
  implementation it is a shared secret nobody agreed to, and invalid-curve
  handling is a standing class of ECDH vulnerabilities.
* The KDF is easy to get subtly wrong: the RFC fixes SHA-256 regardless of key
  size, every `OtherInfo` field is length-prefixed, an absent `apu` still
  contributes four zero octets, and SuppPubInfo (the key length in bits) belongs
  in the hash input. Each mistake changes the derived key with no error
  anywhere, and each produces a value that "works" perfectly against a copy of
  the same mistake.

Meanwhile `Jwk` is a bag of optional fields. Handing a `SoftwareKey` to `agree()`
after one conversion call would enforce none of the above.

## Decision

### `jwk::agreement` exposes two types, never a raw backend key

```text
agreement_key(&Jwk) -> AgreementKey          // own half
peer_key(&Jwk)      -> PeerKey               // the other half
AgreementKey::derive_key(&self, peer, alg_id, apu, apv, key_len) -> Result<Zeroizing<Vec<u8>>>
AgreementKey::agree(&self, peer: &PeerKey)   -> Result<Zeroizing<Vec<u8>>>   // raw Z, low-level
```

`AgreementCurve` is `#[non_exhaustive]` and lists P-256/P-384/P-521 today. An
unsupported `crv` is refused **at the boundary**, with the curve named, rather
than becoming a downstream crypto error or — the failure that matters — a silent
reinterpretation of one curve's bytes as another's.

### Checks on the own key: operation, then purpose, then material

In order: the `kty`/`crv` pair is agreement-capable; `check_op(DeriveKey)`
enforces `use` and `key_ops` (RFC 7517 §4.3 — a key whose `key_ops` says `sign`
cannot reach ECDH by this route, and `use: "sig"` fails independently); an `alg`
present **on the key** must name `ECDH-ES` or one of the three
`ECDH-ES+AxxxKW` variants; and private material must exist. The `alg` check
reuses this crate's existing rule that a JWK's `alg` is a pin, not a hint.

### Checks on the peer key: only what the receiver's own safety requires

The peer is **data, not an identity**: no `use`, no `key_ops`, no `alg` check —
applying the receiver's policy to a sender's ephemeral header would be a new
rejection vector with no security benefit. What *is* enforced:

* **no private component** (`d` in an `epk` is a protocol error, and accepting it
  would let a producer hand over a "public" key whose secret is already known);
* **a valid point on the named curve**, obtained by building the backend key —
  which validates membership — rather than by trusting coordinate lengths;
* **curve equality with the own key**, checked in `agree`.

### `Z` is derived, not delivered

`derive_key` performs agreement *and* the KDF in one step, so the shared secret
never becomes a value a caller can hold, log, or use as a key. `agree` remains
available for the RFC-vector tests and future modes, documented as low-level
with a warning that `Z` is never a key. Both return `Zeroizing`.

### One Concat KDF, shared with the JWE algorithms

`concat_kdf` lives in `jwe::internal` (made `pub(crate)` for exactly this
reason) and is used by `AgreementKey::derive_key` and, from the next commit
onward, by the `ECDH-ES*` key-management modes. It implements RFC 7518 §4.6.2
literally: **SHA-256 always**, `Datalen || Data` prefixes for AlgorithmID,
PartyUInfo and PartyVInfo (four zero octets for an absent parameter), SuppPubInfo
as the big-endian bit length, and `apu` ≠ `apv` when both are present. The
backend's `ConcatKdfParams` carries OtherInfo as three fields, so SuppPubInfo
rides on the tail of `party_v_info`; the bytes hashed are the RFC's, which the
unit tests pin against Appendix C's printed octet array.

### `X25519` is refused for now, by name

`kty: OKP, crv: X25519` *is* an agreement curve and the backend can perform the
agreement, but this crate cannot yet import an X25519 JWK — and importing one
without checking that `d` really derives `x` would let a JWK publish one
identity and agree with another, which is the check the Ed25519 and EC imports
already make. So it gets an explicit "not supported by this crate version" error
until the import and its consistency check land together.

## Consequences

**Good**

* Curve mismatch, off-curve peer, missing private material, private material in
  a peer, and a signing-pinned key are refused before any arithmetic, each with a
  distinct message.
* Agreement and derivation reproduce **RFC 7518 Appendix C** exactly. That
  appendix publishes both private keys, `Z`, every KDF parameter and the derived
  key, so the code is verified against the RFC's numbers rather than against its
  own self-consistency.
* Interop coverage exists before any JWE algorithm does:
  `interop/tests/ecdh_kdf_vectors.py` compares `Z` against OpenSSL's ECDH and the
  derived key against a Python transcription of §4.6.2, on all three curves, and
  checks the refusals.

**Bad**

* Direct key agreement authenticates **nothing** about the sender: an
  unauthenticated attacker can supply `epk` and so co-choose the CEK with the
  recipient. That is inherent to `ECDH-ES`, not to this design; the algorithms
  that consume this boundary must say so in their own documentation and must
  never be presented as authenticated key exchange.
* `agree()` is public, which is a foot-gun. It is documented as low-level and
  `derive_key` is the recommended path; a crate-only `agree` would have pushed
  the RFC vector out of the integration tests.
* Two crate-visible items (`jwe::internal`, `concat_kdf`) exist before a public
  feature uses them.

## Alternatives considered

* **One `jwk_to_agreement_key()` returning a backend key.** Rejected: it cannot
  express "this half must be private, that half must not be", cannot enforce
  curve equality, and leaves the KDF to each caller.
* **Validate the peer's `use`/`alg` too.** Rejected — RFC 7518 §4.6.1.1
  deliberately leaves `epk` unconstrained, and rejecting a sender's ephemeral key
  for policy reasons would break interoperable producers while adding nothing the
  message's own AEAD check does not already cover.
* **Expose the KDF publicly so callers derive their own keys.** Rejected: it
  invites exactly the misuse (treating `Z` as a key, or hand-building OtherInfo)
  the module exists to prevent.
* **Wire ECDH-ES in the same commit.** Rejected for reviewability: the boundary
  has its own security argument and evidence, and the algorithm wiring
  (AlgorithmID choice, `epk` freshness, `apu`/`apv` policy, per-`enc` key sizes)
  deserves its own ADR.

## Verification

* `tests/jwk_agreement.rs` (10 tests): RFC 7518 Appendix C `Z` in both directions
  and its derived key; per-curve symmetry for P-256/384/521; the
  `key_ops: ["sign"]`, `use: "sig"` and `alg: "ES256"` refusals and the
  `alg: "ECDH-ES+A128KW"` acceptance; the two-halves-not-interchangeable rules;
  cross-curve refusal; off-curve and oversized peer points; unsupported
  `kty`/`crv` messages; `apu == apv`; and that an `AgreementKey` publishes a
  well-formed SEC1 point.
* `src/jwe/internal.rs` unit tests (3): OtherInfo equals the byte array printed
  in RFC 7518 Appendix C; an absent `apu` contributes four zero octets (and so
  does an empty one, which is the documented divergence from some peers);
  SuppPubInfo carries the bit length big-endian for 128/192/256-bit keys.
* `interop/tests/ecdh_kdf_vectors.py` (19 checks): RFC §C numbers cross-checked
  against OpenSSL's ECDH and an independent Python Concat KDF; per-curve
  agreement symmetry, `Z` and derived key against Python; five refusals.
