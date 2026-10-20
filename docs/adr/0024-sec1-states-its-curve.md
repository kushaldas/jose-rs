# ADR 0024 — A SEC1 file states its curve, or it is not a key

- Status: Accepted
- Date: 2026-07-31
- RFCs: RFC 5915 (`ECPrivateKey`, `ECParameters`); RFC 5480 (EC named curves); RFC 6090
  (ECDH curves); RFC 7518 §6.2 (EC JWK members); RFC 7517 (JWK)
- Relates to: [ADR 0001](0001-jose-security-boundary-hardening.md) (parsed data is
  untrusted), [ADR 0022](0022-pem-label-dispatch.md) (the label dispatch that routes
  `EC PRIVATE KEY` here), [ADR 0023](0023-pkcs1-rebuilt-not-trusted.md) (the same
  rebuild-and-check posture for PKCS#1)

## Context

`openssl ec -traditional` and most hardware key loaders write SEC1: a scalar, and then two
OPTIONAL members — the curve (`parameters [0]`) and the public point (`publicKey [1]`).
PKCS#8 wraps the same scalar but states the curve in an `AlgorithmIdentifier`, where it is
mandatory. So the format a great many real EC key files use is one where the curve may be
**absent**, or may be present in a form that names nothing.

Each optional member has a plausible-permissive reading, and each of them is wrong:

- **No `parameters`?** "Try each supported curve until the scalar is accepted." That is how a
  P-256 secret gets read as a P-384 key — every member parses, none of them is the key the
  user has, and nothing downstream can tell.
- **`parameters` as a full domain-parameter block** (`field-id`, `a`, `b`, `base`, `order`,
  `cofactor`, as RFC 5915 allows)? "Match it to the nearest named curve." That imports a key
  whose curve is *asserted by the file*. Anomalous and unsafely-generated curves are a known
  attack surface precisely because they look like the real thing; a library that pattern-matches
  a curve onto a name is the place such a key gets accepted.
- **A `publicKey` that belongs to a different scalar?** "Trust the file." The resulting JWK has
  a public half that verifies nothing, while both halves look valid in isolation.

## Decision

`jwk_from_sec1_der` refuses all three, and what survives is normalized to PKCS#8 and run
through `jwk_from_pkcs8_der` — the same shared importer PKCS#1 lands on, so curve dispatch,
the backend's checks and JWK construction happen once for every EC import.

### A scalar without its curve is not a key

Refused, with the reason: guessing a curve would silently change which key this is. There is no
"import anyway and let the caller notice" mode, because the caller cannot notice — the JWK comes
back complete.

### Explicit parameters are refused by name, not by length

The refusal names the structure ("explicit curve parameters") and tells the caller to export a
named curve. That message matters: the file is not corrupt, the caller's tooling just chose the
one form this crate will not read.

One implementation note, because it is the kind of thing that quietly becomes a vulnerability.
The `sec1` crate models only the named-curve form of `ECParameters`, so an explicit-parameter
file fails its decoder with a generic ASN.1 error — "invalid DER" for a file that is perfectly
valid RFC 5915. To say otherwise, this crate walks the top-level `ECPrivateKey` SEQUENCE and
looks at the *tag* of the `parameters [0]` member: OID means named, SEQUENCE means explicit.
That classifier can only ever **turn a vague refusal into a specific one**; it has no path that
causes anything to be accepted, and everything that is accepted still goes through the real
decoder, the curve crate and the PKCS#8 import. The asymmetry is deliberate: error messages may
be smarter than the decoder, acceptances may not.

### A public point is checked against the scalar, and the message covers both failures

`public_key()` is derived from the secret and compared with whatever the file asserts; a
mismatch is refused. The scalar/point parse itself reports through one call, so the message
names both obligations — "the scalar must lie in `[1, n−1]` and any embedded public point must
be a valid point on that curve" — rather than blaming the scalar for a point problem. Saying
less precisely than the code knows is how a caller ends up debugging the wrong member.

### Unsupported named curves are refused with their OID

A Brainpool or secp256k1 file is refused naming the OID and listing what is readable. The
distinction between "your file is broken" and "this curve is not supported here" is the whole
answer to the user's next question.

## Consequences

- SEC1, PKCS#8 and (for the public half) SPKI imports of one EC key produce the same JWK, the
  same RFC 7638 thumbprint, and — asserted directly — **byte-identical signatures**. "Equivalent
  import formats" is tested as an operational property, not a structural one.
- P-256, P-384 and P-521 are covered; per-curve helpers are written concretely rather than
  generically, because the generic form needed an `elliptic_curve` dependency edge this crate
  does not have, and three small bodies beat one trait-bound zoo.
- Import remains strictly asymmetric: we read SEC1, we write PKCS#8. Writing SEC1 would only
  reproduce a format that loses information.
- No export path, no new package: `sec1` was already resolved in `Cargo.lock` as a dependency of
  the nist-curve crates, so naming it as a direct dependency changed one lock line.
- I3 inherits the "the file says what it is" posture: an encrypted PKCS#8 must be refused or
  decrypted deliberately, never misparsed as plaintext.

## Evidence

- `tests/jwk_sec1.rs` — 9 tests on OpenSSL fixtures plus variants built by rebuilding the outer
  SEQUENCE from its own members (drop the curve; swap in another key's public point; swap in
  secp256k1's OID) so each variant is well-formed DER making exactly one wrong claim:
  thumbprint equality and identical signatures across SEC1/PKCS#8 for all three curves;
  sign-with-SEC1-file/verify-with-SPKI-file; no-curve, explicit-parameters, borrowed-point,
  zero-scalar and scalar-equals-`n` refusals; the two DER doors refusing each other's formats
  and trailing bytes; and an unsupported OID refused with the OID named.
- `interop/tests/pem_jwcrypto.py` — now 63 checks: `cryptography`'s SEC1 (`TraditionalOpenSSL`)
  output imports as the same key, and OpenSSL's own `-param_enc explicit` output is refused by
  name.
