# ADR 0026 — A certificate is a claim about a key, and extracting it validates nothing

## Date

2026-07-28

## Status

Accepted

## Context

A certificate contains a public key, and callers will ask for it. It also contains a signature,
an issuer, validity dates, key-usage extensions and a chain — the parts that decide whether the
key may be *trusted*, which this crate cannot decide: it has no trust anchor, no policy, and no
revocation access, and inventing those would be a different project.

Three failure modes are available and two of them are tempting:

* Parse the whole certificate (with a real X.509 crate), because the parser is free, and drift
  into "we handled the certificate".
* Extract the key and name the function something like `verify_certificate`, which suggests the
  caller got an identity.
* Extract the key leniently — scan for something that looks like a public key, accept
  BER-tolerant encodings — which produces a *wrong key with no error*, the worst outcome of the
  three.

## Decision

### Extract, and say nothing else

`jwk::public_jwk_from_certificate_der` / `_pem` return the subject's public key as a public-only
[`Jwk`](crate::jwk::Jwk) and nothing more: no subject string, no dates, no "verified" flag. The
name says `public_jwk_from`, not `verify`, because a test can pin the difference — flipping a bit
in `signatureValue` leaves the extracted key **unchanged**, and `tests/jwk_cert.rs` asserts that
as correct behaviour rather than pretending to notice. `x5c` binding (RFC 7515 §4.1.6) stays a
separate feature with its own rules; conflating "got the key" with "bound the signature" is how
certificate code goes wrong.

### A positional walk, DER-only, with no scanning

`Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }`; inside
`tbsCertificate`, `subjectPublicKeyInfo` sits after `version`(optional `[0] EXPLICIT`, DEFAULT
v1), `serialNumber`, `signature`, `issuer`, `validity` and `subject`. Version presence shifts
every later index, so the first element's **tag** decides the offset — the one non-fixed position
in the walk, and the one place `tests/jwk_cert.rs` exercises with a fixture that has had its
version element deleted.

Nothing is searched for. `rsa_cert_decoy.pem` hides a second, entirely valid SPKI in a private
extension — and its subject key must still come out, and must differ from the decoy. A reader
that looks for "something SPKI-shaped" fails that test by construction.

Structure rules are DER as RFC 5280 Appendix A.1 profiles it: definite lengths only, low-tag
numbers only, minimal length encoding, no trailing bytes. **This is measurably stricter than
OpenSSL and matches `cryptography`**: both indefinite-length fixtures are accepted by
`openssl x509` and refused by `cryptography` (`InvalidLength`) and by us, naming the length form.
Recording which peer tolerates what — instead of assuming strictness is universal — is why the
interop script prints OpenSSL's verdict as a note.

### One SPKI parser, not two

The located element is re-encoded and handed to `jwk_from_spki_der`. So DSA, Brainpool,
`id-RSASSA-PSS`, a truncated BIT STRING and every other SPKI-level rejection is refused here with
the same message as everywhere else, and this module adds no key-type policy of its own. It also
means a future algorithm addition cannot leave the certificate path behind.

### No new dependency, on purpose

`x509-cert` is in the offline cache and would parse certificates properly. It is not used. What
this feature needs is three elements located by position and a strict TLV reader, which is about
150 lines with the refusals — and the risky part of this feature was never the ASN.1. Meanwhile a
full X.509 type set models validity dates, names and extensions, and **a type that models a thing
invites a caller to believe it was checked**. Keeping the surface as "bytes in, public key out"
makes the boundary visible at the type level; if certificate validation is ever added, it should
be its own feature with its own types, not a boolean here.

### Chains and labels are refused, not guessed

A PEM file must contain exactly one `CERTIFICATE` block; a chain is refused **with the block
count** rather than silently using block one, because leaf-versus-root is a decision only the
caller can make and picking wrong presents a different key with no error at all. Conversely
`jwk_from_pem` refuses `CERTIFICATE` and names this function, per ADR 0022's label-dispatch rule:
the label decides the format, and the refusal points at the right door.

### No invented metadata

The returned JWK has no `kid`, `use` or `alg`. A certificate does not state how its key should be
used, and an `alg` here would be a guess that later turns into a key-metadata pin.

## Consequences

* The extraction is independently confirmed twice over: every fixture's key equals the JWK from
  `openssl x509 -pubkey` by thumbprint, and a signature made with the certificate's private key
  **verifies** under the extracted key — the check that rules out landing on the wrong element.
  42 interop checks add a Python-side RFC 7638 thumbprint implementation, so a bug in our
  thumbprint cannot mask a bug in the walk, or vice versa.
* Callers who need trust still have to validate elsewhere. The docs, the rustdoc and the function
  name all say so; the tampered-signature test makes it undeniable.
* BER-tolerant inputs that OpenSSL reads are refused. That is a real interoperability cost,
  taken deliberately, and documented with the measurement rather than as "malformed input".
