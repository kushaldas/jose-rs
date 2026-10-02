# ADR 0023 — PKCS#1 is decoded, then rebuilt and checked against itself

- Status: Accepted
- Date: 2026-07-31
- RFCs: RFC 8017 §A.1.2 (`RSAPrivateKey`, `RSAPublicKey`, multi-prime version);
  RFC 7518 §6.3 (RSA JWK members); RFC 7517 (JWK); RFC 7468 §3 (64-column line limit)
- Relates to: [ADR 0001](0001-jose-security-boundary-hardening.md) (parsed data is
  untrusted), [ADR 0005](0005-operation-aware-jwk-signature-conversion.md) (a conversion
  that loses a restriction fails instead of losing it),
  [ADR 0022](0022-pem-label-dispatch.md) (the label dispatch that routes here)

## Context

`openssl genrsa` writes PKCS#1 by default. So does `id_rsa`. It is the RSA-only older
sibling of PKCS#8: the same key, no `AlgorithmIdentifier`, and no container to say what it
is — which is precisely why ADR 0022's label dispatch had to route it somewhere rather than
guess.

Two things in the structure are not representable in a JWK, and one thing about it is a
trap.

**A third prime.** RFC 8017 defines `multiPrimeVersion` — `r_3 … r_u` in
`otherPrimeInfos`. RFC 7518 §6.3's RSA JWK has `p` and `q`, and nothing else. An importer
that read the first two primes and moved on would return a JWK for a *different modulus
factorization*: a key that verifies nothing and fails no error.

**CRT members the file asserts.** `exponent1`, `exponent2` and `coefficient` are optimizations
the format carries, and nothing in the format requires them to be right.

**The trap** is that decoding is not validation. `der` will happily return integers that
contradict each other — a `q` that does not divide `n`, a `d` that is not the inverse of `e`.
A "successful parse" says the file is well-formed, not that it describes a key.

## Decision

### Import rebuilds the key from its parts, and the rebuild is the validation

`jwk_from_pkcs1_der` decodes the DER, then constructs the key from `n, e, d, p, q` through
`RsaPrivateKey::from_components`, which requires that the primes multiply to the modulus and
that `d·e ≡ 1 (mod p−1)` for each prime. A file whose parts describe two different keys —
the classic splice of one key's public half onto another's private half, which is
byte-length-compatible and parses cleanly — is refused there with `invalid modulus`.

The result is then normalized to PKCS#8 and run through `jwk_from_pkcs8_der`, so the modulus
floor, the backend's own import checks and JWK construction are **the same code path every
other RSA import uses**. PKCS#1 is not a second, weaker door; there is one RSA import and
this is another front door into it. That is deliberate: "reuse complete RSA validation rather
than treating parsing as validation" is the acceptance criterion, and the way to keep two
doors equal is to have them meet at the same lock.

### The file's CRT members are compared, not trusted and not repaired

After the rebuild, `exponent1`, `exponent2` and `coefficient` from the file are each compared
against the values the key implies, and a mismatch is refused **naming the member**.

The two easy alternatives are both worse. Trusting them propagates a wrong exponent into a
key that will produce signatures no one verifies. Recomputing them silently — which is what
"just normalize the key" would do — accepts a corrupt file and hides the corruption, so the
next person to touch the file has no idea it was ever broken. Neither failure announces
itself later. Refusing is the only option that keeps the file's lies visible.

### Multi-prime keys are refused by name

Not "unsupported OID", not a parse error: the message says multi-prime RSA is unsupported and
why — RFC 7518 gives an RSA JWK `p` and `q` and no member for a third factor, so importing
one would produce a different key. The refusal is made from the decoded structure
(`otherPrimeInfos` present), which is also what distinguishes it from a malformed file.

### Public keys get their own entry point, not a sniff

`jwk_from_pkcs1_public_der` takes `RSAPublicKey` DER. A bare `RSAPublicKey` carries no
algorithm identifier to dispatch on, so it cannot be routed by content; the two format-explicit
DER entry points refuse each other's structures rather than trying the other one. The public
key is rebuilt (`RsaPublicKey::new`, which rejects a bad public exponent), the modulus floor
applies, and the result is wrapped in SPKI and run through `jwk_from_spki_der` for the same
reason as above.

### PEM dispatch gains the two RSA labels; the 64-column rule is named when broken

`RSA PRIVATE KEY` and `RSA PUBLIC KEY` now route here. `EC PRIVATE KEY` and `CERTIFICATE`
remain refused by name — the refusal list shrinks by exactly the number of formats
implemented, which is what makes it worth keeping.

One error-quality change fell out of testing: RFC 7468 §3 caps a base64 line at 64 characters,
and the strict decoder reports a wider one as a base64 error. A generic base64 writer emits 76
— `base64.encodebytes` in Python's standard library does — so the message a caller got was
"invalid base64 encoding" while the file's only defect was its wrapping width. The armor now
checks line length itself and refuses with the rule. The limit stays enforced (our exporter,
OpenSSL, `cryptography` and panva all wrap at 64); what changed is that the refusal explains
itself.

## Consequences

- PKCS#1, PKCS#8 and SPKI imports of the same RSA key produce **the same JWK and the same
  RFC 7638 thumbprint**, asserted rather than assumed. That equivalence is the property a
  caller actually depends on when they read a key from whichever file they were given.
- Nothing here adds an export path. We read `RSA PRIVATE KEY` and write `PRIVATE KEY`, which
  is the direction that improves interop; writing PKCS#1 would only reproduce a format we do
  not need.
- A corrupt-but-parseable RSA file is now refused with the member named. Any caller that
  previously (in another library) received such a key and watched signatures fail will
  recognize this as the better outcome.
- I2 (SEC1) inherits the shape of this decision: rebuild and check, refuse what the JWK
  cannot represent (`explicit` curve parameters), and enter by DER type rather than sniffing.

## Evidence

- `tests/jwk_pkcs1.rs` — 9 tests over OpenSSL-generated PKCS#1 fixtures plus variants built
  by flipping one interior octet of one INTEGER (which keeps the DER well-formed and changes
  exactly one claim the file makes): thumbprint equality across PKCS#1/PKCS#8/SPKI import of
  one key; sign-with-one-file, verify-with-another; each CRT member refused by name;
  inconsistent `d`/`q`/`n` refused; multi-prime refused with the reason; the 1024-bit key
  refused by the same floor; 76-column wrapping refused with the rule named; and the two
  DER doors refusing to open into each other, trailing bytes included.
- `interop/tests/pem_jwcrypto.py` — now 62 checks: `cryptography`'s PKCS#1 private *and*
  public output imports as the same key (compared member by member against values computed in
  Python), and the 76-column refusal is asserted from the other side.
- `tests/jwk_pem.rs` — the label-dispatch tests updated: the RSA labels route to the PKCS#1
  importer, and `EC PRIVATE KEY` / `CERTIFICATE` remain refused, so the day one of them stops
  being a refusal the test has to change on purpose.
