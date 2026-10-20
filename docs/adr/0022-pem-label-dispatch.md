# ADR 0022 — PEM reads the label, and writes the form peers parse

- Status: Accepted
- Date: 2026-07-31
- RFCs: RFC 7468 (PEM); RFC 5208 / RFC 5958 (PKCS#8 `PrivateKeyInfo` /
  `OneAsymmetricKey`); RFC 5280 §4.1.2.7 (SubjectPublicKeyInfo); RFC 8017 §A.2
  (PKCS#1 `RSAPrivateKey`); RFC 5915 (SEC1 `ECPrivateKey`); RFC 7517 (JWK)
- Relates to: [ADR 0001](0001-jose-security-boundary-hardening.md) (parsed JOSE data is
  untrusted, and defaults are not relaxed for convenience),
  [ADR 0005](0005-operation-aware-jwk-signature-conversion.md) (a JWK conversion that would
  lose a key's restriction fails instead of losing it),
  [ADR 0021](0021-pbes2-password-based-key-management.md) (the password type, which a
  passphrase named in a `DEK-Info` header must not be quietly routed into)

## Context

Keys live in files, and a file is where an implementation decides how strict it wants to
be. `jwk::import` already read PKCS#8 and SPKI **DER**; the missing layer was the armor
around it — PEM, which is base64 with `-----BEGIN <label>-----` boundaries and nothing else
in the way of structure.

Two things made this worth an ADR rather than a wrapper function.

First, **the label is the only place the format is written**. `PRIVATE KEY` is PKCS#8,
`RSA PRIVATE KEY` is PKCS#1, `EC PRIVATE KEY` is SEC1, `CERTIFICATE` is X.509, `ENCRYPTED
PRIVATE KEY` is PKCS#8 with the key bytes encrypted under a password. A permissive reader
peeks at the DER and infers. That works until two structures happen to be length-compatible
— and then it produces a key that is subtly the wrong thing.

Second, **what we export has to be what other implementations read**. That turned out to be
a live problem, not a hypothetical one, and it is the reason for the shape of `private_pem_from_jwk`.

## Decision

### 1. One block, no preamble, no trailing text — whitespace is free

RFC 7468's strict grammar allows a *preamble* (text before the boundary), and the
`pem-rfc7468` implementation follows it: hand it an email containing a key and it returns
the key. This crate refuses leading text. A file that contains a paragraph and a key is not
self-evidently a key file, and "which key did they mean?" must not be answered silently.

The grammar is simultaneously stricter than any real workflow: it rejects the trailing space
an editor leaves, and even a blank line after the `-----END` line. So the rule this crate
applies is *whitespace around the block is nothing; text around the block is a refusal*. A
re-indented block (a key pasted out of a document) is refused as well, because that
whitespace is **inside** the encapsulated text, not around it.

Two blocks in one file is refused with a count. A certificate chain is the legitimate
multi-block case, and when certificates are supported it will be served by a
certificate-specific entry point, not by relaxing this rule for every label.

### 2. Labels are dispatched, never guessed

Recognized-but-unsupported labels are refused **by name**, each with the reason and the
entry point that will handle it: PKCS#1, SEC1, certificate, certification request. The
legacy RFC 1423 headers (`Proc-Type: 4,ENCRYPTED`, `DEK-Info: …`) get their own message
saying *this key is encrypted under a password and this function does not decrypt it* —
because the tempting failure mode is to treat the ciphertext as if it were a key, or to
route a passphrase into some other function's key argument.

Explicit-format entry points (`jwk_from_pkcs8_pem`, `jwk_from_spki_pem`) refuse a
well-formed file with the other label. A caller who asked for a private key and is handed a
public one should learn that from the error.

The DER importers' own rules keep applying *through* the armor — an RSA-PSS key that cannot
become a generic RSA JWK, and an RSA key below the modulus floor, are refused from the PEM
path too. Armor is not a way around a check.

### 3. Private and public export are different functions

`private_pem_from_jwk` is the only way to get a `PRIVATE KEY` block, and it requires private
material. `public_pem_from_jwk` emits the SPKI public half from either kind of JWK and can
never produce a private block. JWK metadata (`kid`, `alg`, `use`) does not survive the trip
in either direction — PEM has nowhere to put it, and inventing a header for it would produce
a file no one else reads.

An OKP **X25519** public key is refused by name: this backend's X25519 "public component" is
the bare 32-octet `u` coordinate, and wrapping raw bytes in a hand-made SPKI header would
write a file that announces a structure it does not have. Ed25519 — the other OKP curve —
has a real SPKI encoding and exports normally, which is why the check is on the curve and
not on the `kty`.

### 4. What we export is the narrower of the two legal forms

Measured, not assumed: the backend exports Ed25519 as an `OneAsymmetricKey` — PKCS#8
**version 1**, with the public key carried in the `publicKey [1]` attribute (this is what
the `ed25519` crate's own PKCS#8 encoder produces). OpenSSL reads that file happily.
`cryptography` refuses it outright: *"Could not deserialize key data"*. jwcrypto's toolchain
sits on the same library. A private key file that a major library cannot parse is a key the
user has lost.

So the export normalizes: decode, and if a `publicKey` attribute is present, re-encode
without it — which returns the structure to **version 0** `PrivateKeyInfo`, the form OpenSSL,
panva and jwcrypto all emit for these keys. Nothing is lost, because RFC 5958 marks that
attribute OPTIONAL precisely because the public key is computed from the private one. The
normalization goes through the `pkcs8` crate's own types, so no DER is hand-assembled. RSA
and the EC curves already have no attribute and pass through byte for byte — asserted, and
asserted too that the version is 0 for every exported family.

Reading is not writing. The version-1 form is accepted on import (pinned by a fixture),
because refusing to *emit* it is an interop choice, not a claim that it is malformed.

### 5. No new dependency edges that were not already in the resolution

PEM armor uses `pem-rfc7468`, and the private-key normalization uses the already-present
`pkcs8`. Both were already resolved in `Cargo.lock` as dependencies of `der`/`pkcs8`; adding
the explicit edges changed one line of the lock file and added no package. Password-encrypted
PKCS#8 (RFC 5958) remains out of scope: it needs a KDF and a scheme allow-list in front of
it, which is I3, not an armor wrapper.

## Consequences

- A caller gets one function, `jwk_from_pem`, whose every ambiguous case has a decided and
  tested answer. Nothing in this module resolves an ambiguity by guessing.
- Import remains asymmetric-by-policy: strict about our own inputs, liberal about what peers
  send. Both directions are pinned by tests.
- I1 (PKCS#1) and I2 (SEC1) have named call sites already, so their entry points will land
  as additions rather than as a relaxation.
- I3 (encrypted PKCS#8) inherits a refusal message that already tells the caller where to
  go, and the `Password` type from ADR 0021 is the only place a passphrase may arrive.
- I4 (certificates) inherits the multi-block rule: chains get their own entry point.
- Interop is now byte-exact rather than "parses": `interop/tests/pem_jwcrypto.py` compares
  our PEM against what OpenSSL re-encodes for the same key, which is a stronger statement
  than either implementation being able to read the other's file.

## Evidence

- `tests/jwk_pem.rs` — 18 tests over OpenSSL-generated fixtures (RSA-2048, P-256/384/521,
  Ed25519, X25519, PKCS#1, SEC1, certificate, encrypted PKCS#8, legacy `DEK-Info`, RSA-PSS,
  1024-bit RSA): import → sign → verify across two files; thumbprints matching across
  equivalent import formats; metadata loss pinned; label, armor, structure and DER-level
  refusals; version-0 export shape and version-1 import.
- `interop/tests/pem_jwcrypto.py` — 60 checks. `cryptography` generates and jose-rs imports
  (comparing every JWK member against values computed in Python, including fixed-width
  coordinates), jose-rs signs with the imported key and Python verifies with the SPKI half,
  jose-rs exports and both `cryptography` and the `openssl` CLI load it — with our bytes
  compared against OpenSSL's own re-encoding. Strictness in both directions, and whitespace
  accepted.
- `interop/rust-harness`: `import-pem`, `export-pem --pem=private|public`, `sign-pem`, and
  RSA key generation, so the checks exercise the same dispatching entry points a caller uses.
