# ADR 0025 — A key file that arrives with a password arrives with a scheme

## Date

2026-07-28

## Status

Accepted

## Context

An `ENCRYPTED PRIVATE KEY` file (RFC 5958) is not one thing. Inside its `AlgorithmIdentifier`
it names a scheme — PBES1 or PBES2 — a KDF (PBKDF2 or scrypt), a PRF (SHA-1 through SHA-512),
a cipher (DES, 3DES, AES-128/192/256-CBC), a salt, an iteration count and an IV, all chosen by
**whoever wrote the file** and all paid for by **whoever reads it**.

The crate already had the pieces and none of the policy. `pkcs8`/`pkcs5` were in the lock (via
`rsa`'s `pkcs8` feature), and enabling their `encryption` feature adds three packages already in
the offline cache (`pkcs5`, `scrypt`, `salsa20`) and one line to `Cargo.lock`. But a library
that "supports encrypted PKCS#8" by calling `decrypt(password)` supports *whatever the file
asks for*, including HMAC-SHA1 and DES, and spends unbounded CPU before it learns the password
was wrong.

## Decision

### The dependency's feature set is the allow-list, and that is deliberate

`pkcs5` keeps HMAC-SHA1, DES and 3DES behind separately-named `-insecure`/`3des` features. This
crate does not enable them, so those schemes are unreachable by **any** input from **any**
caller — not "refused at runtime and hoping the refusal is correct", but absent from the binary.
The runtime checks in `describe_scheme` sit on top of that floor and handle what a compiled
binary can still be *handed*: PBES1, scrypt, SHA-1/SHA-224 PRFs, AES-192-CBC, iteration counts.

### The budget is checked before deriving, not after

A file names its iteration count and this process pays it. So the count is checked **before**
any PBKDF2 work: refusing a file costs nothing, and a check placed after the derivation would be
placed after the denial of service.

### One number is about the ecosystem, and it is 2 048

`PKCS8_MIN_ITERATIONS` = 2 048, measured on this machine: `openssl pkcs8 -topk8 -v2 aes-256-cbc
-v2prf hmacWithSHA256` and `cryptography` 50's `BestAvailableEncryption` **both** emit exactly
2 048 (`0x0800`) by default. A floor above that refuses every default-encrypted key file in the
wild — and a library that cannot open a user's key does not make them safer, it makes their key
gone. The interop suite re-derives this number on every run, so an OpenSSL or `cryptography`
change shows up as a failing check rather than as a silent floor that is now wrong.

`PKCS8_DEFAULT_ITERATIONS` = 600 000 for files we write (OWASP's current PBKDF2-HMAC-SHA256
figure). Unlike JOSE's PBES2 — where ADR 0021 had to keep our default inside what panva and
jwcrypto are willing to compute — a PKCS#8 reader computes whatever the file names, so the
emit-side default is free to be the careful number. It costs 175 ms measured.

`PKCS8_DEFAULT_MAX_ITERATIONS` = 10 000 000 bounds the read side at about 1.7 s measured (2 048
→ <1 ms, 600 000 → 175 ms, 10 000 000 → 1 694 ms; the ignored benchmark test re-derives them).
`pkcs5`'s own ceiling is 100 000 000, which is minutes of CPU spent on a file that will be
rejected anyway.

### scrypt is refused, including the form our own dependency writes by default

`pkcs8`'s `encrypt()` default is **scrypt + AES-256-CBC**. We refuse it: scrypt's cost comes from
the file's `(log N, r, p)`, and the bound this module can state is a PBKDF2 iteration count, so
accepting scrypt means accepting a work cost we cannot bound.

The consequence is the part worth writing down: **we do not emit what we will not read**. Our
export uses `encrypt_with_params` with PBKDF2 explicitly, because `encrypt()` would have produced
files our own importer rejects. A test pins both halves — that scrypt files are refused, and that
our export's decrypted payload has no scrypt in it.

### No fallback, in either direction, with a reason attached

`jwk_from_encrypted_pkcs8_*` refuses a plaintext `PRIVATE KEY` block and `jwk_from_pem` refuses
`ENCRYPTED PRIVATE KEY`, naming the function that can read it. This is not tidiness: a caller who
asked for the password path and got a key back from an unencrypted file would believe they held
a protected key. The error tells the truth in both directions.

An **empty password is refused on the write side only**, reusing ADR 0021's reasoning: an unset
secret and a deliberately empty one encrypt to indistinguishable files, and the caller cannot
tell them apart later. Reading such a file is not refused on that ground.

### Refusals name the cause, and a byte scan may sharpen a refusal but never grant an acceptance

DES, 3DES and AES-192-CBC are not compiled in, so those files fail to *parse* — and a parse error
is a bad place to lose the real reason. `unsupported_oid_hint` looks for the OIDs the file
actually contains and says "3DES-CBC … re-export with AES-CBC" instead of "invalid DER". It has
no path to an acceptance, exactly like SEC1's explicit-parameters classifier (ADR 0024): error
messages may be smarter than the decoder, acceptances may not.

### The encrypted payload is normalized before it is encrypted

`cryptography` rejects version-1 `OneAsymmetricKey` payloads (ADR 0022's finding), and the
backend emits that form for Ed25519. The first cut of this export encrypted the backend's bytes
as delivered, and the interop suite rejected our own Ed25519 file with an ASN.1 error. The fix is
to route through the same `pkcs8_portable_form` the plaintext PEM export uses — **before**
encryption, because once a file is in a peer's hands, noticing the payload is unreadable helps
nobody.

## Consequences

* Encrypted PKCS#8 support is real in both directions and cross-verified: 65 interop checks run
  `cryptography` ⇄ this crate for EC/RSA/Ed25519 with coordinate equality, plus OpenSSL as a
  third opinion, plus refusals against files those peers *do* read (so a refusal is shown to be
  our policy, not a broken fixture).
* Enabling the feature costs 3 lock entries and one direct edge; `#![forbid(unsafe_code)]` is
  unchanged, and the added code is policy and translation, not crypto.
* Users with scrypt-encrypted or 3DES files get a refusal that names the scheme and tells them to
  re-export. That is a deliberate loss of convenience: those files remain perfectly readable by
  the tools that made them.
* The 2 048 floor is a documented compromise. Anyone who wants a stronger policy can raise it for
  their own deployment; what they cannot do is pretend the ecosystem emits safer defaults than it
  does.
