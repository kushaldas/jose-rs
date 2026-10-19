# ADR 0040 — Transient secrets have zeroizing owners

## Date

2026-10-16

## Status

Accepted.

## Context

Long-lived JWK and backend secret owners already zeroized their material, but several
transient paths briefly used ordinary buffers: decoded private PEM DER, normalized
PKCS#8 plaintext, X25519 scalar copies, and owned password inputs copied through a
borrowed constructor. Encrypted PKCS#8 CBC import also exposed whether decryption failed
at padding removal or produced padding-valid bytes that later failed key parsing.

## Decision

Every transient private-key, password, and X25519-scalar allocation is owned by
`Zeroizing` from creation through its final use. PEM decoding writes directly into a
zeroizing output buffer. PKCS#8 normalization encodes into a pre-sized zeroizing buffer,
and encrypted PKCS#8 decrypts in place in zeroizing storage.

`Password::from_bytes` now accepts a borrowed `&[u8]`. Owned `Vec<u8>` and `String`
inputs use their `From` implementations, which transfer the original allocation directly
into `Password` instead of copying it and dropping the source unwiped.

After an encrypted PKCS#8 scheme and work budget have passed, every failure from CBC
decryption through inner key import maps to the same coarse decryption error. Precise
pre-decryption errors for unsupported schemes and work-budget violations remain.

## Security boundaries

- Zeroization limits allocator residue; it cannot erase caller copies, swap, terminal
  history, or compiler-created copies outside these owners.
- PBES2/PBKDF2 parameters are public policy and retain precise diagnostic errors.
- CBC encryption provides no authenticity. Padding success is therefore never treated as
  evidence that the password or plaintext was correct.

## Consequences

- Source migration for an owned byte vector is `Password::from(bytes)` instead of
  `Password::from_bytes(bytes)`. Borrowed slices continue to use `from_bytes`.
- Wrong-password, damaged-ciphertext and padding-valid malformed-key failures are
  intentionally indistinguishable after decryption begins.
- Private export/import paths may perform one bounded copy, but every owning allocation
  on those paths is wiped on all returns, including errors.

