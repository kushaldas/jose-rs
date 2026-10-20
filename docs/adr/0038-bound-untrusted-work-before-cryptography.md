# ADR 0038 — Bound untrusted work before cryptography

## Date

2026-10-16

## Status

Accepted.

## Context

Several individually bounded inputs could still cause disproportionate work before a
policy refusal. Duplicate detection in JSON objects scanned every earlier name. Raw
PKCS#1 private import constructed and validated arbitrary-size big integers. The JSON
JWE path decoded encrypted fields before checking the caller's algorithm, plaintext,
external-AAD and PBES2 budgets. The JWK-aware General JWS path allocated and decoded
one result per signature before applying its 64-signature ceiling.

Compact JWE already exposed `JweDecryptOptions` to password recipients, but Flattened
and General JSON password entry points did not. Those callers therefore could not lower
the PBES2 work ceiling even though the sender chooses `p2c` and the recipient pays it.

## Decision

All duplicate-member detectors use a hash set while retaining the original ordered
member vector. This keeps one-token-one-reading without quadratic name comparison.

RSA keys have one format-independent modulus policy: 2048 through 8192 bits. Key DER
inputs are capped at 64 KiB before ASN.1 parsing, and raw PKCS#1 checks the modulus width
before constructing big integers or validating private components. Generation, JWK,
PKCS#8, SPKI, PKCS#1, and JWE key import paths enforce the same ceiling.

JWS and JWE verification/decryption perform structural, count, encoded-size, algorithm,
plaintext and public AAD checks before result allocation, encrypted-body decoding, key
construction, derivation, or verification. General JWE bounds selected string fields
before cloning its flattened recipient view.

Add `decrypt_flattened_with_password_options` and
`decrypt_general_with_password_options`. Their PBES2-only family gate cannot be relaxed;
the supplied options can only narrow algorithm acceptance and set resource/AAD/critical
header policy.

## Security boundaries

- A sender may choose input shape, signature count, RSA encoding and PBES2 iteration
  count, but may not choose unbounded recipient work.
- Limits apply to directly constructed public structs as well as text parsed by this
  crate.
- Detached payload bytes remain caller-owned and are not subject to the encoded-token
  size ceiling; callers already possess them before verification begins.

## Consequences

- RSA moduli above 8192 bits and DER key containers above 64 KiB are now refused.
- JSON password recipients can use the same per-call PBES2 ceiling as compact JWE.
- Refusal ordering becomes deliberate: cheap public policy errors precede cryptographic
  or allocation-dependent failures.

