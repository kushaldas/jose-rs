# ADR 0001 - JOSE security boundary hardening

- **Status:** Accepted
- **Date:** 2026-06-24
- **Component:** `src/jws`, `src/jwe`, `src/jwk`, `src/jwt`
- **Related:** Codex Security scan
  `2f0507302c21cf6e3f065841f16dda8a3fa3fb8c_20260624T173237Z/report.md`

## Context

The library accepts attacker-controlled JOSE objects and key material at several
public API boundaries. A Codex Security scan found multiple cases where an
otherwise useful convenience path accepted ambiguous or unbounded input:

- General JWS verification checked each signature's `b64` setting only after
  verifier-specific `alg` filtering, so a mixed-`b64` object could be hidden
  behind a caller's verifier choice.
- General JWS verification allocated and parsed per-signature state without an
  aggregate signature-count cap.
- JWT `Validation::with_max_age` silently did nothing for tokens without `iat`.
- JWE JWK one-shot APIs read symmetric key material from `k` without requiring
  `kty: "oct"`.
- DER RSA imports accepted sub-2048-bit RSA keys even though generated and JWK
  RSA keys already enforce the crate-wide minimum.

The scan also reported the RSA Marvin timing advisory in the upstream `rsa`
dependency. That remains an upstream dependency risk rather than an in-repo
logic bug we can fix locally without replacing the cryptographic backend.

## Decision

Harden the affected public boundaries and prefer fail-closed validation:

- General JWS now validates each protected header's JOSE-level `b64` policy
  before verifier-specific algorithm matching. All valid protected headers in
  one General JWS must agree on the effective `b64` value.
- General JWS signing and verification reject more than 64 signature entries.
  This cap prevents unbounded result allocation, header parsing, and verifier
  attempts on attacker-supplied input while staying above normal JOSE
  multi-signature use.
- `Validation::with_max_age` requires `iat`; `Validation::require_iat` is
  available for callers that need the presence requirement without an age cap.
- JWE one-shot JWK APIs require `kty: "oct"` for `dir` and AES Key Wrap
  algorithms before reading the symmetric `k` field.
- PKCS#8 and SPKI DER RSA imports enforce `MIN_RSA_BITS` just like JWK import,
  RSA generation, and JWE RSA DER parsing.
- The RSA Marvin advisory remains tracked in the audit configuration until the
  upstream dependency provides a fix suitable for this crate.

## Security boundaries

| Threat | Control | Residual risk |
|--------|---------|---------------|
| Mixed General JWS payload encoding hidden behind verifier `alg` filtering | Shared `b64` validation runs before verifier-specific matching | Invalid or unsupported protected headers are still skipped per existing per-signature error semantics |
| CPU or memory exhaustion by enormous General JWS signature arrays | `MAX_GENERAL_SIGNATURES = 64` on signing and verification | Legitimate objects needing more than 64 signatures require a future explicit API decision |
| JWT replay window accidentally unbounded by missing `iat` | `with_max_age` requires `iat` and errors when absent | Issuers must still set a trustworthy `iat`; clock skew is governed by `leeway` |
| Non-symmetric JWK accepted for symmetric JWE key management due to stray `k` | `dir`/`A*KW` require `kty: "oct"` before using `k` | JWK `use`, `key_ops`, and `alg` must still be pinned by callers or the one-shot APIs |
| Weak RSA keys imported from DER | PKCS#8/SPKI imports reject RSA modulus sizes below `MIN_RSA_BITS` | Existing persisted weak keys must be rotated; import will now fail |
| RSA Marvin side channel in upstream dependency | Keep advisory open and tracked pending upstream fix | Side-channel exposure remains wherever affected upstream RSA operations are used |

## Consequences

**Positive**

- The JOSE parsing boundary is stricter and more consistent across compact,
  JSON, JWK, JWT, and DER convenience paths.
- Previously silent security-policy bypasses now return explicit errors.
- Resource usage for General JWS is bounded before per-signature work.

**Negative / accepted trade-offs**

- Some malformed or unsafe objects that previously verified or imported now
  fail fast.
- `with_max_age` is intentionally stricter: callers relying on missing-`iat`
  tokens passing validation must either issue `iat` or remove the max-age policy.
- RSA Marvin is not closed by this decision; it stays visible as an upstream
  dependency risk.

## References

- `src/jws/compact.rs` - protected-header validation helpers.
- `src/jws/json.rs` - General JWS signing and verification caps and `b64`
  agreement checks.
- `src/jwt/validation.rs` - `iat` presence and max-age validation.
- `src/jwe/compact.rs` - JWE JWK one-shot key extraction.
- `src/jwk/import.rs` - PKCS#8/SPKI DER key import.
