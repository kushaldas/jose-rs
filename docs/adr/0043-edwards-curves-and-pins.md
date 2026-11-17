# ADR 0043 — Edwards pins identify a pure signature on one curve

- Date: 2026-11-17
- Status: Accepted; supersedes ADR 0006's Ed25519-only EdDSA and exact Edwards JWK-pin decisions.
- Release: 0.12.0

## Context

Migration consumers publish fully specified Edwards JWK pins while emitting legacy
EdDSA headers. Treating those names as different cryptographic operations prevents
verification of their own tokens. Standalone Ed448 is also required. The locked
kryptering 0.7.1 already implements pure Ed448, DER import/export and PKCS#11 dispatch;
the old capability notes incorrectly described a backend gap.

## Decision

Expose `JwsAlgorithm::Ed448`, `generate_ed448()` and `KeyGeneration::Ed448`.
Accept OKP Ed448 with 57-byte `x` and private seed `d`. Use existing generic
PKCS#8/SPKI encoders for RFC 8410 OID 1.3.101.113, with absent parameters.
All arithmetic and signature validation remain in the locked backend. Generation
uses 57 bytes of OS entropy in a zeroizing owner, then backend derivation.
No crate, feature, MSRV or crypto dependency version changes are needed.

Legacy EdDSA dispatches on the actual key's Ed25519 or Ed448 curve. The raw signer
and verifier boundary accepts EdDSA with either backend primitive. `to_crypto()`
without a key retains its historical Ed25519 mapping for source compatibility.
Only pure signatures with empty context are supported; never Ed448ph.

As requested for the migration, an OKP JWK's pin accepts EdDSA or its matching
fully specified curve name, in either direction. This replaces the old exact
Edwards pin policy. Non-Edwards pins remain exact. Application JWT algorithm
allowlists always compare the original wire name exactly.

## Security boundaries

- Curve and key type are mandatory, including for unpinned keys. Aliases never
  cross Ed25519/Ed448 or admit agreement curves to signing.
- `use`, `key_ops`, algorithm allowlists and critical-header checks still apply.
- Imported `d` must derive the separately supplied `x`. Raw field lengths are
  checked before decoding/allocation. Private DER and seed buffers zeroize.
- Original protected bytes form the signing input; aliases never rewrite them.
- X448 remains outside this change. Ed448 does not require post-quantum support.

## Consequences

Edwards pins now restrict the curve/signature primitive rather than the legacy
versus fully specified spelling. Applications depending on the previous spelling
restriction must use an exact JWT algorithm allowlist. This deliberate policy change,
and new exhaustive enum variants, ship in a minor pre-1.0 release.

Evidence: `tests/migration_features.rs`, the RFC 8032 §7.4 Blank signature vector,
RFC 7638 thumbprint input independently hashed with Python, and bidirectional
jwcrypto signatures for both curves and both wire spellings. Existing fuzz key
import targets gain Ed448 JSON/DER/PEM seeds. Accepted historical ADRs are unchanged.

References: [RFC 8037 §§2–3](https://www.rfc-editor.org/rfc/rfc8037.html),
[RFC 8032 §§5.2, 7.4](https://www.rfc-editor.org/rfc/rfc8032.html),
[RFC 8410 §§3–7](https://www.rfc-editor.org/rfc/rfc8410.html),
[RFC 9864 §2.2](https://www.rfc-editor.org/rfc/rfc9864.html#section-2.2).

RFC Editor errata were checked on 2026-11-17 using its `errata.json` feed.
RFC 8037's reported erratum 5329 concerns ECDH, outside this change. RFC 8410
verified errata 6738/6263 concern the RFC 5958 envelope and reference, and 7384
supplies the missing Ed448 ASN.1 identifiers; existing DER types and backend OIDs
provide those encodings. RFC 8032 verification editorial corrections do not
change the §7.4 Blank vector; strict verification stays in the vetted backend.
No RFC 9864 errata were listed.
