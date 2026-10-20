# Architecture Decision Records

Each ADR captures one significant decision: its context, the decision itself,
the security boundaries it establishes, and the consequences. ADRs are
immutable once accepted; supersede with a new record rather than editing
history.

| # | Title | Status |
|---|-------|--------|
| [0001](0001-jose-security-boundary-hardening.md) | JOSE security boundary hardening | Accepted |
| [0005](0005-operation-aware-jwk-signature-conversion.md) | Validate JWK signature keys against the requested operation | Accepted |
| [0006](0006-explicit-ed25519-wire-identifier.md) | Support the explicit Ed25519 wire identifier | Accepted |
| [0007](0007-configurable-jwk-thumbprint-hashes.md) | Allow explicit SHA-2 JWK thumbprint hashes | Accepted |
| [0008](0008-precise-jwt-numeric-dates.md) | Preserve fractional JWT timestamps | Accepted |
| [0009](0009-unambiguous-jwks-key-selection.md) | Reject ambiguous JWT key identifiers | Accepted |
| [0010](0010-jwe-plaintext-size-limit.md) | Configurable JWE plaintext-size limit | Accepted |
| [0011](0011-jwe-flattened-json-serialization.md) | Flattened JWE JSON Serialization requires a protected header | Accepted |
| [0012](0012-jwe-external-aad.md) | External additional authenticated data is authenticated, never confidential | Accepted |
| [0013](0013-jwe-unprotected-headers.md) | An unauthenticated `alg` is only ever read against a key that pins it | Accepted |
| [0014](0014-jwe-general-serialization.md) | A recipient is named by the caller, never chosen by the library | Accepted |
| [0015](0015-jwe-critical-extensions.md) | `crit` is refused by default and understood only by the caller | Accepted |
| [0016](0016-key-agreement-boundary.md) | The key-agreement boundary enforces operation, material and curve | Accepted, amended by 0019 |
| [0017](0017-direct-ecdh-key-agreement.md) | Direct key agreement agrees the CEK and publishes its own ephemeral key | Accepted, amended by 0018 |
| [0018](0018-ecdh-key-agreement-with-key-wrapping.md) | Agreement with key wrapping agrees a KEK, and waits for a place to put a second `epk` | Accepted |
| [0019](0019-x25519-agreement-keys.md) | X25519 is admitted to agreement only with a `d`-derives-`x` check | Accepted, amends 0016 |
| [0020](0020-aes-gcm-key-management.md) | AES-GCM key management generates its own `iv`/`tag` and puts them in the protected header | Accepted |
| [0021](0021-pbes2-password-based-key-management.md) | A password is its own input type, and the sender's work budget is bounded by what peers will compute | Accepted |
| [0022](0022-pem-label-dispatch.md) | PEM reads the label, and writes the form peers parse | Accepted |
| [0023](0023-pkcs1-rebuilt-not-trusted.md) | PKCS#1 is decoded, then rebuilt and checked against itself | Accepted |
| [0024](0024-sec1-states-its-curve.md) | A SEC1 file states its curve, or it is not a key | Accepted |
| [0025](0025-key-file-schemes-are-allow-listed.md) | A key file that arrives with a password arrives with a scheme | Accepted |
| [0026](0026-certificate-extraction-validates-nothing.md) | A certificate is a claim about a key, and extracting it validates nothing | Accepted |
| [0027](0027-thumbprint-uri-format-is-the-test.md) | A thumbprint URI is a format, so the RFC's example is the test | Accepted |
| [0028](0028-capability-tables-are-checked-by-doing.md) | A capability table nobody runs is a rumour | Accepted |
| [0029](0029-one-token-one-reading.md) | One token, one reading: duplicate claim members are refused | Accepted |
| [0030](0030-json-jws-uses-the-compact-key-rules.md) | The JSON serialization uses the compact path's key rules, literally | Accepted |
| [0031](0031-selection-refuses-it-does-not-guess.md) | Selection refuses; it does not guess, and it does not filter | Accepted |
| [0032](0032-authenticated-results-and-coarse-errors.md) | Authenticated results, and errors coarse enough not to lie | Accepted |
| [0033](0033-definition-of-done-is-a-command.md) | The definition of done is a command, and the rest is judgement | Accepted |
| [0034](0034-fuzz-logic-runs-in-ci.md) | Fuzz logic runs in CI; the fuzzer only searches | Accepted |
| [0035](0035-baselines-are-a-harness-plus-shapes.md) | Baselines are a harness plus shapes; committed numbers are not baselines | Accepted |
| [0036](0036-dependency-record-is-checked-not-trusted.md) | Two majors in one lock, documented, beat one major forced forward | Accepted |
| [0037](0037-kryptering-0-7-coordinated-trait-wave.md) | Kryptering 0.7 closes the split trait-family window | Accepted; supersedes 0036 |
| [0038](0038-bound-untrusted-work-before-cryptography.md) | Bound untrusted work before cryptography | Accepted |
| [0039](0039-jws-header-disjointness-uses-wire-members.md) | JWS header disjointness uses wire members | Accepted |
| [0040](0040-transient-secrets-have-zeroizing-owners.md) | Transient secrets have zeroizing owners | Accepted |
