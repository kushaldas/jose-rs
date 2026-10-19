# Dependencies, MSRV, and platform checks

This is the checked dependency record requested by roadmap item Q2. The raw facts are
regenerated with:

```sh
./scripts/dependency-report.sh
./scripts/dependency-report.sh --duplicates
```

`tests/dependency_policy.rs` checks the version, feature, advisory, and platform claims
below against `Cargo.toml`, `Cargo.lock`, and `.cargo/audit.toml`.

## Toolchain and MSRV

- **Declared MSRV:** `1.88` (`rust-version` in `Cargo.toml`). Raising it is a breaking change
  and requires release notes.
- The package uses Cargo resolver 3. This is security- and compatibility-relevant:
  `aes` 0.9.3 requires Rust 1.89, so a Rust 1.88 resolution selects `aes` 0.9.2 instead
  of silently raising the crate's compiler floor.
- `cargo +1.88.0 check --locked --all-features --all-targets` is the direct MSRV check.
  Normal CI and the local gate use the current stable toolchain with `--locked`.

## The backend is the dependency

| Crate | Locked | Requested as | Role |
|---|---:|---|---|
| `kryptering` | 0.7.0 | `0.7`, `default-features = false`, `features = ["rustcrypto"]` | primitives, opaque keys, PKCS#11 integration, and provider policy |

Kryptering 0.7 moved its RustCrypto provider to one coordinated trait family and added
Ed448, X448, secp256k1, and Brainpool primitives. A backend capability is not automatic
JOSE authorization: jose-rs continues to refuse those algorithms because it has not yet
accepted their wire format, JWK conversion, policy, interop, and negative-test work.

| Plan item | Backend state | jose-rs state |
|---|---|---|
| A0 standalone Ed448 | available in Kryptering 0.7 | recognized but not integrated |
| A1 ES256K / secp256k1 | available in Kryptering 0.7 | recognized and refused by name |
| A2 Brainpool curves | available in Kryptering 0.7 | no accepted JOSE integration |
| X448 agreement | available in Kryptering 0.7 | no accepted JWK/JWE integration |

No local primitive is added to bypass that boundary.

## Feature → dependency mapping

| Feature | Enables | Pulls in |
|---|---|---|
| `default` | `pkcs11` | `kryptering/pkcs11` |
| `post-quantum` | PQ signatures | `kryptering/post-quantum`, optional `ml-dsa` 0.1.1, and transitive `slh-dsa`, `ml-kem`, `sha3` |
| `deprecated` | legacy JOSE algorithms | `kryptering/legacy` |
| `pkcs11` | HSM-backed keys | `kryptering/pkcs11` |

## Direct dependencies and their locked versions

| Crate | Locked | Why it is here |
|---|---:|---|
| `serde`, `serde_json` | 1.0.229 / 1.0.154 | JOSE JSON; raw values preserve duplicate-member evidence and numeric precision |
| `base64` | 0.22.1 | strict unpadded base64url |
| `thiserror` | 2.0.21 | `JoseError` |
| `aes-gcm` | 0.11.1 | AES-GCM content encryption and GCM key wrapping |
| `aes`, `cbc` | 0.9.2 / 0.2.1 | AES-CBC-HMAC content modes |
| `hmac`, `sha2`, `digest` | 0.13.0 / 0.11.1 / 0.11.3 | HMAC content modes, PBES2, and Concat KDF |
| `getrandom` | 0.4.3 | OS entropy and the RustCrypto 0.10 RNG traits |
| `rsa` | 0.10.0-rc.19 | RSA key validation/encoding; the exact pin matches Kryptering 0.7 |
| `pkcs8` | 0.11.0 | PKCS#8 import/export and the encrypted-key allow-list |
| `p256`, `p384`, `p521` | 0.14.0 / 0.14.0 / 0.14.0 | NIST curves with ECDSA and PKCS#8 |
| `ed25519-dalek` | 3.0.0 | Ed25519 encoding and key consistency |
| `ecdsa` | 0.17.0 | shared ECDSA encoding |
| `subtle` | 2.6.1 | constant-time comparison where jose-rs compares values itself |
| `zeroize` | 1.9.1 | secret owners and intermediate buffers |
| `pem-rfc7468` | 1.0.0 | strict RFC 7468 armor |
| `sec1` | 0.8.1 | SEC1 EC private-key parsing |
| `ml-dsa` | 0.1.1 | optional, `post-quantum` only |

`dev-dependencies` is empty. Tests and benchmarks use the normal dependency graph; the
fuzzer remains its own package.

## Duplicated trait-version families

Kryptering 0.7 satisfies the prerequisite ADR 0036 recorded. The direct and backend
paths now share `digest` 0.11, `signature` 3, `elliptic-curve` 0.14, `ecdsa` 0.17,
`pkcs8` 0.11, `rsa` 0.10.0-rc.19, `hmac` 0.13, `sha2` 0.11, `aes-gcm` 0.11,
`aes` 0.9, `cbc` 0.2, and `rand_core` 0.10. The old 0.10/0.11 and 0.13/0.14 splits are
gone from the lock. `cargo tree -d` currently reports only `syn` 2 and 3, used by
independent procedural macros; no cryptographic trait family is duplicated.

`rand` 0.8 and `num-bigint-dig` are absent. Random bytes come from `getrandom`; RSA
integers use the `crypto-bigint` types re-exported by the pinned `rsa` release.

## Security-relevant feature refusals

- `pkcs8` is built with `encryption`, but not `sha1-insecure`, `des-insecure`, or `3des`.
  PBES2/PBKDF2/HMAC-SHA2/AES-CBC is reachable; the legacy schemes are not.
- `base64` is used only through the URL-safe, unpadded engine.
- `deprecated` is opt-in and gates RSA1_5 and RSA-OAEP-SHA1.
- New Kryptering 0.7 curve/algorithm variants stay behind jose-rs conversion refusals;
  a backend addition does not widen a caller's allow-list.

## Advisory posture

`.cargo/audit.toml` carries exactly one tracked ignore:

| Advisory | Why it remains tracked | Mitigation here |
|---|---|---|
| RUSTSEC-2023-0071 (`rsa`, Marvin) | the upstream advisory remains open for every `rsa` release | Kryptering 0.7 blinds RSA private operations using OS entropy; jose-rs collapses RSA-OAEP failure classes, enforces key-size policy, and keeps SHA-1 OAEP opt-in |

Kryptering 0.7 also removes `rand` 0.8 and `num-bigint-dig`, closing the dependency
path implicated by RUSTSEC-2026-0097. Every unignored advisory or warning fails
`cargo audit --deny warnings`.

## Platform and provider notes

- `#![forbid(unsafe_code)]`; no unsafe block under `src/`.
- No async runtime, network I/O, filesystem I/O, or process execution in the library.
- The backend owns PKCS#11 library and session lifetimes. jose-rs does not initialize or
  finalize a vendor module and does not export HSM-backed private material.
- `/proc` is read only by the Linux performance test. OpenSSL, Python, and Node are
  fixture/interop tooling, not runtime dependencies.
- Authentication and integrity failures remain coarse at the public boundary; dependency
  errors are not exposed as a protocol oracle.
