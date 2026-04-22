# jose-rs fuzz targets

Coverage-guided fuzz harnesses for the attacker-controlled parse and
verify paths of `jose-rs`. Uses [`cargo-fuzz`](https://rust-fuzz.github.io/book/cargo-fuzz.html),
which in turn wraps libFuzzer.

## Targets

| Target                    | What it fuzzes                                         |
|---------------------------|--------------------------------------------------------|
| `base64url_decode`        | `jose_rs::base64url::decode`                           |
| `jwk_from_json`           | `Jwk::from_json` plus downstream conversion paths      |
| `jwk_thumbprint`          | RFC 7638 thumbprint computation over parsed JWKs       |
| `jws_decode_header`       | `jws::compact::decode_header` (attacker-controlled)    |
| `jws_verify`              | Full JWS compact verify pipeline (fixed HMAC verifier) |
| `jws_verify_mldsa`        | Full JWS compact verify via `verify_with_jwk` over an ML-DSA-44 AKP JWK (post-quantum AKP parse + sign/verify dispatch) |
| `jwe_decrypt`             | Full JWE compact decrypt pipeline (fixed dir CEK)      |
| `jwt_decode_unverified`   | JWT header + claims parse without crypto               |

## Prerequisites

Fuzzing requires a nightly Rust toolchain and `cargo-fuzz`:

```
rustup toolchain install nightly
cargo install --locked cargo-fuzz
```

## Running a target

From the **repository root**:

```
cargo +nightly fuzz run base64url_decode
```

Replace the target name with any from the table above. libFuzzer will
run until it finds a crash, hits the time limit (`-- -max_total_time=N`),
or is interrupted. Discovered inputs are saved under
`fuzz/corpus/<target>/` and any crash under `fuzz/artifacts/<target>/`.

Examples:

```
# 5-minute run
cargo +nightly fuzz run jwk_from_json -- -max_total_time=300

# Replay a crash artifact
cargo +nightly fuzz run jwk_from_json fuzz/artifacts/jwk_from_json/crash-<hash>
```

## Build-only

CI runs `cargo fuzz build --dev` on every PR (`.github/workflows/fuzz.yml`)
to catch compilation regressions without holding up merges with a long
fuzzing run. To replicate locally:

```
cd fuzz
cargo +nightly fuzz build --dev
```

## Corpus and seeds

No seed corpus is checked in yet. For meaningful coverage you can:

1. Generate a handful of valid JOSE tokens with the library's own tests
   or examples and drop them into `fuzz/corpus/<target>/`.
2. Import public test vectors (RFC 7515 Appendix A, RFC 7520) as seeds.

## Reporting findings

If a target produces a crash, the artifact under
`fuzz/artifacts/<target>/` is a deterministic reproducer. Open an issue
with the target name, the artifact bytes (base64-encoded), and the
Rust version — do not include any real private key material.
