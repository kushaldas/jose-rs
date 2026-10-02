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
| `jws_verify_composite`    | Full compact-JWS verify and aggregate-signature splitting for ML-DSA-44-Ed25519 |
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

CI runs `cargo fuzz build --dev` (`workflow_dispatch`; `.github/workflows/fuzz.yml`)
to catch compilation regressions without holding up merges with a long
fuzzing run. To replicate locally:

```
cd fuzz
cargo +nightly fuzz build --dev
```

## Corpus and seeds

`fuzz/seeds/<target>/` holds a checked-in, generated seed corpus — see
`fuzz/seeds/README.md` for why it is committed and how it is regenerated
(`cargo run --example fuzz_seeds`, or `-- --check` to verify it is current).

Point libFuzzer at it directly:

```sh
cargo +nightly fuzz run certificate_extract fuzz/seeds/certificate_extract
```

libFuzzer writes its *own* discoveries to `fuzz/corpus/<target>/` (gitignored) and
crash artifacts to `fuzz/artifacts/<target>/` (also gitignored). A crash worth
keeping belongs in `fuzz/seeds/<target>/` instead, so it is replayed by the CI test
described next.

## Replay without nightly: `tests/fuzz_regressions.rs`

Each harness's input sequence is mirrored in `tests/fuzz_regressions.rs` as an
ordinary function and driven over every seed plus deterministic mutations (every
truncation, every single-byte flip on inputs short enough to enumerate). That is
not fuzzing — no search, no coverage feedback — but it *runs* on stable in CI,
which is what the build-only fuzz job cannot do. A test additionally requires that
every `jose_rs::…` entry point a harness calls also appears in the mirror, so the
two copies cannot drift apart silently.

## Adding a harness

Add the target file, a `[[bin]]` entry in `fuzz/Cargo.toml`, a row in the table
above, seeds under `fuzz/seeds/<target>/` (via `examples/fuzz_seeds.rs`), and a
mirrored `replay_*` function plus `drive("<target>", replay_*)` test in
`tests/fuzz_regressions.rs`. An entry point the harness reaches but the mirror does
not must either be mirrored or listed in `HARNESS_ONLY_ENTRY_POINTS` with a reason.

## Reporting findings

If a target produces a crash, the artifact under
`fuzz/artifacts/<target>/` is a deterministic reproducer. Open an issue
with the target name, the artifact bytes (base64-encoded), and the
Rust version — do not include any real private key material.
