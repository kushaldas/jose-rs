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
| `jwk_from_pem`            | PEM label dispatch and explicit PEM key importers      |
| `jwk_from_der`            | Bounded PKCS#8, SPKI, PKCS#1 and SEC1 DER import       |
| `certificate_extract`     | Bounded X.509 public-key extraction                    |
| `encrypted_pkcs8`         | Password-encrypted PKCS#8 parsing under a KDF budget   |
| `jwkset_select`           | Bounded JWK Set parsing, diagnostics and selection     |
| `jwe_json_flattened`      | Flattened JSON JWE parsing and decryption paths         |
| `jwe_json_general`        | General JSON JWE parsing and recipient handling        |
| `jwt_claims`              | Claims parsing, duplicate rejection and serialization  |

## Prerequisites

Fuzzing requires a nightly Rust toolchain and `cargo-fuzz`:

```
just fuzz-setup
```

Detached all-target campaigns additionally require `tmux` from the system
package manager.

## Running a target

The Justfile exposes the same workflow for local and remote runs:

```sh
just fuzz-build                         # compile all 17 targets once
just fuzz-one base64url_decode 300      # one target, foreground, five minutes
just fuzz 3600                          # all targets in tmux for one hour
just fuzz-attach                        # inspect the detached campaign
just fuzz-crashes                       # list saved artifacts
just fuzz-stop                          # stop the detached campaign
```

`just fuzz` creates one tmux window per target, builds once before launching,
and divides logical CPUs evenly across targets. A duration of zero runs until
stopped. `just fuzz-one` uses every logical CPU by default through libFuzzer
fork mode. Override worker count or the default 128-KiB input ceiling when a
focused campaign needs it:

```sh
JOBS=4 MAX_LEN=1048577 just fuzz-one jwt_claims 600
```

Each run copies checked-in seeds into the target's working corpus without
overwriting earlier discoveries. Discovered inputs live under
`fuzz/corpus/<target>/`; crashes, timeouts and out-of-memory inputs live under
`fuzz/artifacts/<target>/`.

For direct cargo-fuzz use, run from the repository root:

```sh
cargo +nightly fuzz run jwk_from_json -- -max_total_time=300
```

## Artifacts, coverage and corpus maintenance

```sh
just fuzz-repro jwk_from_json fuzz/artifacts/jwk_from_json/crash-<hash>
just fuzz-coverage jwk_from_json
just fuzz-cmin jwk_from_json
```

Coverage requires `llvm-tools-preview`, installed by `just fuzz-setup`, and
writes HTML to `fuzz/coverage/<target>/html/index.html`. Corpus minimization
keeps only inputs that add coverage; it does not modify the checked-in seeds.

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
