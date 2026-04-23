# Interop tests: jose-rs ↔ panva/jose

Round-trips JWS compact / JWT between this crate and the npm `jose` package
([panva/jose](https://github.com/panva/jose)), with emphasis on **ML-DSA**
(FIPS 204, `draft-ietf-cose-dilithium`).

The CI job (`.github/workflows/interop.yml`) is **non-blocking** —
`continue-on-error: true` at the job level. A red check is a signal to look,
not a merge gate. ML-DSA in panva/jose is still flagged experimental by Node,
so we expect occasional churn.

## Requirements

- **Node >= 24.7.0** with OpenSSL >= 3.5.0 (panva/jose's ML-DSA path uses
  `node:crypto`'s ML-DSA KeyObject, which requires OpenSSL 3.5+).
  Check locally: `just interop-node-version`.
- **Rust stable** and a working `cargo`.
- `jq` and a POSIX shell (CI's `ubuntu-latest` has both).

## Layout

```
interop/
├── rust-harness/        # standalone cargo pkg; binary speaks JSON on stdio
├── js-harness/          # ESM script; same subcommand surface
├── tests/matrix.sh      # drives every cell, writes interop-results.json
├── run-interop.sh       # entrypoint used by CI and `just interop`
└── vectors/             # runtime artifacts (gitignored); one JSON file per cell
```

The Rust harness is **not** a member of the main crate — it's a sibling cargo
package with a path dep, so `cargo publish` on `jose-rs` is untouched and no
new `[[bin]]` target lands on the library.

## Running locally

```
just interop-build            # build Rust harness (release) + npm ci
just interop                  # full matrix; exits 0, results in JSON
```

Full matrix is **32 cells**: 3 ML-DSA variants × 2 formats (compact JWS / JWT)
× 4 directions, plus a tiny Ed25519 / ES256 compact-JWS baseline (catches
generic wire-format regressions that might otherwise look like an ML-DSA bug).

The four directions:

1. `rust-sign-js-verify` — Rust keygen + sign; JS verify
2. `js-sign-rust-verify` — JS keygen + sign; Rust verify
3. `rust-keygen-js-roundtrip` — Rust keygen; JS self-roundtrip with it (JWK-shape canary)
4. `js-keygen-rust-roundtrip` — JS keygen; Rust self-roundtrip with it

### Running a single cell

```
just interop-cell rust-sign-js-verify ML-DSA-65 compact
```

Exit status reflects that one cell. Great for reproducing a failing CI cell
— the `cell` field in `interop-results.json` is a direct copy-paste.

### Inspecting results

```
jq '.[] | select(.result=="fail")' interop/interop-results.json
```

Each cell's intermediate JWK / signed token is preserved under
`interop/vectors/<cell>.{priv,pub,signed}.json`, so you can re-feed them into
either harness by hand.

## Harness contract

Both harnesses expose the **same six subcommands**, reading JSON on stdin and
writing JSON on stdout. Errors go to stderr and the process exits non-zero.

| Subcommand                       | stdin                          | stdout                          |
| -------------------------------- | ------------------------------ | ------------------------------- |
| `gen-key --alg <ALG>`            | —                              | private JWK                     |
| `export-pub`                     | private JWK                    | public JWK (private fields dropped) |
| `sign-compact --alg <ALG>`       | `{jwk, payload_b64u}`          | `{jws}`                         |
| `verify-compact --alg <ALG>`     | `{jwk, jws}`                   | `{ok, payload_b64u}`            |
| `sign-jwt --alg <ALG>`           | `{jwk, claims}`                | `{jwt}`                         |
| `verify-jwt --alg <ALG>`         | `{jwk, jwt}`                   | `{ok, claims}`                  |

Algorithm identifiers are the **exact JOSE strings**: `ML-DSA-44`, `ML-DSA-65`,
`ML-DSA-87`, `EdDSA`, `ES256`.

## Wire-format summary (what we're really testing)

Per `draft-ietf-cose-dilithium-11`, ML-DSA keys live under `kty="AKP"`
("Algorithm Key Pair") with:

- `alg`: `ML-DSA-44` / `ML-DSA-65` / `ML-DSA-87`
- `pub`: raw FIPS 204 public key, base64url (1312 / 1952 / 2592 bytes)
- `priv`: 32-byte FIPS 204 seed, base64url **— not the expanded secret key**

The seed-vs-expanded-sk split is historically where JOSE/COSE ML-DSA
implementations have disagreed. The `js-keygen-rust-roundtrip` direction is
the explicit canary for that regression.

## Why this is a separate workflow

`ci.yml` is the gate. Its failures block merges. This workflow tracks a
third-party (panva/jose) and a Node runtime flagged "experimental" for ML-DSA
— both of which can drift independently. Keeping them in a separate
`continue-on-error` job means:

- Core Rust CI stays green even if panva ships a breaking change.
- Interop regressions are still visible (red check + step summary + artifact).
- Bisecting is straightforward: the failing cell name pinpoints the direction
  and algorithm.

## Adding coverage

- **JWS JSON serialization** (flattened / general) — deferred. Both libraries
  support it. A `sign-json` / `verify-json` pair of subcommands would fit the
  existing pattern.
- **More classical algs** — drop the name into `ALGS_CLASSICAL` in `matrix.sh`
  and handle it in the Rust harness's `gen-key` (JS side uses the name directly).
- **JWE** — out of scope for the first pass; ML-DSA is a signature scheme.
