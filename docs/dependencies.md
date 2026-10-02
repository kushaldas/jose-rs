# Dependencies, MSRV, and platform checks

This is the record Q2 asks for: what this crate depends on, which locked version,
why, what is deliberately *not* upgraded, and where a reviewer should look before
touching any of it. `tests/dependency_policy.rs` fails when the facts below stop
matching `Cargo.toml` / `Cargo.lock` / `.cargo/audit.toml`, so this page cannot drift
into folklore. Regenerate the raw facts with:

```sh
./scripts/dependency-report.sh            # facts, in pasteable markdown
./scripts/dependency-report.sh --check    # fail if this page disagrees
```

## Toolchain and MSRV

- **Declared MSRV:** `1.88` (`rust-version` in `Cargo.toml`).
- The MSRV is a floor, not a target: nothing here uses a feature newer than the floor,
  so a build on 1.88 is expected to work and a build on current stable is tested.
- **Raising it is a breaking change** and needs release notes naming the new floor and
  the dependency or language feature that forced it. Silently drifting the floor via a
  dependency update is how a library becomes unbuildable for downstream users with no
  changelog entry to explain it.
- Builds here are `--offline` (`--locked` in CI): a dependency change is always an
  explicit, reviewable change of its own. `AGENTS.md` §2 states this as a hard rule.

## The backend is the dependency

| Crate | Locked | Requested as | Role |
|---|---|---|---|
| `kryptering` | 0.6.0 | `0.6`, `default-features = false`, `features = ["rustcrypto"]` | every primitive: signing, verification, AEAD, key generation, PKCS#11 |

Everything protocol-level in this crate is written against `kryptering`'s key and
algorithm types, which is why backend capabilities are the ceiling on feature work:

| Plan item | Blocked on | What is missing |
|---|---|---|
| A0 standalone Ed448 | `kryptering` 0.6.0 | no Ed448 key type or signature algorithm (Ed448 exists only *inside* the composite `ML-DSA-87-Ed448`) |
| A1 ES256K / secp256k1 | `kryptering` 0.6.0 | no secp256k1 curve; `ES256K` is recognised and refused by name |
| A2 Brainpool curves | `kryptering` 0.6.0 | no Brainpool curves; refused by name at import |
| A3 post-quantum maintenance | `kryptering` 0.6.0 | PQ algorithms are the backend's to add and version |

These appear in `docs/capabilities.md` as `RecognizedNotSupported` and are tested as
refusals — a name the crate recognises must produce a refusal that names what is
missing, never a fallback.

**Do not "fix" an unsupported algorithm by adding a local implementation.** The
boundary is deliberate: primitives come from the backend so the HSM and software paths
stay one API (`docs/adr/0016-key-agreement-boundary.md`).

## Feature → dependency mapping

| Feature | Enables | Pulls in |
|---|---|---|
| `default` | `pkcs11` | `kryptering/pkcs11` |
| `post-quantum` | PQ signatures | `kryptering/post-quantum`, `ml-dsa` 0.1.1, `pkcs8-pq` (= `pkcs8` **0.11.0**, renamed — see below), and transitively `slh-dsa`, `ml-kem`, `sha3` |
| `deprecated` | legacy algorithms | `kryptering/legacy` |
| `pkcs11` | HSM-backed keys | `kryptering/pkcs11` |

`docs/capabilities.md` is generated from the code and reports what *this* build can do;
this table records why each feature costs what it costs.

## Direct dependencies and their locked versions

Two columns of versions where a crate appears twice in the lock: the version this crate
requires, and any other major resolved for the same name (see "Duplicated families").

| Crate | Locked | Why it is here |
|---|---|---|
| `serde`, `serde_json` | 1.0.229 / 1.0.151 | JOSE JSON; `raw_value` for the duplicate-member and raw-number work (ADR 0029) |
| `base64` | 0.22.1 | unpadded base64url only; padding is refused (RFC 7515 §2) |
| `thiserror` | 2.0.21 | `JoseError` |
| `aes-gcm` | 0.10.3 (+0.11.1) | AES-GCM content encryption and GCM key wrapping |
| `aes`, `cbc` | 0.8.4 (+0.9.2) / 0.1.2 (+0.2.1) | AES-CBC+HMAC content mode |
| `hmac`, `sha2`, `digest` | 0.12.1 / 0.10.9 / 0.10.7 (+0.13.0 / +0.11.0 / +0.11.3) | HMAC-based content modes, PBES2, Concat KDF |
| `rand` | 0.8.8 | IV/nonce and key generation |
| `rsa` | 0.9.10 | RSA key handling and OAEP |
| `pkcs8` | 0.10.2 (+0.11.0) | PKCS#8 import/export; the `encryption` feature *is* the password-encrypted scheme allow-list (ADR 0025) |
| `p256`, `p384`, `p521` | 0.13.2 / 0.13.1 / 0.13.3 | NIST curves, `ecdsa` + `pkcs8` |
| `ed25519-dalek` | 2.2.0 | Ed25519 |
| `ecdsa` | 0.16.9 | ECDSA signature encoding shared with the curve crates |
| `num-bigint-dig` | 0.8.6 | RSA parameter arithmetic, including the PKCS#1 rebuild checks (ADR 0023) |
| `subtle` | 2.6.1 | constant-time comparison where the crate compares secrets itself |
| `zeroize` | 1.9.0 | CEKs, shared secrets, passwords, derived agreement keys |
| `pem-rfc7468` | 0.7.0 | RFC 7468 armour; already resolved in the lock as a `der`/`pkcs8` dependency, so this is an explicit edge, not a new package (ADR 0022) |
| `sec1` | 0.7.3 (+0.8.1) | SEC1 `ECPrivateKey` structure (ADR 0024); likewise an existing package named explicitly |
| `ml-dsa` | 0.1.1 | optional, `post-quantum` only |
| `pkcs8-pq` | 0.11.0 | optional, `post-quantum` only — the *same crate name* at a different major, renamed because two majors cannot coexist under one name |

`dev-dependencies` is empty. That is a deliberate constraint: no test, bench or doc-test
dependency, which is why the performance work (ADR 0035) uses `Instant` and a median
instead of a benchmarking harness, and why fuzzing uses `cargo-fuzz` in its own package
(`fuzz/Cargo.toml`) rather than a workspace dependency.

## Duplicated trait-version families, and why they are not upgraded in place

The lock resolves **two majors** for several RustCrypto families:

| Family | Majors in the lock | Arrives via |
|---|---|---|
| `digest` | 0.10.7, 0.11.3 | our direct deps (0.10) / `kryptering`'s `ed448-goldilocks`, `slh-dsa`, `sha3` path (0.11) |
| `signature` | 2.2.0, 3.0.0 | `ecdsa` 0.16 / `kryptering`'s newer path |
| `elliptic-curve` | 0.13.8, 0.14.1 | `p256`/`p384`/`p521` 0.13 / newer-curve-side path |
| `der`, `spki`, `sec1`, `pkcs8` | 0.7.x/0.8.x, 0.10.2/0.11.0 | our `pkcs8` 0.10 (allow-list work) / `ml-dsa`, `pkcs8-pq` |
| `hmac`, `sha2`, `aes-gcm`, `aead`, `aes`, `cbc` | old + new | our direct requirements / backend-side consumers |
| `rand_core` | 0.6.4, 0.10.1 | `rand` 0.8 / newer ecosystem |

This is not sloppiness that can be tidied crate-by-crate, and pretending otherwise is
the failure mode Q2 names ("document blockers rather than forcing isolated major
upgrades"):

* Trait types across majors are **different types**. `jose-rs` passes
  `digest`/`signature`/`elliptic-curve` values to and from `kryptering`, so an isolated
  jump of our direct dependencies to the new families would not compile against the
  backend we are required to use — and where it did compile, it would still be two
  families, just inverted.
* The newer majors arrive **transitively through the backend even in the default build**
  (measured: `kryptering` → `ed448-goldilocks` → `hash2curve` → `digest` 0.11 with no
  feature enabled), so the duplication is not caused by our feature flags and cannot be
  removed by turning features off.
* `pkcs8` is the special case: `post-quantum` needs `pkcs8` 0.11 while the password-
  encrypted key-file allow-list (ADR 0025) is built on `pkcs8` 0.10's `encryption`
  feature set. Both are kept, under two names, and the duplication is stated rather than
  hidden.

### What a coordinated upgrade would require

1. A `kryptering` release that moves its non-PQ path onto the new families, with the
   trait types in its public API updated to match.
2. Our direct dependencies (`ecdsa`, `rsa`, `p256`/`p384`/`p521`, `pbkdf2`,
   `hmac`/`sha2`/`digest`, `aes-gcm`/`aead`) moving to versions whose traits match #1, in
   one change, with the allow-list work (`pkcs8` `encryption`) re-checked against the
   new scheme feature names.
3. A re-run of the interop suites for every content mode and key format, because these
   are the crates that implement the primitives.

Until #1 exists, the correct action is what this page does: record the split, keep the
families coherent *within* each consumer, and refuse isolated upgrades.

## Security-relevant feature refusals

These are compile-time facts, not runtime checks, and they are the reason certain
algorithms cannot be reached by a crafted file:

- `pkcs8` is required with **only** `encryption`. PBKDF2 with HMAC-SHA2 and AES-CBC is
  what the default feature set provides; the SHA-1 PRF, DES and 3DES paths live behind
  separately named `-insecure` / `3des` features that are **not enabled**, so PBES1-class
  and SHA-1 schemes are unreachable rather than merely declined (ADR 0025).
- `base64` is used with the URL-safe, unpadded engine only; padded input is refused.
- `deprecated` is opt-in and gates RSA1_5 and RSA-OAEP-SHA1 (`kryptering/legacy`); the
  default build cannot select them.
- `p256`/`p384`/`p521` are required with `ecdsa` + `pkcs8` only — no `expose-field` or
  similar internals.

## Advisory posture

`.cargo/audit.toml` carries exactly one ignore:

| Advisory | Why it is ignored | Mitigation here |
|---|---|---|
| RUSTSEC-2023-0071 (`rsa`, "Marvin" timing) | no patched release as of the date recorded in the file; upstream issue open | RSA-OAEP-SHA1 gated behind `deprecated`; RSA keys under 2048-bit rejected at parse and generation; `crypto-aes`-style network-observable path is RSA-OAEP decryption, documented as such |

Everything else fails `cargo audit --deny warnings`, locally and in CI
(`.github/workflows/audit.yml`). An ignore is only acceptable with a justification and
a removal condition — both live as comments in that file, and the test here checks that
every ignore in it is also named above.

## Platform and provider notes

- `#![forbid(unsafe_code)]` at the crate root; no `unsafe` block anywhere in `src/`.
- No async runtime, no network I/O, no global mutable registry, no process state: the
  crate parses and protects bytes and does nothing else. Fetching a JWKS, caching keys
  and issuer trust are caller concerns (ADR 0031).
- **PKCS#11** (`pkcs11`, default): the backend owns the library handle and session
  lifetime. This crate does not call `C_Initialize`, does not fork, and never converts an
  HSM-backed key into software key material (`docs/adr/0016-key-agreement-boundary.md`).
  Provisioning and application lifecycle stay outside JOSE.
- `/proc` is read in exactly one place — `tests/perf_baselines.rs`, to sample RSS — and
  that test states it is Linux-only and passes elsewhere rather than substituting a
  weaker claim. It assumes 4 KiB pages; larger pages only loosen its bound.
- OpenSSL and Python/Node are **test and fixture tooling only** (`interop/`,
  `tests/fixtures/*/README.md`). Nothing at runtime shells out or links OpenSSL.
- Timing: signature verification and MAC comparison are the backend's and this crate's
  constant-time `subtle` comparisons; the crate refuses to expose whether an integrity
  check failed versus input was rejected before it, precisely to avoid becoming a probe
  (ADR 0032).
