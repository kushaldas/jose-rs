# Interop tests: jose-rs ↔ panva/jose

Round-trips JWS compact / JWT / JWE compact / **JWE flattened JSON** between this
crate and the npm `jose` package ([panva/jose](https://github.com/panva/jose))
and Python's jwcrypto 1.6.1, with emphasis on **ML-DSA** (FIPS 204,
`draft-ietf-cose-dilithium`), plus custom-protected-header and
duplicate-header-member cells.

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

For focused Ed25519 and legacy EdDSA compatibility with jwcrypto 1.6.1,
use a Python environment with that package installed:

```sh
cargo build --locked --manifest-path interop/rust-harness/Cargo.toml

uv venv interop/.venv \
  && uv pip install --python interop/.venv/bin/python 'jwcrypto==1.6.1'

interop/.venv/bin/python interop/tests/ed25519_jwcrypto.py interop/rust-harness/target/debug/jose-interop
interop/.venv/bin/python interop/tests/numeric_dates_jwcrypto.py interop/rust-harness/target/debug/jose-interop
interop/.venv/bin/python interop/tests/jwe_json_jwcrypto.py interop/rust-harness/target/debug/jose-interop
interop/.venv/bin/python interop/tests/ecdh_kdf_vectors.py
```

The last check needs `cryptography` (already a `jwcrypto` dependency) and takes
no arguments.

These checks generate disposable keys in memory and verify messages in both
directions; they are separate from the Node matrix below. The Ed25519 check
covers RFC 8037 §1.1 key shapes and RFC 7515 §4.1.9 legacy `EdDSA` labels; the
NumericDate check covers signed JWTs with fractional dates in both directions
(Rust integration tests cover nanosecond boundary decisions).

The `jwe_json_jwcrypto.py` check covers the flattened JSON JWE (RFC 7516
§7.2.2) over nine `alg`/`enc` combinations in both directions, asserting the
emitted member shape on each side, **and** repeats every combination with
external additional authenticated data — including that jose-rs refuses a
message whose `aad` member it cannot match against the caller's bytes. It also
pins the unprotected-header boundary from ADR 0013: the RFC §A.5 shape (enc
protected, `alg` unprotected) decrypts against a pinned key, a tampered
unprotected `alg` is refused by the pin, and jwcrypto's default output (no
protected member at all, `enc` unprotected) is refused because an
unauthenticated `enc` is a substitution attack rather than a trust question.
It also runs the **general** serialization with two recipients in both
directions, and asserts that a recipient element carrying `enc` is refused. It also **pins the documented divergence**
from ADR 0011: jwcrypto's default flattened output puts `alg`/`enc` in the
per-recipient *unprotected* `header` member (the shape RFC 7516 §A.5 uses),
which jose-rs refuses by name rather than reading an unauthenticated `alg`. That
refusal is asserted, so the day the library starts accepting it the test has to
change deliberately.

### Key agreement and the Concat KDF (`ecdh_kdf_vectors.py`)

ECDH is where an implementation can be silently wrong: a missing `0x04` point
prefix, a coordinate padded on the wrong side, or an `OtherInfo` field without
its length prefix all yield a shared secret that looks fine and decrypts
nothing. Since `ECDH-ES` is not wired into JWE yet, there is no whole-message
cell to compare, so this check compares the two primitives directly — 19
assertions through the harness's `agree` and `derive-key` commands:

* **RFC 7518 Appendix C**, which publishes both private keys, the shared secret
  `Z`, every KDF parameter and the derived key: the harness's `Z` and derived key
  are compared against the RFC's printed values, and again against **OpenSSL's**
  ECDH and a Python transcription of RFC 7518 §4.6.2 written from the spec text;
* per-curve (P-256/P-384/P-521) random key pairs: agreement is symmetric, `Z`
  equals OpenSSL's, and the derived key equals the Python KDF's — with `apu`/`apv`
  of deliberately unequal lengths, since equal-length ASCII values are exactly
  the case an implementation that dropped the length prefix still "passes";
* refusals: a peer carrying `d`, an own key pinned to `sign`, a P-256 scalar
  against a P-384 point, an off-curve peer point, and `apu == apv`.

```
just interop-build            # build Rust harness (release) + npm ci
just interop                  # full matrix; exits 0, results in JSON
```

Full matrix is **79 cells**:

| Family | `format` | Cells | What it checks |
| --- | --- | --- | --- |
| ML-DSA | `compact`, `jwt` | 3 algs × 2 formats × 4 directions = 24 | the PQ wire format |
| Classical baseline | `compact` | EdDSA, ES256 × 4 directions = 8 | generic JWS regressions that might otherwise look like an ML-DSA bug |
| Custom protected header | `hdr` | ES256, EdDSA × 2 directions = 4 | producer sets `kid` + a private `tenant` member; consumer must report both back unchanged |
| JWE compact | `jwe` | 4 alg:enc × 2 directions = 8 | `dir:A256GCM`, `dir:A128CBC-HS256`, `A256KW:A256GCM`, `A256KW:A128CBC-HS256`; same custom header; plaintext + header compared |
| JWE flattened JSON | `jwe-json` | 4 alg:enc × 2 directions = 8 | RFC 7516 §7.2.2: same combos and header as `jwe`, emitted as a JSON object. The cell also asserts the **member shape** — `protected`/`ciphertext`/`iv`/`tag` present as strings, `encrypted_key` present for key-wrapped algs and **absent for `dir`** (§7.2.1), and no `unprotected`/`header`/`recipients`/`aad` — so a serialization bug surfaces even though the crypto is shared with `jwe` |
| JWE flattened JSON + external AAD | `jwe-json-aad` | 4 alg:enc × 2 directions = 8 | RFC 7516 §7.2.1 `aad` member: emitted with the right encoding, decryptable by the peer **with** the out-of-band bytes, and **refused without them** |
| JWE critical extensions | `jwe-crit` | 4 alg:enc × 2 directions = 8 | RFC 7516 §4.1.13: jose-rs emits `crit` only for a caller-declared parameter, and the parameter must be integrity protected. jwcrypto refuses to read an extension it cannot process and panva refuses to emit one, so the cell asserts the peer's rejection **and** a control message without `crit` that the peer accepts |
| JWE general JSON (2 recipients) | `jwe-general` | 2 alg:enc × 2 directions = 4 | RFC 7516 §7.2.1: one ciphertext, one `encrypted_key` per recipient. panva's `generalDecrypt` searches the array for a key that works; jose-rs makes the caller name the recipient (ADR 0014), so the cells assert both readings of the same message |
| JWE flattened JSON + unprotected headers | `jwe-json-unprot` | 4 alg:enc × 1 direction = 4 | JS emits the `unprotected` / `header` members jose-rs refuses to produce (RFC 7516 §7.2.1); jose-rs must read them as unauthenticated data and still authenticate the ciphertext |
| Duplicate header member | `jws-dup` | 3 | negative vectors (see below) |

The four JWS directions:

1. `rust-sign-js-verify` — Rust keygen + sign; JS verify
2. `js-sign-rust-verify` — JS keygen + sign; Rust verify
3. `rust-keygen-js-roundtrip` — Rust keygen; JS self-roundtrip with it (JWK-shape canary)
4. `js-keygen-rust-roundtrip` — JS keygen; Rust self-roundtrip with it

`hdr` cells use directions 1–2 only. `jwe` and `jwe-json` cells use
`rust-encrypt-js-decrypt` / `js-encrypt-rust-decrypt`: the producer generates
the symmetric (`oct`) JWK and encrypts, the consumer imports that same JWK and
decrypts — so `oct`-JWK shape is exercised in both directions. The `jwe` alg
label is `<ALG>:<ENC>`.

### Duplicate-member cells (`jws-dup`)

RFC 7515 §4 requires unique Header Parameter names but lets a JWS parser
either reject duplicates or use a lexically-last-wins JSON parser — so both
libraries can be conformant and still disagree. A validator and a consumer
that read a duplicated member differently is a classic confused-deputy
vector (security review finding L-4). These cells test that premise directly.

The Rust harness's `sign-compact-raw` base64url-encodes the caller's *exact*
header bytes and signs `header_b64.payload_b64` with a kryptering
`SoftwareSigner` (ES256) — jose-rs's public API can't emit such a header.
Both harnesses then run `verify-compact` on the same token; each side's
outcome is recorded in the cell's `observed` field:

```
jq '.[] | select(.format=="jws-dup") | {cell, result, observed}' interop/interop-results.json
```

| Cell | Protected header (raw) | jose-rs | panva/jose 6.2.2 (Node 24.12) | Pass criterion |
| --- | --- | --- | --- | --- |
| `dup-kid` | `{"alg":"ES256","kid":"first","kid":"second"}` | **rejects**: ``JSON error: duplicate field `kid` `` | **accepts**, `protectedHeader.kid == "second"` | jose-rs rejects |
| `dup-alg` | `{"alg":"HS256","alg":"ES256","kid":…}` | **rejects**: ``JSON error: duplicate field `alg` `` | **accepts**, `protectedHeader.alg == "ES256"`; verifies as ES256 | jose-rs rejects |
| `dup-ext` | `{"alg":"ES256","kid":…,"tenant":"first","tenant":"second"}` | **accepts**, `tenant == "second"` | **accepts**, `tenant == "second"` | both sides accept and resolve `tenant == "second"` |

Takeaways:

- panva/jose parses the protected header with `JSON.parse`, which is silently
  last-key-wins for every member, including `alg` and `kid`. It neither
  rejects nor warns.
- jose-rs rejects duplicates of every *typed* `JoseHeader` member (serde's
  `duplicate field` error), so a token that the two libraries would read
  differently for `alg`/`kid`/`typ`/`crit`/... cannot be accepted by jose-rs.
- Unregistered (private) members land in `JoseHeader::extra`, a flattened
  map, where jose-rs is **also last-key-wins** — it agrees with panva/jose,
  so there is no cross-implementation differential, but a duplicated private
  member is not rejected. Callers that make security decisions on private
  header members should be aware of this. `dup-ext` requires *both* sides to
  accept and to resolve the last value, so it fails if either side starts
  rejecting the token or picks the first value (merely agreeing is not
  enough: if both rejected, both `tenant` values would be null). A failure
  is the prompt to update this table.

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
`interop/vectors/<cell>.{priv,pub,signed}.json` (JWE cells:
`<cell>.{key,encrypted,decrypted}.json`; `hdr` cells also keep
`<cell>.verified.json`), so you can re-feed them into either harness by hand.

## Harness contract

Both harnesses expose the **same ten subcommands** (plus one Rust-only vector
minter), reading JSON on stdin and writing JSON on stdout. Errors go to stderr
and the process exits non-zero. `jwe` is carried as a *string* in both formats,
so the driver is identical for compact and flattened JSON messages. `aad_b64u`
(optional, flattened only) is external additional authenticated data, base64url
encoded by the caller and turned into the `aad` member by each implementation.

| Subcommand                                  | stdin                                   | stdout                                        |
| ------------------------------------------- | --------------------------------------- | --------------------------------------------- |
Every JWE command accepts an optional `understood_crit` list: the private header parameters the caller implements, which `crit` may then name (ADR 0015).

| `gen-key --alg <ALG> [--enc <ENC>]`         | —                                       | private JWK (`--enc` needed for `dir`)        |
| `export-pub`                                | private JWK                             | public JWK (private fields dropped)           |
| `sign-compact --alg <ALG>`                  | `{jwk, payload_b64u, header?}`          | `{jws}`                                       |
| `verify-compact --alg <ALG>`                | `{jwk, jws}`                            | `{ok, payload_b64u, protected_header}`        |
| `sign-jwt --alg <ALG>`                      | `{jwk, claims}`                         | `{jwt}`                                       |
| `verify-jwt --alg <ALG>`                    | `{jwk, jwt}`                            | `{ok, claims}`                                |
| `encrypt-compact --alg <ALG> --enc <ENC>`   | `{jwk, plaintext_b64u, header?}`        | `{jwe}`                                       |
| `decrypt-compact --alg <ALG> --enc <ENC>`   | `{jwk, jwe}`                            | `{ok, plaintext_b64u, protected_header}`      |
| `encrypt-flattened --alg <ALG> --enc <ENC>` | `{jwk, plaintext_b64u, header?, aad_b64u?, understood_crit?}` | `{jwe}` — RFC 7516 §7.2.2 JSON, as a string |
| `decrypt-flattened --alg <ALG> --enc <ENC>` | `{jwk, jwe, aad_b64u?, understood_crit?}` | `{ok, plaintext_b64u, protected_header, unprotected_header?}` |
| `sign-compact-raw --alg <ALG>` (Rust only)  | `{jwk, header_raw, payload_b64u}`       | `{jws}` signed over `header_raw` verbatim     |
| `agree` (Rust only)                          | `{own_jwk, peer_jwk}`                 | `{z_b64u, curve}` — raw ECDH shared secret |
| `derive-key` (Rust only)                     | `{own_jwk, peer_jwk, alg_id, apu?, apv?, key_len}` | `{derived_b64u, curve}` — RFC 7518 §4.6.2 output |

`header` is an optional object of extra protected-header members (e.g.
`{"kid":"…","tenant":"…"}`); `alg` / `enc` always come from the flags and may
not be overridden. `protected_header` is the header as that library parsed it.

The two agreement commands have no JS counterpart and no matrix cells — they
exist for `tests/ecdh_kdf_vectors.py`, which compares them against OpenSSL and
against RFC 7518 Appendix C. `agree` emits the raw shared secret, which is a test
probe and never a key; `derive-key` is what JOSE actually consumes.

Algorithm identifiers are the **exact JOSE strings**: `ML-DSA-44`, `ML-DSA-65`,
`ML-DSA-87`, `EdDSA`, `ES256`; JWE: `dir`, `A128KW`/`A192KW`/`A256KW` with
`--enc A256GCM`, `A128CBC-HS256`, ….

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
- **More JWE combos** — add `<ALG>:<ENC>` to `ALGS_JWE` in `matrix.sh`.
  `RSA-OAEP-256` would need an RSA branch in both harnesses' `gen-key`.
- **More duplicate-member vectors** — add a `dup-*` case to `run_dup_cell`
  in `matrix.sh` (e.g. duplicated `crit` / `b64`).
