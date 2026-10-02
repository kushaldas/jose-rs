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
interop/.venv/bin/python interop/tests/jwe_ecdh_es_jwcrypto.py interop/rust-harness/target/debug/jose-interop
interop/.venv/bin/python interop/tests/pem_jwcrypto.py interop/rust-harness/target/debug/jose-interop
interop/.venv/bin/python interop/tests/pkcs8_encrypted_cryptography.py
interop/.venv/bin/python interop/tests/cert_cryptography.py
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

### PBES2 against jwcrypto (`jwe_pbes2_jwcrypto.py`)

166 checks over all three PBES2 algorithms and four content algorithms. Beyond the
round-trips, the suite **re-derives the key in Python**: it reads `p2s`/`p2c` out of a
jose-rs token's protected header, runs PBKDF2 over `UTF8(alg) || 0x00 || Salt Input`,
unwraps the conveyed key with AES-KW, requires the result to be exactly the content
algorithm's CEK length, and decrypts the content with it. The salt construction, the PRF,
the derived key length and the RFC 3394 wrap are all pinned by that chain.

It also pins the **work budget as an interop fact**. `p2c` is chosen by the sender and
paid by the recipient, so verifiers cap what they will compute: panva's default
`maxPBES2Count` is 10 000 and jwcrypto's `default_max_pbkdf2_iterations` is 16 384. A
default above either makes every message this crate emits unreadable by that peer — the
suite asserts the default sits inside both ceilings, that a count above them really is
refused by the peer, and that jose-rs's own refusals (below 1 000, above the recipient's
budget) name the parameter rather than failing cryptically.

One divergence is pinned: RFC 7518 §4.8 allows the password to be an octet sequence, and
jwcrypto's `JWK.from_password` takes text and UTF-8 encodes it itself, so it cannot
express a password that is not valid text. jose-rs accepts both forms.

### PEM key files against OpenSSL and `cryptography` (`pem_jwcrypto.py`)

60 checks, and the only suite here that shells out to the `openssl` CLI — because the
question a key file raises is not "does somebody read it" but "is it the file everybody
else would have written".

Python → Rust: `cryptography` generates RSA-2048 / P-256 / P-384 / P-521 / Ed25519 and
exports PKCS#8 and SPKI PEM. jose-rs imports them, and every JWK member is compared against
values computed in Python from the key object — fixed-width coordinates, minimal-width RSA
integers — so an import that guessed at a width shows up. jose-rs then signs with the
imported key and Python verifies with the SPKI half.

Rust → Python: jose-rs exports PEM and `cryptography` loads it, then **`openssl` re-encodes
the same key and the bytes must match**. "Parses" would have been a weaker claim; byte
equality against another implementation's encoder is the one that catches a non-canonical
structure. That check is what found the version-1 problem pinned in ADR 0022: the backend's
Ed25519 PKCS#8 carries its public key as an `OneAsymmetricKey` attribute, which OpenSSL
reads and `cryptography` refuses, so the export normalizes to `PrivateKeyInfo` (version 0)
and the version-1 form is still accepted on the way in.

Strictness is asserted in both directions: PKCS#1, SEC1, certificate, encrypted PKCS#8 and
legacy `DEK-Info` blocks are refused with the reason named; two blocks are refused with a
count; text before `-----BEGIN` and after `-----END` is refused; leading/trailing blank
lines, CRLF endings and a missing final newline are accepted.
### AES-GCM key management against jwcrypto (`jwe_gcm_kw_jwcrypto.py`)

135 checks over all three `*GCMKW` algorithms and four content algorithms. Beyond the
two-directional round-trips and the member shape (which matches on both sides — jwcrypto
and panva both put the wrap's `iv`/`tag` in the protected header, as this crate does),
the suite unwraps the header's key wrap **in Python**, using only the RFC's parameters,
requires the recovered key to be exactly the content algorithm's CEK length, and then
decrypts the content with it. That last step is what makes the check non-circular: the
header's wrap and the content's key are two stages, and a message that carried *a* key
would otherwise pass every round-trip.

It also pins the AES-CBC-HMAC content construction independently, since the point of the
exercise is not to trust either implementation's account of it: the MAC is
`HMAC(MAC_KEY, A || IV || E || AL)` with the 64-bit bit-count appended **last** and the
MAC key in the CEK's *first* half — the order RFC 7518 §5.2.2.1's illustration gives,
which its prose list does not.

### Direct ECDH agreement against jwcrypto (`jwe_ecdh_es_jwcrypto.py`)

104 checks over P-256/P-384/P-521 and X25519 with GCM and CBC-HMAC content
encryption, in both agreement modes:
jose-rs → jwcrypto in both serializations (with the `epk` shape and the empty
encrypted key asserted), and jwcrypto → jose-rs in the compact form — which is the
real crypto cross-check, since only a matching Concat KDF opens jwcrypto's
ciphertext.

It also pins the wrapped key's length against RFC 3394's framing rather than
trusting either implementation's account of it — 40 octets means a 256-bit CEK
wrapped under a 128-bit agreed key, which is the pairing that catches a library
reading `keydatalen` off `enc`.

And it pins one **divergence**. jwcrypto ships `epk` in the *unprotected*
`header` member of its JWE JSON Serialization, and jose-rs refuses a peer key it
cannot authenticate (ADRs 0013/0017), so that one combination is refused by name
before any cryptographic work. Its compact form puts `epk` in the protected header
— where it has to go, since compact has nowhere else to put it — and does
interoperate; panva puts `epk` in the protected header in both serializations and
interoperates in both directions. The refusal is asserted so that any future
loosening of the rule is a deliberate edit rather than a silent behaviour change.

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

Full matrix is **109 cells**:

| Family | `format` | Cells | What it checks |
| --- | --- | --- | --- |
| ML-DSA | `compact`, `jwt` | 3 algs × 2 formats × 4 directions = 24 | the PQ wire format |
| Classical baseline | `compact` | EdDSA, ES256 × 4 directions = 8 | generic JWS regressions that might otherwise look like an ML-DSA bug |
| Custom protected header | `hdr` | ES256, EdDSA × 2 directions = 4 | producer sets `kid` + a private `tenant` member; consumer must report both back unchanged |
| JWE compact | `jwe` | 4 alg:enc × 2 directions = 8 | `dir:A256GCM`, `dir:A128CBC-HS256`, `A256KW:A256GCM`, `A256KW:A128CBC-HS256`; same custom header; plaintext + header compared |
| JWE flattened JSON | `jwe-json` | 4 alg:enc × 2 directions = 8 | RFC 7516 §7.2.2: same combos and header as `jwe`, emitted as a JSON object. The cell also asserts the **member shape** — `protected`/`ciphertext`/`iv`/`tag` present as strings, `encrypted_key` present for key-wrapped algs and **absent for `dir`** (§7.2.1), and no `unprotected`/`header`/`recipients`/`aad` — so a serialization bug surfaces even though the crypto is shared with `jwe` |
| JWE flattened JSON + external AAD | `jwe-json-aad` | 4 alg:enc × 2 directions = 8 | RFC 7516 §7.2.1 `aad` member: emitted with the right encoding, decryptable by the peer **with** the out-of-band bytes, and **refused without them** |
| JWE critical extensions | `jwe-crit` | 4 alg:enc × 2 directions = 8 | RFC 7516 §4.1.13: jose-rs emits `crit` only for a caller-declared parameter, and the parameter must be integrity protected. jwcrypto refuses to read an extension it cannot process and panva refuses to emit one, so the cell asserts the peer's rejection **and** a control message without `crit` that the peer accepts |
| JWE ECDH agreement with key wrapping | `jwe-ecdh-kw` | 4 alg/curve/enc quadruples × 2 directions = 8 | `ECDH-ES+A128KW`/`+A192KW`/`+A256KW` (RFC 7518 §4.6): one wrapping algorithm per curve, and the cell asserts the compact form's encrypted-key segment is **non-empty** — the converse of the `jwe-ecdh` assertion — so a cell that quietly switched key-management mode fails instead of passing on a tag it no longer proves |
| JWE direct ECDH agreement | `jwe-ecdh` | 4 curve/enc pairs × 2 directions = 8 | RFC 7518 §4.6 (`ECDH-ES`): the producer encrypts to the recipient's **public** half and the consumer reads it with the private half, so the cell proves the agreement needs no `d` on the send side. The consuming side must report an authenticated `epk` on the recipient's curve with no private part, and the compact form's encrypted-key segment must be empty |
| JWE AES-GCM key management | `jwe-gcmkw` | 3 alg:enc × 2 directions = 6 | `A128GCMKW`/`A192GCMKW`/`A256GCMKW` (RFC 7518 §4.7), where the key wrap's `iv`/`tag` are **header members** and the envelope has its own members with those same names. The cell requires both pairs, at 12 and 16 octets, holding **different** values — a message that reused them would be readable by nobody — and a non-empty conveyed key |
| JWE PBES2 (password) | `jwe-pbes2` | 3 alg:enc × 2 directions = 6 | `PBES2-HS256+A128KW`/`+HS384+A192KW`/`+HS512+A256KW` (RFC 7518 §4.8). The password is fixed by the cell rather than generated, and the cell requires `p2s` (≥8 octets) and an integer `p2c` **in the protected header** — they are the derivation's inputs — and that a wrong password cannot read the peer's message |
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

| `gen-key --alg <ALG> [--enc <ENC>] [--crv <CRV>]` | —                                 | private JWK (`--enc` for `dir`, `--crv` for `ECDH-ES`) |
| `export-pub`                                | private JWK                             | public JWK (private fields dropped)           |
| `import-pem`                                | PEM text (raw stdin)                    | imported JWK                                  |
| `export-pem --pem=private\|public`           | JWK                                     | PEM text, emitted verbatim                    |
| `sign-pem --alg <ALG>`                      | PEM text (raw stdin)                    | compact JWS over a fixed payload              |
| `sign-compact --alg <ALG>`                  | `{jwk, payload_b64u, header?}`          | `{jws}`                                       |
| `verify-compact --alg <ALG>`                | `{jwk, jws}`                            | `{ok, payload_b64u, protected_header}`        |
| `sign-jwt --alg <ALG>`                      | `{jwk, claims}`                         | `{jwt}`                                       |
| `verify-jwt --alg <ALG>`                    | `{jwk, jwt}`                            | `{ok, claims}`                                |
| `encrypt-compact --alg <ALG> --enc <ENC>`   | `{jwk, plaintext_b64u, header?}`        | `{jwe}`                                       |
| `decrypt-compact --alg <ALG> --enc <ENC>`   | `{jwk, jwe}`                            | `{ok, plaintext_b64u, protected_header}`      |
| `encrypt-compact-password --alg <ALG> --enc <ENC>` | `{password, plaintext_b64u, header?, p2c?}` | `{jwe}` — RFC 7518 §4.8; there is no `gen-key` counterpart, a password is supplied not generated, so the cells fix one |
| `decrypt-compact-password --alg <ALG> --enc <ENC>` | `{password, jwe}` | `{ok, plaintext_b64u, protected_header}` — the header is the interesting part: it must carry the authenticated `p2s`/`p2c` |
| `encrypt-flattened --alg <ALG> --enc <ENC>` | `{jwk, plaintext_b64u, header?, aad_b64u?, understood_crit?}` | `{jwe}` — RFC 7516 §7.2.2 JSON, as a string |
| `decrypt-flattened --alg <ALG> --enc <ENC>` | `{jwk, jwe, aad_b64u?, understood_crit?}` | `{ok, plaintext_b64u, protected_header, unprotected_header?}` |
| `sign-compact-raw --alg <ALG>` (Rust only)  | `{jwk, header_raw, payload_b64u}`       | `{jws}` signed over `header_raw` verbatim     |
| `agree` (Rust only)                          | `{own_jwk, peer_jwk}`                 | `{z_b64u, curve}` — raw ECDH shared secret |
| `derive-key` (Rust only)                     | `{own_jwk, peer_jwk, alg_id, apu?, apv?, key_len}` | `{derived_b64u, curve}` — RFC 7518 §4.6.2 output |

`header` is an optional object of extra protected-header members (e.g.
`{"kid":"…","tenant":"…"}`); `alg` / `enc` always come from the flags and may
not be overridden. `protected_header` is the header as that library parsed it.

`gen-key --alg ECDH-ES --crv <P-256|P-384|P-521|X25519>` produces an agreement recipient
key (curve chosen by the caller, `alg` pinned, `use: enc`); both harnesses do it,
so either side can play producer in an `jwe-ecdh` or `jwe-ecdh-kw` cell.

The two agreement probe commands have no JS counterpart and no matrix cells — they
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
