# jose-rs

Pure-Rust JOSE (JSON Object Signing and Encryption) library covering JWS, JWE, JWK, and JWT standards. Built on [kryptering](https://crates.io/crates/kryptering) for cryptographic operations, supporting both in-memory software keys and PKCS#11 HSM-backed keys.

## Standards

| Standard | RFC | Coverage |
|---|---|---|
| JWS | [7515](https://www.rfc-editor.org/rfc/rfc7515) | Compact + Flattened JSON + General JSON serialization |
| JWE | [7516](https://www.rfc-editor.org/rfc/rfc7516) | Compact serialization |
| JWK | [7517](https://www.rfc-editor.org/rfc/rfc7517) | All key types, JWK Sets, Thumbprints ([RFC 7638](https://www.rfc-editor.org/rfc/rfc7638)), key generation |
| JWT | [7519](https://www.rfc-editor.org/rfc/rfc7519) | Claims, validation (exp/nbf/iss/aud/sub), nested JWT |
| JWA | [7518](https://www.rfc-editor.org/rfc/rfc7518) | All standard signature, encryption, and key management algorithms |

## Supported algorithms

**JWS signatures**: HS256/384/512, RS256/384/512, PS256/384/512, ES256/384/512, EdDSA

**JWS post-quantum signatures (opt-in)**: ML-DSA-44 / ML-DSA-65 / ML-DSA-87 (FIPS 204), enabled with `--features post-quantum`. See *Post-quantum signatures* below.

**JWE key management**: dir, A128KW/A192KW/A256KW, RSA-OAEP, RSA-OAEP-256

**JWE content encryption**: A128GCM/A192GCM/A256GCM, A128CBC-HS256/A192CBC-HS384/A256CBC-HS512

## Feature flags

| Feature | Default | Description |
|---|---|---|
| `pkcs11` | Yes | PKCS#11 HSM key support via kryptering |
| `post-quantum` | No | ML-DSA, SLH-DSA algorithms |
| `deprecated` | No | Legacy algorithms (RSA1_5, none) |

## Usage

### JWT (sign and verify)

```rust
use jose_rs::{JoseHeader, jwt, JwsAlgorithm};
use jose_rs::jwt::{Claims, Validation};

// Create a signer (HMAC-SHA256)
let key = kryptering::SoftwareKey::Hmac(b"my-secret-key-32-bytes-long!!!!!".to_vec());
let signer = kryptering::SoftwareSigner::new(
    JwsAlgorithm::HS256.to_crypto().unwrap(),
    key.clone(),
).unwrap();

// Encode
let header = JoseHeader::jwt("HS256");
let mut claims = Claims::default();
claims.iss = Some("my-service".into());
claims.sub = Some("user-42".into());
let token = jwt::encode(&signer, &header, &claims).unwrap();

// Decode and validate
let verifier = kryptering::SoftwareVerifier::new(
    JwsAlgorithm::HS256.to_crypto().unwrap(),
    key,
).unwrap();
let validation = Validation::new().with_issuer("my-service");
let decoded = jwt::decode(&verifier, &token, &validation).unwrap();
assert_eq!(decoded.sub.as_deref(), Some("user-42"));
```

### JWE (encrypt and decrypt)

```rust
use jose_rs::{JweAlgorithm, JweEncryption};

let cek = [0x42u8; 32]; // 256-bit key for A256GCM
let plaintext = b"sensitive data";

let token = jose_rs::jwe::encrypt(&cek, plaintext, JweAlgorithm::Dir, JweEncryption::A256GCM).unwrap();
let decrypted = jose_rs::jwe::decrypt(&cek, &token).unwrap();
assert_eq!(decrypted, plaintext);
```

### JWK (key management)

```rust
use jose_rs::jwk;

// Generate keys
let rsa_jwk = jwk::generate_rsa(2048).unwrap();
let ec_jwk = jwk::generate_ec("P-256").unwrap();
let ed_jwk = jwk::generate_ed25519().unwrap();

// Convert to/from kryptering keys
let software_key = jwk::jwk_to_software_key(&ec_jwk).unwrap();
let roundtripped = jwk::software_key_to_jwk(&software_key).unwrap();

// Thumbprint (RFC 7638)
let thumbprint = jwk::thumbprint::thumbprint_sha256(&ec_jwk).unwrap();
```

### HSM-backed signing

```rust
use jose_rs::{JoseHeader, jwt};
use jose_rs::jwt::Claims;

// The same JWT API works with HSM keys -- just pass an HSM-backed signer
let provider = kryptering::pkcs11::Pkcs11Provider::new(
    std::path::Path::new("/usr/lib/softhsm/libsofthsm2.so")
).unwrap();
let session = provider.open_session("1234").unwrap();
let signer = kryptering::pkcs11::Pkcs11Signer::new(
    &session, "my-rsa-key",
    kryptering::SignatureAlgorithm::RsaPkcs1v15(kryptering::HashAlgorithm::Sha256),
).unwrap();

let header = JoseHeader::jwt("RS256");
let claims = Claims::default();
let token = jwt::encode(&signer, &header, &claims).unwrap();
```

## Examples

See the [examples directory](https://github.com/kushaldas/jose/tree/main/examples) for complete, runnable examples covering all major JOSE operations:

- **generate_keys** -- generate RSA, EC P-256, Ed25519, HMAC, and AES keys as JWK files
- **jwt_hmac** -- JWT sign/verify with HMAC-SHA256
- **jwt_rsa** -- JWT sign with RS256, verify with public key
- **jwt_ecdsa** -- JWT sign with ES256, verify with public key
- **jwt_eddsa** -- JWT sign with EdDSA (Ed25519), verify with public key
- **jwe_aes_kw** -- JWE encrypt/decrypt with AES Key Wrap + AES-GCM
- **jwe_rsa_oaep** -- JWE encrypt with RSA-OAEP, decrypt with private key
- **jws_json** -- JWS flattened and general JSON serialization (multi-signature)
- **jwk_thumbprint** -- RFC 7638 JWK Thumbprint for all key types
- **nested_jwt** -- sign a JWT then encrypt it inside a JWE

Run `cargo run --example generate_keys` first to create the key files, then run any other example.

## Security notes

- **`rsa` crate advisory (RUSTSEC-2023-0071, a.k.a. "Marvin attack").** The
  upstream `rsa` crate used by this library has a known timing side-channel
  in PKCS#1 v1.5 and OAEP decryption. The vulnerability affects JWE
  `RSA-OAEP-256` (and, with the `deprecated` feature, `RSA-OAEP`) on the
  decryption side. There is no patched `rsa` 0.9.x release yet. If you
  operate a service that decrypts JWEs from untrusted senders, rate-limit
  decryption failures and prefer non-RSA key management algorithms.
- **Trust-sensitive header fields.** `jku`, `x5u`, and `jwk` headers are
  parsed by the library but **never fetched or trusted** — callers must
  never resolve `jku`/`x5u` URLs without an explicit allow-list (SSRF /
  key-substitution risk) and must never treat an inline `jwk` header as a
  verification key without first verifying it against a trusted key store.
- **`jwt::decode_unverified` is for inspection only.** It returns the
  header and claims without any cryptographic check. Production code
  paths must call `jwt::decode` with a real verifier and `Validation`.
- **Algorithm binding.** `jws`/`jwt` verify functions reject tokens whose
  `alg` header does not match the verifier's algorithm and always reject
  `alg: "none"` — even with the `deprecated` feature enabled. Non-empty
  `crit` headers are rejected per RFC 7515 §4.1.11.
- **RSA minimum key size.** Keys below 2048 bits are rejected at parse
  and at generation time (RFC 7518 §3.3 / §4.2).
- **AES-GCM nonce collision bound.** Content encryption with A128GCM /
  A192GCM / A256GCM uses a 96-bit random nonce per RFC 7518 §5.3. Under
  a single CEK the collision probability reaches 2⁻³² after ~2³² messages
  (NIST SP 800-38D §8.3). For high-throughput senders, rotate CEKs well
  before that bound — the `dir` mode with a fresh CEK per message
  avoids the issue entirely.
- **Token size cap.** The JWS and JWE decoders reject any input larger
  than `jose_rs::MAX_TOKEN_BYTES` (1 MiB) before allocating any
  base64url buffer, to bound DoS from oversized attacker-supplied
  tokens.
- **Debug output redaction.** `Jwk`'s `Debug` implementation redacts
  private components (`d`, `p`, `q`, `dp`, `dq`, `qi`, `k`) — logging a
  private `Jwk` will not spill the private material.
- **CEK zeroization.** Content Encryption Keys generated or recovered
  inside JWE `encrypt`/`decrypt` — including the `MAC_KEY || ENC_KEY`
  split used for AES-CBC-HS — are wrapped in `zeroize::Zeroizing` and
  wiped from the heap when they go out of scope. This does not extend
  to key material held inside the underlying cipher crates (which
  manage their own state), and the decrypted plaintext returned to
  the caller is not zeroized — if your plaintext is itself a secret,
  wrap it on the caller side.
- **Signing-side algorithm binding.** Symmetric to the verify path,
  the `jws`/`jwt` sign functions reject a header whose `alg` does not
  match the signer's algorithm, refuse `alg: "none"`, and refuse a
  non-empty `crit`. This prevents emitting malformed tokens whose
  header advertises a different algorithm than the one actually used.
- **JWT Best Current Practices (RFC 8725).** `Validation` supports
  pinning the `typ` header (`with_typ`), capping token age via `iat`
  (`with_max_age`), rejecting future-dated `iat` by default, and
  restricting the accepted signing algorithms independently of the
  verifier (`with_allowed_algorithms`). These close the JWT-context
  confusion and replay-window gaps that fall outside JWS-layer
  verification.
- **JWK authorization (RFC 7517 §4.2/§4.3).** Call `Jwk::check_op`
  before using a key. If the JWK's `use` or `key_ops` field is set,
  the call enforces it — a verify-only key cannot be used to sign, an
  `enc`-marked key cannot be used for signatures, and so on. `Jwk` also
  provides `to_public_jwk()` for safely exporting a key (it strips
  every private component — `d`, `p`, `q`, `dp`, `dq`, `qi`, `k`).
- **JWK `alg` / `kty` consistency.** Importing a JWK whose `alg`
  contradicts its `kty` (e.g. `alg: "RS256"` on a `kty: "oct"` key, or
  `alg: "ES256"` on a `P-384` curve) is rejected at conversion time
  with a clear error, rather than failing opaquely downstream.
- **HMAC key minimum length (RFC 7518 §3.2).** When an `oct` JWK
  declares `alg: "HS256"`, `"HS384"`, or `"HS512"`, the `k` material
  must be at least as long as the hash output (32, 48, or 64 bytes
  respectively). Shorter keys are rejected at JWK import.
- **Private JWK fields zeroize on drop.** `Jwk`'s `Drop` impl calls
  `zeroize::Zeroize` on `d`, `p`, `q`, `dp`, `dq`, `qi`, and `k` when
  present, so private material is wiped from the heap before the
  allocation is returned to the allocator.
- **`jwt::decode_unverified` is `#[deprecated]`.** Every call site now
  emits a compiler warning pointing users to `jwt::decode`. The
  function remains available for legitimate pre-verification
  inspection (e.g. reading a token's `kid` to select the right
  verifier).
- **JWK-first API (safer one-shot for every operation).** Prefer the
  `*_with_jwk` functions over the manual "build a signer/verifier
  yourself" path:
  - Sign/verify: `jws::compact::sign_with_jwk`,
    `jws::compact::verify_with_jwk`, `jwt::encode_with_jwk`,
    `jwt::decode_with_jwk`, `jwt::decode_with_jwkset`.
  - Encrypt/decrypt: `jwe::encrypt_with_jwk`, `jwe::decrypt_with_jwk`.

  Each derives the algorithm from the JWK (or the token header, on the
  receive side), enforces `Jwk::check_op` for the intended operation
  (`Sign`/`Verify`/`Encrypt`/`Decrypt`/`WrapKey`/`UnwrapKey`), requires
  any pinned `jwk.alg` to agree with the token's header, and constructs
  the underlying signer/verifier or key-material form internally.
  `decode_with_jwkset` is the canonical OIDC flow (kid-lookup with
  fall-through to each key in the set).

## Post-quantum signatures (experimental)

ML-DSA support is available behind the opt-in `post-quantum` feature:

```toml
[dependencies]
jose-rs = { version = "0.1", features = ["post-quantum"] }
```

Enabling this pulls in the `ml-dsa` and `pkcs8-pq` crates plus kryptering's
post-quantum backend, and adds three `JwsAlgorithm` variants corresponding
to the IANA-registered identifiers `ML-DSA-44`, `ML-DSA-65`, `ML-DSA-87`
(FIPS 204).

### JWK wire format (`kty = "AKP"`)

Per `draft-ietf-cose-dilithium`, ML-DSA keys use the new `"AKP"`
("Algorithm Key Pair") key type with two base64url members:

- `pub` — the raw FIPS 204 encoded public key (1312 / 1952 / 2592 bytes
  for the three security levels).
- `priv` — the 32-byte FIPS 204 **seed** (not an expanded private key).
  The expanded signing key is derived on demand via
  `ML-DSA.KeyGen_internal(seed)`.

`Jwk.priv` is zeroized on `Drop` alongside the existing RSA/EC/oct
private-component wipe. `Jwk::to_public_jwk()` strips `priv` and keeps
`pub`, which is the correct shape for a JWK Set endpoint.

### Status and caveats

- **Draft-spec, not yet RFC.** The authoritative spec is
  [`draft-ietf-cose-dilithium-11`](https://datatracker.ietf.org/doc/draft-ietf-cose-dilithium/)
  (active, submitted to IESG, expected to publish as an RFC in 2026). The
  wire format may shift before publication — do not use this feature
  for long-lived signed artifacts that you cannot re-issue later.

- **`ml-dsa` crate history.** The RustCrypto `ml-dsa` crate shipped
  three moderate-severity advisories during its 0.1.0 release-candidate
  series. All three are fixed in versions earlier than our pin, and
  `cargo audit` is clean against `ml-dsa 0.1.0-rc.8`:

  | Advisory | Summary | Patched from |
  |---|---|---|
  | [GHSA-hcp2-x6j4-29j7](https://github.com/RustCrypto/signatures/security/advisories/GHSA-hcp2-x6j4-29j7) | `Decompose` timing side-channel during signing | `>= 0.1.0-rc.3` |
  | [GHSA-5x2r-hc65-25f9](https://github.com/RustCrypto/signatures/security/advisories/GHSA-5x2r-hc65-25f9) | Repeated hint indices (signature malleability) | `>= 0.1.0-rc.4` |
  | [GHSA-h37v-hp6w-2pp8](https://github.com/RustCrypto/signatures/security/advisories/GHSA-h37v-hp6w-2pp8) | `UseHint` off-by-two | `>= 0.1.0-rc.5` |

  Because the pin is `=0.1.0-rc.8`, any future `ml-dsa` advisory will
  surface as an explicit lockfile event — consult `cargo audit` before
  bumping, and track [RustCrypto/signatures](https://github.com/RustCrypto/signatures)
  for the `ml-dsa 0.1.0` stable release.

- **Default signing mode is randomized (hedged).** ML-DSA sign uses real
  randomness per FIPS 204 Algorithm 2, so repeated signatures over the
  same message and key are expected to differ while still verifying.
  The optional deterministic signing variant (equivalent to a zero
  `rnd`) is not currently exposed.

- **ML-DSA-87 test note.** The expanded signing key (~5 KiB) exceeds
  the default 2 MiB debug-build test-thread stack; the ML-DSA-87
  round-trip test spawns itself on a larger-stack thread. Release
  builds have smaller stack frames and are unaffected.

## Development tooling

### Dependency audit

The repository is wired for [`cargo-audit`](https://rustsec.org/).
Local run:

```
cargo install --locked cargo-audit
cargo audit
```

CI runs the same command on every push to `main`, every pull request
that touches `Cargo.toml` / `Cargo.lock`, and on a weekly schedule
(`.github/workflows/audit.yml`).

`.cargo/audit.toml` carries a single documented advisory ignore —
RUSTSEC-2023-0071 (the `rsa` crate Marvin timing advisory) — with
mitigations described above. Any advisory that is **not** in the
ignore list fails CI; the ignore file itself is the source of truth
for "what are we accepting, and why".

### Interop test vectors (RFC 7520)

`tests/rfc7520.rs` verifies examples from
[RFC 7520](https://www.rfc-editor.org/rfc/rfc7520.html) — these are the
canonical worked vectors every JOSE implementation is expected to
reproduce, which gives the library a cross-implementation interop
baseline:

- **JWS §4.1–4.4.** RS256, PS384, ES512 verify; HS256 as a full
  byte-for-byte deterministic roundtrip (sign then byte-compare against
  the RFC's published compact serialization).
- **JWE §5.6, §5.8.** Direct encryption with A128GCM and A128KW + A128GCM
  — decrypt the RFC's published JWE and check the recovered plaintext.
- **JWE §5.2.** RSA-OAEP + A256GCM decrypt using the RFC's RSA-4096 key.
  Runs only under `--features deprecated` because RSA-OAEP uses SHA-1.

All vectors are embedded verbatim from `rfcs/rfc7520.txt` with their
original indent-continuations intact; runtime whitespace-stripping
eliminates transcription risk in 1000+-char RSA key material.

### Fuzzing

`fuzz/` is a [`cargo-fuzz`](https://rust-fuzz.github.io/book/cargo-fuzz.html)
project with eight targets covering the attacker-controlled parse and
verify paths (base64url, JWK JSON, thumbprint, JWS decode/verify, JWE
decrypt, JWT header/claims, and post-quantum JWS verify via
`jws_verify_mldsa`). See `fuzz/README.md` for the per-target breakdown.

```
rustup toolchain install nightly
cargo install --locked cargo-fuzz
cargo +nightly fuzz run jwk_from_json         # run indefinitely
cargo +nightly fuzz run jws_verify -- -max_total_time=300
```

CI (`.github/workflows/fuzz.yml`) builds every target on every PR to
catch compilation regressions; the actual fuzzing runs are expected to
live in a longer-running job or OSS-Fuzz once the corpus stabilizes.

## License

BSD-2-Clause
