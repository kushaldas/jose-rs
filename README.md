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
- **JWK-based verify / decode (safer one-shot API).** Prefer
  `jws::compact::verify_with_jwk`, `jwt::decode_with_jwk`, and
  `jwt::decode_with_jwkset` over the manual "build a verifier
  yourself" path. These functions derive the algorithm from the
  token header, require any pinned `jwk.alg` to agree, enforce
  `Jwk::check_op` for the intended operation, and build the
  verifier internally — so the alg-binding, `use`/`key_ops`
  authorization, and `kid` lookup are all handled by the library
  instead of being the caller's responsibility. `decode_with_jwkset`
  is the canonical OIDC flow (kid-lookup with fall-through to each
  key in the set).

## License

BSD-2-Clause
