//! JWE Compact Serialization (RFC 7516 Section 3.1).
//!
//! Format: `BASE64URL(header).BASE64URL(encrypted_key).BASE64URL(iv).BASE64URL(ciphertext).BASE64URL(tag)`

use crate::algorithm::{JweAlgorithm, JweEncryption};
use crate::base64url;
use crate::error::{JoseError, Result};
use crate::header::JoseHeader;

use rand::RngCore;
use zeroize::Zeroizing;

fn ensure_token_size(token: &str) -> Result<()> {
    if token.len() > crate::MAX_TOKEN_BYTES {
        return Err(JoseError::InvalidToken(format!(
            "token size {} exceeds MAX_TOKEN_BYTES ({})",
            token.len(),
            crate::MAX_TOKEN_BYTES
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Encrypt plaintext and produce a JWE Compact Serialization string.
///
/// - For `dir`: `key` is the CEK (must match the `enc` algorithm's key size).
/// - For `A128KW` / `A192KW` / `A256KW`: `key` is the Key Encryption Key.
/// - For `RSA-OAEP` / `RSA-OAEP-256`: `key` is the RSA public key in SPKI DER
///   format.
pub fn encrypt(
    key: &[u8],
    plaintext: &[u8],
    alg: JweAlgorithm,
    enc: JweEncryption,
) -> Result<String> {
    // 1. Build protected header.
    let mut header = JoseHeader::new(alg.as_str());
    header.enc = Some(enc.as_str().to_string());
    let header_json = serde_json::to_vec(&header)?;
    let header_b64 = base64url::encode(&header_json);

    // 2. Generate or use CEK, produce encrypted key.
    let (cek, encrypted_key) = produce_cek(key, alg, enc)?;

    // 3. Content encryption.
    // AAD = ASCII(BASE64URL(header)) per RFC 7516 Section 5.1 step 14.
    let aad = header_b64.as_bytes();
    let (iv, ciphertext, tag) = content_encrypt(enc, &cek, plaintext, aad)?;

    // 4. Assemble compact serialization.
    let encrypted_key_b64 = base64url::encode(&encrypted_key);
    let iv_b64 = base64url::encode(&iv);
    let ciphertext_b64 = base64url::encode(&ciphertext);
    let tag_b64 = base64url::encode(&tag);

    Ok(format!(
        "{header_b64}.{encrypted_key_b64}.{iv_b64}.{ciphertext_b64}.{tag_b64}"
    ))
}

/// Determine which `JwkOp` governs a JWE alg on the encrypt side.
///
/// `Dir` uses the key directly for content encryption (`Encrypt`);
/// key-transport (`A*KW`, `RSA-OAEP*`) wraps a CEK (`WrapKey`).
fn jwe_alg_encrypt_op(alg: JweAlgorithm) -> crate::jwk::JwkOp {
    match alg {
        JweAlgorithm::Dir => crate::jwk::JwkOp::Encrypt,
        _ => crate::jwk::JwkOp::WrapKey,
    }
}

/// Determine which `JwkOp` governs a JWE alg on the decrypt side.
fn jwe_alg_decrypt_op(alg: JweAlgorithm) -> crate::jwk::JwkOp {
    match alg {
        JweAlgorithm::Dir => crate::jwk::JwkOp::Decrypt,
        _ => crate::jwk::JwkOp::UnwrapKey,
    }
}

/// Convert a JWK to the raw key-material form that [`encrypt`] /
/// [`decrypt`] expect for the given JWE algorithm.
///
/// - For `dir`, `A*KW`: returns the `k` bytes of an `oct` JWK.
/// - For `RSA-OAEP*` on the encrypt side: returns SPKI DER of the public key.
/// - For `RSA-OAEP*` on the decrypt side: returns PKCS#8 DER of the private key.
fn jwk_to_jwe_key_bytes(
    jwk: &crate::jwk::Jwk,
    alg: JweAlgorithm,
    for_decrypt: bool,
) -> Result<Vec<u8>> {
    match alg {
        JweAlgorithm::Dir | JweAlgorithm::A128KW | JweAlgorithm::A192KW | JweAlgorithm::A256KW => {
            let k = jwk
                .k
                .as_deref()
                .ok_or_else(|| JoseError::Key("JWK is missing `k`".into()))?;
            base64url::decode(k)
        }
        JweAlgorithm::RsaOaep256 => rsa_jwk_to_der(jwk, for_decrypt),
        #[cfg(feature = "deprecated")]
        JweAlgorithm::RsaOaep => rsa_jwk_to_der(jwk, for_decrypt),
        _ => Err(JoseError::UnsupportedAlgorithm(format!(
            "JWE alg {} not supported via JWK one-shot API",
            alg.as_str()
        ))),
    }
}

fn rsa_jwk_to_der(jwk: &crate::jwk::Jwk, for_decrypt: bool) -> Result<Vec<u8>> {
    let sw = crate::jwk::jwk_to_software_key(jwk)?;
    match &sw {
        kryptering::SoftwareKey::Rsa { public, private } => {
            if for_decrypt {
                use rsa::pkcs8::EncodePrivateKey;
                let pk = private
                    .as_ref()
                    .ok_or_else(|| JoseError::Key("JWK lacks RSA private components".into()))?;
                Ok(pk
                    .to_pkcs8_der()
                    .map_err(|e| JoseError::Key(format!("PKCS#8 encode: {e}")))?
                    .as_bytes()
                    .to_vec())
            } else {
                use rsa::pkcs8::EncodePublicKey;
                Ok(public
                    .to_public_key_der()
                    .map_err(|e| JoseError::Key(format!("SPKI encode: {e}")))?
                    .as_ref()
                    .to_vec())
            }
        }
        _ => Err(JoseError::Key("RSA JWK expected".into())),
    }
}

/// Encrypt plaintext using a JWK directly — the one-shot JWE encrypt API.
///
/// The key management algorithm is read from `jwk.alg` and
/// `Jwk::check_op` is enforced: `Encrypt` for `dir`, `WrapKey` for
/// `A*KW` / `RSA-OAEP*`. The caller supplies the content-encryption
/// algorithm.
pub fn encrypt_with_jwk(
    jwk: &crate::jwk::Jwk,
    plaintext: &[u8],
    enc: JweEncryption,
) -> Result<String> {
    let jwk_alg_str = jwk
        .alg
        .as_deref()
        .ok_or_else(|| JoseError::Key("JWK alg must be set for encrypt_with_jwk".into()))?;
    let alg = JweAlgorithm::from_str(jwk_alg_str)?;
    jwk.check_op(jwe_alg_encrypt_op(alg))?;
    let key_bytes = jwk_to_jwe_key_bytes(jwk, alg, false)?;
    encrypt(&key_bytes, plaintext, alg, enc)
}

/// Decrypt a JWE token using a JWK directly — the one-shot JWE decrypt API.
///
/// The key management algorithm is read from the token's protected
/// header (and cross-checked against `jwk.alg` if pinned).
/// `Jwk::check_op` is enforced: `Decrypt` for `dir`, `UnwrapKey` for
/// `A*KW` / `RSA-OAEP*`.
pub fn decrypt_with_jwk(jwk: &crate::jwk::Jwk, token: &str) -> Result<Vec<u8>> {
    // Read the header's alg for dispatch.
    let header = decode_header(token)?;
    let alg = JweAlgorithm::from_str(&header.alg)?;

    // If the JWK pins an alg, it must agree with the token.
    if let Some(jwk_alg) = jwk.alg.as_deref() {
        if jwk_alg != header.alg {
            return Err(JoseError::InvalidToken(format!(
                "JWK alg {jwk_alg} does not match token header alg {}",
                header.alg
            )));
        }
    }

    jwk.check_op(jwe_alg_decrypt_op(alg))?;
    let key_bytes = jwk_to_jwe_key_bytes(jwk, alg, true)?;
    decrypt(&key_bytes, token)
}

/// Decrypt a JWE Compact Serialization string and return the plaintext.
///
/// Accepts any key-management / content-encryption algorithm the library
/// supports. For strict deployments, use [`decrypt_with_options`] to pin
/// an explicit allow-list.
///
/// - For `dir`: `key` is the CEK.
/// - For `A128KW` / `A192KW` / `A256KW`: `key` is the Key Encryption Key.
/// - For `RSA-OAEP` / `RSA-OAEP-256`: `key` is the RSA private key in PKCS#8
///   DER format.
pub fn decrypt(key: &[u8], token: &str) -> Result<Vec<u8>> {
    decrypt_with_options(key, token, &JweDecryptOptions::permissive())
}

/// Options controlling which JWE algorithms `decrypt_with_options` accepts.
///
/// Use [`JweDecryptOptions::new`] to pin an explicit allow-list of key
/// management algorithms and content encryption algorithms. Tokens whose
/// header advertises anything outside the allow-list are rejected before
/// any cryptographic operation — the canonical defence against
/// algorithm-substitution attacks when one key is reused across configs.
#[derive(Debug, Clone, Default)]
pub struct JweDecryptOptions {
    allowed_alg: Vec<JweAlgorithm>,
    allowed_enc: Vec<JweEncryption>,
    allow_all: bool,
}

impl JweDecryptOptions {
    /// Construct options pinning an explicit allow-list.
    pub fn new(allowed_alg: Vec<JweAlgorithm>, allowed_enc: Vec<JweEncryption>) -> Self {
        Self {
            allowed_alg,
            allowed_enc,
            allow_all: false,
        }
    }

    /// Permit every algorithm the library supports. Used internally by
    /// [`decrypt`] for backwards compatibility — new code should prefer
    /// [`JweDecryptOptions::new`].
    pub fn permissive() -> Self {
        Self {
            allowed_alg: Vec::new(),
            allowed_enc: Vec::new(),
            allow_all: true,
        }
    }

    fn check(&self, alg: JweAlgorithm, enc: JweEncryption) -> Result<()> {
        if self.allow_all {
            return Ok(());
        }
        if !self.allowed_alg.contains(&alg) {
            return Err(JoseError::UnsupportedAlgorithm(format!(
                "JWE alg {} is not in the caller's allow-list",
                alg.as_str()
            )));
        }
        if !self.allowed_enc.contains(&enc) {
            return Err(JoseError::UnsupportedAlgorithm(format!(
                "JWE enc {} is not in the caller's allow-list",
                enc.as_str()
            )));
        }
        Ok(())
    }
}

/// Decrypt a JWE Compact Serialization token, enforcing the caller's
/// algorithm allow-list.
///
/// Rejects the token before any cryptographic operation if its `alg` or
/// `enc` header is outside the allow-list supplied via `options`.
pub fn decrypt_with_options(
    key: &[u8],
    token: &str,
    options: &JweDecryptOptions,
) -> Result<Vec<u8>> {
    ensure_token_size(token)?;
    // 1. Parse compact serialization.
    let parts: Vec<&str> = token.splitn(6, '.').collect();
    if parts.len() != 5 {
        return Err(JoseError::InvalidToken(
            "JWE compact serialization must have 5 dot-separated parts".into(),
        ));
    }

    let header_b64 = parts[0];
    let encrypted_key_b64 = parts[1];
    let iv_b64 = parts[2];
    let ciphertext_b64 = parts[3];
    let tag_b64 = parts[4];

    // 2. Decode header.
    let header_json = base64url::decode(header_b64)?;
    let header: JoseHeader = serde_json::from_slice(&header_json)?;

    // RFC 7516 §4.1.13 / RFC 7515 §4.1.11: reject unknown crit extensions.
    if let Some(crit) = &header.crit {
        if !crit.is_empty() {
            return Err(JoseError::InvalidHeader(format!(
                "unsupported crit extensions: {crit:?}"
            )));
        }
    }

    let alg = JweAlgorithm::from_str(&header.alg)?;
    let enc_str = header
        .enc
        .as_deref()
        .ok_or_else(|| JoseError::InvalidHeader("missing enc field".into()))?;
    let enc = JweEncryption::from_str(enc_str)?;

    // Enforce caller's allow-list before touching any key material.
    options.check(alg, enc)?;

    // 3. Decode parts.
    let encrypted_key = base64url::decode(encrypted_key_b64)?;
    let iv = base64url::decode(iv_b64)?;
    let ciphertext = base64url::decode(ciphertext_b64)?;
    let tag = base64url::decode(tag_b64)?;

    // 4. Recover CEK.
    let cek = recover_cek(key, alg, enc, &encrypted_key)?;

    // 5. Content decryption.
    // AAD = ASCII(BASE64URL(header)).
    let aad = header_b64.as_bytes();
    content_decrypt(enc, &cek, &iv, &ciphertext, &tag, aad)
}

/// Decode the protected header from a JWE compact token without decrypting.
pub fn decode_header(token: &str) -> Result<JoseHeader> {
    ensure_token_size(token)?;
    let header_b64 = token
        .split('.')
        .next()
        .ok_or_else(|| JoseError::InvalidToken("empty token".into()))?;
    let header_json = base64url::decode(header_b64)?;
    serde_json::from_slice(&header_json).map_err(Into::into)
}

// ---------------------------------------------------------------------------
// Key management: produce CEK (encrypt side)
// ---------------------------------------------------------------------------

/// Returns `(cek, encrypted_key)`. For `dir`, `encrypted_key` is empty.
///
/// The CEK is returned wrapped in `Zeroizing` so its heap buffer is
/// wiped when it goes out of scope — key material never lingers in
/// the allocator after the encryption completes.
fn produce_cek(
    key: &[u8],
    alg: JweAlgorithm,
    enc: JweEncryption,
) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>)> {
    let cek_len = enc.cek_size();

    match alg {
        // Direct: the provided key *is* the CEK.
        JweAlgorithm::Dir => {
            if key.len() != cek_len {
                return Err(JoseError::Key(format!(
                    "dir: key length {} does not match required CEK size {}",
                    key.len(),
                    cek_len
                )));
            }
            Ok((Zeroizing::new(key.to_vec()), Vec::new()))
        }

        // AES Key Wrap.
        JweAlgorithm::A128KW | JweAlgorithm::A192KW | JweAlgorithm::A256KW => {
            check_kek_size(alg, key)?;
            let kw_alg = jwe_alg_to_keywrap(alg)?;
            let cek = Zeroizing::new(random_bytes(cek_len));
            let wrapped =
                kryptering::keywrap::wrap(kw_alg, key, &cek).map_err(JoseError::Crypto)?;
            Ok((cek, wrapped))
        }

        // RSA-OAEP.
        JweAlgorithm::RsaOaep256 => {
            let pub_key = parse_rsa_public_key(key)?;
            let kt_alg = jwe_alg_to_keytransport(alg)?;
            let cek = Zeroizing::new(random_bytes(cek_len));
            let encrypted = kryptering::keytransport::kt_encrypt(kt_alg, &pub_key, &cek, None)
                .map_err(JoseError::Crypto)?;
            Ok((cek, encrypted))
        }

        #[cfg(feature = "deprecated")]
        JweAlgorithm::RsaOaep => {
            let pub_key = parse_rsa_public_key(key)?;
            let kt_alg = jwe_alg_to_keytransport(alg)?;
            let cek = Zeroizing::new(random_bytes(cek_len));
            let encrypted = kryptering::keytransport::kt_encrypt(kt_alg, &pub_key, &cek, None)
                .map_err(JoseError::Crypto)?;
            Ok((cek, encrypted))
        }

        _ => Err(JoseError::UnsupportedAlgorithm(format!(
            "key management algorithm {} not yet implemented",
            alg.as_str()
        ))),
    }
}

// ---------------------------------------------------------------------------
// Key management: recover CEK (decrypt side)
// ---------------------------------------------------------------------------

fn recover_cek(
    key: &[u8],
    alg: JweAlgorithm,
    enc: JweEncryption,
    encrypted_key: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let cek_len = enc.cek_size();

    match alg {
        JweAlgorithm::Dir => {
            if !encrypted_key.is_empty() {
                return Err(JoseError::InvalidToken(
                    "dir: encrypted key must be empty".into(),
                ));
            }
            if key.len() != cek_len {
                return Err(JoseError::Key(format!(
                    "dir: key length {} does not match required CEK size {}",
                    key.len(),
                    cek_len
                )));
            }
            Ok(Zeroizing::new(key.to_vec()))
        }

        JweAlgorithm::A128KW | JweAlgorithm::A192KW | JweAlgorithm::A256KW => {
            check_kek_size(alg, key)?;
            let kw_alg = jwe_alg_to_keywrap(alg)?;
            let cek = Zeroizing::new(
                kryptering::keywrap::unwrap(kw_alg, key, encrypted_key)
                    .map_err(JoseError::Crypto)?,
            );
            if cek.len() != cek_len {
                return Err(JoseError::Key(format!(
                    "unwrapped CEK length {} does not match expected {}",
                    cek.len(),
                    cek_len
                )));
            }
            Ok(cek)
        }

        JweAlgorithm::RsaOaep256 => rsa_oaep_recover_cek(key, alg, encrypted_key, cek_len),

        #[cfg(feature = "deprecated")]
        JweAlgorithm::RsaOaep => rsa_oaep_recover_cek(key, alg, encrypted_key, cek_len),

        _ => Err(JoseError::UnsupportedAlgorithm(format!(
            "key management algorithm {} not yet implemented",
            alg.as_str()
        ))),
    }
}

/// Shared RSA-OAEP CEK recovery (used by both RSA-OAEP-256 and the deprecated
/// SHA-1 RSA-OAEP variant). Post-decrypt error paths are deliberately merged
/// into a single opaque error to avoid distinguishable oracles. The recovered
/// CEK is wrapped in `Zeroizing` so it is wiped when dropped.
fn rsa_oaep_recover_cek(
    key: &[u8],
    alg: JweAlgorithm,
    encrypted_key: &[u8],
    cek_len: usize,
) -> Result<Zeroizing<Vec<u8>>> {
    let priv_key = parse_rsa_private_key(key)?;
    let kt_alg = jwe_alg_to_keytransport(alg)?;
    let cek_result = kryptering::keytransport::kt_decrypt(kt_alg, &priv_key, encrypted_key, None);
    let opaque_err = || {
        JoseError::Crypto(kryptering::Error::Crypto(
            "RSA-OAEP key unwrap failed".into(),
        ))
    };
    let cek = Zeroizing::new(cek_result.map_err(|_| opaque_err())?);
    if cek.len() != cek_len {
        return Err(opaque_err());
    }
    Ok(cek)
}

// ---------------------------------------------------------------------------
// Content encryption
// ---------------------------------------------------------------------------

/// Encrypt plaintext and return `(iv, ciphertext, tag)`.
fn content_encrypt(
    enc: JweEncryption,
    cek: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    match enc {
        JweEncryption::A128GCM | JweEncryption::A192GCM | JweEncryption::A256GCM => {
            aes_gcm_encrypt(cek, plaintext, aad)
        }
        JweEncryption::A128CbcHs256 | JweEncryption::A192CbcHs384 | JweEncryption::A256CbcHs512 => {
            aes_cbc_hs_encrypt(enc, cek, plaintext, aad)
        }
    }
}

/// Decrypt and return plaintext.
fn content_decrypt(
    enc: JweEncryption,
    cek: &[u8],
    iv: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    match enc {
        JweEncryption::A128GCM | JweEncryption::A192GCM | JweEncryption::A256GCM => {
            aes_gcm_decrypt(cek, iv, ciphertext, tag, aad)
        }
        JweEncryption::A128CbcHs256 | JweEncryption::A192CbcHs384 | JweEncryption::A256CbcHs512 => {
            aes_cbc_hs_decrypt(enc, cek, iv, ciphertext, tag, aad)
        }
    }
}

// ---------------------------------------------------------------------------
// AES-GCM content encryption (RFC 7518 Section 5.3)
// ---------------------------------------------------------------------------

fn aes_gcm_encrypt(
    cek: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    use aes_gcm::aead::AeadInPlace;
    use aes_gcm::{KeyInit, Nonce};

    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let mut buffer = plaintext.to_vec();

    let gcm_err =
        |e: aes_gcm::Error| JoseError::Crypto(kryptering::Error::Crypto(format!("AES-GCM: {e}")));
    let key_err = |e| JoseError::Key(format!("AES-GCM key init: {e}"));

    let tag_bytes = match cek.len() {
        16 => {
            let cipher = aes_gcm::Aes128Gcm::new_from_slice(cek).map_err(key_err)?;
            cipher
                .encrypt_in_place_detached(nonce, aad, &mut buffer)
                .map_err(gcm_err)?
        }
        24 => {
            use aes_gcm::aead::consts::U12;
            let cipher =
                aes_gcm::AesGcm::<aes::Aes192, U12>::new_from_slice(cek).map_err(key_err)?;
            cipher
                .encrypt_in_place_detached(nonce, aad, &mut buffer)
                .map_err(gcm_err)?
        }
        32 => {
            let cipher = aes_gcm::Aes256Gcm::new_from_slice(cek).map_err(key_err)?;
            cipher
                .encrypt_in_place_detached(nonce, aad, &mut buffer)
                .map_err(gcm_err)?
        }
        other => {
            return Err(JoseError::Key(format!("invalid AES-GCM key size: {other}")));
        }
    };

    Ok((nonce_bytes.to_vec(), buffer, tag_bytes.to_vec()))
}

fn aes_gcm_decrypt(
    cek: &[u8],
    iv: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    use aes_gcm::aead::AeadInPlace;
    use aes_gcm::{KeyInit, Nonce, Tag};

    if iv.len() != 12 {
        return Err(JoseError::InvalidToken(format!(
            "AES-GCM IV must be 12 bytes, got {}",
            iv.len()
        )));
    }
    if tag.len() != 16 {
        return Err(JoseError::InvalidToken(format!(
            "AES-GCM tag must be 16 bytes, got {}",
            tag.len()
        )));
    }

    let nonce = Nonce::from_slice(iv);
    let auth_tag = Tag::from_slice(tag);
    let mut buffer = ciphertext.to_vec();

    let auth_fail = || {
        JoseError::Crypto(kryptering::Error::Crypto(
            "AES-GCM authentication failed".into(),
        ))
    };
    let key_err = |e| JoseError::Key(format!("AES-GCM key init: {e}"));

    match cek.len() {
        16 => {
            let cipher = aes_gcm::Aes128Gcm::new_from_slice(cek).map_err(key_err)?;
            cipher
                .decrypt_in_place_detached(nonce, aad, &mut buffer, auth_tag)
                .map_err(|_| auth_fail())?;
        }
        24 => {
            use aes_gcm::aead::consts::U12;
            let cipher =
                aes_gcm::AesGcm::<aes::Aes192, U12>::new_from_slice(cek).map_err(key_err)?;
            cipher
                .decrypt_in_place_detached(nonce, aad, &mut buffer, auth_tag)
                .map_err(|_| auth_fail())?;
        }
        32 => {
            let cipher = aes_gcm::Aes256Gcm::new_from_slice(cek).map_err(key_err)?;
            cipher
                .decrypt_in_place_detached(nonce, aad, &mut buffer, auth_tag)
                .map_err(|_| auth_fail())?;
        }
        other => {
            return Err(JoseError::Key(format!("invalid AES-GCM key size: {other}")));
        }
    }

    Ok(buffer)
}

// ---------------------------------------------------------------------------
// AES-CBC-HS content encryption (RFC 7518 Section 5.2)
// ---------------------------------------------------------------------------

/// Returns `(aes_key_size_bytes, hmac_tag_truncation_bytes)` for each variant.
fn cbc_hs_params(enc: JweEncryption) -> (usize, usize) {
    match enc {
        JweEncryption::A128CbcHs256 => (16, 16), // AES-128, HMAC-SHA-256, tag = 16
        JweEncryption::A192CbcHs384 => (24, 24), // AES-192, HMAC-SHA-384, tag = 24
        JweEncryption::A256CbcHs512 => (32, 32), // AES-256, HMAC-SHA-512, tag = 32
        _ => unreachable!(),
    }
}

fn aes_cbc_hs_encrypt(
    enc: JweEncryption,
    cek: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let (aes_key_size, tag_len) = cbc_hs_params(enc);
    let expected_cek_len = aes_key_size * 2; // CEK = MAC_KEY || ENC_KEY

    if cek.len() != expected_cek_len {
        return Err(JoseError::Key(format!(
            "AES-CBC-HS: expected {} byte CEK, got {}",
            expected_cek_len,
            cek.len()
        )));
    }

    // Split CEK: first half is MAC key, second half is encryption key.
    let mac_key = &cek[..aes_key_size];
    let enc_key = &cek[aes_key_size..];

    // Generate random 128-bit IV.
    let mut iv = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut iv);

    // PKCS#7 pad and encrypt with AES-CBC.
    let ciphertext = aes_cbc_encrypt_raw(enc_key, &iv, plaintext)?;

    // Compute HMAC tag: HMAC(AAD || IV || ciphertext || AAD_len_bits).
    let tag = compute_cbc_hs_tag(enc, mac_key, aad, &iv, &ciphertext, tag_len)?;

    Ok((iv.to_vec(), ciphertext, tag))
}

fn aes_cbc_hs_decrypt(
    enc: JweEncryption,
    cek: &[u8],
    iv: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    let (aes_key_size, tag_len) = cbc_hs_params(enc);
    let expected_cek_len = aes_key_size * 2;

    if cek.len() != expected_cek_len {
        return Err(JoseError::Key(format!(
            "AES-CBC-HS: expected {} byte CEK, got {}",
            expected_cek_len,
            cek.len()
        )));
    }

    if iv.len() != 16 {
        return Err(JoseError::InvalidToken(format!(
            "AES-CBC IV must be 16 bytes, got {}",
            iv.len()
        )));
    }

    let mac_key = &cek[..aes_key_size];
    let enc_key = &cek[aes_key_size..];

    // Verify HMAC tag first (encrypt-then-MAC: verify before decrypting).
    let expected_tag = compute_cbc_hs_tag(enc, mac_key, aad, iv, ciphertext, tag_len)?;

    // Constant-time comparison.
    if !constant_time_eq(tag, &expected_tag) {
        return Err(JoseError::Crypto(kryptering::Error::Crypto(
            "AES-CBC-HS authentication tag mismatch".into(),
        )));
    }

    // Decrypt AES-CBC and remove PKCS#7 padding.
    aes_cbc_decrypt_raw(enc_key, iv, ciphertext)
}

/// Compute the HMAC authentication tag for AES-CBC-HS (RFC 7518 Section 5.2.2).
///
/// Input to HMAC: AAD || IV || ciphertext || AAD_len_in_bits (big-endian u64).
fn compute_cbc_hs_tag(
    enc: JweEncryption,
    mac_key: &[u8],
    aad: &[u8],
    iv: &[u8],
    ciphertext: &[u8],
    tag_len: usize,
) -> Result<Vec<u8>> {
    use hmac::Mac;

    // AAD length in bits as big-endian u64.
    let aad_len_bits = (aad.len() as u64) * 8;
    let al = aad_len_bits.to_be_bytes();

    let full_mac = match enc {
        JweEncryption::A128CbcHs256 => {
            let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(mac_key)
                .map_err(|e| JoseError::Key(format!("HMAC init: {e}")))?;
            mac.update(aad);
            mac.update(iv);
            mac.update(ciphertext);
            mac.update(&al);
            mac.finalize().into_bytes().to_vec()
        }
        JweEncryption::A192CbcHs384 => {
            let mut mac = hmac::Hmac::<sha2::Sha384>::new_from_slice(mac_key)
                .map_err(|e| JoseError::Key(format!("HMAC init: {e}")))?;
            mac.update(aad);
            mac.update(iv);
            mac.update(ciphertext);
            mac.update(&al);
            mac.finalize().into_bytes().to_vec()
        }
        JweEncryption::A256CbcHs512 => {
            let mut mac = hmac::Hmac::<sha2::Sha512>::new_from_slice(mac_key)
                .map_err(|e| JoseError::Key(format!("HMAC init: {e}")))?;
            mac.update(aad);
            mac.update(iv);
            mac.update(ciphertext);
            mac.update(&al);
            mac.finalize().into_bytes().to_vec()
        }
        _ => unreachable!(),
    };

    // Authentication tag = first tag_len bytes of HMAC output.
    Ok(full_mac[..tag_len].to_vec())
}

// ---------------------------------------------------------------------------
// Raw AES-CBC helpers (PKCS#7 padding)
// ---------------------------------------------------------------------------

fn aes_cbc_encrypt_raw(key: &[u8], iv: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    use cbc::cipher::{BlockEncryptMut, KeyIvInit};

    let padded = pkcs7_pad(plaintext, 16);
    let padded_len = padded.len();
    let mut buf = padded;

    macro_rules! do_encrypt {
        ($aes:ty) => {{
            let enc = cbc::Encryptor::<$aes>::new_from_slices(key, iv)
                .map_err(|e| JoseError::Key(format!("AES-CBC init: {e}")))?;
            enc.encrypt_padded_mut::<cbc::cipher::block_padding::NoPadding>(&mut buf, padded_len)
                .map_err(|e| {
                    JoseError::Crypto(kryptering::Error::Crypto(format!("AES-CBC encrypt: {e}")))
                })?;
        }};
    }

    match key.len() {
        16 => do_encrypt!(aes::Aes128),
        24 => do_encrypt!(aes::Aes192),
        32 => do_encrypt!(aes::Aes256),
        other => {
            return Err(JoseError::Key(format!("invalid AES key size: {other}")));
        }
    }

    Ok(buf)
}

fn aes_cbc_decrypt_raw(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    use cbc::cipher::{BlockDecryptMut, KeyIvInit};

    if ciphertext.is_empty() || ciphertext.len() % 16 != 0 {
        return Err(JoseError::InvalidToken(
            "AES-CBC ciphertext length must be a multiple of 16".into(),
        ));
    }

    let mut buf = ciphertext.to_vec();

    macro_rules! do_decrypt {
        ($aes:ty) => {{
            let dec = cbc::Decryptor::<$aes>::new_from_slices(key, iv)
                .map_err(|e| JoseError::Key(format!("AES-CBC init: {e}")))?;
            dec.decrypt_padded_mut::<cbc::cipher::block_padding::NoPadding>(&mut buf)
                .map_err(|e| {
                    JoseError::Crypto(kryptering::Error::Crypto(format!("AES-CBC decrypt: {e}")))
                })?;
        }};
    }

    match key.len() {
        16 => do_decrypt!(aes::Aes128),
        24 => do_decrypt!(aes::Aes192),
        32 => do_decrypt!(aes::Aes256),
        other => {
            return Err(JoseError::Key(format!("invalid AES key size: {other}")));
        }
    }

    pkcs7_unpad(&buf)
}

/// Apply PKCS#7 padding.
fn pkcs7_pad(data: &[u8], block_size: usize) -> Vec<u8> {
    let pad_len = block_size - (data.len() % block_size);
    let mut padded = Vec::with_capacity(data.len() + pad_len);
    padded.extend_from_slice(data);
    padded.extend(std::iter::repeat_n(pad_len as u8, pad_len));
    padded
}

/// Remove PKCS#7 padding.
///
/// The padding bytes are validated in constant time over a fixed 16-byte
/// window — the decision about padding validity does not branch on the
/// trailing-byte value once the input length is known. Mitigated further
/// upstream by encrypt-then-MAC (HMAC is verified before this function
/// runs), but kept constant-time as defence in depth.
fn pkcs7_unpad(data: &[u8]) -> Result<Vec<u8>> {
    use subtle::ConstantTimeEq;

    const BLOCK: usize = 16;

    // Structural checks on the *length* of the buffer are not secret-dependent
    // (the attacker already controls the ciphertext length) and are safe to
    // branch on.
    if data.is_empty() || data.len() % BLOCK != 0 {
        return Err(JoseError::Crypto(kryptering::Error::Crypto(
            "invalid PKCS#7 padding".into(),
        )));
    }

    let pad_byte = *data.last().unwrap();
    let pad_len_u = pad_byte as u16;

    // `good` accumulates validity as 0xFF (valid) or 0x00 (invalid).
    let mut good: u8 = 0xFF;

    // Branch-free length check. pad_len is valid iff 1 <= pad_byte <= BLOCK.
    //   is_zero_bit : 1 iff pad_byte == 0     (from top bit of (p - 1))
    //   over_block_bit : 1 iff pad_byte > BLOCK  (top bit of ((BLOCK + 1) - 1 - p) after widening)
    let is_zero_bit: u16 = pad_len_u.wrapping_sub(1) >> 15;
    let over_block_bit: u16 = ((BLOCK as u16).wrapping_sub(pad_len_u)) >> 15;
    let invalid_bit: u16 = is_zero_bit | over_block_bit;
    let invalid_mask: u8 = 0u8.wrapping_sub(invalid_bit as u8);
    good &= !invalid_mask;

    // Compare every byte of the final block against pad_byte. For positions
    // whose distance from the end is strictly less than pad_len, the byte
    // MUST equal pad_byte; otherwise the comparison contributes nothing.
    let last_block = &data[data.len() - BLOCK..];
    for (i, &b) in last_block.iter().enumerate() {
        // distance_from_end in [1, BLOCK].
        let dist = (BLOCK - i) as u16;
        // in_region mask: 0xFF iff dist <= pad_len, else 0x00. Branch-free:
        // dist - pad_len - 1 underflows (top bit = 1) when dist <= pad_len.
        let in_region_bit: u16 = (dist.wrapping_sub(pad_len_u).wrapping_sub(1)) >> 15;
        let in_region: u8 = 0u8.wrapping_sub(in_region_bit as u8);

        // ct_eq → Choice → 0/1 → full-byte mask.
        let eq_bit = b.ct_eq(&pad_byte).unwrap_u8();
        let eq_mask: u8 = 0u8.wrapping_sub(eq_bit);

        // Contribution is 0xFF unless we're in the region AND the byte disagrees.
        let contribution = !in_region | eq_mask;
        good &= contribution;
    }

    if good != 0xFF {
        return Err(JoseError::Crypto(kryptering::Error::Crypto(
            "invalid PKCS#7 padding".into(),
        )));
    }
    Ok(data[..data.len() - pad_byte as usize].to_vec())
}

// ---------------------------------------------------------------------------
// Algorithm mapping helpers
// ---------------------------------------------------------------------------

/// Verify that the supplied Key Encryption Key is exactly the size
/// demanded by the declared AES Key Wrap algorithm.
///
/// Prevents silent acceptance of a 32-byte key for `A128KW` (or similar
/// mis-sized KEKs) if the underlying crypto backend does not validate
/// strictly.
fn check_kek_size(alg: JweAlgorithm, key: &[u8]) -> Result<()> {
    let expected = match alg {
        JweAlgorithm::A128KW => 16,
        JweAlgorithm::A192KW => 24,
        JweAlgorithm::A256KW => 32,
        _ => return Ok(()),
    };
    if key.len() != expected {
        return Err(JoseError::Key(format!(
            "{}: KEK must be {} bytes, got {}",
            alg.as_str(),
            expected,
            key.len()
        )));
    }
    Ok(())
}

fn jwe_alg_to_keywrap(alg: JweAlgorithm) -> Result<kryptering::KeyWrapAlgorithm> {
    use kryptering::{AesKeySize, KeyWrapAlgorithm};
    match alg {
        JweAlgorithm::A128KW => Ok(KeyWrapAlgorithm::AesKw(AesKeySize::Aes128)),
        JweAlgorithm::A192KW => Ok(KeyWrapAlgorithm::AesKw(AesKeySize::Aes192)),
        JweAlgorithm::A256KW => Ok(KeyWrapAlgorithm::AesKw(AesKeySize::Aes256)),
        _ => Err(JoseError::UnsupportedAlgorithm(format!(
            "{} is not a key wrap algorithm",
            alg.as_str()
        ))),
    }
}

fn jwe_alg_to_keytransport(alg: JweAlgorithm) -> Result<kryptering::KeyTransportAlgorithm> {
    use kryptering::{HashAlgorithm, KeyTransportAlgorithm, OaepConfig};
    match alg {
        #[cfg(feature = "deprecated")]
        JweAlgorithm::RsaOaep => Ok(KeyTransportAlgorithm::RsaOaep(OaepConfig {
            digest: HashAlgorithm::Sha1,
            mgf_digest: HashAlgorithm::Sha1,
        })),
        JweAlgorithm::RsaOaep256 => Ok(KeyTransportAlgorithm::RsaOaep(OaepConfig {
            digest: HashAlgorithm::Sha256,
            mgf_digest: HashAlgorithm::Sha256,
        })),
        _ => Err(JoseError::UnsupportedAlgorithm(format!(
            "{} is not a key transport algorithm",
            alg.as_str()
        ))),
    }
}

// ---------------------------------------------------------------------------
// RSA key parsing
// ---------------------------------------------------------------------------

fn parse_rsa_public_key(der: &[u8]) -> Result<rsa::RsaPublicKey> {
    use rsa::pkcs8::DecodePublicKey;
    use rsa::traits::PublicKeyParts;
    let key = rsa::RsaPublicKey::from_public_key_der(der)
        .map_err(|e| JoseError::Key(format!("failed to parse RSA public key DER: {e}")))?;
    if key.n().bits() < crate::MIN_RSA_BITS {
        return Err(JoseError::Key(format!(
            "RSA key size {} bits is below the required minimum of {}",
            key.n().bits(),
            crate::MIN_RSA_BITS
        )));
    }
    Ok(key)
}

fn parse_rsa_private_key(der: &[u8]) -> Result<rsa::RsaPrivateKey> {
    use rsa::pkcs8::DecodePrivateKey;
    use rsa::traits::PublicKeyParts;
    let key = rsa::RsaPrivateKey::from_pkcs8_der(der)
        .map_err(|e| JoseError::Key(format!("failed to parse RSA private key PKCS#8 DER: {e}")))?;
    if key.n().bits() < crate::MIN_RSA_BITS {
        return Err(JoseError::Key(format!(
            "RSA key size {} bits is below the required minimum of {}",
            key.n().bits(),
            crate::MIN_RSA_BITS
        )));
    }
    Ok(key)
}

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

fn random_bytes(len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    rand::thread_rng().fill_bytes(&mut buf);
    buf
}

/// Constant-time byte comparison to prevent timing attacks on HMAC tags.
///
/// Uses the audited `subtle` crate. The length-inequality branch is safe
/// because HMAC tag lengths are fixed per `enc` algorithm — mismatched
/// lengths indicate a malformed token, not a secret-dependent value.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::algorithm::{JweAlgorithm, JweEncryption};

    // -- dir + AES-GCM roundtrips --

    #[test]
    fn dir_a256gcm_roundtrip() {
        let cek = [0x42u8; 32]; // 256-bit CEK for A256GCM
        let plaintext = b"Hello, JWE world!";

        let token = encrypt(&cek, plaintext, JweAlgorithm::Dir, JweEncryption::A256GCM).unwrap();

        // Should have 5 dot-separated parts.
        assert_eq!(token.split('.').count(), 5);

        // Encrypted key part should be empty for dir.
        let parts: Vec<&str> = token.splitn(5, '.').collect();
        assert_eq!(parts[1], "", "dir: encrypted key must be empty");

        let recovered = decrypt(&cek, &token).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn dir_a128gcm_roundtrip() {
        let cek = [0x33u8; 16];
        let plaintext = b"AES-128-GCM test";

        let token = encrypt(&cek, plaintext, JweAlgorithm::Dir, JweEncryption::A128GCM).unwrap();
        let recovered = decrypt(&cek, &token).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn dir_a192gcm_roundtrip() {
        let cek = [0x55u8; 24];
        let plaintext = b"AES-192-GCM test";

        let token = encrypt(&cek, plaintext, JweAlgorithm::Dir, JweEncryption::A192GCM).unwrap();
        let recovered = decrypt(&cek, &token).unwrap();
        assert_eq!(recovered, plaintext);
    }

    // -- AES Key Wrap + AES-GCM roundtrips --

    #[test]
    fn a256kw_a128gcm_roundtrip() {
        let kek = [0xABu8; 32]; // 256-bit KEK
        let plaintext = b"Wrapped key encryption test";

        let token = encrypt(
            &kek,
            plaintext,
            JweAlgorithm::A256KW,
            JweEncryption::A128GCM,
        )
        .unwrap();

        // Encrypted key part must not be empty for key wrapping.
        let parts: Vec<&str> = token.splitn(5, '.').collect();
        assert!(
            !parts[1].is_empty(),
            "A256KW: encrypted key must not be empty"
        );

        let recovered = decrypt(&kek, &token).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn a128kw_a256gcm_roundtrip() {
        let kek = [0xCDu8; 16]; // 128-bit KEK
        let plaintext = b"A128KW + A256GCM";

        let token = encrypt(
            &kek,
            plaintext,
            JweAlgorithm::A128KW,
            JweEncryption::A256GCM,
        )
        .unwrap();
        let recovered = decrypt(&kek, &token).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn a192kw_a256gcm_roundtrip() {
        let kek = [0xEFu8; 24]; // 192-bit KEK
        let plaintext = b"A192KW + A256GCM";

        let token = encrypt(
            &kek,
            plaintext,
            JweAlgorithm::A192KW,
            JweEncryption::A256GCM,
        )
        .unwrap();
        let recovered = decrypt(&kek, &token).unwrap();
        assert_eq!(recovered, plaintext);
    }

    // -- RSA-OAEP + AES-GCM roundtrips --

    fn generate_rsa_keypair() -> (Vec<u8>, Vec<u8>) {
        use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey};
        let mut rng = rand::thread_rng();
        let private_key = rsa::RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let public_key = rsa::RsaPublicKey::from(&private_key);

        let pub_der = public_key.to_public_key_der().unwrap();
        let priv_der = private_key.to_pkcs8_der().unwrap();

        (pub_der.as_ref().to_vec(), priv_der.as_bytes().to_vec())
    }

    #[cfg(feature = "deprecated")]
    #[test]
    fn rsa_oaep_a256gcm_roundtrip() {
        let (pub_der, priv_der) = generate_rsa_keypair();
        let plaintext = b"RSA-OAEP encrypted message";

        let token = encrypt(
            &pub_der,
            plaintext,
            JweAlgorithm::RsaOaep,
            JweEncryption::A256GCM,
        )
        .unwrap();
        let recovered = decrypt(&priv_der, &token).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn rsa_oaep_256_a256gcm_roundtrip() {
        let (pub_der, priv_der) = generate_rsa_keypair();
        let plaintext = b"RSA-OAEP-256 encrypted message";

        let token = encrypt(
            &pub_der,
            plaintext,
            JweAlgorithm::RsaOaep256,
            JweEncryption::A256GCM,
        )
        .unwrap();
        let recovered = decrypt(&priv_der, &token).unwrap();
        assert_eq!(recovered, plaintext);
    }

    // -- AES-CBC-HS roundtrips --

    #[test]
    fn a128cbc_hs256_roundtrip() {
        let cek = [0x42u8; 32]; // 32-byte CEK: 16 HMAC + 16 AES
        let plaintext = b"AES-128-CBC-HS256 test";

        let token = encrypt(
            &cek,
            plaintext,
            JweAlgorithm::Dir,
            JweEncryption::A128CbcHs256,
        )
        .unwrap();
        let recovered = decrypt(&cek, &token).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn a192cbc_hs384_roundtrip() {
        let cek = [0x55u8; 48]; // 48-byte CEK: 24 HMAC + 24 AES
        let plaintext = b"AES-192-CBC-HS384 test";

        let token = encrypt(
            &cek,
            plaintext,
            JweAlgorithm::Dir,
            JweEncryption::A192CbcHs384,
        )
        .unwrap();
        let recovered = decrypt(&cek, &token).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn a256cbc_hs512_roundtrip() {
        let cek = [0x77u8; 64]; // 64-byte CEK: 32 HMAC + 32 AES
        let plaintext = b"AES-256-CBC-HS512 test";

        let token = encrypt(
            &cek,
            plaintext,
            JweAlgorithm::Dir,
            JweEncryption::A256CbcHs512,
        )
        .unwrap();
        let recovered = decrypt(&cek, &token).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn a256kw_a128cbc_hs256_roundtrip() {
        let kek = [0xBBu8; 32]; // 256-bit KEK
        let plaintext = b"Key-wrapped CBC-HS test";

        let token = encrypt(
            &kek,
            plaintext,
            JweAlgorithm::A256KW,
            JweEncryption::A128CbcHs256,
        )
        .unwrap();
        let recovered = decrypt(&kek, &token).unwrap();
        assert_eq!(recovered, plaintext);
    }

    // -- Error cases --

    #[test]
    fn wrong_key_fails_decryption_gcm() {
        let key1 = [0x42u8; 32];
        let key2 = [0x99u8; 32];
        let plaintext = b"secret data";

        let token = encrypt(&key1, plaintext, JweAlgorithm::Dir, JweEncryption::A256GCM).unwrap();
        let result = decrypt(&key2, &token);
        assert!(result.is_err(), "decryption with wrong key should fail");
    }

    #[test]
    fn wrong_key_fails_decryption_cbc_hs() {
        let key1 = [0x42u8; 32];
        let key2 = [0x99u8; 32];
        let plaintext = b"secret data";

        let token = encrypt(
            &key1,
            plaintext,
            JweAlgorithm::Dir,
            JweEncryption::A128CbcHs256,
        )
        .unwrap();
        let result = decrypt(&key2, &token);
        assert!(result.is_err(), "decryption with wrong key should fail");
    }

    #[test]
    fn malformed_token_returns_error() {
        let key = [0x42u8; 32];

        // Too few parts.
        let result = decrypt(&key, "one.two.three");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("5 dot-separated parts"),
            "unexpected error: {err}"
        );

        // Empty string.
        let result = decrypt(&key, "");
        assert!(result.is_err());
    }

    #[test]
    fn tampered_ciphertext_fails_gcm() {
        let key = [0x42u8; 32];
        let plaintext = b"integrity test";

        let token = encrypt(&key, plaintext, JweAlgorithm::Dir, JweEncryption::A256GCM).unwrap();

        // Tamper with the ciphertext part (fourth segment).
        let parts: Vec<&str> = token.splitn(5, '.').collect();
        let mut ct_bytes = base64url::decode(parts[3]).unwrap();
        if !ct_bytes.is_empty() {
            ct_bytes[0] ^= 0xFF;
        }
        let tampered_ct = base64url::encode(&ct_bytes);
        let tampered_token = format!(
            "{}.{}.{}.{}.{}",
            parts[0], parts[1], parts[2], tampered_ct, parts[4]
        );

        let result = decrypt(&key, &tampered_token);
        assert!(result.is_err(), "tampered ciphertext should fail GCM auth");
    }

    #[test]
    fn tampered_ciphertext_fails_cbc_hs() {
        let key = [0x42u8; 64];
        let plaintext = b"integrity test cbc";

        let token = encrypt(
            &key,
            plaintext,
            JweAlgorithm::Dir,
            JweEncryption::A256CbcHs512,
        )
        .unwrap();

        // Tamper with the ciphertext part (fourth segment).
        let parts: Vec<&str> = token.splitn(5, '.').collect();
        let mut ct_bytes = base64url::decode(parts[3]).unwrap();
        if !ct_bytes.is_empty() {
            ct_bytes[0] ^= 0xFF;
        }
        let tampered_ct = base64url::encode(&ct_bytes);
        let tampered_token = format!(
            "{}.{}.{}.{}.{}",
            parts[0], parts[1], parts[2], tampered_ct, parts[4]
        );

        let result = decrypt(&key, &tampered_token);
        assert!(
            result.is_err(),
            "tampered ciphertext should fail CBC-HS auth"
        );
    }

    #[test]
    fn dir_wrong_cek_size_fails() {
        let key = [0x42u8; 15]; // Wrong size for any algorithm
        let plaintext = b"test";

        let result = encrypt(&key, plaintext, JweAlgorithm::Dir, JweEncryption::A256GCM);
        assert!(result.is_err());
    }

    #[test]
    fn decode_header_works() {
        let cek = [0x42u8; 32];
        let plaintext = b"header test";

        let token = encrypt(&cek, plaintext, JweAlgorithm::Dir, JweEncryption::A256GCM).unwrap();

        let header = decode_header(&token).unwrap();
        assert_eq!(header.alg, "dir");
        assert_eq!(header.enc.as_deref(), Some("A256GCM"));
    }

    #[test]
    fn empty_plaintext_roundtrip() {
        let cek = [0x42u8; 32];
        let plaintext = b"";

        let token = encrypt(&cek, plaintext, JweAlgorithm::Dir, JweEncryption::A256GCM).unwrap();
        let recovered = decrypt(&cek, &token).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn large_plaintext_roundtrip() {
        let cek = [0x42u8; 32];
        let plaintext: Vec<u8> = (0..10_000).map(|i| (i % 256) as u8).collect();

        let token = encrypt(&cek, &plaintext, JweAlgorithm::Dir, JweEncryption::A256GCM).unwrap();
        let recovered = decrypt(&cek, &token).unwrap();
        assert_eq!(recovered, plaintext);
    }

    /// Phase 9: encrypt_with_jwk + decrypt_with_jwk roundtrip, dir + A256GCM.
    #[test]
    fn jwk_dir_roundtrip() {
        let mut jwk = crate::jwk::generate_symmetric(32).unwrap();
        jwk.alg = Some("dir".into());
        let plaintext = b"jwk-dir";

        let token = encrypt_with_jwk(&jwk, plaintext, JweEncryption::A256GCM).unwrap();
        let recovered = decrypt_with_jwk(&jwk, &token).unwrap();
        assert_eq!(recovered, plaintext);
    }

    /// Phase 9: encrypt_with_jwk + decrypt_with_jwk roundtrip, A256KW + A128GCM.
    #[test]
    fn jwk_aes_kw_roundtrip() {
        let mut jwk = crate::jwk::generate_symmetric(32).unwrap();
        jwk.alg = Some("A256KW".into());
        let plaintext = b"jwk-a256kw";

        let token = encrypt_with_jwk(&jwk, plaintext, JweEncryption::A128GCM).unwrap();
        let recovered = decrypt_with_jwk(&jwk, &token).unwrap();
        assert_eq!(recovered, plaintext);
    }

    /// Phase 9: encrypt_with_jwk + decrypt_with_jwk roundtrip, RSA-OAEP-256.
    #[test]
    fn jwk_rsa_oaep_roundtrip() {
        let mut jwk = crate::jwk::generate_rsa(2048).unwrap();
        jwk.alg = Some("RSA-OAEP-256".into());
        let plaintext = b"jwk-rsa-oaep";

        let token = encrypt_with_jwk(&jwk, plaintext, JweEncryption::A256GCM).unwrap();
        let recovered = decrypt_with_jwk(&jwk, &token).unwrap();
        assert_eq!(recovered, plaintext);
    }

    /// Phase 9: encrypt_with_jwk rejects JWK with no alg.
    #[test]
    fn jwk_encrypt_requires_alg() {
        let jwk = crate::jwk::generate_symmetric(32).unwrap();
        let err = encrypt_with_jwk(&jwk, b"p", JweEncryption::A256GCM)
            .unwrap_err()
            .to_string();
        assert!(err.contains("alg must be set"), "unexpected: {err}");
    }

    /// Phase 9: encrypt_with_jwk honours use="sig" → reject.
    #[test]
    fn jwk_encrypt_rejects_use_sig() {
        let mut jwk = crate::jwk::generate_symmetric(32).unwrap();
        jwk.alg = Some("dir".into());
        jwk.use_ = Some("sig".into());
        let err = encrypt_with_jwk(&jwk, b"p", JweEncryption::A256GCM)
            .unwrap_err()
            .to_string();
        assert!(err.contains("`use` is sig"), "unexpected: {err}");
    }

    /// Phase 9: decrypt_with_jwk rejects use="sig" → reject.
    #[test]
    fn jwk_decrypt_rejects_use_sig() {
        let mut jwk = crate::jwk::generate_symmetric(32).unwrap();
        jwk.alg = Some("dir".into());
        // Encrypt using raw bytes to build a token, then flip use before decrypt.
        let k = crate::base64url::decode(jwk.k.as_ref().unwrap()).unwrap();
        let token = encrypt(&k, b"p", JweAlgorithm::Dir, JweEncryption::A256GCM).unwrap();

        jwk.use_ = Some("sig".into());
        let err = decrypt_with_jwk(&jwk, &token).unwrap_err().to_string();
        assert!(err.contains("`use` is sig"), "unexpected: {err}");
    }

    /// Phase 9: decrypt_with_jwk rejects alg mismatch between JWK and token.
    #[test]
    fn jwk_decrypt_pinned_alg_mismatch() {
        // Encrypt with dir, but JWK claims A256KW at decrypt time.
        let jwk_bytes = crate::jwk::generate_symmetric(32).unwrap();
        let k = crate::base64url::decode(jwk_bytes.k.as_ref().unwrap()).unwrap();
        let token = encrypt(&k, b"p", JweAlgorithm::Dir, JweEncryption::A256GCM).unwrap();

        let mut jwk = jwk_bytes;
        jwk.alg = Some("A256KW".into());
        let err = decrypt_with_jwk(&jwk, &token).unwrap_err().to_string();
        assert!(
            err.contains("does not match token header alg"),
            "unexpected: {err}"
        );
    }

    /// Phase 3: oversized JWE tokens are rejected before any decoding.
    #[test]
    fn oversize_jwe_token_is_rejected() {
        let big = "a".repeat(crate::MAX_TOKEN_BYTES + 1);
        let cek = [0x42u8; 32];
        let err = decrypt(&cek, &big).unwrap_err().to_string();
        assert!(err.contains("MAX_TOKEN_BYTES"), "unexpected error: {err}");
    }

    #[test]
    fn oversize_jwe_decode_header_is_rejected() {
        let big = "a".repeat(crate::MAX_TOKEN_BYTES + 1);
        let err = decode_header(&big).unwrap_err().to_string();
        assert!(err.contains("MAX_TOKEN_BYTES"), "unexpected error: {err}");
    }

    /// Phase 3: A128KW rejects a 32-byte KEK.
    #[test]
    fn a128kw_rejects_wrong_size_kek_on_encrypt() {
        let too_big = [0x11u8; 32];
        let err = encrypt(&too_big, b"p", JweAlgorithm::A128KW, JweEncryption::A128GCM)
            .unwrap_err()
            .to_string();
        assert!(err.contains("A128KW"), "unexpected error: {err}");
        assert!(err.contains("16 bytes"), "unexpected error: {err}");
    }

    /// Phase 3: A256KW rejects a 16-byte KEK.
    #[test]
    fn a256kw_rejects_wrong_size_kek_on_encrypt() {
        let too_small = [0x22u8; 16];
        let err = encrypt(
            &too_small,
            b"p",
            JweAlgorithm::A256KW,
            JweEncryption::A128GCM,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("A256KW"), "unexpected error: {err}");
        assert!(err.contains("32 bytes"), "unexpected error: {err}");
    }

    /// Phase 3: decryption also rejects a mis-sized KEK.
    #[test]
    fn aes_kw_rejects_wrong_size_kek_on_decrypt() {
        // Encrypt with a correct KEK...
        let kek = [0xABu8; 32];
        let token = encrypt(&kek, b"p", JweAlgorithm::A256KW, JweEncryption::A128GCM).unwrap();
        // ...then attempt decryption with a wrong-size key.
        let wrong_size = [0xABu8; 16];
        let err = decrypt(&wrong_size, &token).unwrap_err().to_string();
        assert!(err.contains("A256KW"), "unexpected error: {err}");
        assert!(err.contains("32 bytes"), "unexpected error: {err}");
    }

    /// Phase 2: direct unit tests for the constant-time PKCS#7 unpad implementation.
    #[test]
    fn pkcs7_unpad_valid_cases() {
        // Single block with one pad byte.
        let mut block = [0u8; 16];
        block[15] = 0x01;
        assert_eq!(pkcs7_unpad(&block).unwrap().len(), 15);

        // Single block, all padding (pad_len == 16).
        let block = [16u8; 16];
        assert_eq!(pkcs7_unpad(&block).unwrap(), b"");

        // Two blocks, pad_len = 5.
        let mut buf = [0xAAu8; 32];
        for b in &mut buf[27..] {
            *b = 5;
        }
        let out = pkcs7_unpad(&buf).unwrap();
        assert_eq!(out.len(), 27);
    }

    #[test]
    fn pkcs7_unpad_rejects_zero_pad() {
        let block = [0u8; 16]; // pad_byte = 0 → pad_len = 0 → invalid
        assert!(pkcs7_unpad(&block).is_err());
    }

    #[test]
    fn pkcs7_unpad_rejects_pad_len_over_16() {
        let mut block = [0u8; 16];
        block[15] = 17; // claims pad_len 17 in a 16-byte block
        assert!(pkcs7_unpad(&block).is_err());
    }

    #[test]
    fn pkcs7_unpad_rejects_mismatched_padding() {
        let mut block = [0u8; 16];
        // Claim pad_len = 4 but only the last byte is 4; prior bytes are 0.
        block[15] = 4;
        assert!(pkcs7_unpad(&block).is_err());
    }

    #[test]
    fn pkcs7_unpad_rejects_empty_and_non_block_aligned() {
        assert!(pkcs7_unpad(&[]).is_err());
        assert!(pkcs7_unpad(&[0u8; 15]).is_err());
    }

    /// J-09 regression: a JWE whose alg is not in the caller's allow-list is rejected.
    #[test]
    fn allow_list_rejects_wrong_alg() {
        // Token created with dir + A256GCM...
        let cek = [0x42u8; 32];
        let token = encrypt(&cek, b"p", JweAlgorithm::Dir, JweEncryption::A256GCM).unwrap();

        // ...but caller only accepts AES key-wrap algorithms.
        let options =
            JweDecryptOptions::new(vec![JweAlgorithm::A256KW], vec![JweEncryption::A256GCM]);
        let result = decrypt_with_options(&cek, &token, &options);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("allow-list"), "unexpected error: {err}");
    }

    /// J-09 regression: a JWE whose enc is not in the caller's allow-list is rejected.
    #[test]
    fn allow_list_rejects_wrong_enc() {
        // Token uses A256GCM...
        let cek = [0x42u8; 32];
        let token = encrypt(&cek, b"p", JweAlgorithm::Dir, JweEncryption::A256GCM).unwrap();

        // ...but caller only accepts CBC-HS.
        let options =
            JweDecryptOptions::new(vec![JweAlgorithm::Dir], vec![JweEncryption::A256CbcHs512]);
        let result = decrypt_with_options(&cek, &token, &options);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("allow-list"), "unexpected error: {err}");
    }

    /// J-09 regression: permitted combinations still succeed.
    #[test]
    fn allow_list_accepts_permitted() {
        let cek = [0x42u8; 32];
        let plaintext = b"allow-listed";
        let token = encrypt(&cek, plaintext, JweAlgorithm::Dir, JweEncryption::A256GCM).unwrap();

        let options = JweDecryptOptions::new(vec![JweAlgorithm::Dir], vec![JweEncryption::A256GCM]);
        let recovered = decrypt_with_options(&cek, &token, &options).unwrap();
        assert_eq!(recovered, plaintext);
    }

    /// J-04 regression: a JWE with a non-empty crit header must be rejected.
    #[test]
    fn nonempty_crit_rejected_on_decrypt() {
        let cek = [0x42u8; 32];
        let token = encrypt(&cek, b"p", JweAlgorithm::Dir, JweEncryption::A256GCM).unwrap();

        // Rewrite the header to include a non-empty crit.
        let parts: Vec<&str> = token.splitn(5, '.').collect();
        let mut header: JoseHeader =
            serde_json::from_slice(&base64url::decode(parts[0]).unwrap()).unwrap();
        header.crit = Some(vec!["myext".to_string()]);
        let new_header_b64 = base64url::encode(&serde_json::to_vec(&header).unwrap());
        let tampered_token = format!(
            "{}.{}.{}.{}.{}",
            new_header_b64, parts[1], parts[2], parts[3], parts[4]
        );

        let result = decrypt(&cek, &tampered_token);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("crit"), "unexpected error: {err}");
    }

    #[test]
    fn wrong_kek_fails_unwrap() {
        let kek1 = [0xABu8; 32];
        let kek2 = [0xCDu8; 32];
        let plaintext = b"kek test";

        let token = encrypt(
            &kek1,
            plaintext,
            JweAlgorithm::A256KW,
            JweEncryption::A128GCM,
        )
        .unwrap();
        let result = decrypt(&kek2, &token);
        assert!(result.is_err(), "wrong KEK should fail unwrap");
    }
}
