//! JWE Compact Serialization (RFC 7516 Section 3.1).
//!
//! Format: `BASE64URL(header).BASE64URL(encrypted_key).BASE64URL(iv).BASE64URL(ciphertext).BASE64URL(tag)`

use crate::algorithm::{JweAlgorithm, JweEncryption};
use crate::base64url;
use crate::error::{JoseError, Result};
use crate::header::JoseHeader;

use rand::RngCore;

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

/// Decrypt a JWE Compact Serialization string and return the plaintext.
///
/// - For `dir`: `key` is the CEK.
/// - For `A128KW` / `A192KW` / `A256KW`: `key` is the Key Encryption Key.
/// - For `RSA-OAEP` / `RSA-OAEP-256`: `key` is the RSA private key in PKCS#8
///   DER format.
pub fn decrypt(key: &[u8], token: &str) -> Result<Vec<u8>> {
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

    let alg = JweAlgorithm::from_str(&header.alg)?;
    let enc_str = header
        .enc
        .as_deref()
        .ok_or_else(|| JoseError::InvalidHeader("missing enc field".into()))?;
    let enc = JweEncryption::from_str(enc_str)?;

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
fn produce_cek(
    key: &[u8],
    alg: JweAlgorithm,
    enc: JweEncryption,
) -> Result<(Vec<u8>, Vec<u8>)> {
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
            Ok((key.to_vec(), Vec::new()))
        }

        // AES Key Wrap.
        JweAlgorithm::A128KW | JweAlgorithm::A192KW | JweAlgorithm::A256KW => {
            let kw_alg = jwe_alg_to_keywrap(alg)?;
            let cek = random_bytes(cek_len);
            let wrapped =
                kryptering::keywrap::wrap(kw_alg, key, &cek).map_err(JoseError::Crypto)?;
            Ok((cek, wrapped))
        }

        // RSA-OAEP.
        JweAlgorithm::RsaOaep | JweAlgorithm::RsaOaep256 => {
            let pub_key = parse_rsa_public_key(key)?;
            let kt_alg = jwe_alg_to_keytransport(alg)?;
            let cek = random_bytes(cek_len);
            let encrypted =
                kryptering::keytransport::kt_encrypt(kt_alg, &pub_key, &cek, None)
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
) -> Result<Vec<u8>> {
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
            Ok(key.to_vec())
        }

        JweAlgorithm::A128KW | JweAlgorithm::A192KW | JweAlgorithm::A256KW => {
            let kw_alg = jwe_alg_to_keywrap(alg)?;
            let cek = kryptering::keywrap::unwrap(kw_alg, key, encrypted_key)
                .map_err(JoseError::Crypto)?;
            if cek.len() != cek_len {
                return Err(JoseError::Key(format!(
                    "unwrapped CEK length {} does not match expected {}",
                    cek.len(),
                    cek_len
                )));
            }
            Ok(cek)
        }

        JweAlgorithm::RsaOaep | JweAlgorithm::RsaOaep256 => {
            let priv_key = parse_rsa_private_key(key)?;
            let kt_alg = jwe_alg_to_keytransport(alg)?;
            let cek =
                kryptering::keytransport::kt_decrypt(kt_alg, &priv_key, encrypted_key, None)
                    .map_err(JoseError::Crypto)?;
            if cek.len() != cek_len {
                return Err(JoseError::Key(format!(
                    "decrypted CEK length {} does not match expected {}",
                    cek.len(),
                    cek_len
                )));
            }
            Ok(cek)
        }

        _ => Err(JoseError::UnsupportedAlgorithm(format!(
            "key management algorithm {} not yet implemented",
            alg.as_str()
        ))),
    }
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
        JweEncryption::A128CbcHs256
        | JweEncryption::A192CbcHs384
        | JweEncryption::A256CbcHs512 => aes_cbc_hs_encrypt(enc, cek, plaintext, aad),
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
        JweEncryption::A128CbcHs256
        | JweEncryption::A192CbcHs384
        | JweEncryption::A256CbcHs512 => aes_cbc_hs_decrypt(enc, cek, iv, ciphertext, tag, aad),
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
            return Err(JoseError::Key(format!(
                "invalid AES-GCM key size: {other}"
            )));
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
            return Err(JoseError::Key(format!(
                "invalid AES-GCM key size: {other}"
            )));
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
fn pkcs7_unpad(data: &[u8]) -> Result<Vec<u8>> {
    if data.is_empty() {
        return Err(JoseError::Crypto(kryptering::Error::Crypto(
            "empty data for PKCS#7 unpadding".into(),
        )));
    }
    let pad_byte = *data.last().unwrap();
    let pad_len = pad_byte as usize;
    if pad_len == 0 || pad_len > 16 || pad_len > data.len() {
        return Err(JoseError::Crypto(kryptering::Error::Crypto(
            "invalid PKCS#7 padding".into(),
        )));
    }
    // Verify all padding bytes.
    for &b in &data[data.len() - pad_len..] {
        if b != pad_byte {
            return Err(JoseError::Crypto(kryptering::Error::Crypto(
                "invalid PKCS#7 padding".into(),
            )));
        }
    }
    Ok(data[..data.len() - pad_len].to_vec())
}

// ---------------------------------------------------------------------------
// Algorithm mapping helpers
// ---------------------------------------------------------------------------

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
    rsa::RsaPublicKey::from_public_key_der(der)
        .map_err(|e| JoseError::Key(format!("failed to parse RSA public key DER: {e}")))
}

fn parse_rsa_private_key(der: &[u8]) -> Result<rsa::RsaPrivateKey> {
    use rsa::pkcs8::DecodePrivateKey;
    rsa::RsaPrivateKey::from_pkcs8_der(der)
        .map_err(|e| JoseError::Key(format!("failed to parse RSA private key PKCS#8 DER: {e}")))
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
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
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

        let token =
            encrypt(&kek, plaintext, JweAlgorithm::A256KW, JweEncryption::A128GCM).unwrap();

        // Encrypted key part must not be empty for key wrapping.
        let parts: Vec<&str> = token.splitn(5, '.').collect();
        assert!(!parts[1].is_empty(), "A256KW: encrypted key must not be empty");

        let recovered = decrypt(&kek, &token).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn a128kw_a256gcm_roundtrip() {
        let kek = [0xCDu8; 16]; // 128-bit KEK
        let plaintext = b"A128KW + A256GCM";

        let token =
            encrypt(&kek, plaintext, JweAlgorithm::A128KW, JweEncryption::A256GCM).unwrap();
        let recovered = decrypt(&kek, &token).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn a192kw_a256gcm_roundtrip() {
        let kek = [0xEFu8; 24]; // 192-bit KEK
        let plaintext = b"A192KW + A256GCM";

        let token =
            encrypt(&kek, plaintext, JweAlgorithm::A192KW, JweEncryption::A256GCM).unwrap();
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

        let token =
            encrypt(&key1, plaintext, JweAlgorithm::Dir, JweEncryption::A256GCM).unwrap();
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

        let token =
            encrypt(&key, plaintext, JweAlgorithm::Dir, JweEncryption::A256GCM).unwrap();

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
            "tampered ciphertext should fail GCM auth"
        );
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

        let token =
            encrypt(&cek, plaintext, JweAlgorithm::Dir, JweEncryption::A256GCM).unwrap();

        let header = decode_header(&token).unwrap();
        assert_eq!(header.alg, "dir");
        assert_eq!(header.enc.as_deref(), Some("A256GCM"));
    }

    #[test]
    fn empty_plaintext_roundtrip() {
        let cek = [0x42u8; 32];
        let plaintext = b"";

        let token =
            encrypt(&cek, plaintext, JweAlgorithm::Dir, JweEncryption::A256GCM).unwrap();
        let recovered = decrypt(&cek, &token).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn large_plaintext_roundtrip() {
        let cek = [0x42u8; 32];
        let plaintext: Vec<u8> = (0..10_000).map(|i| (i % 256) as u8).collect();

        let token =
            encrypt(&cek, &plaintext, JweAlgorithm::Dir, JweEncryption::A256GCM).unwrap();
        let recovered = decrypt(&cek, &token).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn wrong_kek_fails_unwrap() {
        let kek1 = [0xABu8; 32];
        let kek2 = [0xCDu8; 32];
        let plaintext = b"kek test";

        let token =
            encrypt(&kek1, plaintext, JweAlgorithm::A256KW, JweEncryption::A128GCM).unwrap();
        let result = decrypt(&kek2, &token);
        assert!(result.is_err(), "wrong KEK should fail unwrap");
    }
}
