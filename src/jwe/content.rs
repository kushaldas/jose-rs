//! JWE content encryption (RFC 7518 §5) shared by every JWE serialization.
//!
//! This module is crate-private on purpose: a content-encryption key must
//! never be handed to a caller, and the AEAD/tag input must always be built
//! by the envelope layer, which owns the *original* serialized header bytes.
//! `aad` here is therefore the exact byte string the caller authenticated
//! (compact: `ASCII(BASE64URL(header))`; JSON: the same, joined with the
//! external-AAD field per RFC 7516 §5.1 / §7.1).
//!
//! Extracted from `compact.rs` unchanged by ADR 0011's preparatory refactor;
//! behaviour is identical, including error variants and messages.

use crate::algorithm::JweEncryption;
use crate::error::{JoseError, Result};

/// Encrypt `plaintext` and return `(iv, ciphertext, tag)`.
pub(crate) fn content_encrypt(
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

/// Decrypt and return plaintext. Never call this with an unauthenticated CEK
/// that came from an unverified envelope: the returned bytes are only
/// trustworthy because the tag checked out.
pub(crate) fn content_decrypt(
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

/// Length of the unpadded base64url encoding of `n` bytes.
///
/// Used by the emit-side size checks so a token that cannot fit in
/// [`crate::MAX_TOKEN_BYTES`] is refused before any key wrapping runs.
pub(crate) fn base64url_len(n: usize) -> usize {
    n.div_ceil(3) * 4 - (3 - n % 3) % 3
}

// ---------------------------------------------------------------------------
// AES-GCM content encryption (RFC 7518 Section 5.3)
// ---------------------------------------------------------------------------

fn aes_gcm_encrypt(
    cek: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    use aes_gcm::aead::AeadInOut;
    use aes_gcm::{KeyInit, Nonce};

    let mut nonce_bytes = [0u8; 12];
    getrandom::fill(&mut nonce_bytes).map_err(|e| {
        JoseError::Crypto(kryptering::Error::Crypto(format!(
            "operating-system randomness failed: {e}"
        )))
    })?;
    let nonce = Nonce::try_from(nonce_bytes.as_slice()).expect("fixed-size AES-GCM nonce");

    let mut buffer = plaintext.to_vec();

    let gcm_err =
        |e: aes_gcm::Error| JoseError::Crypto(kryptering::Error::Crypto(format!("AES-GCM: {e}")));
    let key_err = |e| JoseError::Key(format!("AES-GCM key init: {e}"));

    let tag_bytes = match cek.len() {
        16 => {
            let cipher = aes_gcm::Aes128Gcm::new_from_slice(cek).map_err(key_err)?;
            cipher
                .encrypt_inout_detached(&nonce, aad, (&mut buffer[..]).into())
                .map_err(gcm_err)?
        }
        24 => {
            use aes_gcm::aead::consts::U12;
            let cipher =
                aes_gcm::AesGcm::<aes::Aes192, U12>::new_from_slice(cek).map_err(key_err)?;
            cipher
                .encrypt_inout_detached(&nonce, aad, (&mut buffer[..]).into())
                .map_err(gcm_err)?
        }
        32 => {
            let cipher = aes_gcm::Aes256Gcm::new_from_slice(cek).map_err(key_err)?;
            cipher
                .encrypt_inout_detached(&nonce, aad, (&mut buffer[..]).into())
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
    use aes_gcm::aead::AeadInOut;
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

    let nonce = Nonce::try_from(iv).expect("AES-GCM IV length checked above");
    let auth_tag = Tag::try_from(tag).expect("AES-GCM tag length checked above");
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
                .decrypt_inout_detached(&nonce, aad, (&mut buffer[..]).into(), &auth_tag)
                .map_err(|_| auth_fail())?;
        }
        24 => {
            use aes_gcm::aead::consts::U12;
            let cipher =
                aes_gcm::AesGcm::<aes::Aes192, U12>::new_from_slice(cek).map_err(key_err)?;
            cipher
                .decrypt_inout_detached(&nonce, aad, (&mut buffer[..]).into(), &auth_tag)
                .map_err(|_| auth_fail())?;
        }
        32 => {
            let cipher = aes_gcm::Aes256Gcm::new_from_slice(cek).map_err(key_err)?;
            cipher
                .decrypt_inout_detached(&nonce, aad, (&mut buffer[..]).into(), &auth_tag)
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
    getrandom::fill(&mut iv).map_err(|e| {
        JoseError::Crypto(kryptering::Error::Crypto(format!(
            "operating-system randomness failed: {e}"
        )))
    })?;

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
    use hmac::{KeyInit, Mac};

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
    use cbc::cipher::{BlockModeEncrypt, KeyIvInit};

    let padded = pkcs7_pad(plaintext, 16);
    let padded_len = padded.len();
    let mut buf = padded;

    macro_rules! do_encrypt {
        ($aes:ty) => {{
            let enc = cbc::Encryptor::<$aes>::new_from_slices(key, iv)
                .map_err(|e| JoseError::Key(format!("AES-CBC init: {e}")))?;
            enc.encrypt_padded::<cbc::cipher::block_padding::NoPadding>(&mut buf, padded_len)
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
    use cbc::cipher::{BlockModeDecrypt, KeyIvInit};

    if ciphertext.is_empty() || !ciphertext.len().is_multiple_of(16) {
        return Err(JoseError::InvalidToken(
            "AES-CBC ciphertext length must be a multiple of 16".into(),
        ));
    }

    let mut buf = ciphertext.to_vec();

    macro_rules! do_decrypt {
        ($aes:ty) => {{
            let dec = cbc::Decryptor::<$aes>::new_from_slices(key, iv)
                .map_err(|e| JoseError::Key(format!("AES-CBC init: {e}")))?;
            dec.decrypt_padded::<cbc::cipher::block_padding::NoPadding>(&mut buf)
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
    if data.is_empty() || !data.len().is_multiple_of(BLOCK) {
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

/// Fill `len` bytes from the OS CSPRNG.
pub(crate) fn random_bytes(len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    getrandom::fill(&mut buf).expect("operating-system randomness unavailable");
    buf
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Direct unit tests for the constant-time PKCS#7 unpad implementation.
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

    /// `base64url_len` must match the encoder exactly, because the emit-side
    /// size budget is computed from it before anything is allocated.
    #[test]
    fn base64url_len_matches_encoder() {
        for n in 0..200usize {
            let data = vec![0xA5u8; n];
            assert_eq!(
                crate::base64url::encode(&data).len(),
                base64url_len(n),
                "length prediction wrong for {n} bytes"
            );
        }
    }

    /// AES-GCM requires an exact-size CEK; a truncated key must not be
    /// silently padded.
    #[test]
    fn gcm_rejects_misaligned_cek() {
        let err = aes_gcm_encrypt(&[0u8; 20], b"p", b"aad").unwrap_err();
        assert!(matches!(err, JoseError::Key(_)), "unexpected: {err}");
    }

    /// CBC-HS uses a double-length CEK (MAC || ENC); a single AES length is
    /// the classic mis-wiring and must be refused on both directions.
    #[test]
    fn cbc_hs_rejects_half_length_cek() {
        let err =
            aes_cbc_hs_encrypt(JweEncryption::A128CbcHs256, &[0u8; 16], b"p", b"aad").unwrap_err();
        assert!(err.to_string().contains("expected 32 byte CEK"), "{err}");
        let err = aes_cbc_hs_decrypt(
            JweEncryption::A128CbcHs256,
            &[0u8; 16],
            &[0u8; 16],
            &[0u8; 16],
            &[0u8; 16],
            b"aad",
        )
        .unwrap_err();
        assert!(err.to_string().contains("expected 32 byte CEK"), "{err}");
    }

    /// The AAD is part of the tag input: the same key and ciphertext must not
    /// authenticate under a different AAD (the basis of external-AAD tests).
    #[test]
    fn tag_binds_the_aad() {
        for enc in [
            JweEncryption::A128CbcHs256,
            JweEncryption::A192CbcHs384,
            JweEncryption::A256CbcHs512,
        ] {
            let cek = random_bytes(enc.cek_size());
            let (iv, ct, tag) = aes_cbc_hs_encrypt(enc, &cek, b"payload", b"context-A").unwrap();
            assert!(
                aes_cbc_hs_decrypt(enc, &cek, &iv, &ct, &tag, b"context-B").is_err(),
                "{enc:?} must not authenticate under a changed AAD"
            );
            assert_eq!(
                aes_cbc_hs_decrypt(enc, &cek, &iv, &ct, &tag, b"context-A").unwrap(),
                b"payload"
            );
        }
        for enc in [
            JweEncryption::A128GCM,
            JweEncryption::A192GCM,
            JweEncryption::A256GCM,
        ] {
            let cek = random_bytes(enc.cek_size());
            let (iv, ct, tag) = aes_gcm_encrypt(&cek, b"payload", b"context-A").unwrap();
            assert!(
                aes_gcm_decrypt(&cek, &iv, &ct, &tag, b"context-B").is_err(),
                "{enc:?} must not authenticate under a changed AAD"
            );
            assert_eq!(
                aes_gcm_decrypt(&cek, &iv, &ct, &tag, b"context-A").unwrap(),
                b"payload"
            );
        }
    }
}
