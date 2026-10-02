//! JWE Compact Serialization (RFC 7516 Section 3.1).
//!
//! Format: `BASE64URL(header).BASE64URL(encrypted_key).BASE64URL(iv).BASE64URL(ciphertext).BASE64URL(tag)`
//!
//! This module owns only the *wire shape*: splitting and joining the five
//! base64url parts, plus the public one-shot APIs. Header policy, algorithm
//! allow-lists, size limits and all cryptography live in the crate-private
//! `jwe::internal` and `jwe::content` modules, so the JSON serializations
//! built on the same core cannot drift from it.

use crate::algorithm::{JweAlgorithm, JweEncryption};
use crate::base64url;
use crate::error::{JoseError, Result};
use crate::header::JoseHeader;

use crate::jwe::internal::{
    self, all_enc_algorithms, ensure_token_size, jwe_alg_decrypt_op, jwe_alg_encrypt_op,
    jwk_to_jwe_key_bytes, minimum_plaintext_len, parse_envelope, recover_cek,
};

pub use crate::jwe::internal::{JweDecryptOptions, JweEncryptOptions};

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
    encrypt_with_header(JoseHeader::for_jwe(alg, enc), key, plaintext, alg, enc)
}

/// Encrypt plaintext with an explicit authenticated protected header.
///
/// Key formats are the same as for [`encrypt`]. The header's `alg` and `enc`
/// must match the supplied algorithms (RFC 8725 §3.1). Every serialized
/// header member is authenticated as additional authenticated data; changing
/// it invalidates the token. JWK metadata is not checked by this raw-key API;
/// use [`encrypt_with_jwk_header`] to enforce JWK operation permissions.
///
/// Uses the strict [`JweEncryptOptions::new`] policy; see
/// [`encrypt_with_header_options`] to permit key-reference members.
///
/// # Errors
///
/// Returns [`JoseError::InvalidHeader`] when:
///
/// - `header.alg` / `header.enc` disagree with `alg` / `enc`;
/// - `header.extra` repeats a member that a typed [`JoseHeader`] field
///   already serializes (`alg`, `enc`, `kid`, `typ`, `cty`, `jku`, `jwk`,
///   `x5u`, `x5c`, `x5t`, `x5t#S256`, `crit`), which would put an ambiguous
///   duplicate key in the protected header (RFC 7515 §4);
/// - `header.extra` contains a registered member this crate does not
///   implement for JWE compact: `zip` (compression, which RFC 8725 §3.6
///   advises against), `b64`, `epk`, `apu`, `apv`, `p2s`, `p2c`, `iv` or
///   `tag`;
/// - `header.crit` is set (no JWE critical extensions are implemented);
/// - the header carries `jku`, `jwk`, `x5u` or `x5c` (see
///   [`JweEncryptOptions::allow_key_reference_headers`]);
/// - the encoded header exceeds [`crate::MAX_TOKEN_BYTES`].
///
/// Returns [`JoseError::InvalidToken`] when the resulting token would exceed
/// [`crate::MAX_TOKEN_BYTES`]. Together these mirror [`decrypt`], so every
/// token this function returns can be decrypted by this crate. Other errors
/// are returned for unsupported algorithms, invalid key material or key
/// sizes, or an encryption failure.
pub fn encrypt_with_header(
    header: JoseHeader,
    key: &[u8],
    plaintext: &[u8],
    alg: JweAlgorithm,
    enc: JweEncryption,
) -> Result<String> {
    encrypt_with_header_options(header, key, plaintext, alg, enc, &JweEncryptOptions::new())
}

/// [`encrypt_with_header`] with explicit [`JweEncryptOptions`].
///
/// # Errors
///
/// As for [`encrypt_with_header`], except that key-reference members are
/// accepted when `opts.allow_key_reference_headers` is set.
pub fn encrypt_with_header_options(
    header: JoseHeader,
    key: &[u8],
    plaintext: &[u8],
    alg: JweAlgorithm,
    enc: JweEncryption,
    opts: &JweEncryptOptions,
) -> Result<String> {
    // RFC 7516 §7.1 defines no `aad` member, so this serialization cannot
    // honour external AAD. Refusing beats encrypting under an AAD the
    // recipient has no way to learn.
    ensure_no_external_aad(opts.external_aad())?;

    // All emit-side policy lives in the shared core, which the JSON
    // serializations call too; this function only joins the five parts.
    let core = internal::encrypt_core(&header, key, plaintext, alg, enc, opts, None)?;

    let encrypted_key_b64 = base64url::encode(&core.encrypted_key);
    let iv_b64 = base64url::encode(&core.iv);
    let ciphertext_b64 = base64url::encode(&core.ciphertext);
    let tag_b64 = base64url::encode(&core.tag);

    let token = format!(
        "{}.{}.{}.{}.{}",
        core.header_b64, encrypted_key_b64, iv_b64, ciphertext_b64, tag_b64
    );
    // `decrypt` refuses tokens over MAX_TOKEN_BYTES.
    crate::ensure_emit_size(token.len())?;
    Ok(token)
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
    encrypt_with_header(
        JoseHeader::for_jwe(alg, enc),
        &key_bytes,
        plaintext,
        alg,
        enc,
    )
}

/// Encrypt plaintext using a JWK and an explicit authenticated protected header.
///
/// Refuse external additional authenticated data on the compact path.
///
/// The option is shared between serializations (`JweEncryptOptions` /
/// `JweDecryptOptions` are used by both), so each front end has to say what it
/// cannot do with it. Silent omission here would produce a token whose AAD
/// input differs from the one the sender believed it authenticated.
fn ensure_no_external_aad(external_aad: Option<&[u8]>) -> Result<()> {
    if external_aad.is_some() {
        return Err(JoseError::InvalidHeader(
            "external additional authenticated data requires the JWE JSON serialization \u{2014} \
             the compact form has no \"aad\" member (RFC 7516 \u{a7}7.1)"
                .into(),
        ));
    }
    Ok(())
}

/// The key-management algorithm comes from `jwk.alg`, which must be set and
/// match `header.alg`; `header.enc` must match `enc`. Enforces `Encrypt` for
/// `dir` and `WrapKey` for AES key wrap and RSA-OAEP. All serialized protected
/// header members are authenticated, allowing application fields such as
/// `kid`, `typ`, and `cty` without modifying the encryption implementation.
///
/// # Errors
///
/// Returns an error when the JWK algorithm or operation permissions reject
/// encryption, the header algorithms disagree, key material is invalid, or
/// encryption fails. The header is validated exactly as in
/// [`encrypt_with_header`] (duplicate typed members, unimplemented members
/// such as `zip`, `crit`, key-reference members, and the size limit), using
/// the strict [`JweEncryptOptions::new`] policy.
pub fn encrypt_with_jwk_header(
    jwk: &crate::jwk::Jwk,
    header: JoseHeader,
    plaintext: &[u8],
    enc: JweEncryption,
) -> Result<String> {
    encrypt_with_jwk_header_options(jwk, header, plaintext, enc, &JweEncryptOptions::new())
}

/// [`encrypt_with_jwk_header`] with explicit [`JweEncryptOptions`].
///
/// # Errors
///
/// As for [`encrypt_with_jwk_header`], except that key-reference members are
/// accepted when `opts.allow_key_reference_headers` is set.
pub fn encrypt_with_jwk_header_options(
    jwk: &crate::jwk::Jwk,
    header: JoseHeader,
    plaintext: &[u8],
    enc: JweEncryption,
    opts: &JweEncryptOptions,
) -> Result<String> {
    let jwk_alg_str = jwk
        .alg
        .as_deref()
        .ok_or_else(|| JoseError::Key("JWK alg must be set for encrypt_with_jwk".into()))?;
    let alg = JweAlgorithm::from_str(jwk_alg_str)?;
    jwk.check_op(jwe_alg_encrypt_op(alg))?;
    let key_bytes = jwk_to_jwe_key_bytes(jwk, alg, false)?;
    encrypt_with_header_options(header, &key_bytes, plaintext, alg, enc, opts)
}

/// Decrypt a JWE token using a JWK directly — the one-shot JWE decrypt API.
///
/// The JWK MUST pin `alg`: the key-management algorithm is bound to the
/// key, not taken from the attacker-controlled token header. The token's
/// header `alg` must agree with `jwk.alg`, and the decrypt path is run
/// through an allow-list pinned to that single algorithm so a substituted
/// header `alg` is rejected before any key material is touched.
/// `Jwk::check_op` is enforced: `Decrypt` for `dir`, `UnwrapKey` for
/// `A*KW` / `RSA-OAEP*`.
pub fn decrypt_with_jwk(jwk: &crate::jwk::Jwk, token: &str) -> Result<Vec<u8>> {
    // Read the header's alg for dispatch.
    let header = decode_header(token)?;
    let alg = JweAlgorithm::from_str(&header.alg)?;

    // The JWK must pin alg — otherwise the key-management algorithm would be
    // dictated entirely by the token header (algorithm-substitution risk when
    // a single key is reused across configurations).
    let jwk_alg = jwk
        .alg
        .as_deref()
        .ok_or_else(|| JoseError::Key("JWK alg must be set for decrypt_with_jwk".into()))?;
    if jwk_alg != header.alg {
        return Err(JoseError::InvalidToken(format!(
            "JWK alg {jwk_alg} does not match token header alg {}",
            header.alg
        )));
    }

    jwk.check_op(jwe_alg_decrypt_op(alg))?;
    let key_bytes = jwk_to_jwe_key_bytes(jwk, alg, true)?;

    // Pin the key-management algorithm to the JWK's alg. Content encryption
    // (`enc`) stays flexible — its key length is bound to the CEK size and
    // re-validated in the key-management layer — so we permit every supported
    // `enc`.
    let options = JweDecryptOptions::new(vec![alg], all_enc_algorithms());
    decrypt_with_options(&key_bytes, token, &options)
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

/// Decrypt a JWE Compact Serialization token, enforcing the caller's
/// algorithm allow-list.
///
/// Rejects the token before any cryptographic operation if its `alg` or
/// `enc` header is outside the allow-list supplied via `options`.
/// Enforces [`JweDecryptOptions::with_max_plaintext`] when configured. No
/// plaintext is returned until authentication and the exact size check pass.
pub fn decrypt_with_options(
    key: &[u8],
    token: &str,
    options: &JweDecryptOptions,
) -> Result<Vec<u8>> {
    ensure_token_size(token)?;
    // Symmetric with the emit side: a compact token cannot carry external
    // additional authenticated data, so options that supply it mean the caller
    // is holding the wrong serialization, not that the tag will simply fail.
    ensure_no_external_aad(options.external_aad())?;

    // 1. Parse compact serialization.
    let parts: Vec<&str> = token.splitn(6, '.').collect();
    if parts.len() != 5 {
        return Err(JoseError::InvalidToken(
            "JWE compact serialization must have 5 dot-separated parts".into(),
        ));
    }

    let (header_b64, encrypted_key_b64, iv_b64, ciphertext_b64, tag_b64) =
        (parts[0], parts[1], parts[2], parts[3], parts[4]);

    // 2. Decode the protected header, apply the shared header policy, and
    //    decode the remaining parts. The verbatim `header_b64` is kept for
    //    use as additional authenticated data.
    // The compact serialization exposes no header to the caller, so the
    // parsed protected header is discarded here; the JSON serializations
    // return it as authenticated metadata.
    let (envelope, _protected) = parse_envelope(
        header_b64,
        encrypted_key_b64,
        iv_b64,
        ciphertext_b64,
        tag_b64,
    )?;

    // Enforce caller's allow-list before touching any key material.
    options.check(envelope.alg, envelope.enc)?;

    // Reject content that provably cannot fit the configured plaintext limit
    // before decoding ciphertext or recovering a key.
    options.check_plaintext_size(minimum_plaintext_len(ciphertext_b64.len(), envelope.enc))?;

    // 3. Recover CEK.
    let cek = recover_cek(key, envelope.alg, envelope.enc, &envelope.encrypted_key)?;

    // 4. Content decryption; AAD = ASCII(BASE64URL(header)).
    let aad = envelope.header_b64.as_bytes();
    internal::finish_decrypt(&envelope, &cek, aad, options)
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

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::algorithm::{JweAlgorithm, JweEncryption};
    use crate::jwe::internal::{jwe_alg_to_keytransport, parse_rsa_public_key};

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

    fn assert_rsa_oaep_failure_classes_are_indistinguishable(alg: JweAlgorithm) {
        let (pub_der, priv_der) = generate_rsa_keypair();
        let public_key = parse_rsa_public_key(&pub_der).unwrap();

        for enc in [JweEncryption::A256GCM, JweEncryption::A256CbcHs512] {
            let token = encrypt(&pub_der, b"RSA-OAEP implicit rejection", alg, enc).unwrap();
            let parts: Vec<&str> = token.splitn(5, '.').collect();

            // An all-zero RSA ciphertext deterministically fails OAEP decoding.
            let encrypted_key = base64url::decode(parts[1]).unwrap();
            let invalid_oaep = format!(
                "{}.{}.{}.{}.{}",
                parts[0],
                base64url::encode(&vec![0; encrypted_key.len()]),
                parts[2],
                parts[3],
                parts[4]
            );

            // A valid OAEP ciphertext carrying the wrong CEK length must take
            // the same implicit-rejection path as an OAEP decoding failure.
            let short_cek = kryptering::keytransport::kt_encrypt(
                jwe_alg_to_keytransport(alg).unwrap(),
                &public_key,
                &[0x42],
                None,
            )
            .unwrap();
            let invalid_cek_length = format!(
                "{}.{}.{}.{}.{}",
                parts[0],
                base64url::encode(&short_cek),
                parts[2],
                parts[3],
                parts[4]
            );

            // Preserve the valid RSA-OAEP ciphertext and invalidate only the
            // content-authentication tag.
            let mut tag = base64url::decode(parts[4]).unwrap();
            tag[0] ^= 1;
            let invalid_tag = format!(
                "{}.{}.{}.{}.{}",
                parts[0],
                parts[1],
                parts[2],
                parts[3],
                base64url::encode(&tag)
            );

            let unwrap_error = decrypt(&priv_der, &invalid_oaep).unwrap_err().to_string();
            let cek_length_error = decrypt(&priv_der, &invalid_cek_length)
                .unwrap_err()
                .to_string();
            let content_error = decrypt(&priv_der, &invalid_tag).unwrap_err().to_string();

            assert_eq!(
                unwrap_error,
                content_error,
                "failure oracle for {}/{}",
                alg.as_str(),
                enc.as_str()
            );
            assert_eq!(
                cek_length_error,
                content_error,
                "CEK-length oracle for {}/{}",
                alg.as_str(),
                enc.as_str()
            );
            assert!(!unwrap_error.contains("OAEP"), "unexpected: {unwrap_error}");
        }
    }

    /// RSA-OAEP implicit rejection must make an invalid wrapped CEK
    /// indistinguishable from a valid unwrap followed by failed content
    /// authentication.
    #[test]
    fn rsa_oaep_failure_classes_are_indistinguishable() {
        assert_rsa_oaep_failure_classes_are_indistinguishable(JweAlgorithm::RsaOaep256);
    }

    /// The deprecated SHA-1 RSA-OAEP variant shares the same implicit-
    /// rejection guarantee.
    #[cfg(feature = "deprecated")]
    #[test]
    fn deprecated_rsa_oaep_failure_classes_are_indistinguishable() {
        assert_rsa_oaep_failure_classes_are_indistinguishable(JweAlgorithm::RsaOaep);
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

    /// JWE symmetric one-shot APIs must not accept non-oct JWKs just because
    /// they carry a stray `k` parameter.
    #[test]
    fn jwk_symmetric_alg_rejects_non_oct_kty() {
        for alg in ["dir", "A256KW"] {
            let mut jwk = crate::jwk::generate_symmetric(32).unwrap();
            jwk.kty = "RSA".into();
            jwk.alg = Some(alg.into());

            let err = encrypt_with_jwk(&jwk, b"p", JweEncryption::A256GCM)
                .unwrap_err()
                .to_string();
            assert!(err.contains("requires kty oct"), "unexpected: {err}");
        }
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

    /// Hardening regression: decrypt_with_jwk hard-requires `jwk.alg` so the
    /// key-management algorithm is bound to the key, not taken from the
    /// attacker-controlled token header. A JWK with no `alg` must be rejected
    /// before any key material is touched.
    #[test]
    fn jwk_decrypt_requires_alg() {
        // Build a valid dir/A256GCM token with raw bytes.
        let jwk = crate::jwk::generate_symmetric(32).unwrap(); // no alg set
        let k = crate::base64url::decode(jwk.k.as_ref().unwrap()).unwrap();
        let token = encrypt(&k, b"p", JweAlgorithm::Dir, JweEncryption::A256GCM).unwrap();

        let err = decrypt_with_jwk(&jwk, &token).unwrap_err().to_string();
        assert!(err.contains("alg must be set"), "unexpected: {err}");
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

    /// Regression: an empty-but-present crit array must be rejected on JWE
    /// decrypt (RFC 7515 §4.1.11 requires crit to be non-empty).
    #[test]
    fn empty_crit_rejected_on_decrypt() {
        let cek = [0x42u8; 32];
        let token = encrypt(&cek, b"p", JweAlgorithm::Dir, JweEncryption::A256GCM).unwrap();

        // Rewrite the header to include an empty crit array.
        let parts: Vec<&str> = token.splitn(5, '.').collect();
        let mut header: JoseHeader =
            serde_json::from_slice(&base64url::decode(parts[0]).unwrap()).unwrap();
        header.crit = Some(Vec::new());
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

    /// Regression: a JWE header declaring `zip` (content compression, which
    /// this library does not implement) must be rejected on decrypt instead
    /// of returning the compressed bytes as plaintext.
    #[test]
    fn zip_header_rejected_on_decrypt() {
        let cek = [0x42u8; 32];
        let token = encrypt(&cek, b"p", JweAlgorithm::Dir, JweEncryption::A256GCM).unwrap();

        // Rewrite the header to declare DEFLATE compression.
        let parts: Vec<&str> = token.splitn(5, '.').collect();
        let mut header: JoseHeader =
            serde_json::from_slice(&base64url::decode(parts[0]).unwrap()).unwrap();
        header.extra.insert(
            "zip".to_string(),
            serde_json::Value::String("DEF".to_string()),
        );
        let new_header_b64 = base64url::encode(&serde_json::to_vec(&header).unwrap());
        let tampered_token = format!(
            "{}.{}.{}.{}.{}",
            new_header_b64, parts[1], parts[2], parts[3], parts[4]
        );

        let result = decrypt(&cek, &tampered_token);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("zip"), "unexpected error: {err}");
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
