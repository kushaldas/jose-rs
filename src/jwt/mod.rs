//! JWT (JSON Web Token) — RFC 7519.
//!
//! JWTs are JWS compact-serialized JSON claims. This module provides `encode`
//! and `decode` functions that build on `crate::jws::compact` and add claims
//! validation (expiration, not-before, issuer, audience).

pub mod claims;
pub mod validation;

pub use claims::{Audience, Claims};
pub use validation::Validation;

use crate::error::{JoseError, Result};
use crate::header::JoseHeader;

/// Encode claims as a JWT (JWS Compact Serialization).
pub fn encode(
    signer: &dyn kryptering::Signer,
    header: &JoseHeader,
    claims: &Claims,
) -> Result<String> {
    let payload = serde_json::to_vec(claims)?;
    crate::jws::compact::sign(signer, &payload, header)
}

/// Decode and validate a JWT.
///
/// Returns the validated claims. Signature is verified using the provided
/// verifier, and both the protected header and claims are checked against
/// the `Validation` configuration — header-bound checks (`typ`,
/// `allowed_algorithms`) run alongside the usual claim checks.
pub fn decode(
    verifier: &dyn kryptering::Verifier,
    token: &str,
    validation: &Validation,
) -> Result<Claims> {
    let payload = crate::jws::compact::verify(verifier, token)?;
    let header = crate::jws::compact::decode_header(token)?;
    let claims: Claims = serde_json::from_slice(&payload)?;
    validation.validate_with_header(&claims, &header)?;
    Ok(claims)
}

/// Encode claims as a nested JWT: first signed (JWS), then encrypted (JWE).
///
/// Produces a JWE compact token whose plaintext is a signed JWT.
/// The JWE header will contain `cty: "JWT"` per RFC 7519 §5.2.
///
/// - `signer`: signs the inner JWT
/// - `jws_header`: header for the inner JWS (e.g., `alg: "RS256"`)
/// - `claims`: the JWT claims to sign and encrypt
/// - `encryption_key`: key material for JWE encryption (CEK, KEK, or RSA public key DER)
/// - `alg`: JWE key management algorithm
/// - `enc`: JWE content encryption algorithm
pub fn encode_nested(
    signer: &dyn kryptering::Signer,
    jws_header: &JoseHeader,
    claims: &Claims,
    encryption_key: &[u8],
    alg: crate::algorithm::JweAlgorithm,
    enc: crate::algorithm::JweEncryption,
) -> Result<String> {
    // Step 1: Sign the claims as a regular JWT (JWS compact)
    let signed_jwt = encode(signer, jws_header, claims)?;

    // Step 2: Encrypt the signed JWT inside a JWE
    crate::jwe::compact::encrypt(encryption_key, signed_jwt.as_bytes(), alg, enc)
}

/// Decode a nested JWT: first decrypt the JWE, then verify the inner JWS and validate claims.
///
/// Accepts any JWE algorithm the library supports. For strict deployments,
/// use [`decode_nested_with_options`] to pin an allow-list.
///
/// - `decryption_key`: key material for JWE decryption (CEK, KEK, or RSA private key DER)
/// - `verifier`: verifies the inner JWT signature
/// - `token`: the JWE compact token containing a nested JWT
/// - `validation`: claims validation configuration
pub fn decode_nested(
    decryption_key: &[u8],
    verifier: &dyn kryptering::Verifier,
    token: &str,
    validation: &Validation,
) -> Result<Claims> {
    decode_nested_with_options(
        decryption_key,
        verifier,
        token,
        validation,
        &crate::jwe::JweDecryptOptions::permissive(),
    )
}

/// Decode a nested JWT, enforcing the caller's JWE algorithm allow-list.
///
/// See [`crate::jwe::JweDecryptOptions`] for how to build a strict allow-list.
pub fn decode_nested_with_options(
    decryption_key: &[u8],
    verifier: &dyn kryptering::Verifier,
    token: &str,
    validation: &Validation,
    jwe_options: &crate::jwe::JweDecryptOptions,
) -> Result<Claims> {
    let inner_jwt_bytes =
        crate::jwe::compact::decrypt_with_options(decryption_key, token, jwe_options)?;
    let inner_jwt = std::str::from_utf8(&inner_jwt_bytes)
        .map_err(|e| JoseError::InvalidToken(format!("nested JWT is not valid UTF-8: {e}")))?;
    decode(verifier, inner_jwt, validation)
}

/// Encode claims as a JWT using a JWK directly (sign-side JWK one-shot).
///
/// The signing algorithm is read from `jwk.alg`. `Jwk::check_op(Sign)` is
/// enforced, the header's `alg` must match `jwk.alg`, and the signer is
/// built internally. Mirror of [`decode_with_jwk`].
pub fn encode_with_jwk(
    jwk: &crate::jwk::Jwk,
    header: &JoseHeader,
    claims: &Claims,
) -> Result<String> {
    let payload = serde_json::to_vec(claims)?;
    crate::jws::compact::sign_with_jwk(jwk, &payload, header)
}

/// Encode a nested JWT (sign then encrypt) using JWKs for both ops.
///
/// The inner JWT is signed with `signer_jwk` (which must have
/// `check_op(Sign)` available and `alg` set); the resulting JWT string
/// is then encrypted with `encryption_jwk` (which must have the
/// appropriate op permitted and `alg` set). Mirror of
/// [`encode_nested`] using the JWK-first API.
pub fn encode_nested_with_jwk(
    signer_jwk: &crate::jwk::Jwk,
    jws_header: &JoseHeader,
    claims: &Claims,
    encryption_jwk: &crate::jwk::Jwk,
    enc: crate::algorithm::JweEncryption,
) -> Result<String> {
    let signed = encode_with_jwk(signer_jwk, jws_header, claims)?;
    crate::jwe::compact::encrypt_with_jwk(encryption_jwk, signed.as_bytes(), enc)
}

/// Decode a nested JWT (decrypt then verify and validate claims) using JWKs.
///
/// Mirror of [`decode_nested`] that enforces `check_op(Decrypt)` /
/// `UnwrapKey` on `decryption_jwk` and `check_op(Verify)` on
/// `verifier_jwk`, and cross-checks pinned `jwk.alg` values against
/// the corresponding headers on both layers.
pub fn decode_nested_with_jwk(
    decryption_jwk: &crate::jwk::Jwk,
    verifier_jwk: &crate::jwk::Jwk,
    token: &str,
    validation: &Validation,
) -> Result<Claims> {
    let inner = crate::jwe::compact::decrypt_with_jwk(decryption_jwk, token)?;
    let inner_str = std::str::from_utf8(&inner)
        .map_err(|e| JoseError::InvalidToken(format!("nested JWT is not valid UTF-8: {e}")))?;
    decode_with_jwk(verifier_jwk, inner_str, validation)
}

/// Decode and validate a JWT using a JWK directly.
///
/// One-shot alternative to [`decode`]: derives the verifier from the
/// JWK (matching the token header's algorithm), enforces
/// [`crate::jwk::JwkOp::Verify`] on the JWK, requires any pinned
/// `jwk.alg` to agree with the token's header, and runs claim
/// validation (including header-bound `typ` and allowed-algorithm
/// checks).
pub fn decode_with_jwk(
    jwk: &crate::jwk::Jwk,
    token: &str,
    validation: &Validation,
) -> Result<Claims> {
    let payload = crate::jws::compact::verify_with_jwk(jwk, token)?;
    let header = crate::jws::compact::decode_header(token)?;
    let claims: Claims = serde_json::from_slice(&payload)?;
    validation.validate_with_header(&claims, &header)?;
    Ok(claims)
}

/// Decode and validate a JWT using a JWK Set (the canonical OIDC flow).
///
/// If the token header carries a `kid`, the matching JWK is selected and
/// [`decode_with_jwk`] is called. If no `kid` is present (or no JWK in
/// the set matches), every key in the set is tried in order; the first
/// one whose signature validates wins. Returns the last error if no key
/// in the set validates the token.
pub fn decode_with_jwkset(
    set: &crate::jwk::JwkSet,
    token: &str,
    validation: &Validation,
) -> Result<Claims> {
    let header = crate::jws::compact::decode_header(token)?;

    // Prefer kid-based selection when the header pins one and the set
    // contains a matching JWK.
    if let Some(kid) = header.kid.as_deref() {
        if let Some(jwk) = set.find_by_kid(kid) {
            return decode_with_jwk(jwk, token, validation);
        }
    }

    // Otherwise fall through: try every key until one verifies.
    if set.keys.is_empty() {
        return Err(JoseError::Key("JWK Set is empty".into()));
    }
    let mut last_err: Option<JoseError> = None;
    for jwk in &set.keys {
        match decode_with_jwk(jwk, token, validation) {
            Ok(claims) => return Ok(claims),
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err
        .unwrap_or_else(|| JoseError::InvalidToken("no key in the set verified the token".into())))
}

/// Decode a JWT without verifying the signature (DANGEROUS — for inspection only).
///
/// Emits a deprecation warning at every call site. The function is kept
/// available for legitimate inspection use cases (e.g. logging a token's
/// `kid` before deciding which verifier to use), but production code
/// paths must call [`decode`] with a verifier and `Validation`.
#[deprecated(
    note = "decode_unverified bypasses signature verification; use jwt::decode with a verifier unless you truly need pre-verification inspection"
)]
pub fn decode_unverified(token: &str) -> Result<(JoseHeader, Claims)> {
    let header = crate::jws::compact::decode_header(token)?;
    let parts: Vec<&str> = token.splitn(3, '.').collect();
    if parts.len() != 3 {
        return Err(JoseError::InvalidToken("expected 3 parts".into()));
    }
    let payload = crate::base64url::decode(parts[1])?;
    let claims: Claims = serde_json::from_slice(&payload)?;
    Ok((header, claims))
}

#[cfg(test)]
mod tests {
    use super::*;
    use kryptering::{
        HashAlgorithm, SignatureAlgorithm, SoftwareKey, SoftwareSigner, SoftwareVerifier,
    };
    use std::time::{SystemTime, UNIX_EPOCH};

    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    fn hmac_key() -> SoftwareKey {
        SoftwareKey::Hmac(b"super-secret-key-at-least-32-bytes!!".to_vec())
    }

    fn hmac_algo() -> SignatureAlgorithm {
        SignatureAlgorithm::Hmac(HashAlgorithm::Sha256)
    }

    fn hmac_signer() -> SoftwareSigner {
        SoftwareSigner::new(hmac_algo(), hmac_key()).unwrap()
    }

    fn hmac_verifier() -> SoftwareVerifier {
        SoftwareVerifier::new(hmac_algo(), hmac_key()).unwrap()
    }

    #[test]
    fn jwt_roundtrip() {
        let header = JoseHeader::jwt("HS256");
        let mut claims = Claims::default();
        claims.iss = Some("test-issuer".into());
        claims.sub = Some("user-42".into());
        claims.exp = Some(now() + 3600);

        let token = encode(&hmac_signer(), &header, &claims).unwrap();
        let validation = Validation::new().with_issuer("test-issuer");
        let decoded = decode(&hmac_verifier(), &token, &validation).unwrap();

        assert_eq!(decoded.iss.as_deref(), Some("test-issuer"));
        assert_eq!(decoded.sub.as_deref(), Some("user-42"));
        assert_eq!(decoded.exp, claims.exp);
    }

    #[test]
    fn expired_token() {
        let header = JoseHeader::jwt("HS256");
        let mut claims = Claims::default();
        // Expired 2 hours ago — well past the default 60s leeway
        claims.exp = Some(now() - 7200);

        let token = encode(&hmac_signer(), &header, &claims).unwrap();
        let validation = Validation::new();
        let result = decode(&hmac_verifier(), &token, &validation);

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, JoseError::Expired),
            "expected Expired, got: {err}"
        );
    }

    #[test]
    fn not_yet_valid_token() {
        let header = JoseHeader::jwt("HS256");
        let mut claims = Claims::default();
        // Not valid until 2 hours from now — well past the default 60s leeway
        claims.nbf = Some(now() + 7200);

        let token = encode(&hmac_signer(), &header, &claims).unwrap();
        let validation = Validation::new();
        let result = decode(&hmac_verifier(), &token, &validation);

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, JoseError::NotYetValid),
            "expected NotYetValid, got: {err}"
        );
    }

    #[test]
    fn wrong_issuer() {
        let header = JoseHeader::jwt("HS256");
        let mut claims = Claims::default();
        claims.iss = Some("wrong-issuer".into());
        claims.exp = Some(now() + 3600);

        let token = encode(&hmac_signer(), &header, &claims).unwrap();
        let validation = Validation::new().with_issuer("expected-issuer");
        let result = decode(&hmac_verifier(), &token, &validation);

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, JoseError::InvalidIssuer),
            "expected InvalidIssuer, got: {err}"
        );
    }

    #[test]
    fn wrong_audience() {
        let header = JoseHeader::jwt("HS256");
        let mut claims = Claims::default();
        claims.aud = Some(Audience::Single("other-service".into()));
        claims.exp = Some(now() + 3600);

        let token = encode(&hmac_signer(), &header, &claims).unwrap();
        let validation = Validation::new().with_audience("my-service");
        let result = decode(&hmac_verifier(), &token, &validation);

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, JoseError::InvalidAudience),
            "expected InvalidAudience, got: {err}"
        );
    }

    #[test]
    fn custom_claims_roundtrip() {
        let header = JoseHeader::jwt("HS256");
        let mut claims = Claims::default();
        claims.exp = Some(now() + 3600);
        claims
            .extra
            .insert("role".into(), serde_json::Value::String("admin".into()));
        claims.extra.insert("level".into(), serde_json::json!(42));

        let token = encode(&hmac_signer(), &header, &claims).unwrap();
        let validation = Validation::new();
        let decoded = decode(&hmac_verifier(), &token, &validation).unwrap();

        assert_eq!(
            decoded.extra.get("role"),
            Some(&serde_json::Value::String("admin".into()))
        );
        assert_eq!(decoded.extra.get("level"), Some(&serde_json::json!(42)));
    }

    #[test]
    fn audience_single_string() {
        let header = JoseHeader::jwt("HS256");
        let mut claims = Claims::default();
        claims.aud = Some(Audience::Single("my-service".into()));
        claims.exp = Some(now() + 3600);

        let token = encode(&hmac_signer(), &header, &claims).unwrap();
        let validation = Validation::new().with_audience("my-service");
        let decoded = decode(&hmac_verifier(), &token, &validation).unwrap();

        assert!(decoded.aud.unwrap().contains("my-service"));
    }

    #[test]
    fn audience_array() {
        let header = JoseHeader::jwt("HS256");
        let mut claims = Claims::default();
        claims.aud = Some(Audience::Multiple(vec![
            "service-a".into(),
            "service-b".into(),
        ]));
        claims.exp = Some(now() + 3600);

        let token = encode(&hmac_signer(), &header, &claims).unwrap();

        // Validate against one of the audiences in the array
        let validation = Validation::new().with_audience("service-b");
        let decoded = decode(&hmac_verifier(), &token, &validation).unwrap();

        let aud = decoded.aud.unwrap();
        assert!(aud.contains("service-a"));
        assert!(aud.contains("service-b"));
        assert!(!aud.contains("service-c"));
    }

    #[test]
    #[allow(deprecated)]
    fn decode_unverified_works() {
        let header = JoseHeader::jwt("HS256");
        let mut claims = Claims::default();
        claims.iss = Some("test".into());
        claims.sub = Some("user".into());

        let token = encode(&hmac_signer(), &header, &claims).unwrap();

        let (decoded_header, decoded_claims) = decode_unverified(&token).unwrap();
        assert_eq!(decoded_header.alg, "HS256");
        assert_eq!(decoded_header.typ.as_deref(), Some("JWT"));
        assert_eq!(decoded_claims.iss.as_deref(), Some("test"));
        assert_eq!(decoded_claims.sub.as_deref(), Some("user"));
    }

    #[test]
    fn decode_with_jwkset_rejects_oversize_token_before_header_parse() {
        let set = crate::jwk::JwkSet { keys: Vec::new() };
        let big = "a".repeat(crate::MAX_TOKEN_BYTES + 1);
        let err = decode_with_jwkset(&set, &big, &Validation::new())
            .unwrap_err()
            .to_string();
        assert!(err.contains("MAX_TOKEN_BYTES"), "unexpected error: {err}");
    }

    #[test]
    fn missing_issuer_fails_validation() {
        let header = JoseHeader::jwt("HS256");
        let mut claims = Claims::default();
        // No issuer set
        claims.exp = Some(now() + 3600);

        let token = encode(&hmac_signer(), &header, &claims).unwrap();
        let validation = Validation::new().with_issuer("required-issuer");
        let result = decode(&hmac_verifier(), &token, &validation);

        assert!(matches!(result.unwrap_err(), JoseError::InvalidIssuer));
    }

    #[test]
    fn missing_audience_fails_validation() {
        let header = JoseHeader::jwt("HS256");
        let mut claims = Claims::default();
        // No audience set
        claims.exp = Some(now() + 3600);

        let token = encode(&hmac_signer(), &header, &claims).unwrap();
        let validation = Validation::new().with_audience("required-aud");
        let result = decode(&hmac_verifier(), &token, &validation);

        assert!(matches!(result.unwrap_err(), JoseError::InvalidAudience));
    }

    #[test]
    fn leeway_allows_slightly_expired() {
        let header = JoseHeader::jwt("HS256");
        let mut claims = Claims::default();
        // Expired 30 seconds ago — within default 60s leeway
        claims.exp = Some(now() - 30);

        let token = encode(&hmac_signer(), &header, &claims).unwrap();
        let validation = Validation::new();
        let result = decode(&hmac_verifier(), &token, &validation);

        assert!(result.is_ok(), "should accept token within leeway");
    }

    // ── Nested JWT tests ────────────────────────────────────────────

    #[test]
    fn nested_jwt_roundtrip_dir_a256gcm() {
        // Sign with HMAC, encrypt with dir + A256GCM
        let jws_header = JoseHeader::jwt("HS256");
        let mut claims = Claims::default();
        claims.iss = Some("nested-issuer".into());
        claims.sub = Some("nested-user".into());
        claims.exp = Some(now() + 3600);

        // 32-byte CEK for A256GCM
        let cek = [0x42u8; 32];

        let nested_token = encode_nested(
            &hmac_signer(),
            &jws_header,
            &claims,
            &cek,
            crate::algorithm::JweAlgorithm::Dir,
            crate::algorithm::JweEncryption::A256GCM,
        )
        .unwrap();

        // Should be 5 parts (JWE compact)
        assert_eq!(nested_token.split('.').count(), 5);

        // Decrypt and verify
        let validation = Validation::new().with_issuer("nested-issuer");
        let decoded = decode_nested(&cek, &hmac_verifier(), &nested_token, &validation).unwrap();

        assert_eq!(decoded.iss.as_deref(), Some("nested-issuer"));
        assert_eq!(decoded.sub.as_deref(), Some("nested-user"));
    }

    #[test]
    fn nested_jwt_roundtrip_aes_kw() {
        // Sign with HMAC, encrypt with A128KW + A128GCM
        let jws_header = JoseHeader::jwt("HS256");
        let mut claims = Claims::default();
        claims.iss = Some("kw-issuer".into());
        claims.exp = Some(now() + 3600);

        let kek = [0x99u8; 16]; // 128-bit KEK

        let nested_token = encode_nested(
            &hmac_signer(),
            &jws_header,
            &claims,
            &kek,
            crate::algorithm::JweAlgorithm::A128KW,
            crate::algorithm::JweEncryption::A128GCM,
        )
        .unwrap();

        let validation = Validation::new().with_issuer("kw-issuer");
        let decoded = decode_nested(&kek, &hmac_verifier(), &nested_token, &validation).unwrap();

        assert_eq!(decoded.iss.as_deref(), Some("kw-issuer"));
    }

    #[test]
    fn nested_jwt_wrong_decryption_key_fails() {
        let jws_header = JoseHeader::jwt("HS256");
        let mut claims = Claims::default();
        claims.exp = Some(now() + 3600);

        let cek = [0x42u8; 32];
        let wrong_cek = [0x99u8; 32];

        let nested_token = encode_nested(
            &hmac_signer(),
            &jws_header,
            &claims,
            &cek,
            crate::algorithm::JweAlgorithm::Dir,
            crate::algorithm::JweEncryption::A256GCM,
        )
        .unwrap();

        let validation = Validation::new();
        let result = decode_nested(&wrong_cek, &hmac_verifier(), &nested_token, &validation);
        assert!(result.is_err(), "wrong decryption key should fail");
    }

    #[test]
    fn nested_jwt_wrong_verification_key_fails() {
        let jws_header = JoseHeader::jwt("HS256");
        let mut claims = Claims::default();
        claims.exp = Some(now() + 3600);

        let cek = [0x42u8; 32];

        let nested_token = encode_nested(
            &hmac_signer(),
            &jws_header,
            &claims,
            &cek,
            crate::algorithm::JweAlgorithm::Dir,
            crate::algorithm::JweEncryption::A256GCM,
        )
        .unwrap();

        // Different HMAC key for verification
        let wrong_key = SoftwareKey::Hmac(b"wrong-key-that-is-at-least-32-bytes!!".to_vec());
        let wrong_verifier = SoftwareVerifier::new(hmac_algo(), wrong_key).unwrap();

        let validation = Validation::new();
        let result = decode_nested(&cek, &wrong_verifier, &nested_token, &validation);
        assert!(result.is_err(), "wrong verification key should fail");
    }

    #[test]
    fn nested_jwt_with_cbc_hs() {
        // Sign with HMAC, encrypt with dir + A256CBC-HS512
        let jws_header = JoseHeader::jwt("HS256");
        let mut claims = Claims::default();
        claims.iss = Some("cbc-nested".into());
        claims.exp = Some(now() + 3600);

        // 64-byte CEK for A256CBC-HS512 (32 HMAC + 32 AES)
        let cek = [0x55u8; 64];

        let nested_token = encode_nested(
            &hmac_signer(),
            &jws_header,
            &claims,
            &cek,
            crate::algorithm::JweAlgorithm::Dir,
            crate::algorithm::JweEncryption::A256CbcHs512,
        )
        .unwrap();

        let validation = Validation::new().with_issuer("cbc-nested");
        let decoded = decode_nested(&cek, &hmac_verifier(), &nested_token, &validation).unwrap();

        assert_eq!(decoded.iss.as_deref(), Some("cbc-nested"));
    }

    // ── Phase 10: nested JWT JWK API ──────────────────────────────

    /// Nested JWT JWK roundtrip: HMAC sign + dir A256GCM encrypt, both via JWK.
    #[test]
    fn nested_jwt_jwk_roundtrip_dir() {
        let mut signer_jwk = crate::jwk::generate_symmetric(32).unwrap();
        signer_jwk.alg = Some("HS256".into());

        let mut enc_jwk = crate::jwk::generate_symmetric(32).unwrap();
        enc_jwk.alg = Some("dir".into());

        let jws_header = JoseHeader::jwt_for_alg(crate::algorithm::JwsAlgorithm::HS256);
        let mut claims = Claims::default();
        claims.iss = Some("nested-jwk".into());
        claims.exp = Some(now() + 3600);

        let token = encode_nested_with_jwk(
            &signer_jwk,
            &jws_header,
            &claims,
            &enc_jwk,
            crate::algorithm::JweEncryption::A256GCM,
        )
        .unwrap();

        // Should be a JWE compact (5 parts).
        assert_eq!(token.split('.').count(), 5);

        let validation = Validation::new().with_issuer("nested-jwk");
        let decoded = decode_nested_with_jwk(&enc_jwk, &signer_jwk, &token, &validation).unwrap();
        assert_eq!(decoded.iss.as_deref(), Some("nested-jwk"));
    }

    /// Nested JWT JWK rejects signer JWK with use=enc.
    #[test]
    fn nested_jwt_jwk_rejects_signer_use_enc() {
        let mut signer_jwk = crate::jwk::generate_symmetric(32).unwrap();
        signer_jwk.alg = Some("HS256".into());
        signer_jwk.use_ = Some("enc".into()); // wrong category for signing

        let mut enc_jwk = crate::jwk::generate_symmetric(32).unwrap();
        enc_jwk.alg = Some("dir".into());

        let jws_header = JoseHeader::jwt_for_alg(crate::algorithm::JwsAlgorithm::HS256);
        let mut claims = Claims::default();
        claims.exp = Some(now() + 3600);

        let err = encode_nested_with_jwk(
            &signer_jwk,
            &jws_header,
            &claims,
            &enc_jwk,
            crate::algorithm::JweEncryption::A256GCM,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("`use` is enc"), "unexpected: {err}");
    }

    /// Nested JWT JWK rejects encryption JWK with use=sig.
    #[test]
    fn nested_jwt_jwk_rejects_encryption_use_sig() {
        let mut signer_jwk = crate::jwk::generate_symmetric(32).unwrap();
        signer_jwk.alg = Some("HS256".into());

        let mut enc_jwk = crate::jwk::generate_symmetric(32).unwrap();
        enc_jwk.alg = Some("dir".into());
        enc_jwk.use_ = Some("sig".into()); // wrong category for encrypting

        let jws_header = JoseHeader::jwt_for_alg(crate::algorithm::JwsAlgorithm::HS256);
        let mut claims = Claims::default();
        claims.exp = Some(now() + 3600);

        let err = encode_nested_with_jwk(
            &signer_jwk,
            &jws_header,
            &claims,
            &enc_jwk,
            crate::algorithm::JweEncryption::A256GCM,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("`use` is sig"), "unexpected: {err}");
    }

    // ── Phase 9: encode_with_jwk ───────────────────────────────────

    /// Phase 9: encode_with_jwk + decode_with_jwk full JWT round-trip.
    #[test]
    fn encode_decode_with_jwk_hmac() {
        let mut jwk = crate::jwk::generate_symmetric(32).unwrap();
        jwk.alg = Some("HS256".into());
        jwk.kid = Some("k1".into());

        let header = JoseHeader::jwt("HS256");
        let mut claims = Claims::default();
        claims.iss = Some("me".into());
        claims.exp = Some(now() + 3600);

        let token = encode_with_jwk(&jwk, &header, &claims).unwrap();
        let validation = Validation::new().with_issuer("me");
        let decoded = decode_with_jwk(&jwk, &token, &validation).unwrap();
        assert_eq!(decoded.iss.as_deref(), Some("me"));
    }

    // ── Phase 8: JWK-based decode ──────────────────────────────────

    /// decode_with_jwk: happy path using a symmetric JWK.
    #[test]
    fn decode_with_jwk_hmac() {
        // Prepare a symmetric JWK marked for HS256.
        let mut jwk = crate::jwk::generate_symmetric(32).unwrap();
        jwk.alg = Some("HS256".into());
        jwk.kid = Some("key-1".into());

        // Sign with the same key material.
        let sw = crate::jwk::jwk_to_software_key(&jwk).unwrap();
        let signer = SoftwareSigner::new(hmac_algo(), sw).unwrap();
        let header = JoseHeader::jwt("HS256");
        let mut claims = Claims::default();
        claims.iss = Some("issuer-1".into());
        claims.exp = Some(now() + 3600);
        let token = encode(&signer, &header, &claims).unwrap();

        let validation = Validation::new().with_issuer("issuer-1");
        let decoded = decode_with_jwk(&jwk, &token, &validation).unwrap();
        assert_eq!(decoded.iss.as_deref(), Some("issuer-1"));
    }

    /// decode_with_jwk: a JWK marked use="enc" is rejected for verification.
    #[test]
    fn decode_with_jwk_use_enc_rejected() {
        let mut jwk = crate::jwk::generate_symmetric(32).unwrap();
        jwk.alg = Some("HS256".into());
        jwk.use_ = Some("enc".into());

        let k = crate::base64url::decode(jwk.k.as_ref().unwrap()).unwrap();
        let signer = SoftwareSigner::new(hmac_algo(), SoftwareKey::Hmac(k)).unwrap();
        let header = JoseHeader::jwt("HS256");
        let mut claims = Claims::default();
        claims.exp = Some(now() + 3600);
        let token = encode(&signer, &header, &claims).unwrap();

        let err = decode_with_jwk(&jwk, &token, &Validation::new())
            .unwrap_err()
            .to_string();
        assert!(err.contains("`use` is enc"), "unexpected: {err}");
    }

    /// decode_with_jwkset: kid-based selection.
    #[test]
    fn decode_with_jwkset_kid_match() {
        let mut jwk_a = crate::jwk::generate_symmetric(32).unwrap();
        jwk_a.alg = Some("HS256".into());
        jwk_a.kid = Some("a".into());

        let mut jwk_b = crate::jwk::generate_symmetric(32).unwrap();
        jwk_b.alg = Some("HS256".into());
        jwk_b.kid = Some("b".into());

        // Sign with jwk_b.
        let k_b = crate::base64url::decode(jwk_b.k.as_ref().unwrap()).unwrap();
        let signer = SoftwareSigner::new(hmac_algo(), SoftwareKey::Hmac(k_b)).unwrap();
        let mut header = JoseHeader::jwt("HS256");
        header.kid = Some("b".into()); // kid points at jwk_b
        let mut claims = Claims::default();
        claims.exp = Some(now() + 3600);
        let token = encode(&signer, &header, &claims).unwrap();

        let set = crate::jwk::JwkSet {
            keys: vec![jwk_a, jwk_b],
        };
        let decoded = decode_with_jwkset(&set, &token, &Validation::new()).unwrap();
        assert_eq!(decoded.exp, claims.exp);
    }

    /// decode_with_jwkset: no kid → fall back to trying each key.
    #[test]
    fn decode_with_jwkset_no_kid_fallback() {
        let mut jwk_a = crate::jwk::generate_symmetric(32).unwrap();
        jwk_a.alg = Some("HS256".into());
        // Deliberately no kid on either key.
        let mut jwk_b = crate::jwk::generate_symmetric(32).unwrap();
        jwk_b.alg = Some("HS256".into());

        // Token signed with jwk_b, header has no kid.
        let k_b = crate::base64url::decode(jwk_b.k.as_ref().unwrap()).unwrap();
        let signer = SoftwareSigner::new(hmac_algo(), SoftwareKey::Hmac(k_b)).unwrap();
        let header = JoseHeader::jwt("HS256");
        let mut claims = Claims::default();
        claims.exp = Some(now() + 3600);
        let token = encode(&signer, &header, &claims).unwrap();

        let set = crate::jwk::JwkSet {
            keys: vec![jwk_a, jwk_b],
        };
        // Fallback finds jwk_b on second try.
        decode_with_jwkset(&set, &token, &Validation::new()).unwrap();
    }

    /// decode_with_jwkset: no key in the set matches → error.
    #[test]
    fn decode_with_jwkset_no_match() {
        let mut jwk_a = crate::jwk::generate_symmetric(32).unwrap();
        jwk_a.alg = Some("HS256".into());

        // Sign with a completely different key.
        let other = SoftwareKey::Hmac(b"completely-different-32-byte-key".to_vec());
        let signer = SoftwareSigner::new(hmac_algo(), other).unwrap();
        let header = JoseHeader::jwt("HS256");
        let mut claims = Claims::default();
        claims.exp = Some(now() + 3600);
        let token = encode(&signer, &header, &claims).unwrap();

        let set = crate::jwk::JwkSet { keys: vec![jwk_a] };
        assert!(decode_with_jwkset(&set, &token, &Validation::new()).is_err());
    }

    // ── Phase 11: post-quantum ML-DSA JWT round-trips ──────────────

    /// JWT encode/decode round-trip using ML-DSA-65 as the signature
    /// algorithm. Covers the full JWK-based one-shot API:
    /// `encode_with_jwk` + `decode_with_jwk` with kty="AKP".
    #[cfg(feature = "post-quantum")]
    #[test]
    fn jwt_mldsa_65_jwk_roundtrip() {
        use kryptering::MlDsaVariant;
        let mut jwk = crate::jwk::generate::generate_mldsa(MlDsaVariant::MlDsa65).unwrap();
        jwk.kid = Some("pq-1".into());

        let header = JoseHeader::jwt("ML-DSA-65");
        let mut claims = Claims::default();
        claims.iss = Some("pq-issuer".into());
        claims.exp = Some(now() + 3600);

        let token = encode_with_jwk(&jwk, &header, &claims).unwrap();
        let validation = Validation::new().with_issuer("pq-issuer");
        let decoded = decode_with_jwk(&jwk, &token, &validation).unwrap();
        assert_eq!(decoded.iss.as_deref(), Some("pq-issuer"));
    }

    /// JWT decode_with_jwkset kid-based selection works for ML-DSA keys.
    #[cfg(feature = "post-quantum")]
    #[test]
    fn jwt_mldsa_jwkset_kid_selection() {
        use kryptering::MlDsaVariant;
        let mut jwk_a = crate::jwk::generate::generate_mldsa(MlDsaVariant::MlDsa44).unwrap();
        jwk_a.kid = Some("pq-a".into());
        let mut jwk_b = crate::jwk::generate::generate_mldsa(MlDsaVariant::MlDsa44).unwrap();
        jwk_b.kid = Some("pq-b".into());

        let mut header = JoseHeader::jwt("ML-DSA-44");
        header.kid = Some("pq-b".into());
        let mut claims = Claims::default();
        claims.exp = Some(now() + 3600);

        let token = encode_with_jwk(&jwk_b, &header, &claims).unwrap();

        let set = crate::jwk::JwkSet {
            keys: vec![jwk_a, jwk_b],
        };
        let decoded = decode_with_jwkset(&set, &token, &Validation::new()).unwrap();
        assert_eq!(decoded.exp, claims.exp);
    }
}
