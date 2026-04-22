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

/// Decode a JWT without verifying the signature (DANGEROUS — for inspection only).
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
    use kryptering::{HashAlgorithm, SignatureAlgorithm, SoftwareKey, SoftwareSigner, SoftwareVerifier};
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
        claims
            .extra
            .insert("level".into(), serde_json::json!(42));

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
}
