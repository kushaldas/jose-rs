//! JWS Compact Serialization (RFC 7515 Section 3.1).
//!
//! Format: `BASE64URL(header).BASE64URL(payload).BASE64URL(signature)`

use crate::base64url;
use crate::error::{JoseError, Result};
use crate::header::JoseHeader;

/// Sign a payload and produce a JWS Compact Serialization string.
///
/// The `signer` provides the cryptographic operation -- it can be a software
/// key or an HSM-backed key.
pub fn sign(
    signer: &dyn kryptering::Signer,
    payload: &[u8],
    header: &JoseHeader,
) -> Result<String> {
    let header_json = serde_json::to_vec(header)?;
    let header_b64 = base64url::encode(&header_json);
    let payload_b64 = base64url::encode(payload);
    let signing_input = format!("{header_b64}.{payload_b64}");
    let signature = signer.sign(signing_input.as_bytes())
        .map_err(JoseError::Crypto)?;
    let sig_b64 = base64url::encode(&signature);
    Ok(format!("{signing_input}.{sig_b64}"))
}

/// Verify a JWS Compact Serialization string.
///
/// Returns the decoded payload on success.
pub fn verify(
    verifier: &dyn kryptering::Verifier,
    token: &str,
) -> Result<Vec<u8>> {
    let parts: Vec<&str> = token.splitn(3, '.').collect();
    if parts.len() != 3 {
        return Err(JoseError::InvalidToken(
            "expected 3 dot-separated parts".into(),
        ));
    }
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let signature = base64url::decode(parts[2])?;
    let valid = verifier
        .verify(signing_input.as_bytes(), &signature)
        .map_err(JoseError::Crypto)?;
    if !valid {
        return Err(JoseError::InvalidToken(
            "signature verification failed".into(),
        ));
    }
    base64url::decode(parts[1])
}

/// Decode the header from a JWS Compact Serialization without verifying.
pub fn decode_header(token: &str) -> Result<JoseHeader> {
    let header_b64 = token
        .split('.')
        .next()
        .ok_or_else(|| JoseError::InvalidToken("empty token".into()))?;
    let header_json = base64url::decode(header_b64)?;
    serde_json::from_slice(&header_json).map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kryptering::{HashAlgorithm, SignatureAlgorithm, SoftwareKey, SoftwareSigner, SoftwareVerifier};

    fn hmac_key() -> SoftwareKey {
        SoftwareKey::Hmac(b"my-secret-key-at-least-32-bytes!".to_vec())
    }

    fn hmac_signer() -> SoftwareSigner {
        SoftwareSigner::new(
            SignatureAlgorithm::Hmac(HashAlgorithm::Sha256),
            hmac_key(),
        )
        .unwrap()
    }

    fn hmac_verifier() -> SoftwareVerifier {
        SoftwareVerifier::new(
            SignatureAlgorithm::Hmac(HashAlgorithm::Sha256),
            hmac_key(),
        )
        .unwrap()
    }

    #[test]
    fn sign_verify_hmac_roundtrip() {
        let header = JoseHeader::new("HS256");
        let payload = b"hello, world!";

        let token = sign(&hmac_signer(), payload, &header).unwrap();

        // Token should have 3 dot-separated parts.
        assert_eq!(token.split('.').count(), 3);

        // Verify and recover payload.
        let recovered = verify(&hmac_verifier(), &token).unwrap();
        assert_eq!(recovered, payload);
    }

    #[test]
    fn sign_verify_ed25519_roundtrip() {
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;

        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        let signer_key = SoftwareKey::Ed25519 {
            private: Some(signing_key),
            public: verifying_key,
        };
        let verifier_key = SoftwareKey::Ed25519 {
            private: None,
            public: verifying_key,
        };

        let signer = SoftwareSigner::new(SignatureAlgorithm::Ed25519, signer_key).unwrap();
        let verifier = SoftwareVerifier::new(SignatureAlgorithm::Ed25519, verifier_key).unwrap();

        let header = JoseHeader::new("EdDSA");
        let payload = b"EdDSA test payload";

        let token = sign(&signer, payload, &header).unwrap();
        let recovered = verify(&verifier, &token).unwrap();
        assert_eq!(recovered, payload);

        // Decode header without verification.
        let decoded = decode_header(&token).unwrap();
        assert_eq!(decoded.alg, "EdDSA");
    }

    #[test]
    fn verify_wrong_key_fails() {
        let header = JoseHeader::new("HS256");
        let payload = b"secret data";

        let token = sign(&hmac_signer(), payload, &header).unwrap();

        // Verify with a different key.
        let wrong_key = SoftwareKey::Hmac(b"wrong-key-that-is-also-32-bytes!".to_vec());
        let wrong_verifier = SoftwareVerifier::new(
            SignatureAlgorithm::Hmac(HashAlgorithm::Sha256),
            wrong_key,
        )
        .unwrap();

        let result = verify(&wrong_verifier, &token);
        assert!(result.is_err());
    }

    #[test]
    fn malformed_token_wrong_parts() {
        let result = verify(&hmac_verifier(), "only.two");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("3 dot-separated parts"),
            "unexpected error: {err}"
        );

        let result2 = verify(&hmac_verifier(), "noparts");
        assert!(result2.is_err());
    }

    #[test]
    fn tampered_payload_fails_verification() {
        let header = JoseHeader::new("HS256");
        let payload = b"original payload";

        let token = sign(&hmac_signer(), payload, &header).unwrap();

        // Tamper with the payload part (second segment).
        let parts: Vec<&str> = token.splitn(3, '.').collect();
        let tampered_payload = base64url::encode(b"tampered payload");
        let tampered_token = format!("{}.{}.{}", parts[0], tampered_payload, parts[2]);

        let result = verify(&hmac_verifier(), &tampered_token);
        assert!(result.is_err());
    }
}
