//! JWS JSON Serialization (RFC 7515 Section 7.2).
//!
//! Supports both Flattened (Section 7.2.2) and General (Section 7.2.1) forms.

use serde::{Deserialize, Serialize};

use crate::base64url;
use crate::error::{JoseError, Result};
use crate::header::JoseHeader;

// ---------------------------------------------------------------------------
// Data structures
// ---------------------------------------------------------------------------

/// Flattened JWS JSON Serialization (RFC 7515 Section 7.2.2).
///
/// Contains a single signature over the payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlattenedJws {
    /// Base64url-encoded payload.
    pub payload: String,
    /// Base64url-encoded protected header.
    pub protected: String,
    /// Base64url-encoded signature.
    pub signature: String,
}

/// A single signature entry in General JWS JSON Serialization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwsSignature {
    /// Base64url-encoded protected header.
    pub protected: String,
    /// Base64url-encoded signature.
    pub signature: String,
    /// Optional unprotected header parameters.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub header: Option<serde_json::Value>,
}

/// General JWS JSON Serialization (RFC 7515 Section 7.2.1).
///
/// Contains one or more signatures over a shared payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneralJws {
    /// Base64url-encoded payload (shared across all signatures).
    pub payload: String,
    /// Array of signature objects.
    pub signatures: Vec<JwsSignature>,
}

// ---------------------------------------------------------------------------
// Flattened JWS operations
// ---------------------------------------------------------------------------

/// Create a Flattened JWS JSON from a signer, payload, and header.
pub fn sign_flattened(
    signer: &dyn kryptering::Signer,
    payload: &[u8],
    header: &JoseHeader,
) -> Result<FlattenedJws> {
    let header_json = serde_json::to_vec(header)?;
    let protected_b64 = base64url::encode(&header_json);
    let payload_b64 = base64url::encode(payload);
    let signing_input = format!("{protected_b64}.{payload_b64}");
    let sig = signer
        .sign(signing_input.as_bytes())
        .map_err(JoseError::Crypto)?;
    Ok(FlattenedJws {
        payload: payload_b64,
        protected: protected_b64,
        signature: base64url::encode(&sig),
    })
}

/// Verify a Flattened JWS JSON and return the decoded payload.
pub fn verify_flattened(
    verifier: &dyn kryptering::Verifier,
    jws: &FlattenedJws,
) -> Result<Vec<u8>> {
    let signing_input = format!("{}.{}", jws.protected, jws.payload);
    let sig = base64url::decode(&jws.signature)?;
    let valid = verifier
        .verify(signing_input.as_bytes(), &sig)
        .map_err(JoseError::Crypto)?;
    if !valid {
        return Err(JoseError::InvalidToken(
            "signature verification failed".into(),
        ));
    }
    base64url::decode(&jws.payload)
}

// ---------------------------------------------------------------------------
// General JWS operations
// ---------------------------------------------------------------------------

/// Create a General JWS JSON with multiple signers.
///
/// Each element of `signers` is a `(signer, header)` pair. All signers sign
/// the same payload; their individual protected headers are serialized
/// independently.
pub fn sign_general(
    signers: &[(&dyn kryptering::Signer, &JoseHeader)],
    payload: &[u8],
) -> Result<GeneralJws> {
    if signers.is_empty() {
        return Err(JoseError::InvalidToken(
            "at least one signer is required".into(),
        ));
    }
    let payload_b64 = base64url::encode(payload);
    let mut signatures = Vec::with_capacity(signers.len());

    for (signer, header) in signers {
        let header_json = serde_json::to_vec(header)?;
        let protected_b64 = base64url::encode(&header_json);
        let signing_input = format!("{protected_b64}.{payload_b64}");
        let sig = signer
            .sign(signing_input.as_bytes())
            .map_err(JoseError::Crypto)?;
        signatures.push(JwsSignature {
            protected: protected_b64,
            signature: base64url::encode(&sig),
            header: None,
        });
    }

    Ok(GeneralJws {
        payload: payload_b64,
        signatures,
    })
}

/// Verify at least one signature in a General JWS JSON.
///
/// Iterates through all signatures and returns the decoded payload if any
/// one of them verifies successfully. Returns an error if none verify.
pub fn verify_general(
    verifier: &dyn kryptering::Verifier,
    jws: &GeneralJws,
) -> Result<Vec<u8>> {
    if jws.signatures.is_empty() {
        return Err(JoseError::InvalidToken("no signatures present".into()));
    }
    for entry in &jws.signatures {
        let signing_input = format!("{}.{}", entry.protected, jws.payload);
        let sig = match base64url::decode(&entry.signature) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let valid = match verifier.verify(signing_input.as_bytes(), &sig) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if valid {
            return base64url::decode(&jws.payload);
        }
    }
    Err(JoseError::InvalidToken(
        "no signature verified successfully".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use kryptering::{HashAlgorithm, SignatureAlgorithm, SoftwareKey, SoftwareSigner, SoftwareVerifier};

    fn hmac_key(secret: &[u8]) -> SoftwareKey {
        SoftwareKey::Hmac(secret.to_vec())
    }

    fn hmac_signer(secret: &[u8]) -> SoftwareSigner {
        SoftwareSigner::new(
            SignatureAlgorithm::Hmac(HashAlgorithm::Sha256),
            hmac_key(secret),
        )
        .unwrap()
    }

    fn hmac_verifier(secret: &[u8]) -> SoftwareVerifier {
        SoftwareVerifier::new(
            SignatureAlgorithm::Hmac(HashAlgorithm::Sha256),
            hmac_key(secret),
        )
        .unwrap()
    }

    const KEY_A: &[u8] = b"my-secret-key-at-least-32-bytes!";
    const KEY_B: &[u8] = b"another-key-that-is-32-bytes-xx!";
    const WRONG_KEY: &[u8] = b"wrong-key-that-is-also-32-bytes!";

    // -----------------------------------------------------------------------
    // Flattened JWS tests
    // -----------------------------------------------------------------------

    #[test]
    fn flattened_sign_verify_roundtrip() {
        let header = JoseHeader::new("HS256");
        let payload = b"flattened test payload";

        let jws = sign_flattened(&hmac_signer(KEY_A), payload, &header).unwrap();
        let recovered = verify_flattened(&hmac_verifier(KEY_A), &jws).unwrap();
        assert_eq!(recovered, payload);
    }

    #[test]
    fn flattened_serializes_to_valid_json() {
        let header = JoseHeader::new("HS256");
        let payload = b"json check";

        let jws = sign_flattened(&hmac_signer(KEY_A), payload, &header).unwrap();
        let json_str = serde_json::to_string(&jws).unwrap();

        // Must contain the three expected top-level keys.
        let v: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert!(v.get("payload").is_some());
        assert!(v.get("protected").is_some());
        assert!(v.get("signature").is_some());
        // Must NOT contain "signatures" (that is General form).
        assert!(v.get("signatures").is_none());
    }

    #[test]
    fn flattened_verify_wrong_key_fails() {
        let header = JoseHeader::new("HS256");
        let payload = b"secret data";

        let jws = sign_flattened(&hmac_signer(KEY_A), payload, &header).unwrap();
        let result = verify_flattened(&hmac_verifier(WRONG_KEY), &jws);
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // General JWS tests
    // -----------------------------------------------------------------------

    #[test]
    fn general_two_signatures_verify_with_either_key() {
        let header_a = JoseHeader::new("HS256");
        let header_b = JoseHeader::new("HS256");
        let payload = b"multi-sig payload";

        let signer_a = hmac_signer(KEY_A);
        let signer_b = hmac_signer(KEY_B);

        let signers: Vec<(&dyn kryptering::Signer, &JoseHeader)> =
            vec![(&signer_a, &header_a), (&signer_b, &header_b)];

        let jws = sign_general(&signers, payload).unwrap();
        assert_eq!(jws.signatures.len(), 2);

        // Verify with key A -- should find the first signature valid.
        let recovered_a = verify_general(&hmac_verifier(KEY_A), &jws).unwrap();
        assert_eq!(recovered_a, payload);

        // Verify with key B -- should find the second signature valid.
        let recovered_b = verify_general(&hmac_verifier(KEY_B), &jws).unwrap();
        assert_eq!(recovered_b, payload);
    }

    #[test]
    fn general_verify_wrong_key_fails() {
        let header = JoseHeader::new("HS256");
        let payload = b"general payload";

        let signer_a = hmac_signer(KEY_A);
        let signers: Vec<(&dyn kryptering::Signer, &JoseHeader)> =
            vec![(&signer_a, &header)];

        let jws = sign_general(&signers, payload).unwrap();
        let result = verify_general(&hmac_verifier(WRONG_KEY), &jws);
        assert!(result.is_err());
    }

    #[test]
    fn general_serializes_to_valid_json() {
        let header = JoseHeader::new("HS256");
        let payload = b"json check general";

        let signer = hmac_signer(KEY_A);
        let signers: Vec<(&dyn kryptering::Signer, &JoseHeader)> =
            vec![(&signer, &header)];

        let jws = sign_general(&signers, payload).unwrap();
        let json_str = serde_json::to_string(&jws).unwrap();

        let v: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert!(v.get("payload").is_some());
        assert!(v.get("signatures").is_some());
        let sigs = v["signatures"].as_array().unwrap();
        assert_eq!(sigs.len(), 1);
        assert!(sigs[0].get("protected").is_some());
        assert!(sigs[0].get("signature").is_some());
    }

    #[test]
    fn general_roundtrip_through_json() {
        let header = JoseHeader::new("HS256");
        let payload = b"roundtrip via json";

        let signer = hmac_signer(KEY_A);
        let signers: Vec<(&dyn kryptering::Signer, &JoseHeader)> =
            vec![(&signer, &header)];

        let jws = sign_general(&signers, payload).unwrap();

        // Serialize to JSON and back.
        let json_str = serde_json::to_string(&jws).unwrap();
        let deserialized: GeneralJws = serde_json::from_str(&json_str).unwrap();

        let recovered = verify_general(&hmac_verifier(KEY_A), &deserialized).unwrap();
        assert_eq!(recovered, payload);
    }
}
