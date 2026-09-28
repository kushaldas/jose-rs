//! Regression checks shared across public JOSE verification entry points.

use crate::{base64url, jws, jwt, JoseError, JoseHeader, JwsAlgorithm};
use kryptering::{SignatureAlgorithm, Verifier};

/// Test verifier that makes premature cryptographic dispatch fail the test.
struct RejectBeforeCrypto;

impl Verifier for RejectBeforeCrypto {
    /// Supply a supported algorithm so rejection must come from header policy.
    fn algorithm(&self) -> SignatureAlgorithm {
        JwsAlgorithm::HS256.to_crypto().unwrap()
    }

    /// Fail immediately if an invalid header reaches the cryptographic boundary.
    fn verify(&self, _data: &[u8], _signature: &[u8]) -> kryptering::Result<bool> {
        panic!("invalid algorithm must be rejected before cryptographic verification")
    }
}

/// Require an algorithm-policy error rather than an unrelated parse or
/// signature failure, allowing the explicit lowercase `none` rejection too.
fn assert_algorithm_rejected<T: std::fmt::Debug>(result: crate::Result<T>, alg: &str) {
    match result {
        Err(JoseError::UnsupportedAlgorithm(_)) => {}
        Err(JoseError::InvalidToken(message)) if alg == "none" => {
            assert!(message.contains("none"), "unexpected error: {message}");
        }
        other => panic!("expected algorithm rejection for {alg:?}, got {other:?}"),
    }
}

/// Noncanonical algorithm identifiers must fail before crypto dispatch across
/// compact, JWK, JWT, and JSON APIs, including when legacy algorithms are enabled.
#[test]
fn alg_variants_rejected_across_verification_paths() {
    // JSON escape spellings are decoded before the same exact allow-list
    // check. These fixtures contain no valid signature and must not reach a
    // verifier; generic signature failure would not establish this invariant.
    let algorithm_json = [
        r#""none""#,
        r#""nOne""#,
        r#""NONE""#,
        r#""None""#,
        r#""NoNe""#,
        r#"" none""#,
        r#""none ""#,
        r#""none\t""#,
        r#""none\u0000""#,
        r#""\u006eone""#,
        r#""n\u004fne""#,
        r#""hs256""#,
        r#""Hs256""#,
        r#""HS256 ""#,
        r#""""#,
    ];
    let verifier = RejectBeforeCrypto;
    let validation = jwt::Validation::new();
    let jwk = crate::jwk::generate_symmetric_for_alg("HS256").unwrap();
    let set = crate::jwk::JwkSet {
        keys: vec![jwk.clone()],
    };
    let payload = base64url::encode(b"{}");

    for value in algorithm_json {
        let alg: String = serde_json::from_str(value).unwrap();
        let protected = base64url::encode(format!(r#"{{"alg":{value}}}"#).as_bytes());
        let token = format!("{protected}.{payload}.");
        assert_algorithm_rejected(jws::compact::verify(&verifier, &token), &alg);
        assert_algorithm_rejected(jws::compact::verify_with_jwk(&jwk, &token), &alg);
        assert_algorithm_rejected(jwt::decode(&verifier, &token, &validation), &alg);
        assert_algorithm_rejected(jwt::decode_with_jwk(&jwk, &token, &validation), &alg);
        assert_algorithm_rejected(jwt::decode_with_jwkset(&set, &token, &validation), &alg);

        let flattened = jws::json::FlattenedJws {
            payload: Some(payload.clone()),
            protected: protected.clone(),
            header: None,
            signature: String::new(),
        };
        assert_algorithm_rejected(jws::json::verify_flattened(&verifier, &flattened), &alg);
        let general = jws::json::GeneralJws {
            payload: Some(payload.clone()),
            signatures: vec![jws::json::JwsSignature {
                protected,
                header: None,
                signature: String::new(),
            }],
        };
        assert!(jws::json::verify_general(&verifier, &general).is_err());
        let (results, recovered) =
            jws::json::verify_general_all(&verifier, &general, None, &jws::VerifyOptions::new())
                .unwrap();
        assert_eq!(results.len(), 1);
        assert!(!results[0].verified, "{alg:?} must not count as verified");
        assert!(results[0].error.is_some());
        assert!(recovered.is_none());
    }
}

/// General JWS uses an any-valid-signature policy: an invalid algorithm entry
/// stays unverified while another authenticated entry can release the payload.
#[test]
fn general_jws_invalid_algorithm_does_not_hide_a_valid_signature() {
    let key =
        kryptering::SoftwareKey::from_symmetric_bytes(kryptering::KeyAlgorithm::Hmac, &[0x42; 32])
            .unwrap();
    let alg = JwsAlgorithm::HS256.to_crypto().unwrap();
    let signer = kryptering::SoftwareSigner::new(alg, key.clone()).unwrap();
    let verifier = kryptering::SoftwareVerifier::new(alg, key).unwrap();
    let header = JoseHeader::new("HS256");
    let payload = b"authenticated payload";
    let mut general = jws::json::sign_general(&[(&signer, &header)], payload).unwrap();
    general.signatures.insert(
        0,
        jws::json::JwsSignature {
            protected: base64url::encode(br#"{"alg":"nOne"}"#),
            header: None,
            signature: String::new(),
        },
    );
    assert_eq!(
        jws::json::verify_general(&verifier, &general).unwrap(),
        payload
    );
    let (results, recovered) =
        jws::json::verify_general_all(&verifier, &general, None, &jws::VerifyOptions::new())
            .unwrap();
    assert!(!results[0].verified);
    assert!(results[1].verified);
    assert_eq!(recovered.unwrap(), payload);
}
