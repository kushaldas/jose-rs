use jose_rs::{
    jwk::{self, Jwk, JwkOp},
    jws::compact,
    JoseHeader, JwsAlgorithm,
};

fn oct(len: usize) -> Jwk {
    jwk::generate_symmetric(len).unwrap()
}

#[test]
fn hmac_strength_is_checked_for_each_operation_without_metadata() {
    for (alg, minimum) in [
        (JwsAlgorithm::HS256, 32),
        (JwsAlgorithm::HS384, 48),
        (JwsAlgorithm::HS512, 64),
    ] {
        for op in [JwkOp::Sign, JwkOp::Verify] {
            for len in [16, 24, 32, 47, 48, 63, 64, 80] {
                let key = oct(len);
                let before = key.to_json().unwrap();
                let result = jwk::jwk_to_signature_key(&key, alg, op);
                if len < minimum {
                    assert!(result.is_err(), "{alg:?}/{op:?} accepted {len} bytes");
                } else {
                    assert_eq!(result.unwrap().algorithm(), kryptering::KeyAlgorithm::Hmac);
                }
                assert_eq!(key.to_json().unwrap(), before);
            }
        }
    }
}

#[test]
fn unpinned_hmac_keys_sign_and_verify_with_explicit_context() {
    for (alg, len) in [
        (JwsAlgorithm::HS256, 32),
        (JwsAlgorithm::HS384, 48),
        (JwsAlgorithm::HS512, 64),
    ] {
        let key = oct(len);
        let software = jwk::jwk_to_signature_key(&key, alg, JwkOp::Sign).unwrap();
        let signer = kryptering::SoftwareSigner::new(alg.to_crypto().unwrap(), software).unwrap();
        let header = JoseHeader::new(alg.as_str());
        let token = compact::sign(&signer, b"operation-aware key", &header).unwrap();
        assert_eq!(
            compact::verify_with_jwk(&key, &token).unwrap(),
            b"operation-aware key"
        );
        assert!(key.alg.is_none());
        // The existing one-shot signing API still requires an explicit pin.
        assert!(compact::sign_with_jwk(&key, b"payload", &header).is_err());
    }
}

#[test]
fn metadata_restrictions_cannot_be_overridden() {
    let mut key = oct(64);
    for pinned in ["HS384", "A256KW", "unknown"] {
        key.alg = Some(pinned.into());
        for op in [JwkOp::Sign, JwkOp::Verify] {
            assert!(jwk::jwk_to_signature_key(&key, JwsAlgorithm::HS512, op).is_err());
            assert_eq!(key.alg.as_deref(), Some(pinned));
        }
    }
    key.alg = None;
    key.use_ = Some("enc".into());
    assert!(jwk::jwk_to_signature_key(&key, JwsAlgorithm::HS512, JwkOp::Sign).is_err());
    key.use_ = Some("sig".into());
    key.key_ops = Some(vec!["verify".into()]);
    assert!(jwk::jwk_to_signature_key(&key, JwsAlgorithm::HS512, JwkOp::Sign).is_err());
    assert!(jwk::jwk_to_signature_key(&key, JwsAlgorithm::HS512, JwkOp::Verify).is_ok());
    key.key_ops = Some(vec!["sign".into()]);
    assert!(jwk::jwk_to_signature_key(&key, JwsAlgorithm::HS512, JwkOp::Verify).is_err());
    key.key_ops = None;
    for op in [
        JwkOp::Encrypt,
        JwkOp::Decrypt,
        JwkOp::WrapKey,
        JwkOp::UnwrapKey,
        JwkOp::DeriveKey,
        JwkOp::DeriveBits,
    ] {
        assert!(jwk::jwk_to_signature_key(&key, JwsAlgorithm::HS512, op).is_err());
    }
}

#[test]
fn asymmetric_type_curve_and_private_material_are_checked() {
    let key = jwk::generate_ec("P-256").unwrap();
    assert!(jwk::jwk_to_signature_key(&key, JwsAlgorithm::HS256, JwkOp::Verify).is_err());
    assert!(jwk::jwk_to_signature_key(&key, JwsAlgorithm::ES384, JwkOp::Verify).is_err());
    assert!(jwk::jwk_to_signature_key(&key, JwsAlgorithm::ES256, JwkOp::Sign).is_ok());
    let public = key.to_public_jwk();
    assert!(jwk::jwk_to_signature_key(&public, JwsAlgorithm::ES256, JwkOp::Sign).is_err());
    assert!(jwk::jwk_to_signature_key(&public, JwsAlgorithm::ES256, JwkOp::Verify).is_ok());
    assert!(jwk::jwk_to_signature_key(&oct(32), JwsAlgorithm::RS256, JwkOp::Verify).is_err());
}

#[test]
fn pinned_hmac_and_generic_aes_conversion_remain_supported() {
    let key = jwk::generate_symmetric_for_alg("HS256").unwrap();
    let token = compact::sign_with_jwk(&key, b"payload", &JoseHeader::new("HS256")).unwrap();
    assert_eq!(compact::verify_with_jwk(&key, &token).unwrap(), b"payload");
    for len in [16, 24, 32] {
        assert_eq!(
            jwk::jwk_to_software_key(&oct(len)).unwrap().algorithm(),
            kryptering::KeyAlgorithm::Aes
        );
    }
}

#[test]
fn compact_verification_checks_strength_before_signature_verification() {
    // Deliberately unsigned fixtures: key validation must reject these before
    // attempting authentication. No weak-key signature is constructed.
    for (alg, len) in [("HS384", 32), ("HS512", 48)] {
        let protected =
            jose_rs::base64url::encode(&serde_json::to_vec(&JoseHeader::new(alg)).unwrap());
        let token = format!("{protected}.cGF5bG9hZA.");
        let err = compact::verify_with_jwk(&oct(len), &token).unwrap_err();
        assert!(matches!(err, jose_rs::JoseError::Key(_)));
        assert!(err.to_string().contains("requires an HMAC key"));
    }
}

#[cfg(feature = "post-quantum")]
#[test]
fn operation_context_does_not_supply_required_akp_algorithm() {
    let mut key = jwk::generate_mldsa(kryptering::MlDsaVariant::MlDsa44).unwrap();
    key.alg = None;
    for op in [JwkOp::Sign, JwkOp::Verify] {
        assert!(jwk::jwk_to_signature_key(&key, JwsAlgorithm::MlDsa44, op).is_err());
    }
}
