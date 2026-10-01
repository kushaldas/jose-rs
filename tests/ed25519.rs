//! Explicit Ed25519 wire identifiers retain exact JOSE policy boundaries.

use jose_rs::{
    base64url, jwk,
    jws::{compact, json, SignOptions, VerifyOptions},
    jwt::{self, Claims, Validation},
    JoseHeader, JwsAlgorithm,
};

#[test]
fn identifiers_roundtrip_without_aliasing() {
    for alg in [JwsAlgorithm::Ed25519, JwsAlgorithm::EdDSA] {
        assert_eq!(JwsAlgorithm::from_str(alg.as_str()).unwrap(), alg);
        let serialized = serde_json::to_string(&alg).unwrap();
        assert_eq!(serialized, format!("\"{}\"", alg.as_str()));
        assert_eq!(
            serde_json::from_str::<JwsAlgorithm>(&serialized).unwrap(),
            alg
        );
        assert_eq!(
            alg.to_crypto().unwrap(),
            kryptering::SignatureAlgorithm::Ed25519
        );
    }
    assert_ne!(JwsAlgorithm::Ed25519, JwsAlgorithm::EdDSA);
    for invalid in ["ed25519", "ED25519", "Ed448", "Ed25519ph"] {
        assert!(JwsAlgorithm::from_str(invalid).is_err());
    }
}

#[test]
fn compact_jwk_pins_remain_exact() {
    for (name, other) in [("Ed25519", "EdDSA"), ("EdDSA", "Ed25519")] {
        let mut key = jwk::generate_ed25519().unwrap();
        assert!(key.alg.is_none());
        key.alg = Some(name.into());
        let token = compact::sign_with_jwk(&key, b"payload", &JoseHeader::new(name)).unwrap();
        assert_eq!(compact::decode_header(&token).unwrap().alg, name);
        let mut public = key.to_public_jwk();
        assert_eq!(
            compact::verify_with_jwk(&public, &token).unwrap(),
            b"payload"
        );
        public.alg = Some(other.into());
        assert!(compact::verify_with_jwk(&public, &token).is_err());
        assert!(compact::sign_with_jwk(&key, b"payload", &JoseHeader::new(other)).is_err());
        public.alg = None;
        assert_eq!(
            compact::verify_with_jwk(&public, &token).unwrap(),
            b"payload"
        );
        key.use_ = Some("enc".into());
        assert!(compact::sign_with_jwk(&key, b"payload", &JoseHeader::new(name)).is_err());
        public.key_ops = Some(vec!["sign".into()]);
        assert!(compact::verify_with_jwk(&public, &token).is_err());
    }
}

#[test]
fn explicit_metadata_requires_ed25519_key_material() {
    let mut key = jwk::generate_ed25519().unwrap();
    key.alg = Some("Ed25519".into());
    assert!(jwk::jwk_to_software_key(&key).is_ok());
    for curve in ["Ed448", "X25519", "X448", "P-256"] {
        key.crv = Some(curve.into());
        assert!(jwk::jwk_to_software_key(&key).is_err());
    }
    for mut wrong_type in [
        jwk::generate_symmetric(32).unwrap(),
        jwk::generate_ec("P-256").unwrap(),
    ] {
        wrong_type.alg = Some("Ed25519".into());
        assert!(jwk::jwk_to_software_key(&wrong_type).is_err());
    }
}

#[test]
fn jwt_allowlists_do_not_alias_wire_names() {
    let mut key = jwk::generate_ed25519().unwrap();
    for (alg, other) in [
        (JwsAlgorithm::Ed25519, JwsAlgorithm::EdDSA),
        (JwsAlgorithm::EdDSA, JwsAlgorithm::Ed25519),
    ] {
        key.alg = Some(alg.as_str().into());
        let token =
            jwt::encode_with_jwk(&key, &JoseHeader::jwt(alg.as_str()), &Claims::default()).unwrap();
        let mut public = key.to_public_jwk();
        public.alg = None; // Isolate the allowlist from the independent JWK pin.
        assert!(jwt::decode_with_jwk(
            &public,
            &token,
            &Validation::new().with_allowed_algorithms(vec![alg])
        )
        .is_ok());
        assert!(jwt::decode_with_jwk(
            &public,
            &token,
            &Validation::new().with_allowed_algorithms(vec![other])
        )
        .is_err());
    }
}

#[test]
fn flattened_general_and_detached_unencoded_payloads() {
    let key = jwk::generate_ed25519().unwrap();
    let algorithm = JwsAlgorithm::Ed25519.to_crypto().unwrap();
    let signer =
        kryptering::SoftwareSigner::new(algorithm, jwk::jwk_to_software_key(&key).unwrap())
            .unwrap();
    let verifier = kryptering::SoftwareVerifier::new(
        algorithm,
        jwk::jwk_to_software_key(&key.to_public_jwk()).unwrap(),
    )
    .unwrap();
    let header = JoseHeader::new("Ed25519");
    let payload = b"payload";
    let flattened = json::sign_flattened(&signer, payload, &header).unwrap();
    assert_eq!(
        json::verify_flattened(&verifier, &flattened).unwrap(),
        payload
    );
    let general = json::sign_general(&[(&signer, &header)], payload).unwrap();
    let (results, decoded) =
        json::verify_general_all(&verifier, &general, None, &VerifyOptions::new()).unwrap();
    assert_eq!(decoded.unwrap(), payload);
    assert!(results[0].verified);
    assert_eq!(results[0].protected_header.as_ref().unwrap().alg, "Ed25519");
    let mut header = header;
    header.extra.insert("b64".into(), serde_json::json!(false));
    header.crit = Some(vec!["b64".into()]);
    let detached = json::sign_flattened_detached_opts(
        &signer,
        payload,
        &header,
        None,
        &SignOptions::new().with_b64(false),
    )
    .unwrap();
    assert_eq!(
        json::verify_flattened_detached(&verifier, &detached, payload).unwrap(),
        payload
    );
    assert!(json::verify_flattened_detached(&verifier, &detached, b"different").is_err());
}

#[test]
fn original_protected_bytes_are_authenticated() {
    use ed25519_dalek::Signer;
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
    let key = jwk::Jwk::from_json(
        &serde_json::json!({
            "kty": "OKP", "crv": "Ed25519", "alg": "Ed25519",
            "x": base64url::encode(signing_key.verifying_key().as_bytes())
        })
        .to_string(),
    )
    .unwrap();
    let protected = base64url::encode(br#"{ "typ": "JWT", "alg": "Ed25519" }"#);
    let input = format!("{protected}.{}", base64url::encode(b"payload"));
    let signature = base64url::encode(&signing_key.sign(input.as_bytes()).to_bytes());
    let token = format!("{input}.{signature}");
    assert_eq!(compact::verify_with_jwk(&key, &token).unwrap(), b"payload");
    // Re-serialization or renaming the header must not preserve authentication.
    let mut unpinned = key.clone();
    unpinned.alg = None;
    for replacement in [
        br#"{"alg":"Ed25519","typ":"JWT"}"#.as_slice(),
        br#"{"alg":"EdDSA","typ":"JWT"}"#.as_slice(),
    ] {
        let altered = format!(
            "{}.{}.{}",
            base64url::encode(replacement),
            base64url::encode(b"payload"),
            signature
        );
        assert!(compact::verify_with_jwk(&unpinned, &altered).is_err());
    }
}
