//! Migration acceptance: Ed448, curve-bound pins, authenticated discovery and stable output.
use jose_rs::{
    base64url,
    jwk::{self, Jwk, JwkSet},
    jws::compact,
    jwt::{self, Claims, Validation},
    JoseHeader, JwsAlgorithm,
};
use serde_json::json;

fn signing_key() -> Jwk {
    let mut key = jwk::generate_ed448().unwrap();
    key.alg = Some("Ed448".into());
    key.kid = Some("current".into());
    key
}

#[test]
fn edwards_pins_alias_only_on_their_own_curve() {
    for mut key in [jwk::generate_ed25519().unwrap(), signing_key()] {
        let curve = key.crv.clone().unwrap();
        for (pin, wire) in [(curve.as_str(), "EdDSA"), ("EdDSA", curve.as_str())] {
            key.alg = Some(pin.into());
            let token = compact::sign_with_jwk(&key, b"payload", &JoseHeader::new(wire)).unwrap();
            let public = key.to_public_jwk();
            assert_eq!(
                compact::verify_with_jwk(&public, &token).unwrap(),
                b"payload"
            );
            assert_eq!(compact::decode_header(&token).unwrap().alg, wire);
            let other = if curve == "Ed448" { "Ed25519" } else { "Ed448" };
            let mut wrong_pin = public.clone();
            wrong_pin.alg = Some(other.into());
            assert!(compact::verify_with_jwk(&wrong_pin, &token).is_err());
            let mut denied = key.clone();
            denied.use_ = Some("enc".into());
            assert!(compact::sign_with_jwk(&denied, b"payload", &JoseHeader::new(wire)).is_err());
            denied = public.clone();
            denied.key_ops = Some(vec!["sign".into()]);
            assert!(compact::verify_with_jwk(&denied, &token).is_err());
        }
    }
    let mut agreement = jwk::generate_x25519().unwrap();
    agreement.alg = Some("EdDSA".into());
    assert!(jwk::jwk_to_software_key(&agreement).is_err());
}

#[test]
fn ed448_material_formats_and_policy() {
    let key = signing_key();
    assert_eq!(
        base64url::decode(key.x.as_ref().unwrap()).unwrap().len(),
        57
    );
    assert_eq!(
        base64url::decode(key.d.as_ref().unwrap()).unwrap().len(),
        57
    );
    let generated = jwk::generate_key(jwk::KeyGeneration::Ed448).unwrap();
    assert_eq!(generated.crv.as_deref(), Some("Ed448"));
    assert!(generated.alg.is_none());
    for pem in [
        jwk::private_pem_from_jwk(&key).unwrap(),
        jwk::public_pem_from_jwk(&key).unwrap(),
    ] {
        let imported = jwk::jwk_from_pem(&pem).unwrap();
        assert_eq!(
            jwk::thumbprint::thumbprint_sha256(&imported).unwrap(),
            jwk::thumbprint::thumbprint_sha256(&key).unwrap()
        );
    }
    let other = signing_key();
    let mut bad = key.clone();
    bad.x = other.x.clone();
    assert!(jwk::jwk_to_software_key(&bad)
        .unwrap_err()
        .to_string()
        .contains("does not match"));
    for n in [0, 56, 58] {
        let mut bad = key.clone();
        bad.d = Some(base64url::encode(&vec![1; n]));
        assert!(jwk::jwk_to_software_key(&bad).is_err());
        let mut bad = key.to_public_jwk();
        bad.x = Some(base64url::encode(&vec![1; n]));
        assert!(jwk::jwk_to_software_key(&bad).is_err());
    }
    let token = jwt::encode_with_jwk(&key, &JoseHeader::new("EdDSA"), &Claims::default()).unwrap();
    assert!(jwt::decode_with_jwk(
        &key,
        &token,
        &Validation::new().with_allowed_algorithms(vec![JwsAlgorithm::Ed448])
    )
    .is_err());
    assert!(jwt::decode_with_jwk(
        &key,
        &token,
        &Validation::new().with_allowed_algorithms(vec![JwsAlgorithm::EdDSA])
    )
    .is_ok());
    assert!(compact::verify_with_jwk(&other.to_public_jwk(), &token).is_err());
    let mut ed25519 = jwk::generate_ed25519().unwrap();
    ed25519.alg = Some("EdDSA".into());
    assert!(compact::verify_with_jwk(&ed25519, &token).is_err());
    let reverse = compact::sign_with_jwk(&ed25519, b"payload", &JoseHeader::new("EdDSA")).unwrap();
    assert!(compact::verify_with_jwk(&key, &reverse).is_err());
}

#[test]
fn jwks_authenticated_results_keep_the_successful_index() {
    let key = signing_key();
    let mut header = JoseHeader::new("EdDSA");
    header.kid = key.kid.clone();
    header.typ = Some("entity-statement+jwt".into());
    header
        .extra
        .insert("trust_chain".into(), json!(["statement"]));
    let token = jwt::encode_with_jwk(&key, &header, &Claims::default()).unwrap();
    let mut unrelated = signing_key().to_public_jwk();
    unrelated.kid = Some("old".into());
    let set = JwkSet {
        keys: vec![unrelated, key.to_public_jwk()],
    };
    let validation = Validation::new().with_typ("entity-statement+jwt");
    let result = jwt::decode_with_jwkset_authenticated(&set, &token, &validation).unwrap();
    assert_eq!(result.verified_key_index(), Some(1));
    assert_eq!(result.protected.extra["trust_chain"], json!(["statement"]));
    assert_eq!(result.map(|_| ()).verified_key_index(), Some(1));
    let policy = jwk::selection::SelectionPolicy::default();
    let result =
        jwt::decode_with_jwkset_policy_authenticated(&set, &token, &validation, &policy).unwrap();
    assert_eq!(result.verified_key_index(), Some(1));
    let mut duplicate = set.clone();
    duplicate.keys.push(key.to_public_jwk());
    assert!(jwt::decode_with_jwkset_authenticated(&duplicate, &token, &validation).is_err());
    let mut exhausted = policy.clone();
    exhausted.max_candidates = 0;
    assert!(
        jwt::decode_with_jwkset_policy_authenticated(&set, &token, &validation, &exhausted)
            .is_err()
    );
    let mut altered: Vec<_> = token.split('.').map(str::to_string).collect();
    altered[1] = base64url::encode(b"{}");
    // Original claims are {}, so change the authenticated header instead.
    altered[0] = base64url::encode(br#"{"alg":"EdDSA","kid":"current"}"#);
    assert!(jwt::decode_with_jwkset_authenticated(&set, &altered.join("."), &validation).is_err());
}

#[test]
fn embedded_key_discovery_returns_only_verified_claims() {
    let key = signing_key();
    let mut claims = Claims::default();
    claims
        .extra
        .insert("jwks".into(), json!({"keys":[key.to_public_jwk()]}));
    let mut header = JoseHeader::new("EdDSA");
    header.kid = key.kid.clone();
    let token = jwt::encode_with_jwk(&key, &header, &claims).unwrap();
    let validation = Validation::new();
    let select = |untrusted: &Claims| -> jose_rs::Result<JwkSet> {
        JwkSet::from_json(&untrusted.extra["jwks"].to_string())
    };
    let result = jwt::decode_self_signed(&token, &validation, select).unwrap();
    assert_eq!(result.value, claims);
    let inspected = jwt::UnverifiedJwt::parse(&token).unwrap();
    assert_eq!(inspected.claims(), &claims);
    assert_eq!(inspected.header().alg, "EdDSA");
    assert!(inspected
        .verify_with(
            &JwkSet {
                keys: vec![signing_key().to_public_jwk()]
            },
            &validation
        )
        .is_err());
    let wrong = signing_key().to_public_jwk();
    assert!(
        jwt::decode_self_signed(&token, &validation, |_| Ok(JwkSet { keys: vec![wrong] })).is_err()
    );
    for payload in [br#"{"jwks":{},"jwks":{}}"#.as_slice(), b"[]"] {
        let token = compact::sign_with_jwk(&key, payload, &JoseHeader::new("Ed448")).unwrap();
        assert!(jwt::UnverifiedJwt::parse(&token).is_err());
    }
    assert!(jwt::UnverifiedJwt::parse(&"a".repeat(jose_rs::MAX_TOKEN_BYTES + 1)).is_err());
    assert!(jwt::UnverifiedJwt::parse("a.b.c.d").is_err());
}

#[test]
fn stable_order_and_explicit_time_check_opt_outs() {
    let a: Claims = serde_json::from_value(json!({"z":1,"a":2,"iss":"issuer"})).unwrap();
    let b: Claims = serde_json::from_value(json!({"a":2,"iss":"issuer","z":1})).unwrap();
    assert_eq!(a.to_json_vec().unwrap(), b.to_json_vec().unwrap());
    assert!(String::from_utf8(a.to_json_vec().unwrap())
        .unwrap()
        .ends_with("\"a\":2,\"z\":1}"));
    let mut h1 = JoseHeader::new("Ed448");
    let mut h2 = h1.clone();
    h1.extra.insert("z".into(), json!(1));
    h1.extra.insert("a".into(), json!(2));
    h2.extra.insert("a".into(), json!(2));
    h2.extra.insert("z".into(), json!(1));
    assert_eq!(
        serde_json::to_string(&h1).unwrap(),
        serde_json::to_string(&h2).unwrap()
    );
    let claims: Claims =
        serde_json::from_value(json!({"exp":1,"nbf":9999999999u64,"iat":9999999999u64})).unwrap();
    assert!(Validation::new().validate(&claims).is_err());
    Validation::signature_only().validate(&claims).unwrap();
    Validation::new()
        .without_exp()
        .without_nbf()
        .without_iat_future_check()
        .validate(&claims)
        .unwrap();
    assert!(Validation::signature_only()
        .with_issuer("issuer")
        .validate(&claims)
        .is_err());
}

fn hex(input: &str) -> Vec<u8> {
    input
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

#[test]
fn rfc8032_ed448_blank_vector_and_thumbprint() {
    // RFC 8032 §7.4, "Blank": independent seed, public key and signature.
    // Encoded as RFC 8037 JWK fields; the backend signs the empty message
    // directly because a JWS signing input cannot be empty.
    let key = Jwk::from_json(&json!({
        "kty":"OKP", "crv":"Ed448", "alg":"Ed448",
        "d": base64url::encode(&hex("6c82a562cb808d10d632be89c8513ebf6c929f34ddfa8c9f63c9960ef6e348a3528c8a3fcc2f044e39a3fc5b94492f8f032e7549a20098f95b")),
        "x": base64url::encode(&hex("5fd7449b59b461fd2ce787ec616ad46a1da1342485a70e1f8a0ea75d80e96778edf124769b46c7061bd6783df1e50f6cd1fa1abeafe8256180"))
    }).to_string()).unwrap();
    use kryptering::{Signer, Verifier};
    let signer = kryptering::SoftwareSigner::new(
        kryptering::SignatureAlgorithm::Ed448,
        jwk::jwk_to_software_key(&key).unwrap(),
    )
    .unwrap();
    let expected = hex("533a37f6bbe457251f023c0d88f976ae2dfb504a843e34d2074fd823d41a591f2b233f034f628281f2fd7a22ddd47d7828c59bd0a21bfd3980ff0d2028d4b18a9df63e006c5d1c2d345b925d8dc00b4104852db99ac5c7cdda8530a113a0f4dbb61149f05a7363268c71d95808ff2e652600");
    assert_eq!(signer.sign(b"").unwrap(), expected);
    let verifier = kryptering::SoftwareVerifier::new(
        kryptering::SignatureAlgorithm::Ed448,
        jwk::jwk_to_software_key(&key.to_public_jwk()).unwrap(),
    )
    .unwrap();
    assert!(verifier.verify(b"", &expected).unwrap());
    assert!(!verifier.verify(b"altered", &expected).unwrap());
    // Fixed RFC 7638 canonical input hashed independently with Python hashlib.
    assert_eq!(
        jwk::thumbprint::thumbprint_sha256(&key).unwrap(),
        "zQstisLFDWZb-FiVsZl6490ATVgxw_63L-xYldKyuUY"
    );
    let der = jwk::jwk_to_software_key(&key)
        .unwrap()
        .export_private()
        .unwrap();
    assert_eq!(jwk::jwk_from_pkcs8_der(&der).unwrap().d, key.d);
    let der = jwk::jwk_to_software_key(&key)
        .unwrap()
        .export_spki_der()
        .unwrap();
    assert_eq!(jwk::jwk_from_spki_der(&der).unwrap().x, key.x);
}

#[test]
fn ed448_json_detached_and_original_header_bytes() {
    use jose_rs::jws::{json, SignOptions};
    use kryptering::Signer;
    let key = signing_key();
    let public = key.to_public_jwk();
    for wire in ["EdDSA", "Ed448"] {
        let header = JoseHeader::new(wire);
        let flattened = json::sign_flattened_with_jwk(&key, b"payload", &header).unwrap();
        assert_eq!(
            json::verify_flattened_with_jwk(&public, &flattened).unwrap(),
            b"payload"
        );
        let general = json::sign_general_with_jwk_pairs(&[(&key, &header)], b"payload").unwrap();
        let report = json::verify_general_with_jwks(
            &[&public],
            &general,
            None,
            &Default::default(),
            json::SignaturePolicy::All,
        )
        .unwrap();
        assert!(report.results[0].verified);
        assert_eq!(report.payload.unwrap(), b"payload");
        let signer = kryptering::SoftwareSigner::new(
            kryptering::SignatureAlgorithm::Ed448,
            jwk::jwk_to_software_key(&key).unwrap(),
        )
        .unwrap();
        let verifier = kryptering::SoftwareVerifier::new(
            kryptering::SignatureAlgorithm::Ed448,
            jwk::jwk_to_software_key(&public).unwrap(),
        )
        .unwrap();
        let mut header = header;
        header.extra.insert("b64".into(), json!(false));
        header.crit = Some(vec!["b64".into()]);
        let detached = json::sign_flattened_detached_opts(
            &signer,
            b"a.b",
            &header,
            None,
            &SignOptions::new().with_b64(false),
        )
        .unwrap();
        assert_eq!(
            json::verify_flattened_detached(&verifier, &detached, b"a.b").unwrap(),
            b"a.b"
        );
        assert!(json::verify_flattened_detached(&verifier, &detached, b"wrong").is_err());
        let protected = base64url::encode(format!("{{ \"alg\": \"{wire}\" }}").as_bytes());
        let input = format!("{protected}.{}", base64url::encode(b"payload"));
        let signature = base64url::encode(&signer.sign(input.as_bytes()).unwrap());
        let token = format!("{input}.{signature}");
        assert_eq!(
            compact::verify_with_jwk(&public, &token).unwrap(),
            b"payload"
        );
        let rewritten = format!(
            "{}.{}.{}",
            base64url::encode(format!("{{\"alg\":\"{wire}\"}}").as_bytes()),
            base64url::encode(b"payload"),
            signature
        );
        assert!(compact::verify_with_jwk(&public, &rewritten).is_err());
    }
}

#[test]
fn malformed_ed448_fields_and_algorithm_parameters_are_refused() {
    let key = signing_key();
    for field in ["x", "d"] {
        for size in [0, 56, 58, 100_000] {
            let mut bad = key.clone();
            let encoded = base64url::encode(&vec![0; size]);
            if field == "x" {
                bad.x = Some(encoded);
            } else {
                bad.d = Some(encoded);
            }
            let error = jwk::jwk_to_software_key(&bad).unwrap_err();
            assert!(
                error.to_string().contains("57 bytes"),
                "{field}/{size}: {error}"
            );
        }
    }
    for mut wrong in [
        jwk::generate_symmetric(32).unwrap(),
        jwk::generate_ec("P-256").unwrap(),
    ] {
        wrong.alg = Some("Ed448".into());
        assert!(jwk::jwk_to_software_key(&wrong)
            .unwrap_err()
            .to_string()
            .contains("incompatible"));
    }
    // RFC 8410 §3: parameters MUST be absent, including NULL.
    let mut null_parameters = hex("3045300706032b65710500033a00");
    null_parameters.extend(base64url::decode(key.x.as_ref().unwrap()).unwrap());
    assert!(jwk::jwk_from_spki_der(&null_parameters).is_err());
    let mut public = key.to_public_jwk();
    public.alg = Some("Ed448".into());
    assert!(compact::sign_with_jwk(&public, b"payload", &JoseHeader::new("Ed448")).is_err());
}

#[test]
fn jwks_fallback_index_and_limits_use_original_positions() {
    let mut key = signing_key();
    key.kid = None;
    let token = jwt::encode_with_jwk(&key, &JoseHeader::new("Ed448"), &Claims::default()).unwrap();
    let mut wrong = signing_key().to_public_jwk();
    wrong.kid = None;
    let set = JwkSet {
        keys: vec![wrong, key.to_public_jwk()],
    };
    let validation = Validation::new();
    assert_eq!(
        jwt::decode_with_jwkset_authenticated(&set, &token, &validation)
            .unwrap()
            .verified_key_index(),
        Some(1)
    );
    let mut policy = jwk::selection::SelectionPolicy {
        max_candidates: 1,
        ..Default::default()
    };
    let error = jwt::decode_with_jwkset_policy_authenticated(&set, &token, &validation, &policy)
        .unwrap_err();
    assert!(error.to_string().contains("budget"), "{error}");
    policy.max_candidates = 2;
    assert_eq!(
        jwt::decode_with_jwkset_policy_authenticated(&set, &token, &validation, &policy)
            .unwrap()
            .verified_key_index(),
        Some(1)
    );
    let empty = JwkSet { keys: vec![] };
    assert!(jwt::decode_with_jwkset_authenticated(&empty, &token, &validation).is_err());
    let mut named = key.to_public_jwk();
    named.kid = Some("named".into());
    let named_set = JwkSet { keys: vec![named] };
    let mut header = JoseHeader::new("Ed448");
    header.kid = Some("missing".into());
    let unknown = jwt::encode_with_jwk(&key, &header, &Claims::default()).unwrap();
    assert!(
        jwt::decode_with_jwkset_authenticated(&named_set, &unknown, &validation)
            .unwrap_err()
            .to_string()
            .contains("matches")
    );
}

#[test]
fn discovery_never_promotes_forged_or_policy_denied_claims() {
    let mut key = signing_key();
    key.kid = None;
    let mut claims = Claims::default();
    claims
        .extra
        .insert("jwks".into(), json!({"keys":[key.to_public_jwk()]}));
    let token = jwt::encode_with_jwk(&key, &JoseHeader::new("Ed448"), &claims).unwrap();
    let mut calls = 0;
    let result = jwt::decode_self_signed(&token, &Validation::new(), |untrusted| {
        calls += 1;
        JwkSet::from_json(&untrusted.extra["jwks"].to_string())
    })
    .unwrap();
    assert_eq!(calls, 1);
    assert_eq!(result.verified_key_index(), Some(0));
    assert!(
        jwt::decode_self_signed(&token, &Validation::new().with_issuer("trusted"), |_| Ok(
            JwkSet {
                keys: vec![key.to_public_jwk()]
            }
        ))
        .is_err()
    );
    let mut forged_claims = claims.clone();
    forged_claims.iss = Some("attacker".into());
    let parts: Vec<_> = token.split('.').collect();
    let forged = format!(
        "{}.{}.{}",
        parts[0],
        base64url::encode(&forged_claims.to_json_vec().unwrap()),
        parts[2]
    );
    assert!(jwt::UnverifiedJwt::parse(&forged).is_ok());
    assert!(
        jwt::decode_self_signed(&forged, &Validation::new(), |_| Ok(JwkSet {
            keys: vec![key.to_public_jwk()]
        }))
        .is_err()
    );
    let mut denied = key.to_public_jwk();
    denied.use_ = Some("enc".into());
    assert!(
        jwt::decode_self_signed(&token, &Validation::new(), |_| Ok(JwkSet {
            keys: vec![denied]
        }))
        .is_err()
    );
    assert!(Validation::signature_only()
        .require_exp()
        .validate(&Claims::default())
        .is_err());
}
