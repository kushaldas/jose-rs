//! Discovery must reject ambiguity before any selector receives normalized Values.
use jose_rs::{
    jwk::{self, JwkSet},
    jws::compact,
    jwt::{self, Claims, UnverifiedJwt, Validation},
    JoseError, JoseHeader,
};

fn signer() -> jwk::Jwk {
    let mut key = jwk::generate_ed25519().unwrap();
    key.alg = Some("Ed25519".into());
    key
}

#[test]
fn signed_duplicate_key_data_is_rejected_before_the_selector_runs() {
    let key = signer();
    let public = key.to_public_jwk().to_json().unwrap();
    let cases = [
        (
            format!(r#"{{"jwks":{{"keys":[],"keys":[{public}]}}}}"#),
            "keys",
        ),
        (
            format!(
                r#"{{"jwks":{{"keys":[{{"use":"enc","use":"sig",{}}}]}}}}"#,
                &public[1..public.len() - 1]
            ),
            "use",
        ),
        (
            format!(
                r#"{{"jwks":{{"keys":[{{"alg":"HS256","alg":"Ed25519",{}}}]}}}}"#,
                &public[1..public.len() - 1]
            ),
            "alg",
        ),
        (
            r#"{"jwks":{"keys":[{"alg":"Ed25519","\u0061lg":"Ed25519"}]}}"#.into(),
            "alg",
        ),
        (
            r#"{"candidate_keys":[{"metadata":{"kid":"first","kid":"second"}}]}"#.into(),
            "kid",
        ),
        (r#"{"jwks":{"keys":[{"x":"same","x":"same"}]}}"#.into(), "x"),
    ];
    for (payload, duplicate) in cases {
        // The signature is valid: only the pre-normalization claim boundary can
        // reject the ambiguity. No Value or map is used to construct the input.
        let token =
            compact::sign_with_jwk(&key, payload.as_bytes(), &JoseHeader::new("Ed25519")).unwrap();
        assert_eq!(
            compact::verify_with_jwk(&key.to_public_jwk(), &token).unwrap(),
            payload.as_bytes()
        );
        let error = UnverifiedJwt::parse(&token)
            .expect_err("duplicate key data must fail before normalization");
        assert!(matches!(error, JoseError::InvalidClaims(_)), "{error}");
        assert!(
            error
                .to_string()
                .contains(&format!("duplicate JSON member {duplicate}")),
            "{error}"
        );
        let mut called = false;
        let result = jwt::decode_self_signed(&token, &Validation::new(), |_| {
            called = true;
            Ok(JwkSet {
                keys: vec![key.to_public_jwk()],
            })
        });
        assert!(result.is_err());
        assert!(
            !called,
            "selector must not receive already-collapsed key metadata"
        );
    }
}

#[test]
fn unique_nested_data_and_normal_claim_parsing_keep_their_contracts() {
    let key = signer();
    let public = key.to_public_jwk().to_json().unwrap();
    let payload = format!(
        r#"{{"jwks":{{"keys":[{public}]}},"metadata":[{{"name":"a"}},{{"name":"b"}}],"text":"{{\"alg\":1,\"alg\":2}}","integer":900719925474099312345678901234567890,"decimal":1.234567890123456789e-80,"flags":[true,false,null,-1,1.5]}}"#
    );
    let token =
        compact::sign_with_jwk(&key, payload.as_bytes(), &JoseHeader::new("Ed25519")).unwrap();
    let expected = Claims::from_json_bytes(payload.as_bytes()).unwrap();
    let inspected = UnverifiedJwt::parse(&token).unwrap();
    assert_eq!(inspected.claims(), &expected);
    let authenticated = jwt::decode_self_signed(&token, &Validation::new(), |claims| {
        JwkSet::from_json(&claims.extra["jwks"].to_string())
    })
    .unwrap();
    assert_eq!(authenticated.value, expected);

    // ADR 0029 continues to govern ordinary JWT claims. Only discovery adopts
    // recursive strictness, because its selector may consume nested key data.
    let nested_duplicate = br#"{"metadata":{"name":"first","name":"last"}}"#;
    let claims = Claims::from_json_bytes(nested_duplicate).unwrap();
    assert_eq!(claims.extra["metadata"]["name"], "last");
    let token =
        compact::sign_with_jwk(&key, nested_duplicate, &JoseHeader::new("Ed25519")).unwrap();
    assert_eq!(
        jwt::decode_with_jwk(&key, &token, &Validation::new()).unwrap(),
        claims
    );
}

#[test]
fn discovery_checks_decoded_names_in_all_objects_and_retains_parser_bounds() {
    let key = signer();
    for name in ["key_ops", "kty", "kid", "k", "d", "future_metadata"] {
        let payload = format!(r#"{{"alternate":[{{"{name}":null,"{name}":null}}]}}"#);
        let token =
            compact::sign_with_jwk(&key, payload.as_bytes(), &JoseHeader::new("Ed25519")).unwrap();
        let error = UnverifiedJwt::parse(&token).unwrap_err();
        assert!(
            error
                .to_string()
                .contains(&format!("duplicate JSON member {name}")),
            "{error}"
        );
    }
    for payload in [
        r#"{"jwks":{"keys":[]}} trailing"#.to_string(),
        r#"{"jwks":{"keys":[]}"#.to_string(),
        format!("{{\"nested\":{}0{}}}", "[".repeat(150), "]".repeat(150)),
    ] {
        let token =
            compact::sign_with_jwk(&key, payload.as_bytes(), &JoseHeader::new("Ed25519")).unwrap();
        assert!(UnverifiedJwt::parse(&token).is_err());
    }
}
