//! Mixed JWKS retention and order-independent, unambiguous JWT key selection.

use jose_rs::{
    jwk::{generate_symmetric, Jwk, JwkSet},
    jwt::{decode_with_jwkset, encode_with_jwk, Claims, Validation},
    JoseError, JoseHeader,
};

fn key(kid: Option<&str>) -> Jwk {
    let mut key = generate_symmetric(32).unwrap();
    key.alg = Some("HS256".into());
    key.kid = kid.map(str::to_owned);
    key
}

fn token(key: &Jwk, kid: Option<&str>) -> String {
    let mut header = JoseHeader::jwt("HS256");
    header.kid = kid.map(str::to_owned);
    encode_with_jwk(key, &header, &Claims::default()).unwrap()
}

fn unsupported(kid: Option<&str>) -> Jwk {
    let mut key = Jwk::from_json(r#"{"kty":"OKP","crv":"Ed448","x":"AA"}"#).unwrap();
    key.kid = kid.map(str::to_owned);
    key
}

#[test]
fn unique_lookup_distinguishes_absent_unique_and_ambiguous() {
    let a = key(Some("a"));
    let set = JwkSet {
        keys: vec![a.clone(), key(None)],
    };
    assert!(set.find_unique_by_kid("A").unwrap().is_none());
    assert!(set.find_unique_by_kid("").unwrap().is_none());
    assert!(std::ptr::eq(
        set.find_unique_by_kid("a").unwrap().unwrap(),
        &set.keys[0]
    ));
    let duplicate = JwkSet {
        keys: vec![a.clone(), a],
    };
    assert!(matches!(
        duplicate.find_unique_by_kid("a"),
        Err(JoseError::Key(_))
    ));
    // The legacy inspection helper retains first-match behavior.
    assert!(std::ptr::eq(
        duplicate.find_by_kid("a").unwrap(),
        &duplicate.keys[0]
    ));
}

#[test]
fn duplicate_kid_rejected_regardless_of_order_material_or_usability() {
    let signing = key(Some("shared"));
    let jwt = token(&signing, Some("shared"));
    let mut wrong_algorithm = key(Some("shared"));
    wrong_algorithm.alg = Some("HS512".into());
    for other in [
        signing.clone(),
        key(Some("shared")),
        unsupported(Some("shared")),
        wrong_algorithm,
    ] {
        for keys in [
            vec![signing.clone(), other.clone()],
            vec![other, signing.clone()],
        ] {
            let err = decode_with_jwkset(&JwkSet { keys }, &jwt, &Validation::new()).unwrap_err();
            assert!(
                matches!(err, JoseError::Key(ref message) if message == "multiple JWKs match the requested kid")
            );
        }
    }
}

#[test]
fn mixed_json_set_retains_unsupported_entries_and_verifies_unique_supported_key() {
    let signing = key(Some("supported"));
    let jwt = token(&signing, Some("supported"));
    let unknown = Jwk::from_json(r#"{"kty":"future-type","kid":"future"}"#).unwrap();
    let original = JwkSet {
        keys: vec![unsupported(Some("ed448")), unknown, signing],
    };
    let parsed = JwkSet::from_json(&original.to_json().unwrap()).unwrap();
    assert_eq!(parsed.keys.len(), 3);
    assert_eq!(parsed.keys[0].crv.as_deref(), Some("Ed448"));
    assert_eq!(parsed.keys[1].kty, "future-type");
    decode_with_jwkset(&parsed, &jwt, &Validation::new()).unwrap();
}

#[test]
fn unsupported_or_unknown_pinned_kid_never_uses_unlabelled_key() {
    let signing = key(None);
    let set = JwkSet {
        keys: vec![unsupported(Some("ed448")), signing.clone()],
    };
    for kid in ["ed448", "unknown"] {
        assert!(decode_with_jwkset(&set, &token(&signing, Some(kid)), &Validation::new()).is_err());
    }
}

#[test]
fn kidless_and_entirely_unlabelled_fallbacks_are_unchanged() {
    let signing = key(None);
    let set = JwkSet {
        keys: vec![unsupported(None), signing.clone()],
    };
    for kid in [None, Some("external-label")] {
        decode_with_jwkset(&set, &token(&signing, kid), &Validation::new()).unwrap();
    }
    assert!(decode_with_jwkset(
        &set,
        &token(&signing, None),
        &Validation::new().require_kid()
    )
    .is_err());
}

#[test]
fn malformed_json_key_fields_and_empty_sets_still_fail() {
    for json in [
        r#"{"keys":[{"kty":"future","kid":3}]}"#,
        r#"{"keys":[{"crv":"Ed448"}]}"#,
        r#"{"keys":[null]}"#,
        r#"{"keys":{}}"#,
    ] {
        assert!(JwkSet::from_json(json).is_err());
    }
    let signing = key(None);
    let empty = JwkSet::from_json(r#"{"keys":[]}"#).unwrap();
    assert!(decode_with_jwkset(&empty, &token(&signing, None), &Validation::new()).is_err());
}

#[test]
fn unique_selection_retains_operation_and_validation_policy() {
    let signing = key(Some("selected"));
    let jwt = token(&signing, Some("selected"));
    let mut set = JwkSet {
        keys: vec![
            unsupported(Some("unrelated")),
            unsupported(Some("unrelated")),
            signing,
        ],
    };
    // Duplicates of an unrelated identifier do not affect unique selection.
    decode_with_jwkset(&set, &jwt, &Validation::new()).unwrap();
    for policy in [
        Validation::new().require_exp(),
        Validation::new().with_issuer("required-issuer"),
        Validation::new().with_typ("at+jwt"),
        Validation::new().with_allowed_algorithms(vec![jose_rs::JwsAlgorithm::HS512]),
    ] {
        assert!(decode_with_jwkset(&set, &jwt, &policy).is_err());
    }
    set.keys[2].key_ops = Some(vec!["sign".into()]);
    assert!(decode_with_jwkset(&set, &jwt, &Validation::new()).is_err());
}
