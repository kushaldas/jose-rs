//! JWS signing refuses protected headers whose `extra` map shadows a typed
//! header field.
//!
//! `JoseHeader::extra` is flattened into the same JSON object as the typed
//! fields, so a shadowing entry used to serialize as a duplicate member, e.g.
//! `{"alg":"HS256","alg":"none"}`. The sign-side checks (header/signer `alg`
//! agreement, `crit` policy) only see the typed field, while last-key-wins
//! JSON parsers on the verify side read the `extra` value instead.

use jose_rs::jws::json::{self, GeneralSigner};
use jose_rs::jwt::{self, Claims};
use jose_rs::{jwk, jws, JoseError, JoseHeader, JwsAlgorithm};
use serde_json::{json, Value};

/// Every member name produced by a typed `JoseHeader` field, paired with a
/// value that would change the header's meaning if a peer read it.
fn shadowing_members() -> Vec<(&'static str, Value)> {
    vec![
        ("alg", json!("none")),
        ("enc", json!("A256GCM")),
        ("kid", json!("other")),
        ("typ", json!("at+jwt")),
        ("cty", json!("JWT")),
        ("jku", json!("https://example.com/jwks")),
        ("jwk", json!({"kty": "oct"})),
        ("x5u", json!("https://example.com/cert")),
        ("x5c", json!(["AA"])),
        ("x5t", json!("AA")),
        ("x5t#S256", json!("AA")),
        // Would also smuggle an unvalidated critical extension past the
        // sign-side `crit` policy.
        ("crit", json!(["unknown"])),
    ]
}

fn assert_invalid_header<T: std::fmt::Debug>(result: jose_rs::Result<T>, api: &str, name: &str) {
    assert!(
        matches!(result, Err(JoseError::InvalidHeader(_))),
        "{api} accepted extra[{name:?}]: {result:?}"
    );
}

/// Regression: every public JWS/JWT signing entry point rejects a shadowing
/// `extra` member before signing.
#[test]
fn extra_members_cannot_shadow_typed_header_fields_when_signing() {
    let key = jwk::generate_symmetric_for_alg("HS256").unwrap();
    let signer = kryptering::SoftwareSigner::new(
        JwsAlgorithm::HS256.to_crypto().unwrap(),
        jwk::jwk_to_software_key(&key).unwrap(),
    )
    .unwrap();

    for (name, value) in shadowing_members() {
        let mut header = JoseHeader::jwt_for_alg(JwsAlgorithm::HS256);
        header.extra.insert(name.into(), value);

        assert_invalid_header(
            jws::compact::sign(&signer, b"payload", &header),
            "compact::sign",
            name,
        );
        assert_invalid_header(
            jws::compact::sign_with_jwk(&key, b"payload", &header),
            "compact::sign_with_jwk",
            name,
        );
        assert_invalid_header(
            json::sign_flattened(&signer, b"payload", &header),
            "json::sign_flattened",
            name,
        );
        assert_invalid_header(
            json::sign_general_full(&[GeneralSigner::new(&signer, &header)], b"payload", true),
            "json::sign_general_full",
            name,
        );
        assert_invalid_header(
            jwt::encode_with_jwk(&key, &header, &Claims::default()),
            "jwt::encode_with_jwk",
            name,
        );
    }
}

/// Non-shadowing extension members (including RFC 7797 `b64`, which has no
/// typed field) are still carried and signed normally.
#[test]
fn non_shadowing_extra_members_are_still_signed() {
    let key = jwk::generate_symmetric_for_alg("HS256").unwrap();
    let mut header = JoseHeader::jwt_for_alg(JwsAlgorithm::HS256);
    header.extra.insert("tenant".into(), json!("one"));

    let token = jws::compact::sign_with_jwk(&key, b"payload", &header).unwrap();
    let decoded = jws::compact::decode_header(&token).unwrap();
    assert_eq!(decoded.extra.get("tenant"), Some(&json!("one")));
    assert_eq!(
        jws::compact::verify_with_jwk(&key, &token).unwrap(),
        b"payload"
    );
}
