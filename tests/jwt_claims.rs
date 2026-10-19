//! JWT claim-set consistency at the token boundary (plan L1).
//!
//! The unit tests in `src/jwt/claims.rs` check the claim type. These check the *token*
//! behaviour: that the encode and decode paths actually go through it, so no entry point
//! quietly keeps the old, ambiguity-tolerant `serde_json` behaviour.
//!
//! Every refusal here is tested against a token that another implementation *accepts* — the
//! ambiguity is real, not hypothetical, and the interop script
//! `interop/tests/jwt_claims_jwcrypto.py` demonstrates that on live tokens.

use jose_rs::algorithm::JweEncryption;
use jose_rs::jwk;
use jose_rs::jwt::{Claims, NumericDate, Validation};
use jose_rs::JoseError;
use jose_rs::JoseHeader;
use serde_json::json;

fn signer() -> jwk::Jwk {
    let mut jwk = jwk::generate_ed25519().unwrap();
    jwk.alg = Some("EdDSA".into());
    jwk
}

fn header() -> JoseHeader {
    let mut h = JoseHeader::new("EdDSA");
    h.typ = Some("JWT".into());
    h
}

fn decode(key: &jwk::Jwk, token: &str) -> Result<Claims, JoseError> {
    jose_rs::jwt::decode_with_jwk(key, token, &Validation::default())
}

/// Split a compact JWS, replace the payload with raw bytes, re-encode, and re-sign it.
///
/// This is how the tests get payloads no honest serializer would produce (duplicate members)
/// into a token that carries a valid signature: the point is precisely that the signature is
/// valid, so the claim parser is the only thing left standing between an ambiguous document and
/// an accepted token.
fn resign_payload(key: &jwk::Jwk, payload: &[u8]) -> String {
    jose_rs::jws::compact::sign_with_jwk(key, payload, &header()).unwrap()
}

fn payload_of(token: &str) -> Vec<u8> {
    let parts: Vec<&str> = token.split('.').collect();
    jose_rs::base64url::decode(parts[1]).unwrap()
}

#[test]
fn encoding_emits_one_member_per_claim_name() {
    let key = signer();
    let mut claims = Claims {
        iss: Some("issuer".into()),
        exp: Some(4102444800_u64.into()), // 2100-01-01
        ..Default::default()
    };
    claims.extra.insert("scope".into(), json!("read write"));
    claims
        .extra
        .insert("custom_claim".into(), json!({"nested": true}));

    let token = jose_rs::jwt::encode_with_jwk(&key, &header(), &claims).unwrap();
    let text = String::from_utf8(payload_of(&token)).unwrap();
    for name in ["iss", "exp", "scope", "custom_claim"] {
        assert_eq!(
            text.matches(&format!("\"{name}\"")).count(),
            1,
            "{name} emitted more than once: {text}"
        );
    }
    let back = decode(&key, &token).unwrap();
    assert_eq!(back.iss.as_deref(), Some("issuer"));
    assert_eq!(back.extra["scope"], json!("read write"));
}

/// Regression for the claims fuzz artifacts: unregistered JSON numbers must
/// not drift when a parsed claim set is serialized and parsed again.
#[test]
fn extra_numbers_round_trip_without_precision_drift() {
    let input = br#"{"integer":1000001000000080100080100801000801700005,"tiny":1e-124,"large":1700036.1E125}"#;
    let claims = Claims::from_json_bytes(input).expect("artifact shape parses");
    let emitted = claims.to_json_vec().expect("claims emit");
    let reparsed = Claims::from_json_bytes(&emitted).expect("emitted claims parse");

    for name in ["integer", "tiny", "large"] {
        assert_eq!(
            reparsed.extra[name], claims.extra[name],
            "custom claim number {name} changed across one parse/emit cycle"
        );
    }
}

#[test]
fn a_colliding_extra_claim_cannot_be_signed_at_all() {
    let key = signer();
    let mut claims = Claims {
        exp: Some(4102444800_u64.into()),
        ..Default::default()
    };
    claims.extra.insert("exp".into(), json!(0));

    let err = jose_rs::jwt::encode_with_jwk(&key, &header(), &claims).unwrap_err();
    match err {
        JoseError::InvalidClaims(msg) => assert!(msg.contains("exp"), "{msg}"),
        other => panic!("expected an invalid-claims refusal, got {other:?}"),
    }
}

#[test]
fn a_signed_token_with_duplicate_members_is_not_accepted() {
    let key = signer();
    // `nbf` first so the duplicate is not explainable as "the later field won, so what".
    let token = resign_payload(&key, br#"{"nbf":1,"iss":"a","nbf":2,"iss":"b"}"#);

    let err = decode(&key, &token).unwrap_err();
    match err {
        JoseError::InvalidClaims(msg) => assert!(msg.contains("duplicate JSON member"), "{msg}"),
        other => panic!("expected an invalid-claims refusal, got {other:?}"),
    }

    // Including when the duplicated name is one the validator would act on: expiry is exactly
    // where a last-wins parser turns a token into a different token.
    let token = resign_payload(&key, br#"{"exp":4102444800,"exp":1}"#);
    let err = decode(&key, &token).unwrap_err();
    assert!(matches!(err, JoseError::InvalidClaims(_)), "{err:?}");
}

#[test]
fn decode_unverified_is_as_strict_as_decode() {
    // The inspection path is not a licence to hand back a claim set read differently than the
    // verifying path would: it parses the same bytes with the same rules (signature aside).
    let key = signer();
    let token = resign_payload(&key, br#"{"iat":1,"iat":2}"#);
    #[allow(deprecated)]
    let err = jose_rs::jwt::decode_unverified(&token).unwrap_err();
    assert!(matches!(err, JoseError::InvalidClaims(_)), "{err:?}");
}

#[test]
fn nested_tokens_keep_the_same_claim_rules() {
    // Nested JWTs decode the inner payload through a different function; the consistency claim
    // of L1 is that this is the same behaviour, not a second one that has to be remembered.
    let signer_key = signer();
    let enc_key = {
        let mut k = jwk::generate_ec("P-256").unwrap();
        k.alg = Some("ECDH-ES+A256KW".into());
        k.extra.insert("use".into(), json!("enc"));
        k
    };

    let mut claims = Claims {
        sub: Some("subject".into()),
        ..Default::default()
    };
    claims.extra.insert("scope".into(), json!("openid"));

    let nested = jose_rs::jwt::encode_nested_with_jwk(
        &signer_key,
        &header(),
        &claims,
        &enc_key,
        JweEncryption::A256CbcHs512,
    )
    .unwrap();

    let back = jose_rs::jwt::decode_nested_with_jwk(
        &enc_key,
        &signer_key,
        &nested,
        &Validation::default(),
    )
    .unwrap();
    assert_eq!(back.sub.as_deref(), Some("subject"));
    assert_eq!(back.extra["scope"], json!("openid"));
}

#[test]
fn fractional_timestamps_survive_a_full_token_round_trip() {
    // RFC 7519 allows fractional NumericDate; a token that loses precision in transit can flip a
    // validity decision at the second boundary, which is a security property, not cosmetics.
    let key = signer();
    let claims = Claims {
        iat: Some("1700000000.123456789".parse::<NumericDate>().unwrap()),
        nbf: Some("1700000000.999999999".parse::<NumericDate>().unwrap()),
        ..Default::default()
    };

    let token = jose_rs::jwt::encode_with_jwk(&key, &header(), &claims).unwrap();
    let text = String::from_utf8(payload_of(&token)).unwrap();
    assert!(text.contains("1700000000.123456789"), "{text}");

    let back = decode(&key, &token).unwrap();
    assert_eq!(back.iat.unwrap().subsec_nanos(), 123_456_789);
    assert_eq!(back.nbf.unwrap().subsec_nanos(), 999_999_999);
}

#[test]
fn large_integers_in_unregistered_claims_are_not_rounded() {
    let key = signer();
    let mut claims = Claims::default();
    claims
        .extra
        .insert("account_id".into(), json!(9007199254740993_u64)); // 2^53 + 1
    let token = jose_rs::jwt::encode_with_jwk(&key, &header(), &claims).unwrap();
    let text = String::from_utf8(payload_of(&token)).unwrap();
    assert!(text.contains("9007199254740993"), "{text}");
    assert_eq!(
        decode(&key, &token).unwrap().extra["account_id"],
        json!(9007199254740993_u64)
    );
}

#[test]
fn null_registered_claims_read_as_absent() {
    let key = signer();
    let token = resign_payload(&key, br#"{"exp":null,"iss":null,"sub":null,"scope":null}"#);
    let back = decode(&key, &token).unwrap();
    assert!(back.exp.is_none());
    assert!(back.iss.is_none());
    assert!(back.sub.is_none());
    // An unregistered claim keeps its null value — the absent/null equivalence is a statement
    // about the typed fields, not a general "nulls are dropped" rule.
    assert_eq!(back.extra["scope"], json!(null));
}

#[test]
fn oversized_payloads_are_refused_on_both_sides_of_the_wire() {
    // Emit side: the signer will not build a token it knows it would refuse to read back. That
    // symmetry is the point — an emit guard alone would be a courtesy, and a read guard alone
    // would let a caller produce tokens it cannot consume.
    let key = signer();
    let big = format!(r#"{{"jti":"{}"}}"#, "a".repeat(2 * 1024 * 1024));
    let err = jose_rs::jws::compact::sign_with_jwk(&key, big.as_bytes(), &header()).unwrap_err();
    assert!(
        matches!(&err, JoseError::InvalidToken(msg) if msg.contains("MAX_TOKEN_BYTES")),
        "{err:?}"
    );

    // Read side: splice an oversized payload into a well-formed token (the signature cannot
    // cover it, and the size guard fires before any parsing, which is the order that matters).
    let token = jose_rs::jws::compact::sign_with_jwk(&key, b"{\"iat\":1}", &header()).unwrap();
    let parts: Vec<&str> = token.split('.').collect();
    let spliced = format!(
        "{}.{}.{}",
        parts[0],
        jose_rs::base64url::encode(big.as_bytes()),
        parts[2]
    );
    let err = decode(&key, &spliced).unwrap_err();
    assert!(
        matches!(&err, JoseError::InvalidToken(msg) if msg.contains("MAX_TOKEN_BYTES")),
        "{err:?}"
    );
}

#[test]
fn a_non_object_payload_is_refused_as_such() {
    let key = signer();
    for payload in [
        br#"not json"#.as_slice(),
        br#"[1,2,3]"#.as_slice(),
        br#""a string""#.as_slice(),
        br#"42"#.as_slice(),
    ] {
        let token = resign_payload(&key, payload);
        let err = decode(&key, &token).unwrap_err();
        assert!(
            matches!(
                err,
                JoseError::InvalidClaims(_) | JoseError::Json(_) | JoseError::InvalidToken(_)
            ),
            "{err:?}"
        );
    }
}

#[test]
fn aud_array_and_string_both_validate() {
    let key = signer();
    let mut validation = Validation::default();
    validation.audience = Some("clients".into());

    for payload in [
        br#"{"aud":"clients"}"#.as_slice(),
        br#"{"aud":["other","clients"]}"#.as_slice(),
    ] {
        let token = resign_payload(&key, payload);
        jose_rs::jwt::decode_with_jwk(&key, &token, &validation).unwrap();
    }

    let token = resign_payload(&key, br#"{"aud":"someone-else"}"#);
    let err = jose_rs::jwt::decode_with_jwk(&key, &token, &validation).unwrap_err();
    // A distinct variant, not a generic "invalid claims": a caller must be able to tell "wrong
    // audience" from "malformed payload" without string-matching, and that distinction is what
    // lets a resource server answer 401 versus 400.
    assert!(matches!(err, JoseError::InvalidAudience), "{err:?}");
}
