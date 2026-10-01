//! Decode-side half of the duplicate-member defence.
//!
//! Signing and encryption refuse to emit a protected header with a
//! duplicated member (see `jws_headers.rs` / `jwe_headers.rs`); nothing on
//! the verify side re-checks this explicitly. That is only safe because
//! deserializing a `JoseHeader` fails on a duplicated *typed* member (serde
//! reports `duplicate field`), even though `extra` is `#[serde(flatten)]`ed.
//! RFC 7515 §4 allows a parser either to reject duplicates or to take the
//! last one; this crate relies on rejecting. These tests pin that behaviour
//! so that a custom `Deserialize` impl, a different `extra` representation,
//! or a serde change cannot silently reopen the bypass on the verify side.

use jose_rs::jws::json::{self, FlattenedJws};
use jose_rs::jwt::{self, Validation};
use jose_rs::{base64url, jwe, jwk, jws, JoseError, JoseHeader, JweEncryption, JwsAlgorithm};

/// Protected headers that repeat a typed member, as raw JSON. The last one
/// spells the second `alg` as `\u0061lg`, which JSON unescapes to `alg`
/// before key comparison.
const DUPLICATED_HEADERS: &[&str] = &[
    r#"{"alg":"HS256","alg":"none"}"#,
    r#"{"alg":"HS256","kid":"first","kid":"second"}"#,
    r#"{"alg":"HS256","crit":["b64"],"crit":[]}"#,
    r#"{"alg":"HS256","typ":"JWT","\u0061lg":"none"}"#,
];

fn assert_duplicate_field<T: std::fmt::Debug>(result: jose_rs::Result<T>, what: &str) {
    match result {
        Err(JoseError::Json(e)) if e.to_string().contains("duplicate field") => {}
        other => panic!("{what}: expected a duplicate-field JSON error, got {other:?}"),
    }
}

#[test]
fn deserializing_a_duplicated_typed_member_fails() {
    for raw in DUPLICATED_HEADERS {
        assert_duplicate_field(
            serde_json::from_str::<JoseHeader>(raw).map_err(JoseError::from),
            raw,
        );
    }
}

/// Duplicated *unknown* members land in `extra` with the last value, which
/// matches what `JSON.parse` does, so they are not a divergence.
#[test]
fn duplicated_extension_member_keeps_last_value() {
    let header: JoseHeader =
        serde_json::from_str(r#"{"alg":"HS256","tenant":"a","tenant":"b"}"#).unwrap();
    assert_eq!(header.extra["tenant"], "b");
}

/// Every JWS / JWT verify entry point refuses a token whose protected header
/// repeats a typed member, even when the signature over those exact header
/// bytes is valid.
#[test]
fn verify_rejects_validly_signed_duplicated_header() {
    let key = jwk::generate_symmetric_for_alg("HS256").unwrap();
    let alg = JwsAlgorithm::HS256.to_crypto().unwrap();
    let software_key = || jwk::jwk_to_software_key(&key).unwrap();
    let signer = kryptering::SoftwareSigner::new(alg, software_key()).unwrap();
    let verifier = kryptering::SoftwareVerifier::new(alg, software_key()).unwrap();
    let payload_b64 = base64url::encode(br#"{"sub":"x"}"#);

    for raw in DUPLICATED_HEADERS {
        // jose-rs cannot emit this header, so build the signing input by hand.
        let protected = base64url::encode(raw.as_bytes());
        let input = format!("{protected}.{payload_b64}");
        let signature =
            base64url::encode(&kryptering::Signer::sign(&signer, input.as_bytes()).unwrap());
        let token = format!("{input}.{signature}");

        assert_duplicate_field(jws::compact::decode_header(&token), "decode_header");
        assert_duplicate_field(jws::compact::verify(&verifier, &token), "verify");
        assert_duplicate_field(
            jws::compact::verify_with_jwk(&key, &token),
            "verify_with_jwk",
        );
        assert_duplicate_field(
            jwt::decode_with_jwk(&key, &token, &Validation::default()),
            "jwt::decode_with_jwk",
        );
        let flattened = FlattenedJws {
            payload: Some(payload_b64.clone()),
            protected,
            header: None,
            signature,
        };
        assert_duplicate_field(
            json::verify_flattened(&verifier, &flattened),
            "verify_flattened",
        );
    }
}

/// JWE decryption refuses a token whose protected header repeats a typed
/// member at header parse time, before any key unwrapping or tag check.
#[test]
fn decrypt_rejects_duplicated_header() {
    let key = jwk::generate_direct_symmetric(JweEncryption::A128GCM).unwrap();
    let token = jwe::encrypt_with_jwk(&key, b"secret", JweEncryption::A128GCM).unwrap();
    let rest = token.split_once('.').unwrap().1;

    for raw in [
        r#"{"alg":"dir","enc":"A128GCM","alg":"A128KW"}"#,
        r#"{"alg":"dir","enc":"A128GCM","enc":"A256GCM"}"#,
        r#"{"alg":"dir","enc":"A128GCM","\u0061lg":"A128KW"}"#,
    ] {
        let tampered = format!("{}.{rest}", base64url::encode(raw.as_bytes()));
        assert_duplicate_field(jwe::compact::decode_header(&tampered), "jwe decode_header");
        assert_duplicate_field(jwe::decrypt_with_jwk(&key, &tampered), "decrypt_with_jwk");
    }
}
