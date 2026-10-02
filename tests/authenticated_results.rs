//! Authenticated result objects and error categories (plan L4).
//!
//! Two claims, both about the trust boundary rather than convenience:
//!
//! * an authenticated outcome carries the header the *signature or tag* covered, and keeps
//!   unauthenticated metadata visibly separate — so a key/algorithm decision cannot be
//!   steered by cleartext metadata that travelled next to a perfectly valid signature;
//! * `ErrorCategory` groups errors without ever distinguishing an integrity failure from
//!   a key failure, because that distinction is an oracle.

use jose_rs::jwe::{
    self,
    general::{GeneralJwe, Recipient},
    json as jwe_json,
};
use jose_rs::jwk;
use jose_rs::jws::{self, json as jws_json};
use jose_rs::jwt::{self, Claims, Validation};
use jose_rs::{Authenticated, ErrorCategory, JoseError, JoseHeader};
use serde_json::{json, Map};

/// A `dir` content-encryption key with fresh material (independent per call, so two
/// calls never return the same key).
fn oct_key(counter: &mut u8, bytes: usize) -> jwk::Jwk {
    let seed = *counter;
    *counter = counter.wrapping_add(1);
    let material: Vec<u8> = (0..bytes).map(|i| i as u8 ^ seed ^ 0x5A).collect();
    let value = json!({
        "kty": "oct",
        "k": jose_rs::base64url::encode(&material),
        "alg": "dir",
    });
    serde_json::from_value(value).expect("oct key parses")
}

fn ec(alg: &str, crv: &str) -> jwk::Jwk {
    let mut jwk = jwk::generate_ec(crv).unwrap();
    jwk.alg = Some(alg.into());
    jwk
}

#[test]
fn a_compact_jws_returns_the_header_it_authenticated() {
    let key = ec("ES256", "P-256");
    let mut header = JoseHeader::new("ES256");
    header.typ = Some("at+jwt".into());
    header.kid = Some("kid-auth".into());
    let token = jws::compact::sign_with_jwk(&key, b"payload", &header).unwrap();

    let outcome = jws::compact::verify_with_jwk_authenticated(&key, &token).unwrap();
    assert_eq!(outcome.value, b"payload");
    assert_eq!(outcome.algorithm(), "ES256");
    assert_eq!(outcome.kid(), Some("kid-auth"));
    assert_eq!(outcome.protected.typ.as_deref(), Some("at+jwt"));
    assert!(!outcome.has_unprotected());
}

#[test]
fn unprotected_metadata_stays_out_of_the_authenticated_header() {
    // The core assertion of the module: a document that verifies perfectly, carrying a
    // hostile `kid` in its unprotected member. The authenticated view must report the
    // signed kid, and the forgery must still be *visible* (it is data, just not authority).
    let key = ec("ES256", "P-256");
    let mut header = JoseHeader::new("ES256");
    header.kid = Some("real".into());
    // Signed with an innocuous unprotected member; our own serializer refuses one that repeats
    // a protected name (ADR 0013), so the hostile `kid` is added the way an on-path attacker
    // would add it: after the fact, in the clear.
    let mut flat = jws_json::sign_flattened_with_jwk_opts(
        &key,
        b"payload",
        &header,
        Some(json!({"comment": "look at me"})),
        &jws::SignOptions::new(),
    )
    .unwrap();
    flat.header = Some(json!({"kid": "attacker", "comment": "look at me"}));

    let outcome = jws_json::verify_flattened_with_jwk_authenticated(&key, &flat).unwrap();
    assert_eq!(outcome.kid(), Some("real"));
    assert_eq!(outcome.protected.kid.as_deref(), Some("real"));
    assert!(outcome.has_unprotected());
    assert_eq!(outcome.unprotected[0]["kid"], json!("attacker"));
    // And merging them is not something this type can be tricked into.
    assert!(!outcome.protected.extra.contains_key("kid"));
    // A JWS serializer that *did* let both through would be ambiguous on the wire; ours refuses.
    let err = jws_json::sign_flattened_with_jwk_opts(
        &key,
        b"payload",
        &header,
        Some(json!({"kid": "attacker"})),
        &jws::SignOptions::new(),
    )
    .unwrap_err();
    assert!(matches!(err, JoseError::InvalidHeader(_)), "{err:?}");

    // The forgery is only metadata: changing it cannot change who verifies.
    flat.header = Some(json!({"kid": "someone-else"}));
    let outcome = jws_json::verify_flattened_with_jwk_authenticated(&key, &flat).unwrap();
    assert_eq!(outcome.kid(), Some("real"));
}

#[test]
fn mapping_a_verified_payload_keeps_the_authenticated_context() {
    let key = ec("ES256", "P-256");
    let claims = Claims {
        sub: Some("subject".into()),
        ..Default::default()
    };
    let mut header = JoseHeader::new("ES256");
    header.kid = Some("jwt-kid".into());
    let token = jwt::encode_with_jwk(&key, &header, &claims).unwrap();

    let outcome: Authenticated<Claims> =
        jwt::decode_with_jwk_authenticated(&key, &token, &Validation::default()).unwrap();
    assert_eq!(outcome.value.sub.as_deref(), Some("subject"));
    assert_eq!(outcome.kid(), Some("jwt-kid"));

    // `map` turns claims into a domain type without losing the header.
    let subject = outcome.map(|claims| claims.sub.unwrap_or_default());
    assert_eq!(subject.value, "subject");
    assert_eq!(subject.kid(), Some("jwt-kid"));
}

#[test]
fn a_jwe_returns_the_header_the_tag_authenticated_and_labels_the_rest() {
    let key = {
        let mut k = jwk::generate_ec("P-256").unwrap();
        k.alg = Some("ECDH-ES+A256KW".into());
        k.extra.insert("use".into(), json!("enc"));
        k
    };
    let mut protected = JoseHeader::for_jwe(
        jose_rs::JweAlgorithm::EcdhEsA256kw,
        jose_rs::JweEncryption::A256GCM,
    );
    protected.cty = Some("JWT".into());

    // Flattened, with both unprotected members populated.
    let mut flat = jwe_json::FlattenedJwe {
        protected: None,
        unprotected: None,
        header: None,
        aad: None,
        encrypted_key: None,
        iv: None,
        ciphertext: String::new(),
        tag: None,
        other: Vec::new(),
    };
    flat.unprotected = Some(Map::from_iter([(
        "shared_note".to_string(),
        json!("cleartext"),
    )]));
    flat.header = Some(Map::from_iter([("alg".to_string(), json!("bogus"))]));
    // Encrypt into the flattened form via the general API's single-recipient path,
    // then graft the unprotected members on. They are unauthenticated, so grafting
    // them is exactly what an on-path attacker may do.
    let encrypted = jwe::json::encrypt_flattened_with_jwk_header(
        &key,
        protected.clone(),
        b"plaintext",
        jose_rs::JweEncryption::A256GCM,
    )
    .unwrap();
    flat.protected = encrypted.protected;
    flat.encrypted_key = encrypted.encrypted_key;
    flat.iv = encrypted.iv;
    flat.ciphertext = encrypted.ciphertext;
    flat.tag = encrypted.tag;

    let outcome = jwe_json::decrypt_flattened_with_jwk_authenticated(&key, &flat).unwrap();
    assert_eq!(outcome.value, b"plaintext");
    assert_eq!(outcome.protected.cty.as_deref(), Some("JWT"));
    // Both unauthenticated objects are reported, and neither overwrote the protected view:
    // the forged `alg` in the recipient header is data, not the algorithm that ran.
    assert_eq!(outcome.unprotected.len(), 2);
    assert_eq!(outcome.unprotected[1]["alg"], json!("bogus"));
    assert_eq!(outcome.algorithm(), "ECDH-ES+A256KW");

    // Compact form: no unprotected member exists at all.
    let compact =
        jwe::compact::encrypt_with_jwk(&key, b"plaintext", jose_rs::JweEncryption::A256GCM)
            .unwrap();
    let outcome = jwe::compact::decrypt_with_jwk_authenticated(&key, &compact).unwrap();
    assert_eq!(outcome.value, b"plaintext");
    assert!(!outcome.has_unprotected());
    assert_eq!(outcome.algorithm(), "ECDH-ES+A256KW");
}

#[test]
fn general_jwe_metadata_is_reported_per_recipient_without_being_merged() {
    let first = {
        let mut k = jwk::generate_ec("P-256").unwrap();
        k.alg = Some("ECDH-ES+A256KW".into());
        k.extra.insert("use".into(), json!("enc"));
        k
    };
    let encrypted = jwe::json::encrypt_flattened_with_jwk_header(
        &first,
        JoseHeader::for_jwe(
            jose_rs::JweAlgorithm::EcdhEsA256kw,
            jose_rs::JweEncryption::A256GCM,
        ),
        b"shared plaintext",
        jose_rs::JweEncryption::A256GCM,
    )
    .unwrap();
    let mut jwe = GeneralJwe {
        protected: None,
        unprotected: None,
        aad: None,
        iv: None,
        ciphertext: String::new(),
        tag: None,
        recipients: Vec::new(),
        other: Vec::new(),
    };
    jwe.protected = encrypted.protected;
    jwe.unprotected = Some(Map::from_iter([("shared".to_string(), json!("x"))]));
    jwe.iv = encrypted.iv;
    jwe.ciphertext = encrypted.ciphertext;
    jwe.tag = encrypted.tag;
    jwe.recipients = vec![Recipient {
        header: Some(Map::from_iter([(
            "kid".to_string(),
            json!("unauthenticated"),
        )])),
        encrypted_key: encrypted.encrypted_key,
        other: Vec::new(),
    }];

    let outcome = jwe::general::decrypt_general_with_jwk_authenticated(&first, &jwe, 0).unwrap();
    assert_eq!(outcome.value, b"shared plaintext");
    assert_eq!(outcome.unprotected.len(), 2);
    assert_eq!(outcome.unprotected[0]["shared"], json!("x"));
    assert_eq!(outcome.unprotected[1]["kid"], json!("unauthenticated"));
    // The authenticated header has no kid at all — reading `kid` "from the token"
    // without this type would have found the unauthenticated one.
    assert_eq!(outcome.kid(), None);
}

#[test]
fn error_categories_group_without_leaking_the_failure_reason() {
    // Unsupported capability. `ES256K` *parses* — recognizing an identifier and being able to
    // perform it are different claims, which is what L0's capability table asserts — so the
    // refusal arrives when the algorithm is asked for.
    let parsed = jose_rs::JwsAlgorithm::from_str("ES256K");
    assert!(parsed.is_ok(), "ES256K must be recognized");
    let err = parsed.unwrap().to_crypto().unwrap_err();
    assert_eq!(err.category(), ErrorCategory::UnsupportedCapability);
    // And a name we do not know at all is the same kind of answer.
    let unknown = jose_rs::JwsAlgorithm::from_str("FROB-9000").unwrap_err();
    assert_eq!(unknown.category(), ErrorCategory::UnsupportedCapability);

    // Encoding faults are their own bucket: base64url and JSON failures say "the bytes were
    // not well-formed", which a caller logs differently from "the document was invalid".
    let key = ec("ES256", "P-256");
    let err = jws::compact::verify_with_jwk(&key, "not.a.real.token").unwrap_err();
    assert_eq!(err.category(), ErrorCategory::Encoding);

    // Authentication failure. Ed25519 verification returns a clean "does not verify"
    // verdict, which is the one case this crate labels precisely.
    let mut ed = jwk::generate_ed25519().unwrap();
    ed.alg = Some("EdDSA".into());
    let token = jws::compact::sign_with_jwk(&ed, b"payload", &JoseHeader::new("EdDSA")).unwrap();
    let mut parts: Vec<String> = token.split('.').map(str::to_string).collect();
    let mut sig = jose_rs::base64url::decode(&parts[2]).unwrap();
    let last = sig.len() - 1;
    sig[last] ^= 0x01;
    parts[2] = jose_rs::base64url::encode(&sig);
    let tampered = parts.join(".");
    let err = jws::compact::verify_with_jwk(&ed, &tampered).unwrap_err();
    assert_eq!(
        err.category(),
        ErrorCategory::AuthenticationFailure,
        "a completed check that failed must be identifiable: {err}"
    );
    assert!(err.is_authentication_failure());

    // An ECDSA signature with a garbage scalar is *refused* by the backend rather than
    // returned as "did not verify". Same security meaning, different category — and the
    // merged accessor is what a caller should branch on, because telling those two apart
    // from the outside is an oracle.
    let ec_token =
        jws::compact::sign_with_jwk(&key, b"payload", &JoseHeader::new("ES256")).unwrap();
    let mut parts: Vec<String> = ec_token.split('.').map(str::to_string).collect();
    parts[2] = jose_rs::base64url::encode(&[0u8; 64]);
    let garbage = parts.join(".");
    let err = jws::compact::verify_with_jwk(&key, &garbage).unwrap_err();
    assert!(
        err.is_authentication_failure(),
        "a refused signature is still an authentication failure: {err}"
    );
    assert!(
        matches!(
            err.category(),
            ErrorCategory::Cryptographic | ErrorCategory::AuthenticationFailure
        ),
        "{err}"
    );

    // Policy rejection: expired token, well-formed and correctly signed.
    let claims = Claims {
        exp: Some(1u64.into()),
        ..Default::default()
    };
    let mut header = JoseHeader::new("ES256");
    header.kid = Some("k".into());
    let expired = jwt::encode_with_jwk(&key, &header, &claims).unwrap();
    let err = jwt::decode_with_jwk(&key, &expired, &Validation::default()).unwrap_err();
    assert_eq!(err.category(), ErrorCategory::PolicyRejection);

    // Key material: a key the conversion refuses, and a key whose metadata forbids the
    // operation. Both are "your key is wrong for this", which is neither a structural nor a
    // policy complaint about the *document*.
    let short_oct: jwk::Jwk = serde_json::from_value(json!({"kty": "oct", "k": "AAAA"})).unwrap();
    let err = jwk::jwk_to_software_key(&short_oct).unwrap_err();
    assert_eq!(err.category(), ErrorCategory::KeyMaterial);

    let mut enc_only = ec("ES256", "P-256");
    enc_only.extra.insert("use".into(), json!("enc"));
    let err = jws::compact::verify_with_jwk(&enc_only, &token).unwrap_err();
    assert!(
        matches!(
            err.category(),
            ErrorCategory::KeyMaterial | ErrorCategory::InvalidStructure
        ),
        "{err}"
    );
}

#[test]
fn an_integrity_failure_and_a_key_failure_are_not_distinguishable_by_category() {
    // The oracle we refuse to build: if "the tag did not match" and "the key could not
    // be used" reported differently, a caller (or a prober with a timing side) could ask
    // whether a ciphertext was well-formed without ever learning the plaintext.
    let mut seed = 0u8;
    let symmetric = oct_key(&mut seed, 32);
    let key = symmetric.clone();
    let token =
        jwe::compact::encrypt_with_jwk(&symmetric, b"secret", jose_rs::JweEncryption::A256GCM)
            .unwrap();

    // Wrong key of the right kind: the tag will not match.
    let other = oct_key(&mut seed, 32); // independent material
    let wrong_key = jwe::compact::decrypt_with_jwk(&other, &token).unwrap_err();

    // Tampered ciphertext, same length as the original so the structural checks pass and
    // the failure really is the tag.
    let mut parts: Vec<String> = token.split('.').map(str::to_string).collect();
    // A compact JWE is header.encryptedKey.iv.ciphertext.tag — five segments.
    let mut tag = jose_rs::base64url::decode(&parts[4]).unwrap();
    let last = tag.len() - 1;
    tag[last] ^= 0xFF;
    parts[4] = jose_rs::base64url::encode(&tag);
    let tampered = parts.join(".");
    let tampered_err = jwe::compact::decrypt_with_jwk(&symmetric, &tampered).unwrap_err();

    assert_eq!(
        wrong_key.category(),
        tampered_err.category(),
        "the two must land in the same bucket: {wrong_key} / {tampered_err}"
    );
    assert_eq!(wrong_key.category(), ErrorCategory::Cryptographic);
    assert!(wrong_key.is_authentication_failure());
    assert!(tampered_err.is_authentication_failure());
    // Neither message carries plaintext or key material.
    for message in [wrong_key.to_string(), tampered_err.to_string()] {
        assert!(!message.contains("secret"), "{message}");
    }
    let _ = key;
}

#[test]
fn categories_are_stable_across_the_surfaces_that_raise_the_same_error() {
    // One defect, two entry points: the same bad base64url segment reached through header
    // inspection and through verification must classify identically, or the category is a
    // per-entry-point opinion rather than a property of the error.
    let token = "not-base64!!.Q.a";
    let first = jws::compact::decode_header(token).unwrap_err();
    let second = jws::compact::verify_with_jwk(&ec("ES256", "P-256"), token).unwrap_err();
    assert_eq!(first.category(), second.category());
    assert_eq!(first.category(), ErrorCategory::Encoding);
    // And classification is a pure function of the error, not of how many times it is asked.
    assert_eq!(first.category(), first.category());
}
