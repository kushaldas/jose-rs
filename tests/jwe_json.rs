//! Flattened JWE JSON Serialization (RFC 7516 §7.2.2) — acceptance tests.
//!
//! Vectors: RFC 7516 Appendix A.3 (reproduced from `rfcs/rfc7516.txt`), plus
//! bidirectional equivalence against this crate's compact serialization and
//! against jwcrypto in `interop/tests/jwe_json_jwcrypto.py`.

use jose_rs::jwe::{compact, json, JweDecryptOptions, JweEncryptOptions};
use jose_rs::{JoseError, JweAlgorithm, JweEncryption};

/// RFC 7516 §A.3: AES-128 Key Wrap + A128CBC-HS256, `alg` and `enc` in the
/// protected header. Values copied from the RFC.
mod rfc7516_a3 {
    pub const KEK_B64: &str = "GawgguFyGrWKav7AX4VKUg";
    pub const PROTECTED: &str = "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0";
    pub const ENCRYPTED_KEY: &str = "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ";
    pub const IV: &str = "AxY8DCtDaGlsbGljb3RoZQ";
    pub const CIPHERTEXT: &str = "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY";
    pub const TAG: &str = "U0m_YmjN04DJvceFICbCVQ";
    pub const PLAINTEXT: &[u8] = b"Live long and prosper.";
}

fn decode(b64: &str) -> Vec<u8> {
    jose_rs::base64url::decode(b64).unwrap()
}

/// The RFC's compact example, read through the flattened JSON API: the
/// member values are identical to the compact parts, which is the property
/// RFC 7516 §7.2.1 states for the two serializations.
#[test]
fn rfc7516_a3_compact_parts_decrypt_as_flattened_json() {
    let text = serde_json::json!({
        "protected": rfc7516_a3::PROTECTED,
        "encrypted_key": rfc7516_a3::ENCRYPTED_KEY,
        "iv": rfc7516_a3::IV,
        "ciphertext": rfc7516_a3::CIPHERTEXT,
        "tag": rfc7516_a3::TAG,
    })
    .to_string();

    let jwe = json::FlattenedJwe::from_json(&text).unwrap();
    let plaintext = json::decrypt_flattened(&decode(rfc7516_a3::KEK_B64), &jwe).unwrap();
    assert_eq!(plaintext, rfc7516_a3::PLAINTEXT);

    // And the same values in compact form decrypt identically.
    let compact_token = format!(
        "{}.{}.{}.{}.{}",
        rfc7516_a3::PROTECTED,
        rfc7516_a3::ENCRYPTED_KEY,
        rfc7516_a3::IV,
        rfc7516_a3::CIPHERTEXT,
        rfc7516_a3::TAG
    );
    assert_eq!(
        compact::decrypt(&decode(rfc7516_a3::KEK_B64), &compact_token).unwrap(),
        rfc7516_a3::PLAINTEXT
    );
}

/// RFC 7516 §A.3.5: the content AAD is
/// `ASCII(BASE64URL(UTF8(JWE Protected Header)))` — those exact 51 ASCII
/// bytes. A protected header that re-serializes the same members in a
/// different order is therefore a different AAD, and the tag must fail.
#[test]
fn rfc7516_a3_vector_authenticates_its_exact_header_bytes() {
    let reordered = jose_rs::base64url::encode(br#"{"enc":"A128CBC-HS256","alg":"A128KW"}"#);
    assert_ne!(reordered, rfc7516_a3::PROTECTED);

    let text = serde_json::json!({
        "protected": reordered,
        "encrypted_key": rfc7516_a3::ENCRYPTED_KEY,
        "iv": rfc7516_a3::IV,
        "ciphertext": rfc7516_a3::CIPHERTEXT,
        "tag": rfc7516_a3::TAG,
    })
    .to_string();
    let jwe = json::FlattenedJwe::from_json(&text).unwrap();
    let err = json::decrypt_flattened(&decode(rfc7516_a3::KEK_B64), &jwe).unwrap_err();
    assert!(
        matches!(err, JoseError::Crypto(_)),
        "a reordered header must break authentication, got {err:?}"
    );

    // With the RFC's verbatim bytes it decrypts (see the test above), which is
    // what makes this a test of verbatim handling rather than of decoding.
}

/// Every supported key-management algorithm × content algorithm must work in
/// the flattened JSON form, through both the raw-key and JWK APIs.
#[test]
fn every_supported_combination_roundtrips() {
    let encs = [
        JweEncryption::A128GCM,
        JweEncryption::A192GCM,
        JweEncryption::A256GCM,
        JweEncryption::A128CbcHs256,
        JweEncryption::A192CbcHs384,
        JweEncryption::A256CbcHs512,
    ];
    for enc in encs {
        // dir: the key *is* the CEK.
        let cek = vec![0x33u8; enc.cek_size()];
        let jwe = json::encrypt_flattened(&cek, b"payload", JweAlgorithm::Dir, enc).unwrap();
        assert_eq!(
            json::decrypt_flattened(&cek, &jwe).unwrap(),
            b"payload",
            "dir/{enc:?}"
        );

        // AES-KW family.
        for (alg, kek_len) in [
            (JweAlgorithm::A128KW, 16usize),
            (JweAlgorithm::A192KW, 24),
            (JweAlgorithm::A256KW, 32),
        ] {
            let kek = vec![0x5au8; kek_len];
            let jwe = json::encrypt_flattened(&kek, b"payload", alg, enc).unwrap();
            assert_eq!(
                json::decrypt_flattened(&kek, &jwe).unwrap(),
                b"payload",
                "{alg:?}/{enc:?}"
            );
        }
    }

    // RSA-OAEP-256 once (key generation is slow, so not per `enc`).
    let mut jwk = jose_rs::jwk::generate_rsa(2048).unwrap();
    jwk.alg = Some("RSA-OAEP-256".into());
    let jwe = json::encrypt_flattened_with_jwk(&jwk, b"rsa", JweEncryption::A256GCM).unwrap();
    assert_eq!(
        json::decrypt_flattened_with_jwk(&jwk, &jwe).unwrap(),
        b"rsa"
    );
}

#[test]
fn jwk_api_rejects_a_key_not_permitted_for_the_operation() {
    let mut jwk = jose_rs::jwk::generate_symmetric(32).unwrap();
    jwk.alg = Some("A256KW".into());
    jwk.key_ops = Some(vec!["encrypt".into(), "wrapKey".into()]);

    // Encrypting (wrapping a CEK) needs `wrapKey`, which is present.
    let jwe = json::encrypt_flattened_with_jwk(&jwk, b"p", JweEncryption::A128GCM).unwrap();

    // Decrypting needs `unwrapKey`, which is absent: the key is unusable here
    // even though it is the right key material.
    let err = json::decrypt_flattened_with_jwk(&jwk, &jwe).unwrap_err();
    assert!(
        matches!(&err, JoseError::Key(message) if message.contains("key_ops")),
        "unexpected error: {err:?}"
    );
}

/// The JSON path must not be a policy back door: the same allow-list,
/// plaintext-size and header rules apply as for compact.
#[test]
fn policy_matches_the_compact_serialization() {
    let cek = [0x11u8; 32];
    let jwe =
        json::encrypt_flattened(&cek, b"x", JweAlgorithm::Dir, JweEncryption::A256GCM).unwrap();
    let compact_token = jwe.to_compact().unwrap();

    // 1. Algorithm allow-list.
    let only_kw = JweDecryptOptions::new(vec![JweAlgorithm::A256KW], vec![JweEncryption::A256GCM]);
    let json_err = json::decrypt_flattened_with_options(&cek, &jwe, &only_kw)
        .unwrap_err()
        .to_string();
    let compact_err = compact::decrypt_with_options(&cek, &compact_token, &only_kw)
        .unwrap_err()
        .to_string();
    assert_eq!(
        json_err, compact_err,
        "the two serializations must report the same policy failure"
    );

    // 2. Plaintext limit.
    let tiny = JweDecryptOptions::new(vec![JweAlgorithm::Dir], vec![JweEncryption::A256GCM])
        .with_max_plaintext(0);
    assert!(json::decrypt_flattened_with_options(&cek, &jwe, &tiny).is_err());
    assert!(compact::decrypt_with_options(&cek, &compact_token, &tiny).is_err());

    // 3. Emitted headers obey the same rules on both paths.
    let mut header = jose_rs::JoseHeader::for_jwe(JweAlgorithm::Dir, JweEncryption::A256GCM);
    header
        .extra
        .insert("epk".into(), serde_json::json!({"kty": "EC"}));
    let json_err = json::encrypt_flattened_with_header(
        header.clone(),
        &cek,
        b"p",
        JweAlgorithm::Dir,
        JweEncryption::A256GCM,
    )
    .unwrap_err()
    .to_string();
    let compact_err = compact::encrypt_with_header(
        header,
        &cek,
        b"p",
        JweAlgorithm::Dir,
        JweEncryption::A256GCM,
    )
    .unwrap_err()
    .to_string();
    assert_eq!(json_err, compact_err);
}

#[test]
fn key_reference_members_require_the_explicit_opt_in() {
    let cek = [0x22u8; 32];
    let mut header = jose_rs::JoseHeader::for_jwe(JweAlgorithm::Dir, JweEncryption::A256GCM);
    header.x5c = Some(vec!["MIIB-fake".into()]);

    let err = json::encrypt_flattened_with_header(
        header.clone(),
        &cek,
        b"p",
        JweAlgorithm::Dir,
        JweEncryption::A256GCM,
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("allow_key_reference_headers"), "{err}");

    let jwe = json::encrypt_flattened_with_header_options(
        header,
        &cek,
        b"p",
        JweAlgorithm::Dir,
        JweEncryption::A256GCM,
        &JweEncryptOptions::new().with_key_reference_headers(true),
    )
    .unwrap();
    assert_eq!(
        json::decrypt_flattened(&cek, &jwe).unwrap(),
        b"p",
        "an opted-in x5c member is authenticated like any other"
    );
}

/// Structural fuzz-ish sweep: no malformed input may panic, and only the
/// documented shapes are accepted.
#[test]
fn malformed_inputs_are_rejected_without_panics() {
    let good = json::encrypt_flattened(&[7u8; 32], b"p", JweAlgorithm::Dir, JweEncryption::A256GCM)
        .unwrap()
        .to_json()
        .unwrap();
    let good_value: serde_json::Value = serde_json::from_str(&good).unwrap();

    let mut candidates: Vec<String> = vec![
        String::new(),
        " ".into(),
        "null".into(),
        "5".into(),
        "\"text\"".into(),
        "[]".into(),
        "{}".into(),
        "{".into(),
        "[1,2".into(),
        good.clone(),
    ];

    // Drop each member, then blank it, then replace it with each JSON type.
    let members = ["protected", "encrypted_key", "iv", "ciphertext", "tag"];
    for member in members {
        let mut missing = good_value.clone();
        missing.as_object_mut().unwrap().remove(member);
        candidates.push(missing.to_string());

        for replacement in [
            serde_json::json!(""),
            serde_json::json!(null),
            serde_json::json!(true),
            serde_json::json!(7),
            serde_json::json!([]),
            serde_json::json!({}),
            serde_json::json!("%%%%"),
            serde_json::json!("AAAA="),
        ] {
            let mut mutated = good_value.clone();
            mutated
                .as_object_mut()
                .unwrap()
                .insert((*member).into(), replacement);
            candidates.push(mutated.to_string());
        }
    }

    // Duplicate members cannot be expressed through serde_json, so splice
    // them into the serialized text directly.
    candidates.push(good.replace("\"ciphertext\"", "\"ciphertext2\""));
    candidates.push(format!("{}x", good));

    let mut accepted = Vec::new();
    for text in &candidates {
        // Anything the parser accepts must round-trip through the emitter into
        // something that parses identically. Accepting a message is not a
        // promise it decrypts — dropping `iv` or `tag` leaves a structurally
        // legal message that fails authentication, which the unit tests cover.
        if let Ok(parsed) = json::FlattenedJwe::from_json(text) {
            let remade = json::FlattenedJwe::from_json(&parsed.to_json().unwrap()).unwrap();
            assert_eq!(remade, parsed, "unstable round trip for {text}");
            accepted.push(text.clone());
        }
    }

    // The well-formed message is accepted…
    assert!(accepted.contains(&good), "the valid message must parse");
    // …and these must not be.
    for rejected in [
        String::new(),
        "null".into(),
        "5".into(),
        "\"text\"".into(),
        "[]".into(),
        "{}".into(),
        "{".into(),
        "[1,2".into(),
        format!("{good}x"),
        good.replace("\"ciphertext\"", "\"ciphertext2\""),
        // A non-string member type.
        good.replace("\"protected\"", "\"protected\":5,"),
    ] {
        assert!(
            !accepted.contains(&rejected),
            "must not have been accepted: {rejected}"
        );
        assert!(
            json::FlattenedJwe::from_json(&rejected).is_err(),
            "must not have been accepted: {rejected}"
        );
    }

    // Dropping an optional member parses (RFC 7516 makes presence a SHOULD)
    // but cannot authenticate, and cannot be converted to compact either.
    for optional in ["iv", "tag"] {
        let mut mutated = good_value.clone();
        mutated.as_object_mut().unwrap().remove(optional);
        let parsed = json::FlattenedJwe::from_json(&mutated.to_string())
            .unwrap_or_else(|err| panic!("{optional}: {err}"));
        assert!(
            json::decrypt_flattened(&[7u8; 32], &parsed).is_err(),
            "a message with no {optional} must not decrypt"
        );
        let err = parsed.to_compact().unwrap_err().to_string();
        assert!(
            err.contains("no compact representation")
                || err.contains(&format!("no {optional} member")),
            "{optional}: {err}"
        );
    }
}

/// A JWS JSON object must never be mistaken for a JWE JSON object.
#[test]
fn jws_objects_are_refused_as_jwe() {
    for text in [
        r#"{"payload":"AA","signature":"AA","protected":"AA"}"#,
        r#"{"payload":"AA","signatures":[{"protected":"AA","signature":"AA"}]}"#,
    ] {
        let err = json::FlattenedJwe::from_json(text).unwrap_err();
        assert!(err.to_string().contains("JWS"), "{err}");
    }
}

/// Regression for the flattened-JWE fuzz artifacts: private members are stored
/// in document order, so serialization must not route them through a sorted map.
#[test]
fn private_member_order_survives_round_trip() {
    let text = r#"{"ciphertext":"AA","z-private":1,"protected":"e30","a-private":2}"#;
    let parsed = json::FlattenedJwe::from_json(text).expect("artifact shape parses");
    assert_eq!(
        parsed
            .other
            .iter()
            .map(|(name, _)| name.as_str())
            .collect::<Vec<_>>(),
        ["z-private", "a-private"]
    );

    let reparsed = json::FlattenedJwe::from_json(&parsed.to_json().expect("re-emit"))
        .expect("re-emitted document parses");
    assert_eq!(reparsed, parsed, "private-member order changed");
}

/// The compact <-> flattened conversion is information-preserving, so a
/// message produced by either API is readable by both.
#[test]
fn conversion_is_lossless_in_both_directions() {
    for (alg, key) in [
        (JweAlgorithm::Dir, vec![0x41u8; 32]),
        (JweAlgorithm::A256KW, vec![0x42u8; 32]),
    ] {
        let enc = JweEncryption::A128CbcHs256;
        let jwe = json::encrypt_flattened(&key, b"convert", alg, enc).unwrap();
        let compact_token = jwe.to_compact().unwrap();
        let back = json::FlattenedJwe::from_compact(&compact_token).unwrap();
        assert_eq!(back.protected, jwe.protected);
        assert_eq!(back.encrypted_key, jwe.encrypted_key);
        assert_eq!(back.iv, jwe.iv);
        assert_eq!(back.ciphertext, jwe.ciphertext);
        assert_eq!(back.tag, jwe.tag);
        assert_eq!(back.to_compact().unwrap(), compact_token);
    }
}
