//! General JWE JSON Serialization (RFC 7516 §7.2.1) — multiple recipients.
//!
//! The property these tests pin is *scoping*. One ciphertext, one IV and one
//! tag are shared, but the header the content tag is validated under is
//! **per-recipient** (the union of the protected header, the shared unprotected
//! header and that element's own header). So every decrypt call names the
//! recipient it is for; there is deliberately no "decrypt it for whoever"
//! entry point, because choosing a recipient means choosing a header to
//! authenticate against, and that choice must not be made from
//! attacker-controlled data.
//!
//! The vector is RFC 7516 §A.4 — two recipients, the first `RSA1_5`, the second
//! `A128KW`, sharing `{"enc":"A128CBC-HS256"}` protected and a `jku` in the
//! shared unprotected header. Only the second recipient is this crate's.

use jose_rs::jwe::general::{self, GeneralJwe, RecipientSpec, MAX_RECIPIENTS};
use jose_rs::jwe::{json, JweDecryptOptions, JweEncryptOptions};
use jose_rs::{JoseHeader, JweAlgorithm, JweEncryption};

/// RFC 7516 §A.4.7, transcribed from `rfcs/rfc7516.txt`.
const RFC_A4: &str = r#"{
  "protected": "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
  "unprotected": {"jku":"https://server.example.com/keys.jwks"},
  "recipients": [
    {
      "header": {"alg":"RSA1_5","kid":"2011-04-29"},
      "encrypted_key": "UGhIOguC7IuEvf_NPVaXsGMoLOmwvc1GyqlIKOK1nN94nHPoltGRhWhw7Zx0-kFm1NJn8LE9XShH59_i8J0PH5ZZyNfGy2xGdULU7sHNF6Gp2vPLgNZ__deLKxGHZ7PcHALUzoOegEI-8E66jX2E4zyJKx-YxzZIItRzC5hlRirb6Y5Cl_p-ko3YvkkysZIFNPccxRU7qve1WYPxqbb2Yw8kZqa2rMWI5ng8OtvzlV7elprCbuPhcCdZ6XDP0_F8rkXds2vE4X-ncOIM8hAYHHi29NX0mcKiRaD0-D-ljQTP-cFPgwCp6X-nZZd9OHBv-B3oWh2TbqmScqXMR4gp_A"
    },
    {
      "header": {"alg":"A128KW","kid":"7"},
      "encrypted_key": "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ"
    }
  ],
  "iv": "AxY8DCtDaGlsbGljb3RoZQ",
  "ciphertext": "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY",
  "tag": "Mz-VPPyU4RlcuYv1IwIvzw"
}"#;

const KEK_B64: &str = "GawgguFyGrWKav7AX4VKUg";
const PLAINTEXT: &[u8] = b"Live long and prosper.";

/// A KEK as a JWK with the algorithm pinned on the key — which is what licenses
/// reading an `alg` the message does not authenticate (ADR 0013).
fn kek(kid: &str) -> jose_rs::jwk::Jwk {
    serde_json::from_value(serde_json::json!({
        "kty": "oct", "k": KEK_B64, "alg": "A128KW", "kid": kid,
    }))
    .unwrap()
}

fn kek_pinned(kid: &str, alg: &str, k: &str) -> jose_rs::jwk::Jwk {
    serde_json::from_value(serde_json::json!({
        "kty": "oct", "k": k, "alg": alg, "kid": kid,
    }))
    .unwrap()
}

fn kek_bytes(len: usize, fill: u8) -> Vec<u8> {
    vec![fill; len]
}

#[test]
fn rfc_7516_a_4_second_recipient_decrypts() {
    let jwe = GeneralJwe::from_json(RFC_A4).expect("the RFC's own general example must parse");
    assert_eq!(jwe.recipient_count(), 2);
    assert_eq!(
        jwe.recipient_kids(),
        vec![Some("2011-04-29"), Some("7")],
        "kids come from the per-recipient headers, unauthenticated"
    );

    assert_eq!(
        general::decrypt_general_with_jwk(&kek("7"), &jwe, 1).unwrap(),
        PLAINTEXT
    );
}

#[test]
fn decryption_is_scoped_to_the_named_recipient() {
    let jwe = GeneralJwe::from_json(RFC_A4).unwrap();

    // The same key pointed at the *first* element: its encrypted key is an RSA
    // ciphertext, so unwrapping fails. That the attempt is even expressible is
    // the point — an API that picked a recipient itself would have quietly used
    // element 2 and reported success.
    assert!(general::decrypt_general_with_jwk(&kek("7"), &jwe, 0).is_err());

    // Out of range is a structural error, not a fallback to "the" recipient.
    let err = general::decrypt_general_with_jwk(&kek("7"), &jwe, 2)
        .unwrap_err()
        .to_string();
    assert!(err.contains("out of range"), "{err}");
}

#[test]
fn the_key_pin_is_checked_per_recipient() {
    let jwe = GeneralJwe::from_json(RFC_A4).unwrap();

    // Element 2 declares `A128KW` in an *unprotected* header. A key pinned to a
    // different algorithm refuses it instead of following the unauthenticated
    // value (ADR 0013).
    let wrong_pin = kek_pinned("7", "A256KW", KEK_B64);
    let err = general::decrypt_general_with_jwk(&wrong_pin, &jwe, 1)
        .unwrap_err()
        .to_string();
    assert!(err.contains("does not match"), "{err}");
}

#[test]
fn peeked_header_is_that_recipients_union() {
    let jwe = GeneralJwe::from_json(RFC_A4).unwrap();

    let second = jwe.peek_jose_header_for(1).unwrap();
    assert_eq!(second["alg"], serde_json::json!("A128KW"));
    assert_eq!(second["kid"], serde_json::json!("7"));
    assert_eq!(second["enc"], serde_json::json!("A128CBC-HS256"));
    // ADR 0001: a key *reference* is data — reported, never fetched, never
    // believed, even sitting in a shared unprotected header.
    assert_eq!(
        second["jku"],
        serde_json::json!("https://server.example.com/keys.jwks")
    );

    let first = jwe.peek_jose_header_for(0).unwrap();
    assert_eq!(first["alg"], serde_json::json!("RSA1_5"));
    assert_eq!(first["kid"], serde_json::json!("2011-04-29"));

    assert!(jwe.peek_jose_header_for(9).is_err());
}

#[test]
fn round_trip_with_two_recipients() {
    let header = JoseHeader::for_jwe(JweAlgorithm::A128KW, JweEncryption::A128GCM);
    let kek_a = kek_bytes(16, 0xa1);
    let kek_b = kek_bytes(16, 0xb2);
    let message = general::encrypt_general(
        &header,
        &[
            RecipientSpec::with_kid(&kek_a, "a"),
            RecipientSpec::with_kid(&kek_b, "b"),
        ],
        b"two of us",
        JweAlgorithm::A128KW,
        JweEncryption::A128GCM,
    )
    .unwrap();

    let text = message.to_json().unwrap();
    let reparsed = GeneralJwe::from_json(&text).unwrap();
    assert_eq!(reparsed, message, "parse/emit must be stable");

    // One ciphertext, two encrypted keys.
    let value: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert!(value["ciphertext"].is_string());
    assert_eq!(value["recipients"].as_array().unwrap().len(), 2);

    // Each key opens only its own element.
    let key_a = kek_pinned("a", "A128KW", &jose_rs::base64url::encode(&kek_a));
    let key_b = kek_pinned("b", "A128KW", &jose_rs::base64url::encode(&kek_b));
    assert_eq!(
        general::decrypt_general_with_jwk(&key_a, &reparsed, 0).unwrap(),
        b"two of us"
    );
    assert_eq!(
        general::decrypt_general_with_jwk(&key_b, &reparsed, 1).unwrap(),
        b"two of us"
    );
    assert!(general::decrypt_general_with_jwk(&key_b, &reparsed, 0).is_err());
    assert!(general::decrypt_general_with_jwk(&key_a, &reparsed, 1).is_err());
}

#[test]
fn jwk_addressed_encryption_uses_each_keys_kid() {
    let header = JoseHeader::for_jwe(JweAlgorithm::A128KW, JweEncryption::A128CbcHs256);
    let key_a = kek_pinned(
        "a",
        "A128KW",
        &jose_rs::base64url::encode(&kek_bytes(16, 0x11)),
    );
    let key_b = kek_pinned(
        "b",
        "A128KW",
        &jose_rs::base64url::encode(&kek_bytes(16, 0x22)),
    );
    let message = general::encrypt_general_with_jwks(
        &header,
        &[&key_a, &key_b],
        b"both of you",
        JweEncryption::A128CbcHs256,
    )
    .unwrap();

    assert_eq!(
        general::decrypt_general_with_jwk_by_kid(&key_a, &message).unwrap(),
        b"both of you"
    );
    assert_eq!(
        general::decrypt_general_with_jwk_by_kid(&key_b, &message).unwrap(),
        b"both of you"
    );

    // The kid in each element is the key's own, taken from the key rather than
    // invented — and it stays a hint, not a credential.
    let kids: Vec<Option<&str>> = message
        .recipients
        .iter()
        .map(|entry| {
            entry
                .header
                .as_ref()
                .and_then(|header| header.get("kid"))
                .and_then(serde_json::Value::as_str)
        })
        .collect();
    assert_eq!(kids, vec![Some("a"), Some("b")]);

    // Recipients that disagree about the algorithm cannot address one message:
    // the algorithm would then have to travel unauthenticated.
    let mismatched = kek_pinned(
        "c",
        "A256KW",
        &jose_rs::base64url::encode(&kek_bytes(32, 0x33)),
    );
    let err = general::encrypt_general_with_jwks(
        &header,
        &[&key_a, &mismatched],
        b"x",
        JweEncryption::A128CbcHs256,
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("same alg"), "{err}");
}

#[test]
fn kid_selection_refuses_guessing() {
    let header = JoseHeader::for_jwe(JweAlgorithm::A256KW, JweEncryption::A256GCM);
    let kek_a = kek_bytes(32, 0xaa);
    let kek_b = kek_bytes(32, 0xbb);
    let message = general::encrypt_general(
        &header,
        &[
            RecipientSpec::with_kid(&kek_a, "a"),
            RecipientSpec::with_kid(&kek_b, "b"),
        ],
        b"find me",
        JweAlgorithm::A256KW,
        JweEncryption::A256GCM,
    )
    .unwrap();
    let key_b = kek_pinned("b", "A256KW", &jose_rs::base64url::encode(&kek_b));
    assert_eq!(
        general::decrypt_general_with_jwk_by_kid(&key_b, &message).unwrap(),
        b"find me"
    );

    // A key whose kid matches nothing must not be aimed at an arbitrary element.
    let key_c = kek_pinned(
        "c",
        "A256KW",
        &jose_rs::base64url::encode(&kek_bytes(32, 0xcc)),
    );
    let err = general::decrypt_general_with_jwk_by_kid(&key_c, &message)
        .unwrap_err()
        .to_string();
    assert!(err.contains("no recipient"), "{err}");

    // Two elements carrying the same kid is a real ambiguity in unauthenticated
    // data: refuse rather than choose.
    let protected = message.protected.as_ref().unwrap();
    let wrapped = message.recipients[0].encrypted_key.as_ref().unwrap();
    let duplicated = serde_json::json!({
        "protected": protected,
        "recipients": [
            { "header": { "kid": "b" }, "encrypted_key": wrapped },
            { "header": { "kid": "b" }, "encrypted_key": wrapped },
        ],
        "iv": message.iv.as_ref().unwrap(),
        "ciphertext": message.ciphertext,
        "tag": message.tag.as_ref().unwrap(),
    })
    .to_string();
    let duplicated = GeneralJwe::from_json(&duplicated).unwrap();
    let err = general::decrypt_general_with_jwk_by_kid(&key_b, &duplicated)
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("2 recipients") && err.contains("unauthenticated"),
        "{err}"
    );
}

#[test]
fn external_aad_is_authenticated_once_for_everyone() {
    let header = JoseHeader::for_jwe(JweAlgorithm::A128KW, JweEncryption::A128GCM);
    let kek_shared = kek_bytes(16, 0x5a);
    let opts = JweEncryptOptions::new().with_external_aad(b"tenant=42");
    let message = general::encrypt_general_options(
        &header,
        &[
            RecipientSpec::new(&kek_shared),
            RecipientSpec::with_kid(&kek_shared, "b"),
        ],
        b"context",
        JweAlgorithm::A128KW,
        JweEncryption::A128GCM,
        &opts,
    )
    .unwrap();
    assert_eq!(
        message.aad.as_deref(),
        Some(jose_rs::base64url::encode(b"tenant=42").as_str())
    );

    let text = message.to_json().unwrap();
    let reparsed = GeneralJwe::from_json(&text).unwrap();
    let key = kek_pinned("b", "A128KW", &jose_rs::base64url::encode(&kek_shared));
    let dec_opts = JweDecryptOptions::new(vec![JweAlgorithm::A128KW], vec![JweEncryption::A128GCM])
        .with_external_aad(b"tenant=42");
    assert_eq!(
        general::decrypt_general_with_jwk_and_aad(&key, &reparsed, 1, b"tenant=42").unwrap(),
        b"context"
    );
    assert!(general::decrypt_general_with_jwk_and_aad(&key, &reparsed, 1, b"tenant=43").is_err());

    // A message carrying an `aad` member cannot be read by the AAD-free entry
    // point: the caller has to supply the bytes the tag was computed over.
    let err = general::decrypt_general_with_jwk(&key, &reparsed, 1)
        .unwrap_err()
        .to_string();
    assert!(err.contains("aad"), "{err}");
    assert!(dec_opts.external_aad().is_some());
}

#[test]
fn malformed_general_messages_are_refused_by_name() {
    let valid: serde_json::Value = serde_json::from_str(RFC_A4).unwrap();

    // No `recipients` → that is the flattened syntax, and the error says so.
    let mut missing = valid.clone();
    missing.as_object_mut().unwrap().remove("recipients");
    let err = GeneralJwe::from_json(&missing.to_string())
        .unwrap_err()
        .to_string();
    assert!(err.contains("FlattenedJwe"), "{err}");

    // An empty array: RFC 7516 §7.2.1 requires one element per recipient.
    let mut empty = valid.clone();
    empty["recipients"] = serde_json::json!([]);
    let err = GeneralJwe::from_json(&empty.to_string())
        .unwrap_err()
        .to_string();
    assert!(err.contains("at least one recipient"), "{err}");

    // A recipient array is attacker-sized data, so its length is bounded.
    let mut many = valid.clone();
    many["recipients"] = serde_json::json!((0..=MAX_RECIPIENTS)
        .map(|_| serde_json::json!({ "encrypted_key": "AA" }))
        .collect::<Vec<_>>());
    let err = GeneralJwe::from_json(&many.to_string())
        .unwrap_err()
        .to_string();
    assert!(err.contains("bound"), "{err}");

    // Elements must be objects.
    let mut scalar = valid.clone();
    scalar["recipients"] = serde_json::json!(["nope"]);
    let err = GeneralJwe::from_json(&scalar.to_string())
        .unwrap_err()
        .to_string();
    assert!(err.contains("must be a JSON object"), "{err}");

    // `header` / `encrypted_key` belong to an element, not the top level:
    // reading them there would apply one recipient's key to all of them.
    for member in ["header", "encrypted_key"] {
        let mut moved = valid.clone();
        moved[member] = valid["recipients"][1][member].clone();
        let err = GeneralJwe::from_json(&moved.to_string())
            .unwrap_err()
            .to_string();
        assert!(err.contains("recipients\" element"), "{err}");
    }

    // The two JSON syntaxes are not interchangeable, in either direction.
    let flat = json::FlattenedJwe::from_json(RFC_A4)
        .unwrap_err()
        .to_string();
    assert!(flat.contains("general JWE JSON serialization"), "{flat}");

    // A JWS is neither.
    let err = GeneralJwe::from_json(r#"{"payload":"AAA","signatures":[]}"#)
        .unwrap_err()
        .to_string();
    assert!(err.contains("belongs to a JWS"), "{err}");

    // Without a protected header, `enc` would be unauthenticated.
    let mut unprotected_enc = valid.clone();
    unprotected_enc.as_object_mut().unwrap().remove("protected");
    let err = GeneralJwe::from_json(&unprotected_enc.to_string())
        .unwrap_err()
        .to_string();
    assert!(err.contains("integrity protected"), "{err}");

    // Duplicate member names (RFC 8725 §3).
    let duplicated = RFC_A4.replace(
        "\"iv\": \"AxY8DCtDaGlsbGljb3RoZQ\"",
        "\"iv\": \"AxY8DCtDaGlsbGljb3RoZQ\", \"iv\": \"AAAAAAAAAAAAAAAAAAAAAA\"",
    );
    let err = GeneralJwe::from_json(&duplicated).unwrap_err().to_string();
    assert!(err.contains("duplicate"), "{err}");
}

#[test]
fn unprotected_positions_keep_their_limits() {
    // `enc` in a recipient header would decide how the ciphertext and tag octets
    // are split, so it must be integrity protected (ADR 0013).
    let mut message: serde_json::Value = serde_json::from_str(RFC_A4).unwrap();
    message["recipients"][0]["header"]["enc"] = serde_json::json!("A128GCM");
    let err = GeneralJwe::from_json(&message.to_string())
        .unwrap_err()
        .to_string();
    assert!(err.contains("integrity protected"), "{err}");

    // Same rule in the shared unprotected header.
    let mut message: serde_json::Value = serde_json::from_str(RFC_A4).unwrap();
    message["unprotected"]["zip"] = serde_json::json!("DEF");
    let err = GeneralJwe::from_json(&message.to_string())
        .unwrap_err()
        .to_string();
    assert!(err.contains("integrity protected"), "{err}");

    // Disjointness (RFC 7516 §7.2.1), reported per recipient.
    let mut message: serde_json::Value = serde_json::from_str(RFC_A4).unwrap();
    message["unprotected"]["kid"] = serde_json::json!("shared");
    let err = GeneralJwe::from_json(&message.to_string())
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("disjoint") && err.contains("recipient 0"),
        "{err}"
    );

    // An empty per-recipient header must be absent, not `{}`.
    let mut message: serde_json::Value = serde_json::from_str(RFC_A4).unwrap();
    message["recipients"][1]["header"] = serde_json::json!({});
    let err = GeneralJwe::from_json(&message.to_string())
        .unwrap_err()
        .to_string();
    assert!(err.contains("absent rather than empty"), "{err}");

    // A non-string `encrypted_key` is structural.
    let mut message: serde_json::Value = serde_json::from_str(RFC_A4).unwrap();
    message["recipients"][1]["encrypted_key"] = serde_json::json!(42);
    let err = GeneralJwe::from_json(&message.to_string())
        .unwrap_err()
        .to_string();
    assert!(err.contains("must be a string"), "{err}");
}

#[test]
fn unknown_members_survive_and_do_not_interfere() {
    // RFC 7516 §7.2.1: unrecognized members are ignored for processing, which is
    // not the same as deleting them.
    let mut message: serde_json::Value = serde_json::from_str(RFC_A4).unwrap();
    message["audit"] = serde_json::json!({"trace": "abc"});
    message["recipients"][1]["note"] = serde_json::json!("per-recipient");

    let jwe = GeneralJwe::from_json(&message.to_string()).unwrap();
    let reparsed: serde_json::Value = serde_json::from_str(&jwe.to_json().unwrap()).unwrap();
    assert_eq!(reparsed["audit"], serde_json::json!({"trace": "abc"}));
    assert_eq!(
        reparsed["recipients"][1]["note"],
        serde_json::json!("per-recipient")
    );

    assert_eq!(
        general::decrypt_general_with_jwk(&kek("7"), &jwe, 1).unwrap(),
        PLAINTEXT
    );
}

#[test]
fn dir_cannot_address_two_recipients() {
    // Direct key agreement conveys no encrypted key at all, so there is nothing
    // to hand a second recipient. Saying that beats emitting a message whose
    // second element is a copy of the CEK.
    let cek = kek_bytes(16, 0x21);
    let header = JoseHeader::for_jwe(JweAlgorithm::Dir, JweEncryption::A128GCM);
    let err = general::encrypt_general(
        &header,
        &[RecipientSpec::new(&cek), RecipientSpec::new(&cek)],
        b"x",
        JweAlgorithm::Dir,
        JweEncryption::A128GCM,
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("second recipient"), "{err}");
}

#[test]
fn nothing_unauthenticated_is_emitted() {
    // jose-rs reads unprotected header locations; it never writes the shared
    // one, and the only per-recipient parameter it ever writes is the `kid` the
    // caller supplied for its own key.
    let header = JoseHeader::for_jwe(JweAlgorithm::A128KW, JweEncryption::A128GCM);
    let kek_shared = kek_bytes(16, 0x77);
    let message = general::encrypt_general(
        &header,
        &[RecipientSpec::new(&kek_shared)],
        b"quiet",
        JweAlgorithm::A128KW,
        JweEncryption::A128GCM,
    )
    .unwrap();

    let value: serde_json::Value = serde_json::from_str(&message.to_json().unwrap()).unwrap();
    let object = value.as_object().unwrap();
    assert!(!object.contains_key("unprotected"), "{object:?}");
    assert!(
        message.recipients[0].header.is_none(),
        "no kid asked for, no kid invented"
    );

    // One recipient in the general syntax is still general: it parses, and it
    // still needs the index — the shape is not a licence to try keys at random.
    assert_eq!(message.recipient_count(), 1);
    let key = kek_pinned("x", "A128KW", &jose_rs::base64url::encode(&kek_shared));
    assert_eq!(
        general::decrypt_general_with_jwk(&key, &message, 0).unwrap(),
        b"quiet"
    );
    assert!(general::decrypt_general_with_jwk(&key, &message, 1).is_err());
}

#[test]
fn the_protected_header_must_declare_what_was_used() {
    let cek = kek_bytes(16, 0x22);
    let mut header = JoseHeader::for_jwe(JweAlgorithm::A256KW, JweEncryption::A128GCM);
    let err = general::encrypt_general(
        &header,
        &[RecipientSpec::new(&cek)],
        b"x",
        JweAlgorithm::A128KW,
        JweEncryption::A128GCM,
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("does not match JWE algorithm"), "{err}");

    header = JoseHeader::for_jwe(JweAlgorithm::A128KW, JweEncryption::A256GCM);
    let err = general::encrypt_general(
        &header,
        &[RecipientSpec::new(&cek)],
        b"x",
        JweAlgorithm::A128KW,
        JweEncryption::A128GCM,
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("does not match JWE encryption"), "{err}");

    // No recipients, and too many recipients, are refused before any crypto.
    let header = JoseHeader::for_jwe(JweAlgorithm::A128KW, JweEncryption::A128GCM);
    let err = general::encrypt_general(
        &header,
        &[],
        b"x",
        JweAlgorithm::A128KW,
        JweEncryption::A128GCM,
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("at least one recipient"), "{err}");

    let many: Vec<RecipientSpec<'_>> = (0..=MAX_RECIPIENTS)
        .map(|_| RecipientSpec::new(&cek))
        .collect();
    let err = general::encrypt_general(
        &header,
        &many,
        b"x",
        JweAlgorithm::A128KW,
        JweEncryption::A128GCM,
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("bound"), "{err}");
}
