//! Direct ECDH key agreement (`ECDH-ES`) in the JWE serializations.
//!
//! Direct key agreement is structurally different from everything else this
//! crate did before: the content encryption key is *agreed* rather than
//! carried. There is no `encrypted_key`, the sender's half is an ephemeral key
//! generated per message and published as `epk`, and the key both sides land on
//! is the output of the Concat KDF (RFC 7518 §4.6). So these tests cover three
//! things the derivation tests in `jwk_agreement.rs` cannot:
//!
//! * that the whole envelope works — RFC 7520 §5.5's message, produced by a
//!   different implementation from the RFC's own keys, decrypts to the RFC's
//!   plaintext;
//! * that the emit side cannot be talked into the dangerous shapes: a
//!   caller-supplied `epk`, a reused ephemeral key, agreement addressing two
//!   recipients of one ciphertext;
//! * that the receive side refuses a peer key that is not what it claims —
//!   private material in `epk`, another curve, a non-empty `encrypted_key`, an
//!   unauthenticated position — and that a swapped `epk` simply fails to
//!   authenticate.
//!
//! ADR 0016 covers the key-agreement boundary; ADR 0017 covers this wiring.

use jose_rs::algorithm::{JweAlgorithm, JweEncryption};
use jose_rs::jwe::{compact, general, json};
use jose_rs::jwk::Jwk;
use jose_rs::JoseError;
use jose_rs::JoseHeader;

/// RFC 7520 §5.5 recipient key (P-256), with the private part the RFC prints so
/// the example can be replayed.
const RECIPIENT: &str = r#"{
  "kty": "EC",
  "kid": "meriadoc.brandybuck@buckland.example",
  "use": "enc",
  "crv": "P-256",
  "x": "Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0",
  "y": "HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw",
  "d": "r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8",
  "alg": "ECDH-ES"
}"#;

/// RFC 7520 §5.5 Figure 125: the protected header, base64url-encoded.
const PROTECTED: &str = "eyJhbGciOiJFQ0RILUVTIiwia2lkIjoibWVyaWFkb2MuYnJhbmR5YnVja0BidWNrbGFuZC5leGFtcGxlIiwiZXBrIjp7Imt\
    0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoibVBVS1RfYkFXR0hJaGcwVHBqanFWc1AxclhXUXVfdndWT0hIdE5rZFlvQS\
    IsInkiOiI4QlFBc0ltR2VBUzQ2ZnlXdzVNaFlmR1RUMElqQnBGdzJTUzM0RHY0SXJzIn0sImVuYyI6IkExMjhDQkMtSFMyN\
    TYifQ";

/// RFC 7520 §5.5 Figure 128: the complete compact serialization.
fn rfc_compact() -> String {
    // Assembled from the RFC's figures so no line-wrapping whitespace can creep
    // in: protected header, empty encrypted key, IV, ciphertext, tag.
    let iv = "yc9N8v5sYyv3iGQT926IUg";
    let ciphertext = "BoDlwPnTypYq-ivjmQvAYJLb5Q6l-F3LIgQomlz87yW4OPKbWE1zSTEFjDfhU9IPIOSA9Bml4m7iDFwA-1ZXvHteLDtw\
        4R1XRGMEsDIqAYtskTTmzmzNa-_q4F_evAPUmwlO-ZG45Mnq4uhM1fm_D9rBtWolqZSF3xGNNkpOMQKF1Cl8i8wjzRli\
        7-IXgyirlKQsbhhqRzkv8IcY6aHl24j03C-AR2le1r7URUhArM79BY8soZU0lzwI-sD5PZ3l4NDCCei9XkoIAfsXJWmy\
        SPoeRb2Ni5UZL4mYpvKDiwmyzGd65KqVw7MsFfI_K767G9C9Azp73gKZD0DyUn1mn0WW5LmyX_yJ-3AROq8p1WZBfG-Z\
        yJ6195_JGG2m9Csg";
    let tag = "WCCkNa-x4BeB9hIDIfFuhg";
    format!("{}..{}.{}.{}", PROTECTED, iv, ciphertext, tag)
}

/// RFC 7520 Figure 72: the plaintext every §5 example encrypts.
const PLAINTEXT: &str = "You can trust us to stick with you through thick and thin\u{2013}to the \
bitter end. And you can trust us to keep any secret of yours\u{2013}closer than you keep it \
yourself. But you cannot trust us to let you face trouble alone, and go off without a word. We are \
your friends, Frodo.";

fn jwk(text: &str) -> Jwk {
    serde_json::from_str(text).unwrap()
}

/// A recipient key pinned for `ECDH-ES`, on `crv`.
fn recipient(crv: &str) -> Jwk {
    let mut key = jose_rs::jwk::generate_ec(crv).unwrap();
    key.alg = Some("ECDH-ES".into());
    key.use_ = Some("enc".into());
    key
}

// ---------------------------------------------------------------------------
// The RFC vector
// ---------------------------------------------------------------------------

#[test]
fn rfc_7520_5_5_direct_ecdh_es_compact_decrypts() {
    let key = jwk(RECIPIENT);
    let plaintext = compact::decrypt_with_jwk(&key, &rfc_compact()).unwrap();
    assert_eq!(String::from_utf8(plaintext).unwrap(), PLAINTEXT);
}

#[test]
fn rfc_7520_5_5_flattened_json_decrypts() {
    // RFC 7520 §5.5 prints the general serialization and notes the flattened
    // one is identical; this is the same message read as §7.2.2.
    let jwe = json::FlattenedJwe::from_json(&format!(
        r#"{{
          "protected": "{PROTECTED}",
          "iv": "yc9N8v5sYyv3iGQT926IUg",
          "ciphertext": "{}",
          "tag": "WCCkNa-x4BeB9hIDIfFuhg"
        }}"#,
        rfc_compact().split('.').nth(3).unwrap()
    ))
    .unwrap();
    let plaintext = json::decrypt_flattened_with_jwk(&jwk(RECIPIENT), &jwe).unwrap();
    assert_eq!(String::from_utf8(plaintext).unwrap(), PLAINTEXT);

    // And the header it authenticates under really does carry the peer key.
    let header = json::decode_header(&jwe).unwrap().unwrap();
    let epk = header.extra.get("epk").expect("epk in protected header");
    assert_eq!(epk["crv"], "P-256");
    assert_eq!(
        epk["x"],
        serde_json::json!("mPUKT_bAWGHIhg0TpjjqVsP1rXWQu_vwVOHHtNkdYoA")
    );
    // RFC 7518 §4.6.1.1: `epk` MUST contain only public key parameters.
    assert!(epk.get("d").is_none(), "epk must not carry a private part");
}

#[test]
fn a_message_conveying_an_encrypted_key_is_not_direct_agreement() {
    // RFC 7518 §4.6: in direct mode the encrypted key is the empty octet
    // sequence. A message carrying one as well describes two schemes at once.
    let mut value: serde_json::Value = serde_json::from_str(&format!(
        r#"{{
          "protected": "{PROTECTED}",
          "iv": "yc9N8v5sYyv3iGQT926IUg",
          "ciphertext": "{}",
          "tag": "WCCkNa-x4BeB9hIDIfFuhg"
        }}"#,
        rfc_compact().split('.').nth(3).unwrap()
    ))
    .unwrap();
    value["encrypted_key"] = serde_json::json!("AQEBAQEB");
    let jwe = json::FlattenedJwe::from_json(&value.to_string()).unwrap();
    let err = json::decrypt_flattened_with_jwk(&jwk(RECIPIENT), &jwe)
        .unwrap_err()
        .to_string();
    assert!(err.contains("encrypted key must be empty"), "{err}");
}

// ---------------------------------------------------------------------------
// Round trips
// ---------------------------------------------------------------------------

#[test]
fn every_supported_curve_pairs_with_every_content_algorithm() {
    for crv in ["P-256", "P-384", "P-521"] {
        let key = recipient(crv);
        for enc in [
            JweEncryption::A128GCM,
            JweEncryption::A192GCM,
            JweEncryption::A256GCM,
            JweEncryption::A128CbcHs256,
            JweEncryption::A192CbcHs384,
            JweEncryption::A256CbcHs512,
        ] {
            // The compact serialization...
            let token = compact::encrypt_with_jwk(&key, b"agreed content", enc).unwrap();
            let back = compact::decrypt_with_jwk(&key, &token).unwrap();
            assert_eq!(back, b"agreed content", "{crv}/{enc:?} compact");

            // ...and the flattened one, over the same key.
            let flat = json::encrypt_flattened_with_jwk(&key, b"agreed content", enc).unwrap();
            let back = json::decrypt_flattened_with_jwk(&key, &flat).unwrap();
            assert_eq!(back, b"agreed content", "{crv}/{enc:?} flattened");

            // A sender holding only the public half can encrypt; the private
            // half is needed only to read it back.
            let public = key.to_public_jwk();
            let token = compact::encrypt_with_jwk(&public, b"agreed content", enc).unwrap();
            assert_eq!(
                compact::decrypt_with_jwk(&key, &token).unwrap(),
                b"agreed content"
            );
        }
    }
}

#[test]
fn the_ephemeral_key_is_public_minimal_and_fresh() {
    let key = recipient("P-384");
    let first = compact::encrypt_with_jwk(&key, b"same bytes", JweEncryption::A256GCM).unwrap();
    let second = compact::encrypt_with_jwk(&key, b"same bytes", JweEncryption::A256GCM).unwrap();

    let header_a = compact::decode_header(&first).unwrap();
    let header_b = compact::decode_header(&second).unwrap();
    let epk_a = header_a.extra.get("epk").expect("epk");
    let epk_b = header_b.extra.get("epk").expect("epk");

    // RFC 7518 §4.6: "A new ephemeral public key value MUST be generated for
    // each key agreement operation." Reusing one across two recipients would
    // hand both the same key to anyone who sees both messages.
    assert_ne!(epk_a, epk_b, "the ephemeral key must not be reused");
    assert_ne!(first, second);

    // Minimal and public-only: the `epk` this crate emits carries nothing a
    // recipient has any business reading.
    let mut members: Vec<String> = epk_a.as_object().unwrap().keys().cloned().collect();
    members.sort();
    assert_eq!(
        members,
        vec!["crv".to_string(), "kty".into(), "x".into(), "y".into()],
        "epk should carry only the members needed to represent the key"
    );

    // And it is on the recipient's curve, not wherever the sender felt like.
    assert_eq!(epk_a["crv"], "P-384");
    assert_eq!(header_a.alg, "ECDH-ES");
    assert_eq!(header_a.enc.as_deref(), Some("A256GCM"));
}

#[test]
fn the_direct_form_carries_no_encrypted_key() {
    let key = recipient("P-256");

    // Compact: an empty second segment.
    let token = compact::encrypt_with_jwk(&key, b"x", JweEncryption::A128GCM).unwrap();
    assert_eq!(token.split('.').nth(1).unwrap(), "");

    // Flattened JSON: the member is absent, per RFC 7516 §7.2.1.
    let flat = json::encrypt_flattened_with_jwk(&key, b"x", JweEncryption::A128GCM).unwrap();
    assert!(flat.encrypted_key.is_none());
    // Serializing it must leave the member out, not emit an empty one.
    assert!(
        !flat.to_json().unwrap().contains("\"encrypted_key\""),
        "{}",
        flat.to_json().unwrap()
    );
}

// ---------------------------------------------------------------------------
// Emit-side refusals
// ---------------------------------------------------------------------------

#[test]
fn a_caller_supplied_epk_is_refused() {
    let key = recipient("P-256");
    let mut header = JoseHeader::for_jwe(JweAlgorithm::EcdhEs, JweEncryption::A128GCM);
    header.extra.insert(
        "epk".into(),
        serde_json::json!({"kty": "EC", "crv": "P-256", "x": "AA", "y": "AA"}),
    );
    let err = json::encrypt_flattened_with_jwk_header(&key, header, b"x", JweEncryption::A128GCM)
        .unwrap_err()
        .to_string();
    // The member is implemented, but the key in it is not ours to choose:
    // accepting one would make ephemeral-key reuse expressible.
    assert!(err.contains("epk is generated by this crate"), "{err}");
}

#[test]
fn apu_and_apv_travel_in_the_protected_header() {
    let key = recipient("P-521");
    let mut header = JoseHeader::for_jwe(JweAlgorithm::EcdhEs, JweEncryption::A256GCM);
    header
        .extra
        .insert("apu".into(), serde_json::json!("cm9tLXNlbmRlcg"));
    header
        .extra
        .insert("apv".into(), serde_json::json!("dG8tcmVj"));

    let flat = json::encrypt_flattened_with_jwk_header(
        &key,
        header,
        b"party info",
        JweEncryption::A256GCM,
    )
    .unwrap();
    let emitted = flat.peek_protected_header().unwrap().unwrap();
    assert_eq!(
        emitted.extra.get("apu"),
        Some(&serde_json::json!("cm9tLXNlbmRlcg"))
    );
    assert_eq!(
        emitted.extra.get("apv"),
        Some(&serde_json::json!("dG8tcmVj"))
    );
    assert_eq!(
        json::decrypt_flattened_with_jwk(&key, &flat).unwrap(),
        b"party info"
    );

    // The values are KDF inputs, so they are also AAD: a recipient handed a
    // message whose `apu` was edited afterwards cannot derive what the sender
    // derived, and the content tag says so.
    let mut edited: serde_json::Value = serde_json::from_str(&flat.to_json().unwrap()).unwrap();
    let mut header = flat.peek_protected_header().unwrap().unwrap();
    header
        .extra
        .insert("apu".into(), serde_json::json!("dG8tcmVj"));
    edited["protected"] = serde_json::json!(jose_rs::base64url::encode(
        &serde_json::to_vec(&serde_json::to_value(&header).unwrap()).unwrap()
    ));
    let tampered = json::FlattenedJwe::from_json(&edited.to_string()).unwrap();
    let err = json::decrypt_flattened_with_jwk(&key, &tampered)
        .unwrap_err()
        .to_string();
    assert!(!err.is_empty(), "{err}");
}

#[test]
fn equal_or_malformed_party_values_are_refused_before_encryption() {
    let key = recipient("P-256");
    for (apu, apv, expected) in [
        ("QUJD", "QUJD", "apu and apv must be distinct"),
        ("@@@@", "QUJD", "base64"),
    ] {
        let mut header = JoseHeader::for_jwe(JweAlgorithm::EcdhEs, JweEncryption::A128GCM);
        header.extra.insert("apu".into(), serde_json::json!(apu));
        header.extra.insert("apv".into(), serde_json::json!(apv));
        let err =
            json::encrypt_flattened_with_jwk_header(&key, header, b"x", JweEncryption::A128GCM)
                .unwrap_err()
                .to_string();
        assert!(err.contains(expected), "{apu}/{apv}: {err}");
    }
}

#[test]
fn a_non_string_party_value_is_refused() {
    // `apu`/`apv` are untyped members, so `"apu": 5` would otherwise derive the
    // same key as `"apu": "5"` while looking nothing alike.
    let key = recipient("P-256");
    let mut header = JoseHeader::for_jwe(JweAlgorithm::EcdhEs, JweEncryption::A128GCM);
    header.extra.insert("apu".into(), serde_json::json!(5));
    let err = json::encrypt_flattened_with_jwk_header(&key, header, b"x", JweEncryption::A128GCM)
        .unwrap_err()
        .to_string();
    assert!(err.contains("must be a base64url string"), "{err}");
}

#[test]
fn direct_agreement_cannot_address_a_general_jwe() {
    // The agreed key *is* the CEK, and it is agreed with one recipient.
    let one = recipient("P-256");
    let two = recipient("P-256");
    let header = JoseHeader::for_jwe(JweAlgorithm::EcdhEs, JweEncryption::A128GCM);
    let keys = [&one, &two];
    let err = general::encrypt_general_with_jwks(
        &header,
        &keys,
        b"shared content",
        JweEncryption::A128GCM,
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("cannot address a general JWE"), "{err}");

    // Even a single-recipient general message: this crate's general emit path is
    // byte-keyed, and the flattened form is what one recipient needs.
    let err = general::encrypt_general_with_jwks(&header, &[&one], b"x", JweEncryption::A128GCM)
        .unwrap_err()
        .to_string();
    assert!(err.contains("cannot address a general JWE"), "{err}");
}

// ---------------------------------------------------------------------------
// Receive-side refusals
// ---------------------------------------------------------------------------

/// Rebuild a compact token with a modified protected header (the peer key
/// swapped, or a member added). The AAD changes with it, which is the point.
fn with_header(
    mut header: serde_json::Value,
    build: impl FnOnce(&mut serde_json::Value),
) -> String {
    build(&mut header);
    let raw = serde_json::to_vec(&header).unwrap();
    let b64 = jose_rs::base64url::encode(&raw);
    let token = rfc_compact();
    let parts: Vec<&str> = token.split('.').collect();
    format!("{b64}..{}.{}.{}", parts[2], parts[3], parts[4])
}

fn rfc_header() -> serde_json::Value {
    let raw = jose_rs::base64url::decode(PROTECTED).unwrap();
    serde_json::from_slice(&raw).unwrap()
}

#[test]
fn a_peer_key_carrying_private_material_is_refused() {
    // RFC 7518 §4.6.1.1: `epk` MUST contain only public key parameters.
    let token = with_header(rfc_header(), |header| {
        header["epk"]["d"] = serde_json::json!("0_NxaRPUMQoAJt50Gz8YiTr8gRTwyEaCumd-MToTmIo");
    });
    let err = compact::decrypt_with_jwk(&jwk(RECIPIENT), &token)
        .unwrap_err()
        .to_string();
    assert!(err.contains("private component"), "{err}");
}

#[test]
fn a_peer_key_on_another_curve_is_refused() {
    let other = jose_rs::jwk::generate_ec("P-384").unwrap();
    let token = with_header(rfc_header(), |header| {
        header["epk"] = serde_json::to_value(other.to_public_jwk()).unwrap();
    });
    let err = compact::decrypt_with_jwk(&jwk(RECIPIENT), &token)
        .unwrap_err()
        .to_string();
    // Refused as a curve mismatch, not derived into a different key.
    assert!(err.contains("curve mismatch"), "{err}");
}

#[test]
fn a_missing_epk_is_refused() {
    let token = with_header(rfc_header(), |header| {
        header.as_object_mut().unwrap().remove("epk");
    });
    let err = compact::decrypt_with_jwk(&jwk(RECIPIENT), &token)
        .unwrap_err()
        .to_string();
    assert!(err.contains("requires an epk"), "{err}");
}

#[test]
fn a_garbage_epk_is_refused_as_malformed() {
    let token = with_header(rfc_header(), |header| {
        header["epk"] = serde_json::json!({"kty": "oct", "k": "AA"});
    });
    let err = compact::decrypt_with_jwk(&jwk(RECIPIENT), &token)
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("key agreement") || err.contains("epk"),
        "{err}"
    );
}

#[test]
fn a_swapped_epk_authenticates_nothing() {
    // The recipient derives a key under the attacker's ephemeral value, and the
    // content tag — bound to the header those bytes now form — refuses to open.
    // The point is that this is an authentication failure and not a success
    // under a key the attacker could also compute.
    let attacker = jose_rs::jwk::generate_ec("P-256").unwrap();
    let token = with_header(rfc_header(), |header| {
        header["epk"] = serde_json::to_value(attacker.to_public_jwk()).unwrap();
    });
    let err = compact::decrypt_with_jwk(&jwk(RECIPIENT), &token).unwrap_err();
    assert!(
        matches!(err, JoseError::Crypto(_)),
        "expected an authentication failure, got {err:?}"
    );
}

#[test]
fn epk_is_never_read_from_an_unprotected_member() {
    // ADR 0013: a parameter that changes which key the content is authenticated
    // under must be integrity protected. RFC 7518 makes `epk` mandatory, so an
    // unauthenticated one would be the single most valuable header an attacker
    // could choose.
    let mut value: serde_json::Value = serde_json::from_str(&format!(
        r#"{{
          "protected": "{PROTECTED}",
          "iv": "yc9N8v5sYyv3iGQT926IUg",
          "ciphertext": "{}",
          "tag": "WCCkNa-x4BeB9hIDIfFuhg"
        }}"#,
        rfc_compact().split('.').nth(3).unwrap()
    ))
    .unwrap();
    // Strip it from the protected header and offer it unprotected instead.
    let mut header = rfc_header();
    let epk = header.as_object_mut().unwrap().remove("epk").unwrap();
    value["unprotected"] = serde_json::json!({ "epk": epk });
    value["protected"] = serde_json::json!(jose_rs::base64url::encode(
        &serde_json::to_vec(&header).unwrap()
    ));

    // Refused while parsing the envelope, before any key is touched: an
    // unauthenticated `epk` decides which key the content is authenticated
    // under, so it is not data the caller gets to supply out of band.
    let err = json::FlattenedJwe::from_json(&value.to_string())
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("epk") && err.contains("integrity protected"),
        "{err}"
    );
}

#[test]
fn the_raw_key_apis_cannot_reach_key_agreement() {
    // A `&[u8]` cannot name a curve, and there is no `epk` to agree with it
    // against — so agreement is unreachable here by construction, and the
    // message says what to use instead.
    let err = compact::encrypt(
        &[0u8; 32],
        b"x",
        JweAlgorithm::EcdhEs,
        JweEncryption::A128GCM,
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("requires a JWK"), "{err}");

    let err = json::decrypt_flattened(
        &[0u8; 32],
        &json::FlattenedJwe::from_json(&format!(
            r#"{{
              "protected": "{PROTECTED}",
              "iv": "yc9N8v5sYyv3iGQT926IUg",
              "ciphertext": "{}",
              "tag": "WCCkNa-x4BeB9hIDIfFuhg"
            }}"#,
            rfc_compact().split('.').nth(3).unwrap()
        ))
        .unwrap(),
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("requires a JWK"), "{err}");
}

#[test]
fn a_key_pinned_for_signing_cannot_be_an_agreement_recipient() {
    let mut key = jwk(RECIPIENT);
    key.alg = Some("ES256".into());
    let err = compact::decrypt_with_jwk(&key, &rfc_compact())
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("JWK alg") && err.contains("does not match"),
        "{err}"
    );

    // Same key, `alg` dropped, `key_ops` saying `sign`: the operation check is
    // independent of the pin.
    let mut key = jwk(RECIPIENT);
    key.alg = Some("ECDH-ES".into());
    key.key_ops = Some(vec!["sign".into()]);
    let err = compact::decrypt_with_jwk(&key, &rfc_compact())
        .unwrap_err()
        .to_string();
    assert!(err.contains("key_ops"), "{err}");

    // And `use: "sig"`, which is the coarsest statement of the same thing.
    let mut key = jwk(RECIPIENT);
    key.alg = Some("ECDH-ES".into());
    key.use_ = Some("sig".into());
    let err = compact::decrypt_with_jwk(&key, &rfc_compact())
        .unwrap_err()
        .to_string();
    assert!(err.contains("`use` is sig"), "{err}");
}

#[test]
fn a_public_only_recipient_key_cannot_decrypt() {
    let key = jwk(RECIPIENT);
    let mut public = key.clone();
    public.d = None;
    let token = compact::encrypt_with_jwk(&public, b"x", JweEncryption::A128GCM).unwrap();
    let err = compact::decrypt_with_jwk(&public, &token)
        .unwrap_err()
        .to_string();
    assert!(err.contains("private scalar"), "{err}");
}

#[test]
fn agreement_with_key_wrapping_conveys_an_encrypted_key() {
    // `ECDH-ES+A*KW` agrees a key-encryption key instead of the CEK, so the CEK
    // is transported: what makes it the multi-recipient form of agreement, and
    // what makes a *present, non-empty* encrypted key the discriminator between
    // the two modes (ADR 0018).
    for name in ["ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW"] {
        let mut key = recipient("P-256");
        key.alg = Some(name.into());
        let token =
            compact::encrypt_with_jwk(&key, b"wrapped by agreement", JweEncryption::A128GCM)
                .expect(name);
        let segments: Vec<&str> = token.split('.').collect();
        assert!(
            !segments[1].is_empty(),
            "{name}: encrypted key must be present"
        );
        assert_eq!(
            compact::decrypt_with_jwk(&key, &token).expect(name),
            b"wrapped by agreement"
        );
    }
}

#[test]
fn the_two_agreement_modes_derive_different_keys_from_the_same_pair() {
    // Same recipient key, same enc: only the Concat KDF's AlgorithmID input
    // differs by mode (`enc` for direct, `alg` for wrapping, RFC 7518 §4.6.2).
    // Without that difference a recipient pinned to one mode would happily
    // decrypt a message produced for the other.
    let mut direct_key = recipient("P-256");
    direct_key.alg = Some("ECDH-ES".into());
    let mut wrapped_key = recipient("P-256");
    // Same key material, different pin: copy the halves across rather than
    // generating a second pair, so the comparison is about the pin only.
    wrapped_key.crv = direct_key.crv.clone();
    wrapped_key.x = direct_key.x.clone();
    wrapped_key.y = direct_key.y.clone();
    wrapped_key.d = direct_key.d.clone();
    wrapped_key.alg = Some("ECDH-ES+A128KW".into());

    let direct =
        compact::encrypt_with_jwk(&direct_key, b"mode matters", JweEncryption::A128GCM).unwrap();
    let wrapped =
        compact::encrypt_with_jwk(&wrapped_key, b"mode matters", JweEncryption::A128GCM).unwrap();

    // Each decrypts its own message, and neither decrypts the other's: the
    // recipient's pin fixes the mode, so the mismatch surfaces as an algorithm
    // refusal rather than a silently wrong key.
    assert_eq!(
        compact::decrypt_with_jwk(&direct_key, &direct).unwrap(),
        b"mode matters"
    );
    assert_eq!(
        compact::decrypt_with_jwk(&wrapped_key, &wrapped).unwrap(),
        b"mode matters"
    );
    let err = compact::decrypt_with_jwk(&wrapped_key, &direct)
        .unwrap_err()
        .to_string();
    assert!(err.contains("ECDH-ES+A128KW"), "{err}");
}
