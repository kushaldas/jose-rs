//! AES-GCM key management (`A128GCMKW`, `A192GCMKW`, `A256GCMKW`, RFC 7518 §4.7).
//!
//! The third and last key-management family in RFC 7518 that needs no HSM and no
//! password. It is a different shape from both families already here: the CEK is
//! carried (like `A*KW`), but instead of RFC 3394's self-authenticating wrap it is
//! an AES-GCM encryption whose **IV and authentication tag are header members**
//! (§4.7.1) — which is what puts it in the same "these values change the protected
//! header" class as `epk`, and why the key work happens before serialization.
//!
//! What these tests pin down:
//!
//! * the header members are present, mandatory, correctly sized, and *inside* the
//!   authenticated protected header — and they are the key wrap's, never to be
//!   confused with the envelope's own `iv`/`tag` members that belong to the content
//!   encryption;
//! * the values are generated here: a caller that supplies an `iv` is choosing the
//!   IV of a key wrap, so it is refused for every algorithm;
//! * the key length comes from `alg` and the CEK length from `enc`;
//! * a wrapped key is exactly the CEK's length (GCM does not expand), which is the
//!   structural counterpart to RFC 3394's +8 octets;
//! * and several recipients stay refused, because per-recipient `iv`/`tag` have no
//!   authenticated home (ADR 0020).

use jose_rs::algorithm::JweEncryption;
use jose_rs::jwe::{compact, general, json};
use jose_rs::jwk::Jwk;
use jose_rs::JoseHeader;

/// An `oct` key of the size `alg` names, pinned and marked for encryption.
fn key(alg: &str) -> Jwk {
    oct_key(alg, rand_fill)
}

/// An `oct` JWK of the size `alg` names, with its key material produced by `fill`.
fn oct_key(alg: &str, fill: impl FnOnce(&mut [u8])) -> Jwk {
    let len = match alg {
        "A128GCMKW" => 16,
        "A192GCMKW" => 24,
        _ => 32,
    };
    let mut material = vec![0u8; len];
    fill(&mut material);
    serde_json::from_value(serde_json::json!({
        "kty": "oct",
        "k": jose_rs::base64url::encode(&material),
        "alg": alg,
        "use": "enc",
    }))
    .unwrap()
}

fn rand_fill(bytes: &mut [u8]) {
    use rand::RngCore;
    rand::thread_rng().fill_bytes(bytes);
}

/// The protected header of a compact token, decoded.
fn header_of(token: &str) -> serde_json::Value {
    let bytes = jose_rs::base64url::decode(token.split('.').next().unwrap()).unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

#[test]
fn every_gcm_key_management_algorithm_round_trips() {
    for alg in ["A128GCMKW", "A192GCMKW", "A256GCMKW"] {
        let key = key(alg);
        for enc in [
            JweEncryption::A128GCM,
            JweEncryption::A256GCM,
            JweEncryption::A128CbcHs256,
            JweEncryption::A256CbcHs512,
        ] {
            let token = compact::encrypt_with_jwk(&key, b"wrapped by gcm", enc)
                .unwrap_or_else(|e| panic!("{alg} with {enc:?}: {e}"));
            assert_eq!(
                compact::decrypt_with_jwk(&key, &token)
                    .unwrap_or_else(|e| panic!("{alg} with {enc:?}: {e}")),
                b"wrapped by gcm"
            );

            let flat = json::encrypt_flattened_with_jwk(&key, b"wrapped by gcm", enc).unwrap();
            assert_eq!(
                json::decrypt_flattened_with_jwk(&key, &flat).unwrap(),
                b"wrapped by gcm"
            );
            // The JSON form must carry the key wrap's members in the *protected*
            // header and the content's members at the top level — the same names in
            // two places, meaning two different things (RFC 7516 §7.2, RFC 7518
            // §4.7.1). They must not be equal, and dropping either must break.
            let protected = header_of(&flat.protected.clone().unwrap());
            assert_ne!(
                protected["iv"],
                serde_json::json!(flat.iv.as_deref().unwrap()),
                "{alg}: key-wrap iv and content IV are different values"
            );
            assert_ne!(
                protected["tag"],
                serde_json::json!(flat.tag.as_deref().unwrap()),
                "{alg}: key-wrap tag and content tag are different values"
            );
        }
    }
}

#[test]
fn the_mandatory_members_are_in_the_authenticated_header_with_the_rfc_sizes() {
    for alg in ["A128GCMKW", "A192GCMKW", "A256GCMKW"] {
        let key = key(alg);
        let token = compact::encrypt_with_jwk(&key, b"x", JweEncryption::A128GCM).unwrap();
        let header = header_of(&token);
        let iv = jose_rs::base64url::decode(header["iv"].as_str().expect("iv member")).unwrap();
        let tag = jose_rs::base64url::decode(header["tag"].as_str().expect("tag member")).unwrap();
        assert_eq!(iv.len(), 12, "{alg}: RFC 7518 §4.7 requires a 96-bit IV");
        assert_eq!(tag.len(), 16, "{alg}: RFC 7518 §4.7 requires a 128-bit tag");
        assert!(!token.split('.').nth(1).unwrap().is_empty());
        assert_eq!(header["alg"], serde_json::json!(alg));
    }
}

#[test]
fn a_wrapped_key_is_exactly_the_cek_length() {
    // AES-GCM is a stream construction: the ciphertext is the plaintext's length,
    // with the tag carried separately. That is the structural difference from RFC
    // 3394 (which adds 8 octets) and it is what makes "did I wrap the CEK or the
    // KEK" checkable from the message alone.
    let wide = key("A256GCMKW");
    let token = compact::encrypt_with_jwk(&wide, b"x", JweEncryption::A256GCM).unwrap();
    let wrapped = jose_rs::base64url::decode(token.split('.').nth(1).unwrap()).unwrap();
    assert_eq!(wrapped.len(), 32, "A256GCM's CEK, unexpanded");

    let narrow = key("A128GCMKW");
    let token = compact::encrypt_with_jwk(&narrow, b"x", JweEncryption::A128CbcHs256).unwrap();
    let wrapped = jose_rs::base64url::decode(token.split('.').nth(1).unwrap()).unwrap();
    assert_eq!(wrapped.len(), 32, "A128CBC-HS256 needs a 32-byte CEK");
    // …under a 128-bit key, because the key size comes from `alg`, not from `enc`.
    assert_eq!(
        jose_rs::base64url::decode(narrow.k.as_deref().unwrap())
            .unwrap()
            .len(),
        16
    );
}

#[test]
fn the_initialization_vector_is_fresh_and_cannot_be_supplied() {
    let key = key("A128GCMKW");
    let first = compact::encrypt_with_jwk(&key, b"x", JweEncryption::A128GCM).unwrap();
    let second = compact::encrypt_with_jwk(&key, b"x", JweEncryption::A128GCM).unwrap();
    assert_ne!(header_of(&first)["iv"], header_of(&second)["iv"]);
    assert_ne!(
        first.split('.').nth(1).unwrap(),
        second.split('.').nth(1).unwrap(),
        "the same CEK under a fresh IV must not repeat the wrapped key"
    );

    // And the caller cannot supply one: choosing a key-wrap IV is not a caller's
    // job, and a reused IV under the same key would be catastrophic for GCM.
    for member in ["iv", "tag"] {
        let mut header = JoseHeader::for_jwe(
            jose_rs::algorithm::JweAlgorithm::A128Gcmkw,
            JweEncryption::A128GCM,
        );
        header.extra.insert(
            member.into(),
            serde_json::json!(jose_rs::base64url::encode(&[1u8; 12])),
        );
        let err = compact::encrypt_with_jwk_header(&key, header, b"x", JweEncryption::A128GCM)
            .unwrap_err()
            .to_string();
        assert!(err.contains(member), "{member}: {err}");
    }
}

#[test]
fn a_message_missing_either_mandatory_member_is_refused() {
    // RFC 7518 §4.7.1: both members MUST be present. Neither has a safe default —
    // a zero IV or a zero tag would turn a malformed message into a decryption
    // attempt under a key nobody intended.
    let key = key("A128GCMKW");
    let token = compact::encrypt_with_jwk(&key, b"x", JweEncryption::A128GCM).unwrap();
    for member in ["iv", "tag", "both"] {
        let mut header: serde_json::Value = header_of(&token);
        match member {
            "iv" => {
                header.as_object_mut().unwrap().remove("iv");
            }
            "tag" => {
                header.as_object_mut().unwrap().remove("tag");
            }
            _ => {
                header["iv"] = serde_json::json!(12);
            }
        }
        let rebuilt = format!(
            "{}.{}",
            jose_rs::base64url::encode(&serde_json::to_vec(&header).unwrap()),
            token.split('.').skip(1).collect::<Vec<_>>().join(".")
        );
        let err = compact::decrypt_with_jwk(&key, &rebuilt)
            .unwrap_err()
            .to_string();
        assert!(err.contains("iv") || err.contains("tag"), "{member}: {err}");
    }
}

#[test]
fn wrong_sized_or_wrongly_typed_members_are_refused() {
    let key = key("A128GCMKW");
    let token = compact::encrypt_with_jwk(&key, b"x", JweEncryption::A128GCM).unwrap();
    for (member, value, expected) in [
        ("iv", serde_json::json!("AQID"), "12"),
        (
            "tag",
            serde_json::json!(jose_rs::base64url::encode(&[0u8; 8])),
            "16",
        ),
        ("iv", serde_json::json!(42), "base64url string"),
    ] {
        let mut header = header_of(&token);
        header[member] = value;
        let rebuilt = format!(
            "{}.{}",
            jose_rs::base64url::encode(&serde_json::to_vec(&header).unwrap()),
            token.split('.').skip(1).collect::<Vec<_>>().join(".")
        );
        let err = compact::decrypt_with_jwk(&key, &rebuilt)
            .unwrap_err()
            .to_string();
        assert!(err.contains(expected), "{member}: {err}");
    }
}

#[test]
fn tampering_with_any_of_the_three_parts_fails() {
    // The wrap authenticates the CEK, and the header authenticates the IV and tag
    // as AAD — so every one of the three is covered by something, and editing any
    // of them ends in a failed authentication rather than a wrong CEK.
    let key = key("A256GCMKW");
    let token = compact::encrypt_with_jwk(&key, b"authenticated", JweEncryption::A256GCM).unwrap();
    let parts: Vec<&str> = token.split('.').collect();

    let flip = |text: &str| {
        let mut bytes = jose_rs::base64url::decode(text).unwrap();
        bytes[0] ^= 0x01;
        jose_rs::base64url::encode(&bytes)
    };

    // Encrypted key edited, header left intact.
    let edited = format!(
        "{}.{}.{}.{}.{}",
        parts[0],
        flip(parts[1]),
        parts[2],
        parts[3],
        parts[4]
    );
    assert!(compact::decrypt_with_jwk(&key, &edited).is_err());

    // IV or tag edited inside the protected header: the content tag no longer
    // matches the header bytes, so this fails before the key wrap is even tried.
    for member in ["iv", "tag"] {
        let mut header = header_of(&token);
        let current = header[member].as_str().unwrap().to_string();
        header[member] = serde_json::json!(flip(&current));
        let edited = format!(
            "{}.{}.{}.{}.{}",
            jose_rs::base64url::encode(&serde_json::to_vec(&header).unwrap()),
            parts[1],
            parts[2],
            parts[3],
            parts[4]
        );
        assert!(
            compact::decrypt_with_jwk(&key, &edited).is_err(),
            "edited {member} must not decrypt"
        );
    }
}

#[test]
fn the_wrong_key_size_is_refused_before_any_crypto() {
    for (alg, len) in [("A128GCMKW", 32usize), ("A256GCMKW", 16)] {
        // A key of the *other* GCMKW size: right family, wrong length, so the
        // refusal must be the explicit size check rather than a garbled wrap.
        let jwk: Jwk = serde_json::from_value(serde_json::json!({
            "kty": "oct",
            "k": jose_rs::base64url::encode(&vec![9u8; len]),
            "alg": alg,
            "use": "enc",
        }))
        .unwrap();
        let err = compact::encrypt_with_jwk(&jwk, b"x", JweEncryption::A128GCM)
            .unwrap_err()
            .to_string();
        assert!(err.contains("KEK must be"), "{alg} with {len} bytes: {err}");
    }
}

#[test]
fn a_recipient_with_the_wrong_key_fails_to_unwrap_rather_than_guessing() {
    let sender = key("A128GCMKW");
    // Same size, different bytes: the wrap refuses it, and does so out loud.
    let recipient: Jwk = serde_json::from_value(serde_json::json!({
        "kty": "oct",
        "k": jose_rs::base64url::encode(&[1u8; 16]),
        "alg": "A128GCMKW",
        "use": "enc",
    }))
    .unwrap();
    let token = compact::encrypt_with_jwk(&sender, b"x", JweEncryption::A128GCM).unwrap();
    let err = compact::decrypt_with_jwk(&recipient, &token)
        .unwrap_err()
        .to_string();
    // Explicit failure, unlike RSA-OAEP's implicit rejection: AES-GCM's tag says so
    // itself, and the content tag would fail anyway, so there is nothing to hide.
    assert!(
        err.to_lowercase().contains("aes-gcm") || err.contains("tag"),
        "{err}"
    );
}

#[test]
fn several_recipients_are_refused_with_the_reason() {
    let a = key("A128GCMKW");
    let b = key("A128GCMKW");
    let header = JoseHeader::for_jwe(
        jose_rs::algorithm::JweAlgorithm::A128Gcmkw,
        JweEncryption::A128GCM,
    );
    let err = general::encrypt_general_with_jwks(
        &header,
        &[&a, &b],
        b"two recipients",
        JweEncryption::A128GCM,
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("iv and tag"), "{err}");
    assert!(err.contains("protected"), "{err}");
}

#[test]
fn unprotected_iv_and_tag_are_refused_at_parse_time() {
    // The rule is ADR 0013's, and it is what makes "read them from the protected
    // header" safe rather than merely convenient: a recipient never unwraps a CEK
    // under a peer-chosen IV or tag.
    let key = key("A128GCMKW");
    let flat = json::encrypt_flattened_with_jwk(&key, b"x", JweEncryption::A128GCM).unwrap();
    let mut value: serde_json::Value = serde_json::from_str(&flat.to_json().unwrap()).unwrap();
    let protected: serde_json::Value = serde_json::from_slice(
        &jose_rs::base64url::decode(value["protected"].as_str().unwrap()).unwrap(),
    )
    .unwrap();
    value["header"] = serde_json::json!({"iv": protected["iv"], "tag": protected["tag"]});
    value["protected"] = serde_json::json!(jose_rs::base64url::encode(
        &serde_json::to_vec(&serde_json::json!({"alg": "A128GCMKW", "enc": "A128GCM"})).unwrap()
    ));
    // Refused while parsing, before any key is touched: the member is not merely
    // ignored in that position, it cannot appear there at all.
    let err = json::FlattenedJwe::from_json(&value.to_string())
        .unwrap_err()
        .to_string();
    assert!(err.contains("integrity protected"), "{err}");
    assert!(err.contains("iv") || err.contains("tag"), "{err}");
}

#[test]
fn a_key_marked_for_signing_is_refused() {
    let mut jwk = oct_key("A128GCMKW", |_| ());
    jwk.use_ = Some("sig".into());
    let err = compact::encrypt_with_jwk(&jwk, b"x", JweEncryption::A128GCM)
        .unwrap_err()
        .to_string();
    assert!(err.contains("`use` is sig"), "{err}");
}
