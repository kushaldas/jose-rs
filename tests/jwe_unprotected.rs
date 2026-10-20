//! JWE unprotected header members (RFC 7516 §7.2.1) — acceptance tests.
//!
//! The headline case is RFC 7516 §A.5: a flattened JWE whose protected header
//! carries only `enc`, with `alg` and `kid` in the per-recipient unprotected
//! `header` member and a `jku` in the shared `unprotected` member. Before ADR
//! 0011 this shape was refused outright; it is now read, under one rule that
//! makes it safe:
//!
//! **an `alg` the recipient cannot authenticate must be pinned by the key.**
//!
//! The raw-key APIs have no pin, so they still refuse it. The JWK APIs pin
//! `alg` on the key, so the header value is *checked* against the key rather
//! than believed — which is what turns an attacker-controlled field into an
//! assertion the attacker cannot steer.

use jose_rs::jwe::json;
use jose_rs::jwk::{Jwk, JwkSet};
use jose_rs::{JoseError, JweAlgorithm, JweEncryption};

/// The RFC's KEK as a JWK with the algorithm pinned on the key, which is what
/// licenses reading an `alg` the message does not authenticate.
fn pinned_kek(alg: &str, kid: Option<&str>) -> Jwk {
    let mut object = serde_json::json!({
        "kty": "oct",
        "k": vector::KEK_B64,
        "alg": alg,
    });
    if let Some(kid) = kid {
        object["kid"] = serde_json::json!(kid);
    }
    serde_json::from_value(object).unwrap()
}

mod vector {
    /// RFC 7516 §A.5 (values identical to §A.4's second recipient).
    pub const PROTECTED: &str = "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0"; // {"enc":"A128CBC-HS256"}
    pub const UNPROTECTED_JKU: &str = "https://server.example.com/keys.jwks";
    pub const ALG: &str = "A128KW";
    pub const KID: &str = "7";
    pub const ENCRYPTED_KEY: &str = "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ";
    pub const IV: &str = "AxY8DCtDaGlsbGljb3RoZQ";
    pub const CIPHERTEXT: &str = "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY";
    pub const TAG: &str = "Mz-VPPyU4RlcuYv1IwIvzw";
    /// §A.4: the oct key that wraps the CEK (`kid` "7").
    pub const KEK_B64: &str = "GawgguFyGrWKav7AX4VKUg";
    pub const PLAINTEXT: &[u8] = b"Live long and prosper.";
}

fn a5_message() -> String {
    serde_json::json!({
        "protected": vector::PROTECTED,
        "unprotected": { "jku": vector::UNPROTECTED_JKU },
        "header": { "alg": vector::ALG, "kid": vector::KID },
        "encrypted_key": vector::ENCRYPTED_KEY,
        "iv": vector::IV,
        "ciphertext": vector::CIPHERTEXT,
        "tag": vector::TAG,
    })
    .to_string()
}

/// The RFC's own flattened example, read by a key that pins the algorithm.
#[test]
fn rfc7516_a5_flattened_vector_decrypts_with_a_pinned_key() {
    let jwe = json::FlattenedJwe::from_json(&a5_message()).unwrap();

    // Structure first: the three header locations are all populated, disjoint.
    assert_eq!(jwe.unprotected_alg(), Some(vector::ALG));
    assert_eq!(
        jwe.unprotected
            .as_ref()
            .and_then(|m| m.get("jku"))
            .and_then(|v| v.as_str()),
        Some(vector::UNPROTECTED_JKU)
    );

    let jwk = pinned_kek(vector::ALG, Some(vector::KID));
    let plaintext = json::decrypt_flattened_with_jwk(&jwk, &jwe).unwrap();
    assert_eq!(plaintext, vector::PLAINTEXT);

    // The header the message is *about* — protected plus what the unprotected
    // members add. Reported, never fetched: `jku` stays a string.
    let union = jwe.peek_jose_header().unwrap();
    assert_eq!(union["enc"], serde_json::json!("A128CBC-HS256"));
    assert_eq!(union["alg"], serde_json::json!(vector::ALG));
    assert_eq!(union["kid"], serde_json::json!(vector::KID));
    assert_eq!(union["jku"], serde_json::json!(vector::UNPROTECTED_JKU));

    // And the authenticated subset is exactly the protected member.
    let authenticated = json::decode_header(&jwe).unwrap().unwrap();
    assert_eq!(authenticated.enc.as_deref(), Some("A128CBC-HS256"));
    assert_eq!(
        authenticated.kid, None,
        "kid was never integrity protected, so it must not appear as such"
    );
}

/// A key pinned to a *different* algorithm refuses the same bytes before doing
/// any key management — the defence the unprotected-`alg` allowance depends on.
#[test]
fn a_key_pinned_elsewhere_refuses_the_unprotected_alg() {
    let jwe = json::FlattenedJwe::from_json(&a5_message()).unwrap();

    for pinned in ["A256KW", "A192KW", "dir"] {
        let mut jwk = jose_rs::jwk::generate_symmetric(32).unwrap();
        jwk.alg = Some(pinned.into());
        let err = json::decrypt_flattened_with_jwk(&jwk, &jwe).unwrap_err();
        let message = err.to_string();
        assert!(
            message.contains("does not match token header alg A128KW"),
            "{pinned}: {message}"
        );
        assert!(
            !message.contains("decryption"),
            "must refuse on policy, not after a crypto attempt: {message}"
        );
    }
}

/// An RSA key pinned to RSA-OAEP-256 cannot be talked into the A128KW the
/// message claims, and an oct key pinned to RSA-OAEP-256 is refused by the
/// kty/alg consistency check — either way, the token's unprotected `alg` never
/// gets to choose the algorithm.
#[test]
fn other_key_types_cannot_be_steered_by_the_unprotected_alg() {
    let jwe = json::FlattenedJwe::from_json(&a5_message()).unwrap();

    let mut rsa = jose_rs::jwk::generate_rsa(2048).unwrap();
    rsa.alg = Some("RSA-OAEP-256".into());
    let err = json::decrypt_flattened_with_jwk(&rsa, &jwe)
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("JWK alg RSA-OAEP-256 does not match token header alg A128KW"),
        "{err}"
    );

    let mut confused_oct = jose_rs::jwk::generate_symmetric(16).unwrap();
    confused_oct.alg = Some("RSA-OAEP-256".into());
    let err = json::decrypt_flattened_with_jwk(&confused_oct, &jwe).unwrap_err();
    assert!(
        matches!(err, JoseError::Key(_)),
        "kty/alg inconsistency must be a key error, got {err:?}"
    );
}

/// The raw-key APIs have nothing to check an unauthenticated `alg` against, so
/// they refuse the shape instead of picking the attacker's algorithm.
#[test]
fn raw_key_api_still_requires_an_authenticated_alg() {
    let jwe = json::FlattenedJwe::from_json(&a5_message()).unwrap();
    let kek = jose_rs::base64url::decode(vector::KEK_B64).unwrap();

    let err = json::decrypt_flattened(&kek, &jwe).unwrap_err().to_string();
    assert!(err.contains("raw-key API cannot trust"), "{err}");
    assert!(err.contains("alg A128KW"), "{err}");

    // The same key and bytes, with `alg` moved into the protected header, do
    // decrypt — the refusal is about placement, not about the algorithm.
    let protected_only = json::encrypt_flattened(
        &kek,
        vector::PLAINTEXT,
        JweAlgorithm::A128KW,
        JweEncryption::A128CbcHs256,
    )
    .unwrap();
    assert_eq!(
        json::decrypt_flattened(&kek, &protected_only).unwrap(),
        vector::PLAINTEXT
    );
}

/// `use` and `key_ops` are enforced on this path too: a key that may not be
/// used for decryption is refused even when its pinned `alg` matches.
#[test]
fn key_authorization_still_applies_to_unprotected_alg_messages() {
    let jwe = json::FlattenedJwe::from_json(&a5_message()).unwrap();

    let mut signing_key = jose_rs::jwk::generate_symmetric(16).unwrap();
    signing_key.alg = Some(vector::ALG.into());
    signing_key.use_ = Some("sig".into());
    let err = json::decrypt_flattened_with_jwk(&signing_key, &jwe)
        .unwrap_err()
        .to_string();
    assert!(err.contains("use"), "{err}");

    let mut ops_key = jose_rs::jwk::generate_symmetric(16).unwrap();
    ops_key.alg = Some(vector::ALG.into());
    ops_key.key_ops = Some(vec!["encrypt".into(), "wrapKey".into()]);
    let err = json::decrypt_flattened_with_jwk(&ops_key, &jwe)
        .unwrap_err()
        .to_string();
    assert!(err.contains("key_ops"), "{err}");
}

/// Key selection from a JWK Set uses the *authenticated* subset when there is
/// one, and the unprotected `kid` only ever as an untrusted hint. This test
/// pins that a JWK Set lookup by an unprotected `kid` never becomes an
/// authorization decision by itself.
#[test]
fn unprotected_kid_is_a_hint_not_an_authorization() {
    let jwe = json::FlattenedJwe::from_json(&a5_message()).unwrap();
    let union = jwe.peek_jose_header().unwrap();
    let kid = union["kid"].as_str().unwrap().to_string();

    let right = pinned_kek(vector::ALG, Some(&kid));
    let set = JwkSet {
        keys: vec![right.clone()],
    };
    // Unique match, or an explicit ambiguity error — never a silent first hit.
    let found = set
        .find_unique_by_kid(&kid)
        .expect("ambiguous set")
        .expect("kid must be present");
    assert_eq!(found.kid.as_deref(), Some(kid.as_str()));
    // Selecting by the hint is fine; decrypting still pins alg through the key.
    assert!(json::decrypt_flattened_with_jwk(found, &jwe).is_ok());

    // A *different* key carrying the same unprotected kid is still refused,
    // because the key — not the hint — decides the algorithm.
    let mut impostor = jose_rs::jwk::generate_symmetric(16).unwrap();
    impostor.alg = Some("A256KW".into());
    impostor.kid = Some(kid.clone());
    let err = json::decrypt_flattened_with_jwk(&impostor, &jwe)
        .unwrap_err()
        .to_string();
    assert!(err.contains("does not match token header alg"), "{err}");
}

/// Nothing this crate emits puts a header parameter in an unauthenticated
/// place: the unprotected members exist for reading the ecosystem, not for
/// producing more of it.
#[test]
fn jose_rs_never_emits_unprotected_header_members() {
    for alg in [
        JweAlgorithm::Dir,
        JweAlgorithm::A128KW,
        JweAlgorithm::A256KW,
    ] {
        for enc in [JweEncryption::A128GCM, JweEncryption::A256CbcHs512] {
            let key = vec![
                0x0fu8;
                match alg {
                    JweAlgorithm::Dir => enc.cek_size(),
                    JweAlgorithm::A128KW => 16,
                    _ => 32,
                }
            ];
            let jwe = json::encrypt_flattened(&key, b"p", alg, enc).unwrap();
            assert!(jwe.unprotected.is_none(), "{alg:?}/{enc:?}");
            assert!(jwe.header.is_none(), "{alg:?}/{enc:?}");
            let text = jwe.to_json().unwrap();
            assert!(!text.contains("\"unprotected\""), "{text}");
            assert!(!text.contains("\"header\""), "{text}");
        }
    }
}

/// A peer message with unprotected members survives a parse/emit cycle
/// byte-for-byte in meaning, and still decrypts afterwards.
#[test]
fn peer_messages_round_trip_without_losing_members() {
    let jwe = json::FlattenedJwe::from_json(&a5_message()).unwrap();
    let remade = json::FlattenedJwe::from_json(&jwe.to_json().unwrap()).unwrap();
    assert_eq!(remade, jwe);

    let jwk = pinned_kek(vector::ALG, None);
    assert_eq!(
        json::decrypt_flattened_with_jwk(&jwk, &remade).unwrap(),
        vector::PLAINTEXT,
        "re-serializing must not disturb the authenticated members"
    );
    assert!(
        matches!(remade.to_compact(), Err(JoseError::InvalidToken(_))),
        "and must still refuse the lossy compact conversion"
    );
}
