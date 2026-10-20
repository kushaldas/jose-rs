//! ECDH key agreement **with key wrapping** (`ECDH-ES+A128KW`, `+A192KW`,
//! `+A256KW`).
//!
//! These three algorithms look like `ECDH-ES` with a suffix and are a different
//! key-management mode in the RFC's own terms (RFC 7518 §4.6): the agreement
//! output is a **key-encryption key**, and the content encryption key is
//! generated normally and wrapped under it. Four things follow, and each is
//! asserted here rather than inferred:
//!
//! * the message **carries** an encrypted key — its absence is an error, not a
//!   hint to fall back to direct agreement;
//! * the Concat KDF's AlgorithmID input is the ASCII `alg` value, not `enc`, and
//!   `keydatalen` is the KEK's bit length, not the CEK's — so the same key pair
//!   and the same `enc` derive a different key than direct agreement does;
//! * the KEK length comes from the algorithm while the CEK length comes from
//!   `enc`, so `ECDH-ES+A128KW` protects a 256-bit CEK with a 128-bit KEK without
//!   the two lengths being confused;
//! * this is the mode that can address several recipients, because the CEK is no
//!   longer the agreed value — which is also why it needs an `epk` *per
//!   recipient*, and why that part is still refused (ADR 0018).
//!
//! RFC 7520 §5.4's message is the cross-implementation check: written by other
//! code, from other keys, it yields the RFC's plaintext only if ECDH, the Concat
//! KDF inputs and RFC 3394 unwrapping all agree with the RFC's reading.

use jose_rs::algorithm::{JweAlgorithm, JweEncryption};
use jose_rs::jwe::{compact, general, json};
use jose_rs::jwk::Jwk;
use jose_rs::JoseHeader;

/// RFC 7520 Figure 108: the P-384 recipient key, including the private part the
/// RFC prints so the example can be replayed.
const RECIPIENT: &str = r#"{
  "kty": "EC",
  "kid": "peregrin.took@tuckborough.example",
  "use": "enc",
  "crv": "P-384",
  "x": "YU4rRUzdmVqmRtWOs2OpDE_T5fsNIodcG8G5FWPrTPMyxpzsSOGaQLpe2FpxBmu2",
  "y": "A8-yxCHxkfBz3hKZfI1jUYMjUhsEveZ9THuwFjH2sCNdtksRJU7D5-SkgaFL1ETP",
  "d": "iTx2pk7wW-GqJkHcEkFQb2EFyYcO7RugmaW3mRrQVAOUiPommT0IdnYK2xDlZh-j"
}"#;

/// RFC 7520 Figures 114, 112, 110, 115, 116: the §5.4 message, member by member.
const PROTECTED: &str =
    "eyJhbGciOiJFQ0RILUVTK0ExMjhLVyIsImtpZCI6InBlcmVncmluLnRvb2tAdHVja2Jvcm91Z2guZXhhbXBsZSIsImVwayI6eyJrdHkiOiJFQyIsImNydiI6IlAtMzg0IiwieCI6InVCbzRrSFB3Nmtiang1bDB4b3dyZF9vWXpCbWF6LUdLRlp1NHhBRkZrYllpV2d1dEVLNml1RURzUTZ3TmROZzMiLCJ5Ijoic3AzcDVTR2haVkMyZmFYdW1JLWU5SlUyTW84S3BvWXJGRHI1eVBOVnRXNFBnRXdaT3lRVEEtSmRhWTh0YjdFMCJ9LCJlbmMiOiJBMTI4R0NNIn0";
const ENCRYPTED_KEY: &str = "0DJjBXri_kBcC46IkU5_Jk9BqaQeHdv2";
const IV: &str = "mH-G2zVqgztUtnW_";
const CIPHERTEXT: &str =
    "tkZuOO9h95OgHJmkkrfLBisku8rGf6nzVxhRM3sVOhXgz5NJ76oID7lpnAi_cPWJRCjSpAaUZ5dOR3Spy7QuEkmKx8-3RCMhSYMzsXaEwDdXta9Mn5B7cCBoJKB0IgEnj_qfo1hIi-uEkUpOZ8aLTZGHfpl05jMwbKkTe2yK3mjF6SBAsgicQDVCkcY9BLluzx1RmC3ORXaM0JaHPB93YcdSDGgpgBWMVrNU1ErkjcMqMoT_wtCex3w03XdLkjXIuEr2hWgeP-nkUZTPU9EoGSPj6fAS-bSz87RCPrxZdj_iVyC6QWcqAu07WNhjzJEPc4jVntRJ6K53NgPQ5p99l3Z408OUqj4ioYezbS6vTPlQ";
const TAG: &str = "WuGzxmcreYjpHGJoa17EBg";

/// RFC 7520 Figure 117: the complete compact serialization.
fn rfc_compact() -> String {
    format!("{PROTECTED}.{ENCRYPTED_KEY}.{IV}.{CIPHERTEXT}.{TAG}")
}

/// The same message as §7.2.2 JSON.
fn rfc_flattened_json() -> String {
    format!(
        r#"{{
          "protected": "{PROTECTED}",
          "encrypted_key": "{ENCRYPTED_KEY}",
          "iv": "{IV}",
          "ciphertext": "{CIPHERTEXT}",
          "tag": "{TAG}"
        }}"#
    )
}

/// RFC 7520 Figure 72: the plaintext every §5 example encrypts.
const PLAINTEXT: &str = "You can trust us to stick with you through thick and thin\u{2013}to the \
bitter end. And you can trust us to keep any secret of yours\u{2013}closer than you keep it \
yourself. But you cannot trust us to let you face trouble alone, and go off without a word. We are \
your friends, Frodo.";

fn jwk(text: &str) -> Jwk {
    serde_json::from_str(text).unwrap()
}

/// The RFC's recipient key pinned to `alg`.
///
/// The pin is load-bearing, not decoration: it is what fixes the key-management
/// mode for a message, and therefore the Concat KDF's AlgorithmID and key length.
fn recipient(alg: &str) -> Jwk {
    let mut key = jwk(RECIPIENT);
    key.alg = Some(alg.into());
    key
}

/// A freshly generated recipient key on `crv`, pinned to `alg`.
fn generated(crv: &str, alg: &str) -> Jwk {
    let mut key = jose_rs::jwk::generate_ec(crv).unwrap();
    key.alg = Some(alg.into());
    key.use_ = Some("enc".into());
    key
}

/// The `epk` member of a compact token's protected header.
fn epk_of(token: &str) -> serde_json::Value {
    let bytes = jose_rs::base64url::decode(token.split('.').next().unwrap()).unwrap();
    serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()["epk"].clone()
}

// ---------------------------------------------------------------------------
// The RFC vector
// ---------------------------------------------------------------------------

#[test]
fn rfc_7520_5_4_compact_decrypts() {
    // A match on the plaintext means the ECDH, the KDF inputs (AlgorithmID
    // "ECDH-ES+A128KW", keydatalen 128) and the RFC 3394 unwrap all agree with
    // the RFC's reading — none of which this crate shares with its author.
    let plaintext =
        compact::decrypt_with_jwk(&recipient("ECDH-ES+A128KW"), &rfc_compact()).unwrap();
    assert_eq!(String::from_utf8(plaintext).unwrap(), PLAINTEXT);
}

#[test]
fn rfc_7520_5_4_flattened_decrypts() {
    let jwe = json::FlattenedJwe::from_json(&rfc_flattened_json()).unwrap();
    let plaintext = json::decrypt_flattened_with_jwk(&recipient("ECDH-ES+A128KW"), &jwe).unwrap();
    assert_eq!(String::from_utf8(plaintext).unwrap(), PLAINTEXT);

    // The sender's half travels in the authenticated header, public-only, on the
    // recipient's own curve (RFC 7518 §4.6.1.1).
    let header = json::decode_header(&jwe).unwrap().unwrap();
    let epk = header
        .extra
        .get("epk")
        .expect("epk in the protected header");
    assert_eq!(epk["crv"], "P-384");
    assert_eq!(
        epk["x"],
        serde_json::json!("uBo4kHPw6kbjx5l0xowrd_oYzBmaz-GKFZu4xAFFkbYiWgutEK6iuEDsQ6wNdNg3")
    );
    assert!(epk.get("d").is_none(), "epk must not carry a private part");
}

// ---------------------------------------------------------------------------
// Round trips across the mode's whole shape space
// ---------------------------------------------------------------------------

#[test]
fn every_wrapping_mode_round_trips_on_every_curve_and_content_algorithm() {
    for alg in ["ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW"] {
        for crv in ["P-256", "P-384", "P-521"] {
            let key = generated(crv, alg);
            for enc in [
                JweEncryption::A128GCM,
                JweEncryption::A256GCM,
                JweEncryption::A128CbcHs256,
                JweEncryption::A256CbcHs512,
            ] {
                let token = compact::encrypt_with_jwk(&key, b"agreed then wrapped", enc)
                    .unwrap_or_else(|e| panic!("{alg} on {crv} with {enc:?}: {e}"));
                assert_eq!(
                    compact::decrypt_with_jwk(&key, &token)
                        .unwrap_or_else(|e| panic!("{alg} on {crv} with {enc:?}: {e}")),
                    b"agreed then wrapped"
                );

                let flat =
                    json::encrypt_flattened_with_jwk(&key, b"agreed then wrapped", enc).unwrap();
                assert_eq!(
                    json::decrypt_flattened_with_jwk(&key, &flat).unwrap(),
                    b"agreed then wrapped"
                );
                // Unlike direct agreement, this mode carries a key, and it has to
                // survive serialization to be worth having.
                assert!(
                    flat.encrypted_key.as_deref().is_some_and(|k| !k.is_empty()),
                    "{alg}: the encrypted key must be present"
                );
            }
        }
    }
}

#[test]
fn a_sender_holding_only_the_public_half_can_encrypt() {
    // The reason to use the mode at all: no shared secret to provision.
    for alg in ["ECDH-ES+A128KW", "ECDH-ES+A256KW"] {
        let key = generated("P-256", alg);
        let mut public = key.clone();
        public.d = None;
        let token =
            compact::encrypt_with_jwk(&public, b"public half is enough", JweEncryption::A256GCM)
                .unwrap();
        assert_eq!(
            compact::decrypt_with_jwk(&key, &token).unwrap(),
            b"public half is enough"
        );
    }
}

#[test]
fn the_kek_length_comes_from_the_algorithm_and_the_cek_length_from_enc() {
    // `ECDH-ES+A128KW` with `A256GCM`: a 128-bit agreed KEK wrapping a 256-bit
    // CEK. RFC 3394's output is the wrapped key plus one 64-bit integrity block,
    // so the encrypted key's length reports which length was used for what —
    // 40 octets means the 32-octet CEK came from `enc`, not the 16-octet KEK.
    let key = generated("P-384", "ECDH-ES+A128KW");
    let token = compact::encrypt_with_jwk(&key, b"x", JweEncryption::A256GCM).unwrap();
    let wrapped = jose_rs::base64url::decode(token.split('.').nth(1).unwrap()).unwrap();
    assert_eq!(wrapped.len(), 32 + 8, "the CEK is wrapped, not the KEK");
    assert_eq!(compact::decrypt_with_jwk(&key, &token).unwrap(), b"x");

    // The converse pairing: largest KEK, smallest CEK.
    let key = generated("P-384", "ECDH-ES+A256KW");
    let token = compact::encrypt_with_jwk(&key, b"x", JweEncryption::A128GCM).unwrap();
    let wrapped = jose_rs::base64url::decode(token.split('.').nth(1).unwrap()).unwrap();
    assert_eq!(wrapped.len(), 16 + 8);
    assert_eq!(compact::decrypt_with_jwk(&key, &token).unwrap(), b"x");
}

// ---------------------------------------------------------------------------
// Refusals
// ---------------------------------------------------------------------------

#[test]
fn a_wrapping_message_without_an_encrypted_key_is_refused() {
    // The counterpart of direct agreement's "encrypted key must be empty" rule,
    // and not redundant with it: a recipient that read a missing key as "agree
    // the CEK instead" would accept a message whose key-management mode it had
    // misread.
    let mut value: serde_json::Value = serde_json::from_str(&rfc_flattened_json()).unwrap();
    value["encrypted_key"] = serde_json::json!("");
    let jwe = json::FlattenedJwe::from_json(&value.to_string()).unwrap();
    let err = json::decrypt_flattened_with_jwk(&recipient("ECDH-ES+A128KW"), &jwe).unwrap_err();
    assert!(
        err.to_string().contains("an encrypted key is required"),
        "{err}"
    );
}

#[test]
fn a_sender_key_on_another_curve_is_refused() {
    // The RFC's P-384 message offered to a P-256 recipient. Agreement is only
    // defined within one curve, so this is a refusal, not garbage derivation.
    let key = generated("P-256", "ECDH-ES+A128KW");
    let jwe = json::FlattenedJwe::from_json(&rfc_flattened_json()).unwrap();
    let err = json::decrypt_flattened_with_jwk(&key, &jwe).unwrap_err();
    assert!(err.to_string().contains("curve"), "{err}");
}

#[test]
fn a_tampered_epk_fails_authentication() {
    // Swapping the sender's half changes the derived KEK, so the unwrap yields
    // something wrong and the content tag refuses it. The message is malleable in
    // that way for anyone; what it cannot do is leak or forge.
    let key = recipient("ECDH-ES+A128KW");
    let other = generated("P-384", "ECDH-ES+A128KW");
    let token =
        compact::encrypt_with_jwk(&key, b"authenticated content", JweEncryption::A128GCM).unwrap();
    let mut parts: Vec<String> = token.split('.').map(str::to_string).collect();
    parts[0] = {
        // Replace epk with a different, valid, public P-384 key — and keep `enc`,
        // so the only change is which sender key the recipient derives with.
        let mut header: serde_json::Value = serde_json::from_slice(
            &jose_rs::base64url::decode(token.split('.').next().unwrap()).unwrap(),
        )
        .unwrap();
        let replacement =
            epk_of(&compact::encrypt_with_jwk(&other, b"x", JweEncryption::A128GCM).unwrap());
        header["epk"] = replacement;
        jose_rs::base64url::encode(&serde_json::to_vec(&header).unwrap())
    };
    let swapped = parts.join(".");
    assert_ne!(swapped, token);
    assert!(
        compact::decrypt_with_jwk(&key, &swapped).is_err(),
        "a swapped epk must not decrypt"
    );
}

#[test]
fn the_ephemeral_key_is_generated_public_and_fresh() {
    let key = generated("P-256", "ECDH-ES+A192KW");
    let first = compact::encrypt_with_jwk(&key, b"x", JweEncryption::A128GCM).unwrap();
    let second = compact::encrypt_with_jwk(&key, b"x", JweEncryption::A128GCM).unwrap();
    let (a, b) = (epk_of(&first), epk_of(&second));
    assert_ne!(a["x"], b["x"], "one ephemeral key per operation");
    assert_eq!(a["crv"], "P-256");
    assert_eq!(
        a.as_object().unwrap().keys().collect::<Vec<_>>(),
        vec!["crv", "kty", "x", "y"],
        "epk carries nothing but the public key"
    );

    // And a caller cannot supply one: generating it is this crate's job.
    let mut header = JoseHeader::for_jwe(JweAlgorithm::EcdhEsA192kw, JweEncryption::A128GCM);
    header.extra.insert(
        "epk".into(),
        serde_json::json!({"kty": "EC", "crv": "P-256", "x": "AAAA", "y": "BBBB"}),
    );
    let err = compact::encrypt_with_jwk_header(&key, header, b"x", JweEncryption::A128GCM)
        .unwrap_err()
        .to_string();
    assert!(err.contains("epk"), "{err}");
}

#[test]
fn party_values_travel_authenticated_and_are_validated() {
    // `apu`/`apv` are Concat KDF inputs here too, so they belong in the protected
    // header — which makes them AAD as well as derivation material.
    let key = generated("P-256", "ECDH-ES+A256KW");
    let mut header = JoseHeader::for_jwe(JweAlgorithm::EcdhEsA256kw, JweEncryption::A128GCM);
    header
        .extra
        .insert("apu".into(), serde_json::json!("QWxpY2U"));
    header.extra.insert("apv".into(), serde_json::json!("Qm9i"));
    let token =
        compact::encrypt_with_jwk_header(&key, header, b"party info", JweEncryption::A128GCM)
            .unwrap();
    let bytes = jose_rs::base64url::decode(token.split('.').next().unwrap()).unwrap();
    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(value["apu"], "QWxpY2U");
    assert_eq!(value["apv"], "Qm9i");
    assert_eq!(
        compact::decrypt_with_jwk(&key, &token).unwrap(),
        b"party info"
    );

    // Equal party values, and non-base64url ones, are refused before any work.
    for (apu, apv) in [("QWxpY2U", "QWxpY2U"), ("not base64!!", "Qm9i")] {
        let mut header = JoseHeader::for_jwe(JweAlgorithm::EcdhEsA256kw, JweEncryption::A128GCM);
        header.extra.insert("apu".into(), serde_json::json!(apu));
        header.extra.insert("apv".into(), serde_json::json!(apv));
        assert!(
            compact::encrypt_with_jwk_header(&key, header, b"x", JweEncryption::A128GCM).is_err(),
            "{apu}/{apv} must not be accepted"
        );
    }
}

#[test]
fn several_recipients_are_refused_with_the_reason() {
    // This is the mode that *can* carry one CEK to several recipients, but each
    // recipient needs its own `epk`, and RFC 7516 gives a recipient element no
    // protected header of its own to carry it in. Refused until that trade-off is
    // decided (ADR 0018) — and the message has to name that reason rather than
    // shrugging.
    let a = generated("P-256", "ECDH-ES+A128KW");
    let b = generated("P-256", "ECDH-ES+A128KW");
    let header = JoseHeader::for_jwe(JweAlgorithm::EcdhEsA128kw, JweEncryption::A128GCM);
    let err = general::encrypt_general_with_jwks(
        &header,
        &[&a, &b],
        b"two recipients",
        JweEncryption::A128GCM,
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("epk"), "{err}");
    assert!(err.contains("protected"), "{err}");
    assert!(
        !err.contains("not implemented by this crate"),
        "the refusal must be specific: {err}"
    );
}

#[test]
fn the_raw_key_apis_cannot_reach_a_wrapping_mode() {
    // The same structural wall as direct agreement: bytes cannot name a curve,
    // and the peer value comes from the message's `epk`.
    let err = compact::encrypt(
        &[0u8; 32],
        b"x",
        JweAlgorithm::EcdhEsA128kw,
        JweEncryption::A128GCM,
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("requires a JWK"), "{err}");
}
