//! Critical (`crit`) header extensions in JWE — RFC 7516 §4.1.13, which adopts
//! RFC 7515 §4.1.11.
//!
//! `crit` is the mechanism by which a sender says "if you cannot *process* this
//! extension, do not accept the message". A library that ignores it turns a
//! refusal into a silent success, so this crate's default is to refuse any
//! message carrying it. This module opens exactly one controlled exception: the
//! caller, who is the only party that knows which extensions its own code
//! processes, lists them (`with_understood_crit`) — and the library then checks
//! the structural rules that make the marker mean something, on both the emit
//! and the receive side.
//!
//! What jose-rs never does is *act* on an extension. It checks that a listed
//! parameter exists, that it is integrity protected, and that the caller claims
//! to understand it; the value is handed over in
//! [`JoseHeader::extra`](jose_rs::JoseHeader::extra) for the caller to interpret.

use jose_rs::jwe::general::{self, RecipientSpec};
use jose_rs::jwe::{compact, json, JweDecryptOptions, JweEncryptOptions};
use jose_rs::{JoseHeader, JweAlgorithm, JweEncryption};

const EXT: &str = "etsiU";

fn enc_opts(crit: &[&str]) -> JweEncryptOptions {
    let opts = JweEncryptOptions::new();
    if crit.is_empty() {
        opts
    } else {
        opts.with_understood_crit(crit.iter().copied())
    }
}

fn dec_opts(alg: JweAlgorithm, enc: JweEncryption, crit: &[&str]) -> JweDecryptOptions {
    let opts = JweDecryptOptions::new(vec![alg], vec![enc]);
    if crit.is_empty() {
        opts
    } else {
        opts.with_understood_crit(crit.iter().copied())
    }
}

/// A header that actually uses the extension: `crit` names it, and the
/// parameter itself is present (RFC 7515 §4.1.11 forbids listing a name that
/// does not occur in the header).
fn header_with_extension(crit: &[&str], value: Option<&str>) -> JoseHeader {
    let mut header = JoseHeader::for_jwe(JweAlgorithm::A128KW, JweEncryption::A128GCM);
    if !crit.is_empty() {
        header.crit = Some(crit.iter().map(|name| (*name).to_string()).collect());
    }
    if let Some(value) = value {
        header
            .extra
            .insert(EXT.to_string(), serde_json::json!(value));
    }
    header
}

fn kek() -> Vec<u8> {
    vec![0x37u8; 16]
}

/// Compact encryption, wrapping the by-value header the compact API takes.
fn encrypt_compact(header: &JoseHeader, opts: &JweEncryptOptions, plaintext: &[u8]) -> String {
    compact::encrypt_with_header_options(
        header.clone(),
        &kek(),
        plaintext,
        JweAlgorithm::A128KW,
        JweEncryption::A128GCM,
        opts,
    )
    .unwrap()
}

/// The same, refusing (and returning the error text).
fn encrypt_compact_err(header: &JoseHeader, opts: &JweEncryptOptions) -> String {
    compact::encrypt_with_header_options(
        header.clone(),
        &kek(),
        b"x",
        JweAlgorithm::A128KW,
        JweEncryption::A128GCM,
        opts,
    )
    .unwrap_err()
    .to_string()
}

#[test]
fn an_understood_extension_round_trips_through_every_serialization() {
    let header = header_with_extension(&[EXT], Some("policy-42"));

    // Compact.
    let token = encrypt_compact(&header, &enc_opts(&[EXT]), b"critical payload");
    let peeked = compact::decode_header(&token).unwrap();
    assert_eq!(peeked.crit.as_deref(), Some(&[EXT.to_string()][..]));
    let decrypted = compact::decrypt_with_options(
        &kek(),
        &token,
        &dec_opts(JweAlgorithm::A128KW, JweEncryption::A128GCM, &[EXT]),
    )
    .unwrap();
    assert_eq!(decrypted, b"critical payload");

    // Flattened JSON, and the same message read back as compact.
    let flattened = json::encrypt_flattened_with_header_options(
        header.clone(),
        &kek(),
        b"critical payload",
        JweAlgorithm::A128KW,
        JweEncryption::A128GCM,
        &enc_opts(&[EXT]),
    )
    .unwrap();
    assert_eq!(
        json::decrypt_flattened_with_options(
            &kek(),
            &flattened,
            &dec_opts(JweAlgorithm::A128KW, JweEncryption::A128GCM, &[EXT]),
        )
        .unwrap(),
        b"critical payload"
    );
    // `crit` lives in the protected header, so the two serializations differ
    // only in framing: the AAD input — the encoded protected header — is
    // identical, which is the RFC 7516 §7.2.1 equivalence. The tokens
    // themselves differ, being separate CEKs and IVs.
    let as_compact = flattened.to_compact().unwrap();
    assert_eq!(
        as_compact.split('.').next().unwrap(),
        token.split('.').next().unwrap(),
        "the crit extension must reach the AAD input identically"
    );
    assert_eq!(
        compact::decrypt_with_options(
            &kek(),
            &as_compact,
            &dec_opts(JweAlgorithm::A128KW, JweEncryption::A128GCM, &[EXT]),
        )
        .unwrap(),
        b"critical payload"
    );

    // General syntax: the extension is shared, so it belongs in the protected
    // header and every recipient authenticates it.
    let message = general::encrypt_general_options(
        &header,
        &[RecipientSpec::new(&kek())],
        b"critical payload",
        JweAlgorithm::A128KW,
        JweEncryption::A128GCM,
        &enc_opts(&[EXT]),
    )
    .unwrap();
    // The general path shares the flattened policy, so the same opt-in is what
    // lets a recipient read the extension — and its absence still refuses.
    let key = jose_key();
    assert_eq!(
        general::decrypt_general_with_jwk_options(
            &key,
            &message,
            0,
            &dec_opts(JweAlgorithm::A128KW, JweEncryption::A128GCM, &[EXT]),
        )
        .unwrap(),
        b"critical payload"
    );
    let err = general::decrypt_general_with_jwk(&key, &message, 0)
        .unwrap_err()
        .to_string();
    assert!(err.contains("unsupported crit extension"), "{err}");
}

#[test]
fn the_extension_value_reaches_the_caller_verbatim() {
    // The library checks structure and hands the value over; interpreting it is
    // the caller's job, and nothing here invents a meaning for it.
    let header = header_with_extension(&[EXT], Some("policy-42"));
    let token = encrypt_compact(&header, &enc_opts(&[EXT]), b"x");
    let peeked = compact::decode_header(&token).unwrap();
    assert_eq!(peeked.extra.get(EXT), Some(&serde_json::json!("policy-42")));
}

#[test]
fn an_unlisted_extension_is_refused_on_both_sides() {
    // Emit: the caller has not declared `etsiU`, so `crit` naming it is refused
    // before anything is encrypted.
    let header = header_with_extension(&[EXT], Some("policy-42"));
    let err = encrypt_compact_err(&header, &enc_opts(&[]));
    assert!(err.contains("unsupported crit extension: etsiU"), "{err}");

    // Receive: the same message, built by hand, against default options.
    let accepted = encrypt_compact(&header, &enc_opts(&[EXT]), b"x");
    let err = compact::decrypt(&kek(), &accepted).unwrap_err().to_string();
    assert!(err.contains("unsupported crit extension"), "{err}");

    // Understanding *some* extension does not licence another one.
    let err = compact::decrypt_with_options(
        &kek(),
        &accepted,
        &dec_opts(JweAlgorithm::A128KW, JweEncryption::A128GCM, &["otherExt"]),
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("unsupported crit extension: etsiU"), "{err}");
}

#[test]
fn crit_must_name_a_real_private_extension() {
    // A registered parameter is not an extension: listing it says nothing the
    // recipient did not already have to do (RFC 7515 §4.1.11).
    for name in ["enc", "alg", "kid", "zip", "crit", "epk", "b64"] {
        let mut header = JoseHeader::for_jwe(JweAlgorithm::A128KW, JweEncryption::A128GCM);
        header.crit = Some(vec![name.to_string()]);
        header.extra.insert(EXT.to_string(), serde_json::json!("v"));
        let err = encrypt_compact_err(&header, &enc_opts(&[name]));
        assert!(
            err.contains("registered header parameter")
                || err.contains("unsupported JWE header member"),
            "{name}: {err}"
        );
    }

    // Listing a name that is not in the header at all.
    let absent = header_with_extension(&[EXT], None);
    let err = encrypt_compact_err(&absent, &enc_opts(&[EXT]));
    assert!(err.contains("absent from the protected header"), "{err}");

    // The empty list is invalid (RFC 7515 §4.1.11).
    let mut empty = header_with_extension(&[EXT], Some("v"));
    empty.crit = Some(vec![]);
    let err = encrypt_compact_err(&empty, &enc_opts(&[EXT]));
    assert!(err.contains("must not be empty"), "{err}");

    // Duplicate names are refused rather than quietly deduplicated.
    let mut duplicated = header_with_extension(&[EXT], Some("v"));
    duplicated.crit = Some(vec![EXT.to_string(), EXT.to_string()]);
    let err = encrypt_compact_err(&duplicated, &enc_opts(&[EXT]));
    assert!(err.contains("more than once"), "{err}");
}

#[test]
fn criticality_cannot_be_claimed_by_unauthenticated_bytes() {
    // The JSON serialization has unprotected header locations. `crit` itself is
    // refused there (ADR 0013), and so is a parameter whose criticality the
    // protected header asserts: an attacker who could add `etsiU` unprotected
    // could satisfy a check the sender never made.
    let protected = jose_rs::base64url::encode(
        &serde_json::to_vec(&serde_json::json!({
            "alg": "A128KW",
            "enc": "A128GCM",
            "crit": [EXT],
        }))
        .unwrap(),
    );
    let message = serde_json::json!({
        "protected": protected,
        "unprotected": { EXT: "injected" },
        "encrypted_key": jose_rs::base64url::encode(&[0u8; 24]),
        "iv": jose_rs::base64url::encode(&[0u8; 12]),
        "ciphertext": jose_rs::base64url::encode(b"whatever"),
        "tag": jose_rs::base64url::encode(&[0u8; 16]),
    })
    .to_string();

    let jwe = json::FlattenedJwe::from_json(&message).unwrap();
    let err = json::decrypt_flattened_with_options(
        &kek(),
        &jwe,
        &dec_opts(JweAlgorithm::A128KW, JweEncryption::A128GCM, &[EXT]),
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("absent from the protected header"), "{err}");

    // And `crit` itself may not be moved out of the protected header at all.
    let moved = serde_json::json!({
        "protected": jose_rs::base64url::encode(
            &serde_json::to_vec(&serde_json::json!({"alg":"A128KW","enc":"A128GCM"})).unwrap()
        ),
        "unprotected": { "crit": [EXT], EXT: "injected" },
        "encrypted_key": jose_rs::base64url::encode(&[0u8; 24]),
        "iv": jose_rs::base64url::encode(&[0u8; 12]),
        "ciphertext": jose_rs::base64url::encode(b"whatever"),
        "tag": jose_rs::base64url::encode(&[0u8; 16]),
    })
    .to_string();
    let err = json::FlattenedJwe::from_json(&moved)
        .unwrap_err()
        .to_string();
    assert!(err.contains("integrity protected"), "{err}");
}

#[test]
fn two_understood_extensions_are_both_checked() {
    let mut header = JoseHeader::for_jwe(JweAlgorithm::A128KW, JweEncryption::A128GCM);
    header.crit = Some(vec![EXT.to_string(), "secondExt".to_string()]);
    header.extra.insert(EXT.to_string(), serde_json::json!("a"));
    header
        .extra
        .insert("secondExt".to_string(), serde_json::json!(7));

    // Understanding one of two is not understanding both.
    let err = encrypt_compact_err(&header, &enc_opts(&[EXT]));
    assert!(
        err.contains("unsupported crit extension: secondExt"),
        "{err}"
    );

    let token = encrypt_compact(&header, &enc_opts(&[EXT, "secondExt"]), b"two extensions");
    assert_eq!(
        compact::decrypt_with_options(
            &kek(),
            &token,
            &dec_opts(
                JweAlgorithm::A128KW,
                JweEncryption::A128GCM,
                &[EXT, "secondExt"]
            ),
        )
        .unwrap(),
        b"two extensions"
    );
}

fn jose_key() -> jose_rs::jwk::Jwk {
    serde_json::from_value(serde_json::json!({
        "kty": "oct",
        "k": jose_rs::base64url::encode(&kek()),
        "alg": "A128KW",
        "kid": "crit-key",
    }))
    .unwrap()
}
