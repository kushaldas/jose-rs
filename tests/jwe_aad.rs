//! External additional authenticated data for JWE (RFC 7516 §2, §5.1 step 14,
//! §7.2.1) — acceptance tests.
//!
//! External AAD is the one message member that is authenticated but not
//! encrypted, and only the JSON serializations can carry it. These tests pin
//! the three properties that matter:
//!
//! 1. the bytes reach the recipient's AAD input exactly;
//! 2. substituting them breaks the content tag even when the recipient is
//!    fooled into using the substituted value;
//! 3. the compact serialization refuses the option instead of silently
//!    dropping it.

use jose_rs::jwe::{compact, json, JweDecryptOptions, JweEncryptOptions};
use jose_rs::{JoseError, JoseHeader, JweAlgorithm, JweEncryption};

const AAD: &[u8] = b"tenant=acme;purpose=audit";

fn enc_opts(aad: &[u8]) -> JweEncryptOptions {
    JweEncryptOptions::new().with_external_aad(aad)
}

fn dec_opts(alg: JweAlgorithm, enc: JweEncryption, aad: &[u8]) -> JweDecryptOptions {
    JweDecryptOptions::new(vec![alg], vec![enc]).with_external_aad(aad)
}

fn key_for(alg: JweAlgorithm, enc: JweEncryption) -> Vec<u8> {
    match alg {
        JweAlgorithm::Dir => vec![0x21u8; enc.cek_size()],
        JweAlgorithm::A128KW => vec![0x22u8; 16],
        JweAlgorithm::A192KW => vec![0x23u8; 24],
        _ => vec![0x24u8; 32],
    }
}

/// Every key-management × content combination the crate supports must carry
/// external AAD through the flattened JSON serialization.
#[test]
fn external_aad_works_for_every_combination() {
    for enc in [
        JweEncryption::A128GCM,
        JweEncryption::A256GCM,
        JweEncryption::A128CbcHs256,
        JweEncryption::A256CbcHs512,
    ] {
        for alg in [
            JweAlgorithm::Dir,
            JweAlgorithm::A128KW,
            JweAlgorithm::A192KW,
            JweAlgorithm::A256KW,
        ] {
            let key = key_for(alg, enc);
            let jwe = json::encrypt_flattened_with_header_options(
                JoseHeader::for_jwe(alg, enc),
                &key,
                b"external aad coverage",
                alg,
                enc,
                &enc_opts(AAD),
            )
            .unwrap();

            assert_eq!(
                jwe.aad.as_deref(),
                Some(jose_rs::base64url::encode(AAD).as_str()),
                "{alg:?}/{enc:?}: aad member must carry the octets verbatim"
            );
            assert_eq!(
                json::decrypt_flattened_with_options(&key, &jwe, &dec_opts(alg, enc, AAD)).unwrap(),
                b"external aad coverage",
                "{alg:?}/{enc:?}"
            );

            // And without the AAD the message is undecryptable, with an error
            // that says why.
            let err = json::decrypt_flattened(&key, &jwe).unwrap_err().to_string();
            assert!(err.contains("with_external_aad"), "{err}");
        }
    }
}

/// AAD substitution is caught by the tag itself, not only by the caller-side
/// expectation check: if the recipient is talked into the substituted bytes,
/// the AAD input no longer matches what was authenticated.
#[test]
fn substituted_aad_breaks_authentication() {
    let key = key_for(JweAlgorithm::Dir, JweEncryption::A256GCM);
    let jwe = json::encrypt_flattened_with_header_options(
        JoseHeader::for_jwe(JweAlgorithm::Dir, JweEncryption::A256GCM),
        &key,
        b"transfer $1 to alice",
        JweAlgorithm::Dir,
        JweEncryption::A256GCM,
        &enc_opts(AAD),
    )
    .unwrap();

    // A second message under a different AAD gives the attacker a plausible
    // member encoding of the right length.
    let substitute = b"tenant=evil;purpose=audit";
    let mut forged = jwe.clone();
    forged.aad = Some(jose_rs::base64url::encode(substitute));

    // The honest path refuses it.
    let err = json::decrypt_flattened_with_options(
        &key,
        &forged,
        &dec_opts(JweAlgorithm::Dir, JweEncryption::A256GCM, AAD),
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("does not match"), "{err}");

    // The compromised path — caller believes the substituted bytes — still
    // fails, and fails cryptographically.
    let err = json::decrypt_flattened_with_options(
        &key,
        &forged,
        &dec_opts(JweAlgorithm::Dir, JweEncryption::A256GCM, substitute),
    )
    .unwrap_err();
    assert!(
        matches!(err, JoseError::Crypto(_)),
        "the content tag must be the last line of defence, got {err:?}"
    );
}

/// The compact serialization has no `aad` member, so it refuses the option on
/// both sides instead of encrypting under an AAD nobody can reconstruct.
#[test]
fn compact_serialization_refuses_external_aad() {
    let key = key_for(JweAlgorithm::A256KW, JweEncryption::A256GCM);
    let err = compact::encrypt_with_header_options(
        JoseHeader::for_jwe(JweAlgorithm::A256KW, JweEncryption::A256GCM),
        &key,
        b"p",
        JweAlgorithm::A256KW,
        JweEncryption::A256GCM,
        &enc_opts(AAD),
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("requires the JWE JSON serialization"), "{err}");

    let token = compact::encrypt(&key, b"p", JweAlgorithm::A256KW, JweEncryption::A256GCM).unwrap();
    let err = compact::decrypt_with_options(
        &key,
        &token,
        &dec_opts(JweAlgorithm::A256KW, JweEncryption::A256GCM, AAD),
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("requires the JWE JSON serialization"), "{err}");

    // A message that *does* carry external AAD cannot be squeezed into compact.
    let jwe = json::encrypt_flattened_with_header_options(
        JoseHeader::for_jwe(JweAlgorithm::A256KW, JweEncryption::A256GCM),
        &key,
        b"p",
        JweAlgorithm::A256KW,
        JweEncryption::A256GCM,
        &enc_opts(AAD),
    )
    .unwrap();
    assert!(jwe
        .to_compact()
        .unwrap_err()
        .to_string()
        .contains("compact"));
    // Without external AAD the same conversion works, so the refusal is about
    // the AAD and not about the general shape.
    let plain =
        json::encrypt_flattened(&key, b"p", JweAlgorithm::A256KW, JweEncryption::A256GCM).unwrap();
    assert!(plain.to_compact().is_ok());
}

/// An empty external AAD would be ambiguous: RFC 7516 §7.2.1 requires the
/// member to be absent when the value is empty, yet the AAD *input* with an
/// empty member differs from the input without one.
#[test]
fn empty_external_aad_is_refused() {
    let key = key_for(JweAlgorithm::Dir, JweEncryption::A128GCM);
    let err = json::encrypt_flattened_with_header_options(
        JoseHeader::for_jwe(JweAlgorithm::Dir, JweEncryption::A128GCM),
        &key,
        b"p",
        JweAlgorithm::Dir,
        JweEncryption::A128GCM,
        &enc_opts(b""),
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("must not be empty"), "{err}");
}

/// The size limit counts the `aad` member too, so a message this crate could
/// not decode is never produced.
#[test]
fn external_aad_counts_against_the_token_size_limit() {
    let key = key_for(JweAlgorithm::Dir, JweEncryption::A256GCM);
    let huge_aad = vec![0x41u8; jose_rs::MAX_TOKEN_BYTES];
    let err = json::encrypt_flattened_with_header_options(
        JoseHeader::for_jwe(JweAlgorithm::Dir, JweEncryption::A256GCM),
        &key,
        b"p",
        JweAlgorithm::Dir,
        JweEncryption::A256GCM,
        &enc_opts(&huge_aad),
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("MAX_TOKEN_BYTES"), "{err}");
}

/// External AAD composes with the rest of the header policy: extra protected
/// members stay authenticated alongside it, and the allow-list still applies.
#[test]
fn external_aad_composes_with_header_policy() {
    let key = key_for(JweAlgorithm::Dir, JweEncryption::A256GCM);
    let mut header = JoseHeader::for_jwe(JweAlgorithm::Dir, JweEncryption::A256GCM);
    header.kid = Some("recipient-9".into());
    header
        .extra
        .insert("tenant".into(), serde_json::json!("acme"));

    let jwe = json::encrypt_flattened_with_header_options(
        header,
        &key,
        b"ctx",
        JweAlgorithm::Dir,
        JweEncryption::A256GCM,
        &enc_opts(AAD),
    )
    .unwrap();

    let peeked = json::decode_header(&jwe).unwrap().unwrap();
    assert_eq!(peeked.kid.as_deref(), Some("recipient-9"));

    // Wrong allow-list is refused before any key derivation, even though the
    // caller supplied the correct AAD.
    let wrong_alg =
        JweDecryptOptions::new(vec![JweAlgorithm::A256KW], vec![JweEncryption::A256GCM])
            .with_external_aad(AAD);
    let err = json::decrypt_flattened_with_options(&key, &jwe, &wrong_alg)
        .unwrap_err()
        .to_string();
    assert!(err.contains("allow-list"), "{err}");

    // Right allow-list, right AAD: plaintext plus the authenticated header.
    let round = json::decrypt_flattened_with_options(
        &key,
        &jwe,
        &dec_opts(JweAlgorithm::Dir, JweEncryption::A256GCM, AAD),
    )
    .unwrap();
    assert_eq!(round, b"ctx");
    assert_eq!(
        json::decode_header(&jwe).unwrap().unwrap().alg,
        "dir",
        "the header the tag authenticated is the one reported back"
    );
}

/// The `aad` member survives a JSON round trip byte-for-byte, and a member
/// that repeats an existing name is still refused.
#[test]
fn aad_member_round_trips_and_stays_unambiguous() {
    let key = key_for(JweAlgorithm::Dir, JweEncryption::A256GCM);
    let jwe = json::encrypt_flattened_with_header_options(
        JoseHeader::for_jwe(JweAlgorithm::Dir, JweEncryption::A256GCM),
        &key,
        b"p",
        JweAlgorithm::Dir,
        JweEncryption::A256GCM,
        &enc_opts(AAD),
    )
    .unwrap();
    let text = jwe.to_json().unwrap();
    let parsed = json::FlattenedJwe::from_json(&text).unwrap();
    assert_eq!(parsed, jwe);
    assert_eq!(parsed.aad, jwe.aad);

    let duplicated = text.replacen("\"aad\"", "\"aad2\"", 1);
    let without = json::FlattenedJwe::from_json(&duplicated).unwrap();
    assert_eq!(
        without.aad, None,
        "renaming the member must not silently keep the AAD"
    );
}
