//! Inclusive plaintext limits across every supported content-encryption mode.

use jose_rs::{base64url, jwe, jwk, JoseError, JweAlgorithm, JweEncryption};

const ENCRYPTIONS: [JweEncryption; 6] = [
    JweEncryption::A128GCM,
    JweEncryption::A192GCM,
    JweEncryption::A256GCM,
    JweEncryption::A128CbcHs256,
    JweEncryption::A192CbcHs384,
    JweEncryption::A256CbcHs512,
];

fn key(len: usize) -> Vec<u8> {
    base64url::decode(jwk::generate_symmetric(len).unwrap().k.as_deref().unwrap()).unwrap()
}

fn is_size_error(result: Result<Vec<u8>, JoseError>) {
    assert!(matches!(result, Err(JoseError::InvalidToken(ref message))
        if message == "plaintext exceeds configured maximum size"));
}

#[test]
fn inclusive_limits_cover_empty_plaintext_and_padding_boundaries() {
    for enc in ENCRYPTIONS {
        let key = key(enc.cek_size());
        for len in [0, 1, 2, 3, 15, 16, 17, 31, 32, 33] {
            let plaintext = vec![42; len];
            let token = jwe::encrypt(&key, &plaintext, JweAlgorithm::Dir, enc).unwrap();
            let options = jwe::JweDecryptOptions::new(vec![JweAlgorithm::Dir], vec![enc]);
            for limit in [len, len + 1, usize::MAX] {
                assert_eq!(
                    jwe::decrypt_with_options(
                        &key,
                        &token,
                        &options.clone().with_max_plaintext(limit)
                    )
                    .unwrap(),
                    plaintext,
                );
            }
            if len > 0 {
                is_size_error(jwe::decrypt_with_options(
                    &key,
                    &token,
                    &options.with_max_plaintext(len - 1),
                ));
            }
        }
    }
}

#[test]
fn preflight_rejects_obviously_oversized_input_before_key_use() {
    for enc in ENCRYPTIONS {
        let token = jwe::encrypt(&key(enc.cek_size()), &[0; 48], JweAlgorithm::Dir, enc).unwrap();
        // Invalid key proves this check runs before key recovery/decryption.
        is_size_error(jwe::decrypt_with_options(
            &[],
            &token,
            &jwe::JweDecryptOptions::permissive().with_max_plaintext(1),
        ));
    }
}

#[test]
fn authentication_is_still_required_at_and_below_limit() {
    for enc in ENCRYPTIONS {
        let key = key(enc.cek_size());
        let token = jwe::encrypt(&key, b"message", JweAlgorithm::Dir, enc).unwrap();
        let mut parts: Vec<String> = token.split('.').map(str::to_owned).collect();
        let mut tag = base64url::decode(&parts[4]).unwrap();
        tag[0] ^= 1;
        parts[4] = base64url::encode(&tag);
        for limit in [7, 8] {
            assert!(jwe::decrypt_with_options(
                &key,
                &parts.join("."),
                &jwe::JweDecryptOptions::permissive().with_max_plaintext(limit)
            )
            .is_err());
        }
        if matches!(
            enc,
            JweEncryption::A128CbcHs256 | JweEncryption::A192CbcHs384 | JweEncryption::A256CbcHs512
        ) {
            // The 16-byte ciphertext passes preflight for limit 6, but its
            // seven-byte plaintext would fail the exact check. Authentication
            // must fail first for this altered tag.
            assert!(matches!(
                jwe::decrypt_with_options(
                    &key,
                    &parts.join("."),
                    &jwe::JweDecryptOptions::permissive().with_max_plaintext(6)
                ),
                Err(JoseError::Crypto(_))
            ));
        }
    }
}

#[test]
fn default_permissive_and_algorithm_policies_are_preserved() {
    let key = key(32);
    let token = jwe::encrypt(&key, b"message", JweAlgorithm::Dir, JweEncryption::A256GCM).unwrap();
    assert_eq!(jwe::decrypt(&key, &token).unwrap(), b"message");
    assert_eq!(
        jwe::decrypt_with_options(&key, &token, &jwe::JweDecryptOptions::permissive()).unwrap(),
        b"message"
    );
    for options in [
        jwe::JweDecryptOptions::default(),
        jwe::JweDecryptOptions::new(vec![JweAlgorithm::A128KW], vec![JweEncryption::A256GCM]),
        jwe::JweDecryptOptions::new(vec![JweAlgorithm::Dir], vec![JweEncryption::A128GCM]),
    ] {
        assert!(matches!(
            jwe::decrypt_with_options(&key, &token, &options.with_max_plaintext(0)),
            Err(JoseError::UnsupportedAlgorithm(_))
        ));
    }
}

#[test]
fn limit_applies_to_wrapped_keys_too() {
    let key = key(16);
    for enc in ENCRYPTIONS {
        let token = jwe::encrypt(&key, b"wrapped payload", JweAlgorithm::A128KW, enc).unwrap();
        let options = jwe::JweDecryptOptions::new(vec![JweAlgorithm::A128KW], vec![enc]);
        assert_eq!(
            jwe::decrypt_with_options(&key, &token, &options.clone().with_max_plaintext(15))
                .unwrap(),
            b"wrapped payload"
        );
        is_size_error(jwe::decrypt_with_options(
            &key,
            &token,
            &options.with_max_plaintext(14),
        ));
    }
}

#[test]
fn token_size_and_encoding_checks_are_not_disabled() {
    let options = jwe::JweDecryptOptions::permissive().with_max_plaintext(usize::MAX);
    assert!(
        jwe::decrypt_with_options(&[], &"a".repeat(jose_rs::MAX_TOKEN_BYTES + 1), &options)
            .is_err()
    );
    let key = key(32);
    let token = jwe::encrypt(&key, b"message", JweAlgorithm::Dir, JweEncryption::A256GCM).unwrap();
    let mut parts: Vec<&str> = token.split('.').collect();
    for invalid in ["A", "AA=", "++", "AB"] {
        parts[3] = invalid;
        assert!(jwe::decrypt_with_options(&key, &parts.join("."), &options).is_err());
    }
}

#[test]
fn nested_jwt_limit_counts_the_complete_inner_signed_token() {
    use jose_rs::{jwt, JoseHeader, JwsAlgorithm};
    let signing = jwk::generate_symmetric_for_alg("HS256").unwrap();
    let inner =
        jwt::encode_with_jwk(&signing, &JoseHeader::jwt("HS256"), &jwt::Claims::default()).unwrap();
    let verifier = kryptering::SoftwareVerifier::new(
        JwsAlgorithm::HS256.to_crypto().unwrap(),
        jwk::jwk_to_signature_key(&signing, JwsAlgorithm::HS256, jwk::JwkOp::Verify).unwrap(),
    )
    .unwrap();
    let key = key(32);
    let outer = jwe::encrypt(
        &key,
        inner.as_bytes(),
        JweAlgorithm::Dir,
        JweEncryption::A256GCM,
    )
    .unwrap();
    let options =
        jwe::JweDecryptOptions::new(vec![JweAlgorithm::Dir], vec![JweEncryption::A256GCM]);
    jwt::decode_nested_with_options(
        &key,
        &verifier,
        &outer,
        &jwt::Validation::new(),
        &options.clone().with_max_plaintext(inner.len()),
    )
    .unwrap();
    assert!(matches!(
        jwt::decode_nested_with_options(
            &key,
            &verifier,
            &outer,
            &jwt::Validation::new(),
            &options.with_max_plaintext(inner.len() - 1)
        ),
        Err(JoseError::InvalidToken(_))
    ));
}
