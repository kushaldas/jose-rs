//! Public header-encryption APIs preserve authentication and key policy.

use jose_rs::{base64url, jwe, jwk, JoseError, JoseHeader, JweAlgorithm, JweEncryption};

#[test]
fn custom_headers_are_authenticated_for_all_content_algorithms() {
    for enc in [
        JweEncryption::A128GCM,
        JweEncryption::A192GCM,
        JweEncryption::A256GCM,
        JweEncryption::A128CbcHs256,
        JweEncryption::A192CbcHs384,
        JweEncryption::A256CbcHs512,
    ] {
        let mut key = jwk::generate_symmetric(enc.cek_size()).unwrap();
        key.alg = Some("dir".into());
        let raw = base64url::decode(key.k.as_deref().unwrap()).unwrap();
        let mut header = JoseHeader::for_jwe(JweAlgorithm::Dir, enc);
        header.kid = Some("recipient".into());
        header.typ = Some("application/example".into());
        header.extra.insert("tenant".into(), "one".into());

        for token in [
            jwe::encrypt_with_header(header.clone(), &raw, b"payload", JweAlgorithm::Dir, enc)
                .unwrap(),
            jwe::encrypt_with_jwk_header(&key, header.clone(), b"payload", enc).unwrap(),
        ] {
            let decoded = jwe::compact::decode_header(&token).unwrap();
            assert_eq!(decoded.kid, header.kid);
            assert_eq!(decoded.typ, header.typ);
            assert_eq!(decoded.extra, header.extra);
            assert_eq!(jwe::decrypt_with_jwk(&key, &token).unwrap(), b"payload");

            let mut segments: Vec<String> = token.split('.').map(str::to_owned).collect();
            let mut altered = decoded;
            altered.extra.insert("tenant".into(), "two".into());
            segments[0] = base64url::encode(&serde_json::to_vec(&altered).unwrap());
            assert!(jwe::decrypt_with_jwk(&key, &segments.join(".")).is_err());
        }
    }
}

#[test]
fn header_algorithms_must_agree_with_caller_and_jwk() {
    let enc = JweEncryption::A128GCM;
    let mut key = jwk::generate_symmetric(16).unwrap();
    key.alg = Some("dir".into());
    let raw = base64url::decode(key.k.as_deref().unwrap()).unwrap();
    for header in [
        JoseHeader::for_jwe(JweAlgorithm::A128KW, enc),
        JoseHeader::for_jwe(JweAlgorithm::Dir, JweEncryption::A256GCM),
    ] {
        assert!(matches!(
            jwe::encrypt_with_header(header.clone(), &raw, b"payload", JweAlgorithm::Dir, enc),
            Err(JoseError::InvalidHeader(_))
        ));
        assert!(matches!(
            jwe::encrypt_with_jwk_header(&key, header, b"payload", enc),
            Err(JoseError::InvalidHeader(_))
        ));
    }
}

#[test]
fn header_encryption_enforces_jwk_operation_permissions() {
    let enc = JweEncryption::A128GCM;
    for (alg, denied, allowed) in [
        (JweAlgorithm::Dir, "wrapKey", "encrypt"),
        (JweAlgorithm::A128KW, "encrypt", "wrapKey"),
    ] {
        let mut key = jwk::generate_symmetric(16).unwrap();
        key.alg = Some(alg.as_str().into());
        let header = JoseHeader::for_jwe(alg, enc);
        key.key_ops = Some(vec![denied.into()]);
        assert!(matches!(
            jwe::encrypt_with_jwk_header(&key, header.clone(), b"payload", enc),
            Err(JoseError::Key(_))
        ));
        key.key_ops = Some(vec![allowed.into()]);
        assert!(jwe::encrypt_with_jwk_header(&key, header, b"payload", enc).is_ok());
    }
}

/// Build a `dir` JWK of `size` bytes together with its raw key bytes, so a
/// test can drive both the raw-key and the JWK encrypt APIs with one key.
fn dir_key_and_raw(size: usize) -> (jwk::Jwk, Vec<u8>) {
    let mut key = jwk::generate_symmetric(size).unwrap();
    key.alg = Some("dir".into());
    let raw = base64url::decode(key.k.as_deref().unwrap()).unwrap();
    (key, raw)
}

/// Assert that both `encrypt_with_header` and `encrypt_with_jwk_header`
/// refuse `header` with `InvalidHeader` before producing any token.
fn assert_both_reject(header: JoseHeader) {
    let enc = JweEncryption::A128GCM;
    let (key, raw) = dir_key_and_raw(enc.cek_size());
    assert!(
        matches!(
            jwe::encrypt_with_header(header.clone(), &raw, b"payload", JweAlgorithm::Dir, enc),
            Err(JoseError::InvalidHeader(_))
        ),
        "encrypt_with_header accepted {header:?}"
    );
    assert!(
        matches!(
            jwe::encrypt_with_jwk_header(&key, header.clone(), b"payload", enc),
            Err(JoseError::InvalidHeader(_))
        ),
        "encrypt_with_jwk_header accepted {header:?}"
    );
}

/// Regression: `extra` is flattened into the same JSON object as the typed
/// fields, so e.g. `extra["alg"]` used to emit `{"alg":"dir",...,"alg":"A128KW"}`
/// and bypass the `alg`/`enc` agreement check. Last-key-wins parsers would
/// then read a different algorithm than the one validated and used.
#[test]
fn extra_members_cannot_shadow_typed_header_fields() {
    for (name, value) in [
        ("alg", serde_json::json!("A128KW")),
        ("enc", serde_json::json!("A256GCM")),
        ("kid", serde_json::json!("other")),
        ("typ", serde_json::json!("JWT")),
        ("cty", serde_json::json!("JWT")),
        ("jku", serde_json::json!("https://example.com/jwks")),
        ("jwk", serde_json::json!({"kty": "oct"})),
        ("x5u", serde_json::json!("https://example.com/cert")),
        ("x5c", serde_json::json!(["AA"])),
        ("x5t", serde_json::json!("AA")),
        ("x5t#S256", serde_json::json!("AA")),
        ("crit", serde_json::json!(["exp"])),
    ] {
        let mut header = JoseHeader::for_jwe(JweAlgorithm::Dir, JweEncryption::A128GCM);
        header.extra.insert(name.into(), value);
        assert_both_reject(header);
    }
}

/// Regression: `zip` and `crit` used to be accepted at encrypt time even
/// though the plaintext is never compressed and no critical extension is
/// implemented, producing tokens this crate's own decrypt rejects.
#[test]
fn unsupported_zip_and_crit_are_rejected_at_encrypt() {
    let base = JoseHeader::for_jwe(JweAlgorithm::Dir, JweEncryption::A128GCM);

    let mut zip = base.clone();
    zip.extra.insert("zip".into(), "DEF".into());
    assert_both_reject(zip);

    // A non-empty `crit` naming a present member is still unsupported.
    let mut crit = base.clone();
    crit.crit = Some(vec!["tenant".into()]);
    crit.extra.insert("tenant".into(), "one".into());
    assert_both_reject(crit);

    // An empty `crit` array is invalid per RFC 7515 §4.1.11.
    let mut empty_crit = base;
    empty_crit.crit = Some(vec![]);
    assert_both_reject(empty_crit);
}
