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
