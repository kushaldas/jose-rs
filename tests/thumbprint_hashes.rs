//! Fixed SHA-2 thumbprint vectors and canonicalization compatibility checks.

use jose_rs::{
    base64url,
    jwk::{
        thumbprint::{thumbprint, thumbprint_sha256, ThumbprintHash},
        Jwk,
    },
};
use sha2::Digest;

const HASHES: [ThumbprintHash; 3] = [
    ThumbprintHash::Sha256,
    ThumbprintHash::Sha384,
    ThumbprintHash::Sha512,
];

fn public_okp() -> Jwk {
    // Public key from RFC 8037. Expected values independently computed with
    // jwcrypto.JWK.thumbprint and cryptography SHA256/SHA384/SHA512.
    Jwk::from_json(
        r#"{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#,
    )
    .unwrap()
}

#[test]
fn sha384_matches_fixed_jwcrypto_reference() {
    let actual = thumbprint(&public_okp(), ThumbprintHash::Sha384).unwrap();
    assert_eq!(
        actual,
        "ePy6LSb6I7JWK2uWQyYJQ4DBrwGE4QoxPl6INUviCtqplTLCwzo6fD9Eaw69Wvtt"
    );
    assert_eq!(base64url::decode(&actual).unwrap().len(), 48);
}

#[test]
fn sha512_matches_fixed_jwcrypto_reference() {
    let actual = thumbprint(&public_okp(), ThumbprintHash::Sha512).unwrap();
    assert_eq!(
        actual,
        "SfSqAgfmPYvpuNzfHCiQXi6Mr51GG78hHopngoabsV9xvLR0hcUfVCoJLfyzi08Dbnds6kmcAt23CpNV-8qLTg"
    );
    assert_eq!(base64url::decode(&actual).unwrap().len(), 64);
}

#[test]
fn default_and_sha256_wrapper_match_fixed_reference() {
    let key = public_okp();
    let expected = "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k";
    assert_eq!(ThumbprintHash::default(), ThumbprintHash::Sha256);
    assert_eq!(
        thumbprint(&key, ThumbprintHash::default()).unwrap(),
        expected
    );
    assert_eq!(thumbprint(&key, ThumbprintHash::Sha256).unwrap(), expected);
    assert_eq!(thumbprint_sha256(&key).unwrap(), expected);
}

#[test]
fn every_key_type_uses_only_its_required_members() {
    // Representation fixtures: thumbprints deliberately do not validate the
    // mathematical key material. Canonical bytes are specified independently.
    for canonical in [
        r#"{"e":"AQAB","kty":"RSA","n":"AQID"}"#,
        r#"{"crv":"P-256","kty":"EC","x":"AQID","y":"BAUG"}"#,
        r#"{"k":"AQID","kty":"oct"}"#,
        r#"{"crv":"Ed25519","kty":"OKP","x":"AQID"}"#,
        r#"{"alg":"ML-DSA-44","kty":"AKP","pub":"AQID"}"#,
    ] {
        let mut value: serde_json::Value = serde_json::from_str(canonical).unwrap();
        value["kid"] = "ignored identifier".into();
        value["use"] = "sig".into();
        value["d"] = "ignored private material".into();
        value["priv"] = "ignored private material".into();
        value["extension"] = serde_json::json!({"nested": true});
        if value["kty"] != "AKP" {
            value["alg"] = "ignored optional algorithm".into();
        }
        let key = Jwk::from_json(&value.to_string()).unwrap();
        let before = key.to_json().unwrap();
        let expected = [
            base64url::encode(&sha2::Sha256::digest(canonical.as_bytes())),
            base64url::encode(&sha2::Sha384::digest(canonical.as_bytes())),
            base64url::encode(&sha2::Sha512::digest(canonical.as_bytes())),
        ];
        for (hash, expected) in HASHES.into_iter().zip(expected) {
            assert_eq!(thumbprint(&key, hash).unwrap(), expected);
        }
        assert_eq!(
            thumbprint_sha256(&key).unwrap(),
            thumbprint(&key, ThumbprintHash::Sha256).unwrap()
        );
        assert_eq!(key.to_json().unwrap(), before);

        let required: serde_json::Value = serde_json::from_str(canonical).unwrap();
        for field in required
            .as_object()
            .unwrap()
            .keys()
            .filter(|name| *name != "kty")
        {
            let mut incomplete = required.clone();
            incomplete.as_object_mut().unwrap().remove(field);
            let key = Jwk::from_json(&incomplete.to_string()).unwrap();
            for hash in HASHES {
                assert!(thumbprint(&key, hash).is_err(), "missing {field}");
            }
        }
    }
}

#[test]
fn escaping_and_unsupported_types_remain_consistent() {
    let key = Jwk::from_json(r#"{"kty":"oct","k":"a\"b\\c"}"#).unwrap();
    let canonical = br#"{"k":"a\"b\\c","kty":"oct"}"#;
    let expected = [
        base64url::encode(&sha2::Sha256::digest(canonical)),
        base64url::encode(&sha2::Sha384::digest(canonical)),
        base64url::encode(&sha2::Sha512::digest(canonical)),
    ];
    let unknown = Jwk::from_json(r#"{"kty":"unknown"}"#).unwrap();
    for (hash, expected) in HASHES.into_iter().zip(expected) {
        assert_eq!(thumbprint(&key, hash).unwrap(), expected);
        assert!(thumbprint(&unknown, hash).is_err());
    }
}

#[test]
fn generated_asymmetric_private_and_public_keys_have_equal_thumbprints() {
    for key in [
        jose_rs::jwk::generate_ed25519().unwrap(),
        jose_rs::jwk::generate_ec("P-256").unwrap(),
    ] {
        for hash in HASHES {
            assert_eq!(
                thumbprint(&key, hash).unwrap(),
                thumbprint(&key.to_public_jwk(), hash).unwrap()
            );
        }
    }
}
