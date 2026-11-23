//! Public string parsing for JOSE header values and application configuration.

use jose_rs::{JoseError, JweAlgorithm, JweEncryption, JwsAlgorithm};
use std::str::FromStr;

#[test]
fn parse_exact_jose_wire_names() {
    assert_eq!(
        "Ed448".parse::<JwsAlgorithm>().unwrap(),
        JwsAlgorithm::Ed448
    );
    assert_eq!(
        "EdDSA".parse::<JwsAlgorithm>().unwrap(),
        JwsAlgorithm::EdDSA
    );
    assert_eq!(
        "ECDH-ES+A128KW".parse::<JweAlgorithm>().unwrap(),
        JweAlgorithm::EcdhEsA128kw
    );
    assert_eq!(
        "A128CBC-HS256".parse::<JweEncryption>().unwrap(),
        JweEncryption::A128CbcHs256
    );
}

fn assert_unsupported<T: FromStr<Err = JoseError>>(wire: &str) {
    assert!(
        matches!(wire.parse::<T>(), Err(JoseError::UnsupportedAlgorithm(name)) if name == wire)
    );
}

#[test]
fn reject_inexact_and_wrong_family_names() {
    assert_unsupported::<JwsAlgorithm>("ed448");
    assert_unsupported::<JweAlgorithm>("dir ");
    assert_unsupported::<JweEncryption>("A128KW");
}

#[test]
fn respect_compile_time_feature_gates() {
    #[cfg(feature = "deprecated")]
    {
        assert_eq!("none".parse::<JwsAlgorithm>().unwrap(), JwsAlgorithm::None);
        assert_eq!(
            "RSA-OAEP".parse::<JweAlgorithm>().unwrap(),
            JweAlgorithm::RsaOaep
        );
    }
    #[cfg(not(feature = "deprecated"))]
    {
        assert_unsupported::<JwsAlgorithm>("none");
        #[cfg(not(feature = "rsa-oaep"))]
        assert_unsupported::<JweAlgorithm>("RSA-OAEP");
        #[cfg(feature = "rsa-oaep")]
        assert_eq!(
            "RSA-OAEP".parse::<JweAlgorithm>().unwrap(),
            JweAlgorithm::RsaOaep
        );
    }
    #[cfg(feature = "post-quantum")]
    assert_eq!(
        "ML-DSA-44".parse::<JwsAlgorithm>().unwrap(),
        JwsAlgorithm::MlDsa44
    );
    #[cfg(not(feature = "post-quantum"))]
    assert_unsupported::<JwsAlgorithm>("ML-DSA-44");
}
