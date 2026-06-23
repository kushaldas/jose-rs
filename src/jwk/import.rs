//! Import keys from DER encodings (PKCS#8 private keys, X.509 SPKI public
//! keys) into the crate's `Jwk` / `SoftwareKey` representation.
//!
//! These are the jose-rs equivalents of josekit's `signer_from_der` /
//! `verifier_from_der`: given the DER bytes that an X.509 toolchain or an
//! HSM export produces, build a `Jwk` (and from there a signer or verifier
//! via the existing JWK-first entry points).
//!
//! Dispatch is by the algorithm OID carried in the PKCS#8
//! `AlgorithmIdentifier` / SPKI header, so an attacker cannot smuggle, say,
//! an RSA key past an EC decoder. Each concrete key type is then handed to
//! its own vetted RustCrypto decoder. Supported families mirror what the
//! crate already signs/verifies with: RSA (RS/PS), EC (P-256/384/521 →
//! ES256/384/512), and Ed25519 (EdDSA).

use p521::elliptic_curve::sec1::ToEncodedPoint;
use pkcs8::der::Decode;
use pkcs8::spki::{DecodePublicKey, SubjectPublicKeyInfoRef};
use pkcs8::{DecodePrivateKey, ObjectIdentifier, PrivateKeyInfo};

use crate::error::{JoseError, Result};
use crate::jwk::convert::software_key_to_jwk;
use crate::jwk::Jwk;

// Algorithm OIDs (RFC 8017, RFC 5480, RFC 8410). Declared inline rather than
// pulled from a const-oid database feature so the set we accept is explicit
// and auditable.
const OID_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
const OID_EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const OID_ED25519: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");

// Named-curve OIDs that ride in the EC `AlgorithmIdentifier` parameters.
const OID_P256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
const OID_P384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");
const OID_P521: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.35");

/// Import a PKCS#8 DER-encoded private key into a [`Jwk`].
///
/// Accepts the unencrypted PKCS#8 `OneAsymmetricKey` / `PrivateKeyInfo`
/// structure (RFC 5208 / RFC 5958) for the signature families this crate
/// supports: RSA, EC (P-256/384/521), and Ed25519. The returned JWK carries
/// the full private key material plus the matching public components, with
/// no `alg` pinned (the caller selects the precise JWS algorithm — e.g.
/// `RS256` vs `PS256` for the same RSA key — by setting `jwk.alg`).
///
/// This is the private-key counterpart of josekit's `signer_from_der`:
/// follow it with [`crate::jws::compact::sign_with_jwk`] after pinning
/// `jwk.alg`.
pub fn jwk_from_pkcs8_der(der: &[u8]) -> Result<Jwk> {
    let info = PrivateKeyInfo::from_der(der)
        .map_err(|e| JoseError::Key(format!("invalid PKCS#8 DER: {e}")))?;
    let oid = info.algorithm.oid;

    let sw = if oid == OID_RSA {
        let key = rsa::RsaPrivateKey::from_pkcs8_der(der)
            .map_err(|e| JoseError::Key(format!("invalid RSA PKCS#8 key: {e}")))?;
        let public = key.to_public_key();
        kryptering::SoftwareKey::Rsa {
            private: Some(key),
            public,
        }
    } else if oid == OID_ED25519 {
        let key = ed25519_dalek::SigningKey::from_pkcs8_der(der)
            .map_err(|e| JoseError::Key(format!("invalid Ed25519 PKCS#8 key: {e}")))?;
        let public = key.verifying_key();
        kryptering::SoftwareKey::Ed25519 {
            private: Some(key),
            public,
        }
    } else if oid == OID_EC_PUBLIC_KEY {
        let curve = info
            .algorithm
            .parameters_oid()
            .map_err(|e| JoseError::Key(format!("EC key missing curve parameters: {e}")))?;
        ec_private_from_pkcs8(der, curve)?
    } else {
        return Err(JoseError::Key(format!(
            "unsupported PKCS#8 algorithm OID: {oid}"
        )));
    };

    software_key_to_jwk(&sw)
}

/// Import an X.509 SubjectPublicKeyInfo (SPKI) DER-encoded public key into a
/// [`Jwk`].
///
/// Accepts the SPKI structure (RFC 5280 §4.1.2.7) for RSA, EC
/// (P-256/384/521), and Ed25519 public keys. The returned JWK carries only
/// public components and pins no `alg`.
///
/// This is the public-key counterpart of josekit's `verifier_from_der`:
/// follow it with [`crate::jws::compact::verify_with_jwk`] (which derives
/// the algorithm from the token header) or build a verifier explicitly.
pub fn jwk_from_spki_der(der: &[u8]) -> Result<Jwk> {
    let spki = SubjectPublicKeyInfoRef::from_der(der)
        .map_err(|e| JoseError::Key(format!("invalid SPKI DER: {e}")))?;
    let oid = spki.algorithm.oid;

    let sw = if oid == OID_RSA {
        let key = rsa::RsaPublicKey::from_public_key_der(der)
            .map_err(|e| JoseError::Key(format!("invalid RSA SPKI key: {e}")))?;
        kryptering::SoftwareKey::Rsa {
            private: None,
            public: key,
        }
    } else if oid == OID_ED25519 {
        let key = ed25519_dalek::VerifyingKey::from_public_key_der(der)
            .map_err(|e| JoseError::Key(format!("invalid Ed25519 SPKI key: {e}")))?;
        kryptering::SoftwareKey::Ed25519 {
            private: None,
            public: key,
        }
    } else if oid == OID_EC_PUBLIC_KEY {
        let curve = spki
            .algorithm
            .parameters_oid()
            .map_err(|e| JoseError::Key(format!("EC key missing curve parameters: {e}")))?;
        ec_public_from_spki(der, curve)?
    } else {
        return Err(JoseError::Key(format!(
            "unsupported SPKI algorithm OID: {oid}"
        )));
    };

    software_key_to_jwk(&sw)
}

// ── EC dispatch by named-curve OID ──────────────────────────────────────

fn ec_private_from_pkcs8(der: &[u8], curve: ObjectIdentifier) -> Result<kryptering::SoftwareKey> {
    match curve {
        OID_P256 => {
            let sk = p256::ecdsa::SigningKey::from_pkcs8_der(der)
                .map_err(|e| JoseError::Key(format!("invalid P-256 PKCS#8 key: {e}")))?;
            let public = *sk.verifying_key();
            Ok(kryptering::SoftwareKey::EcP256 {
                private: Some(sk),
                public,
            })
        }
        OID_P384 => {
            let sk = p384::ecdsa::SigningKey::from_pkcs8_der(der)
                .map_err(|e| JoseError::Key(format!("invalid P-384 PKCS#8 key: {e}")))?;
            let public = *sk.verifying_key();
            Ok(kryptering::SoftwareKey::EcP384 {
                private: Some(sk),
                public,
            })
        }
        OID_P521 => {
            // p521's ECDSA key types don't implement the pkcs8/spki decoder
            // traits directly; decode the curve key and convert via scalar
            // bytes (matching the `from_slice` path used elsewhere).
            let secret = p521::SecretKey::from_pkcs8_der(der)
                .map_err(|e| JoseError::Key(format!("invalid P-521 PKCS#8 key: {e}")))?;
            let sk = p521::ecdsa::SigningKey::from_slice(&secret.to_bytes())
                .map_err(|e| JoseError::Key(format!("invalid P-521 private scalar: {e}")))?;
            let public = p521::ecdsa::VerifyingKey::from(&sk);
            Ok(kryptering::SoftwareKey::EcP521 {
                private: Some(sk),
                public,
            })
        }
        other => Err(JoseError::Key(format!("unsupported EC curve OID: {other}"))),
    }
}

fn ec_public_from_spki(der: &[u8], curve: ObjectIdentifier) -> Result<kryptering::SoftwareKey> {
    match curve {
        OID_P256 => {
            let vk = p256::ecdsa::VerifyingKey::from_public_key_der(der)
                .map_err(|e| JoseError::Key(format!("invalid P-256 SPKI key: {e}")))?;
            Ok(kryptering::SoftwareKey::EcP256 {
                private: None,
                public: vk,
            })
        }
        OID_P384 => {
            let vk = p384::ecdsa::VerifyingKey::from_public_key_der(der)
                .map_err(|e| JoseError::Key(format!("invalid P-384 SPKI key: {e}")))?;
            Ok(kryptering::SoftwareKey::EcP384 {
                private: None,
                public: vk,
            })
        }
        OID_P521 => {
            let public = p521::PublicKey::from_public_key_der(der)
                .map_err(|e| JoseError::Key(format!("invalid P-521 SPKI key: {e}")))?;
            let vk = p521::ecdsa::VerifyingKey::from_sec1_bytes(
                public.to_encoded_point(false).as_bytes(),
            )
            .map_err(|e| JoseError::Key(format!("invalid P-521 public point: {e}")))?;
            Ok(kryptering::SoftwareKey::EcP521 {
                private: None,
                public: vk,
            })
        }
        other => Err(JoseError::Key(format!("unsupported EC curve OID: {other}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::JoseHeader;
    use pkcs8::spki::EncodePublicKey;
    use pkcs8::EncodePrivateKey;

    /// Sign with a JWK imported from a PKCS#8 private key, verify with a JWK
    /// imported from the matching SPKI public key. Exercises the full
    /// DER → Jwk → signer/verifier path for one algorithm.
    fn der_roundtrip(alg: &str, priv_der: &[u8], pub_der: &[u8]) {
        let mut priv_jwk = jwk_from_pkcs8_der(priv_der).unwrap();
        priv_jwk.alg = Some(alg.to_string());

        let mut pub_jwk = jwk_from_spki_der(pub_der).unwrap();
        pub_jwk.alg = Some(alg.to_string());

        let header = JoseHeader::new(alg);
        let payload = b"der-import roundtrip payload";

        let token = crate::jws::compact::sign_with_jwk(&priv_jwk, payload, &header)
            .unwrap_or_else(|e| panic!("{alg} sign failed: {e}"));
        let recovered = crate::jws::compact::verify_with_jwk(&pub_jwk, &token)
            .unwrap_or_else(|e| panic!("{alg} verify failed: {e}"));
        assert_eq!(recovered, payload);
    }

    #[test]
    fn rsa_pkcs8_spki_roundtrip_rs256_and_ps256() {
        let sk = rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap();
        let pk = sk.to_public_key();
        let priv_der = sk.to_pkcs8_der().unwrap();
        let pub_der = pk.to_public_key_der().unwrap();

        // Same RSA key, two distinct JWS algorithms selected via jwk.alg.
        der_roundtrip("RS256", priv_der.as_bytes(), pub_der.as_bytes());
        der_roundtrip("PS256", priv_der.as_bytes(), pub_der.as_bytes());
        der_roundtrip("PS512", priv_der.as_bytes(), pub_der.as_bytes());
    }

    #[test]
    fn ec_p256_pkcs8_spki_roundtrip_es256() {
        let sk = p256::ecdsa::SigningKey::random(&mut rand::thread_rng());
        let priv_der = sk.to_pkcs8_der().unwrap();
        let pub_der = sk.verifying_key().to_public_key_der().unwrap();
        der_roundtrip("ES256", priv_der.as_bytes(), pub_der.as_bytes());
    }

    #[test]
    fn ec_p384_pkcs8_spki_roundtrip_es384() {
        let sk = p384::ecdsa::SigningKey::random(&mut rand::thread_rng());
        let priv_der = sk.to_pkcs8_der().unwrap();
        let pub_der = sk.verifying_key().to_public_key_der().unwrap();
        der_roundtrip("ES384", priv_der.as_bytes(), pub_der.as_bytes());
    }

    #[test]
    fn ec_p521_pkcs8_spki_roundtrip_es512() {
        // p521 ECDSA keys don't implement the pkcs8/spki encoders directly;
        // round-trip the DER through the curve key types.
        let secret = p521::SecretKey::random(&mut rand::thread_rng());
        let public = secret.public_key();
        let priv_der = secret.to_pkcs8_der().unwrap();
        let pub_der = public.to_public_key_der().unwrap();
        der_roundtrip("ES512", priv_der.as_bytes(), pub_der.as_bytes());
    }

    #[test]
    fn ed25519_pkcs8_spki_roundtrip_eddsa() {
        use pkcs8::EncodePrivateKey;
        let sk = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let priv_der = sk.to_pkcs8_der().unwrap();
        let pub_der = sk.verifying_key().to_public_key_der().unwrap();
        der_roundtrip("EdDSA", priv_der.as_bytes(), pub_der.as_bytes());
    }

    /// A public-only JWK imported from SPKI must not carry private material.
    #[test]
    fn spki_import_has_no_private_material() {
        let sk = p256::ecdsa::SigningKey::random(&mut rand::thread_rng());
        let pub_der = sk.verifying_key().to_public_key_der().unwrap();
        let jwk = jwk_from_spki_der(pub_der.as_bytes()).unwrap();
        assert!(jwk.d.is_none(), "SPKI import must not produce a private d");
        assert_eq!(jwk.kty, "EC");
        assert_eq!(jwk.crv.as_deref(), Some("P-256"));
    }

    /// A PKCS#8 import carries the private scalar.
    #[test]
    fn pkcs8_import_has_private_material() {
        let sk = p256::ecdsa::SigningKey::random(&mut rand::thread_rng());
        let priv_der = sk.to_pkcs8_der().unwrap();
        let jwk = jwk_from_pkcs8_der(priv_der.as_bytes()).unwrap();
        assert!(jwk.d.is_some(), "PKCS#8 import must produce a private d");
    }

    /// Garbage DER is rejected, not silently mishandled.
    #[test]
    fn invalid_der_is_rejected() {
        let err = jwk_from_pkcs8_der(b"not der at all")
            .unwrap_err()
            .to_string();
        assert!(err.contains("PKCS#8"), "unexpected: {err}");
        let err2 = jwk_from_spki_der(b"not der at all")
            .unwrap_err()
            .to_string();
        assert!(err2.contains("SPKI"), "unexpected: {err2}");
    }
}
