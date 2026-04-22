//! JWK key generation.

use crate::error::{JoseError, Result};
use crate::jwk::convert::software_key_to_jwk;
use crate::jwk::Jwk;

/// Generate an RSA key pair as a JWK.
///
/// `bits` is the modulus size in bits (e.g. 2048, 3072, 4096). Must be at
/// least [`crate::MIN_RSA_BITS`] (2048) per RFC 7518 §3.3.
pub fn generate_rsa(bits: usize) -> Result<Jwk> {
    if bits < crate::MIN_RSA_BITS {
        return Err(JoseError::Key(format!(
            "requested RSA key size {} bits is below the required minimum of {}",
            bits,
            crate::MIN_RSA_BITS
        )));
    }
    let private_key = rsa::RsaPrivateKey::new(&mut rand::thread_rng(), bits)
        .map_err(|e| JoseError::Key(format!("RSA keygen failed: {e}")))?;
    let public_key = private_key.to_public_key();
    let sw = kryptering::SoftwareKey::Rsa {
        public: public_key,
        private: Some(private_key),
    };
    software_key_to_jwk(&sw)
}

/// Generate an EC key pair as a JWK.
///
/// `curve` must be one of `"P-256"`, `"P-384"`, or `"P-521"`.
pub fn generate_ec(curve: &str) -> Result<Jwk> {
    let sw = match curve {
        "P-256" => {
            let sk = p256::ecdsa::SigningKey::random(&mut rand::thread_rng());
            let vk = *sk.verifying_key();
            kryptering::SoftwareKey::EcP256 {
                private: Some(sk),
                public: vk,
            }
        }
        "P-384" => {
            let sk = p384::ecdsa::SigningKey::random(&mut rand::thread_rng());
            let vk = *sk.verifying_key();
            kryptering::SoftwareKey::EcP384 {
                private: Some(sk),
                public: vk,
            }
        }
        "P-521" => {
            let sk = p521::ecdsa::SigningKey::random(&mut rand::thread_rng());
            let vk = p521::ecdsa::VerifyingKey::from(&sk);
            kryptering::SoftwareKey::EcP521 {
                private: Some(sk),
                public: vk,
            }
        }
        other => return Err(JoseError::Key(format!("unsupported EC curve: {other}"))),
    };
    software_key_to_jwk(&sw)
}

/// Generate an Ed25519 key pair as a JWK.
pub fn generate_ed25519() -> Result<Jwk> {
    let sk = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
    let vk = sk.verifying_key();
    let sw = kryptering::SoftwareKey::Ed25519 {
        private: Some(sk),
        public: vk,
    };
    software_key_to_jwk(&sw)
}

/// Generate a symmetric (oct) key as a JWK.
///
/// `len` is the key length in bytes (e.g. 16 for AES-128, 32 for AES-256 / HS256).
pub fn generate_symmetric(len: usize) -> Result<Jwk> {
    use rand::RngCore;
    let mut key_bytes = vec![0u8; len];
    rand::thread_rng().fill_bytes(&mut key_bytes);
    let sw = kryptering::SoftwareKey::Hmac(key_bytes);
    software_key_to_jwk(&sw)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jwk::convert::jwk_to_software_key;

    #[test]
    fn generate_rsa_2048() {
        let jwk = generate_rsa(2048).unwrap();
        assert_eq!(jwk.kty, "RSA");
        assert!(jwk.n.is_some());
        assert!(jwk.d.is_some());

        // Roundtrip back to SoftwareKey
        let sw = jwk_to_software_key(&jwk).unwrap();
        match &sw {
            kryptering::SoftwareKey::Rsa { private, .. } => {
                assert!(private.is_some());
            }
            _ => panic!("expected RSA"),
        }
    }

    #[test]
    fn generate_ec_p256() {
        let jwk = generate_ec("P-256").unwrap();
        assert_eq!(jwk.kty, "EC");
        assert_eq!(jwk.crv.as_deref(), Some("P-256"));
        assert!(jwk.x.is_some());
        assert!(jwk.y.is_some());
        assert!(jwk.d.is_some());
    }

    #[test]
    fn generate_ec_p384() {
        let jwk = generate_ec("P-384").unwrap();
        assert_eq!(jwk.crv.as_deref(), Some("P-384"));
    }

    #[test]
    fn generate_ec_p521() {
        let jwk = generate_ec("P-521").unwrap();
        assert_eq!(jwk.crv.as_deref(), Some("P-521"));
    }

    #[test]
    fn generate_ec_unsupported() {
        let err = generate_ec("P-192").unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("unsupported EC curve"));
    }

    #[test]
    fn generate_ed25519_key() {
        let jwk = generate_ed25519().unwrap();
        assert_eq!(jwk.kty, "OKP");
        assert_eq!(jwk.crv.as_deref(), Some("Ed25519"));
        assert!(jwk.x.is_some());
        assert!(jwk.d.is_some());
    }

    #[test]
    fn generate_symmetric_32() {
        let jwk = generate_symmetric(32).unwrap();
        assert_eq!(jwk.kty, "oct");
        assert!(jwk.k.is_some());

        // Verify key bytes length
        let k_bytes = crate::base64url::decode(jwk.k.as_ref().unwrap()).unwrap();
        assert_eq!(k_bytes.len(), 32);
    }

    /// J-07 regression: sub-2048-bit RSA keys must be refused at generation time.
    #[test]
    fn generate_rsa_below_2048_is_rejected() {
        let err = generate_rsa(1024).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("2048") || msg.contains("minimum"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn generate_symmetric_unique() {
        let jwk1 = generate_symmetric(32).unwrap();
        let jwk2 = generate_symmetric(32).unwrap();
        // Two generated keys should be different
        assert_ne!(jwk1.k, jwk2.k);
    }
}
