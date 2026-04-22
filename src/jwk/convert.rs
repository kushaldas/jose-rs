//! Conversion between JWK and kryptering SoftwareKey.

use crate::base64url;
use crate::error::{JoseError, Result};
use crate::jwk::Jwk;

/// Convert a JWK to a kryptering SoftwareKey.
pub fn jwk_to_software_key(jwk: &Jwk) -> Result<kryptering::SoftwareKey> {
    match jwk.kty.as_str() {
        "RSA" => jwk_to_rsa(jwk),
        "EC" => jwk_to_ec(jwk),
        "OKP" => jwk_to_okp(jwk),
        "oct" => jwk_to_oct(jwk),
        other => Err(JoseError::Key(format!("unsupported kty: {other}"))),
    }
}

/// Convert a kryptering SoftwareKey to a JWK.
pub fn software_key_to_jwk(key: &kryptering::SoftwareKey) -> Result<Jwk> {
    match key {
        kryptering::SoftwareKey::Rsa { private, public } => rsa_to_jwk(private.as_ref(), public),
        kryptering::SoftwareKey::EcP256 { private, public } => {
            ec_p256_to_jwk(private.as_ref(), public)
        }
        kryptering::SoftwareKey::EcP384 { private, public } => {
            ec_p384_to_jwk(private.as_ref(), public)
        }
        kryptering::SoftwareKey::EcP521 { private, public } => {
            ec_p521_to_jwk(private.as_ref(), public)
        }
        kryptering::SoftwareKey::Ed25519 { private, public } => {
            ed25519_to_jwk(private.as_ref(), public)
        }
        kryptering::SoftwareKey::Hmac(bytes) => oct_to_jwk(bytes),
        kryptering::SoftwareKey::Aes(bytes) => oct_to_jwk(bytes),
        _ => Err(JoseError::Key(
            "unsupported SoftwareKey variant for JWK conversion".into(),
        )),
    }
}

// ── Helpers ────────────────────────────────────────────────────────────

/// Decode a required base64url field from a JWK.
fn require(jwk: &Jwk, field: &str) -> Result<Vec<u8>> {
    let value = match field {
        "n" => jwk.n.as_deref(),
        "e" => jwk.e.as_deref(),
        "d" => jwk.d.as_deref(),
        "p" => jwk.p.as_deref(),
        "q" => jwk.q.as_deref(),
        "dp" => jwk.dp.as_deref(),
        "dq" => jwk.dq.as_deref(),
        "qi" => jwk.qi.as_deref(),
        "x" => jwk.x.as_deref(),
        "y" => jwk.y.as_deref(),
        "k" => jwk.k.as_deref(),
        _ => None,
    };
    let s = value.ok_or_else(|| JoseError::Key(format!("missing JWK field: {field}")))?;
    base64url::decode(s)
}

/// Left-pad a byte slice with zeros to reach the target length.
/// If the input is already at or beyond the target length, return it as-is.
fn pad_left(bytes: &[u8], target_len: usize) -> Vec<u8> {
    if bytes.len() >= target_len {
        return bytes.to_vec();
    }
    let mut padded = vec![0u8; target_len - bytes.len()];
    padded.extend_from_slice(bytes);
    padded
}

/// Build a new Jwk with only the common metadata cleared.
fn new_jwk(kty: &str) -> Jwk {
    Jwk {
        kty: kty.into(),
        use_: None,
        key_ops: None,
        alg: None,
        kid: None,
        n: None,
        e: None,
        d: None,
        p: None,
        q: None,
        dp: None,
        dq: None,
        qi: None,
        crv: None,
        x: None,
        y: None,
        k: None,
        extra: Default::default(),
    }
}

// ── RSA ────────────────────────────────────────────────────────────────

fn jwk_to_rsa(jwk: &Jwk) -> Result<kryptering::SoftwareKey> {
    use num_bigint_dig::BigUint;
    use rsa::{traits::PublicKeyParts, RsaPrivateKey, RsaPublicKey};

    let n_bytes = require(jwk, "n")?;
    let e_bytes = require(jwk, "e")?;
    let n = BigUint::from_bytes_be(&n_bytes);
    let e = BigUint::from_bytes_be(&e_bytes);

    let public = RsaPublicKey::new(n.clone(), e.clone())
        .map_err(|err| JoseError::Key(format!("invalid RSA public key: {err}")))?;

    // RFC 7518 §3.3 / §4.2: RSA keys must be at least 2048 bits.
    if public.n().bits() < crate::MIN_RSA_BITS {
        return Err(JoseError::Key(format!(
            "RSA key size {} bits is below the required minimum of {}",
            public.n().bits(),
            crate::MIN_RSA_BITS
        )));
    }

    let private = if jwk.d.is_some() {
        let d_bytes = require(jwk, "d")?;
        let d = BigUint::from_bytes_be(&d_bytes);

        let primes = if jwk.p.is_some() && jwk.q.is_some() {
            let p = BigUint::from_bytes_be(&require(jwk, "p")?);
            let q = BigUint::from_bytes_be(&require(jwk, "q")?);
            vec![p, q]
        } else {
            vec![]
        };

        let private_key = RsaPrivateKey::from_components(n, e, d, primes)
            .map_err(|err| JoseError::Key(format!("invalid RSA private key: {err}")))?;
        Some(private_key)
    } else {
        None
    };

    Ok(kryptering::SoftwareKey::Rsa { private, public })
}

fn rsa_to_jwk(
    private: Option<&rsa::RsaPrivateKey>,
    public: &rsa::RsaPublicKey,
) -> Result<Jwk> {
    use rsa::traits::PublicKeyParts;

    let mut jwk = new_jwk("RSA");
    jwk.n = Some(base64url::encode(&public.n().to_bytes_be()));
    jwk.e = Some(base64url::encode(&public.e().to_bytes_be()));

    if let Some(priv_key) = private {
        use rsa::traits::PrivateKeyParts;

        jwk.d = Some(base64url::encode(&priv_key.d().to_bytes_be()));

        let primes = priv_key.primes();
        if primes.len() >= 2 {
            jwk.p = Some(base64url::encode(&primes[0].to_bytes_be()));
            jwk.q = Some(base64url::encode(&primes[1].to_bytes_be()));
            jwk.dp = priv_key
                .dp()
                .map(|v| base64url::encode(&v.to_bytes_be()));
            jwk.dq = priv_key
                .dq()
                .map(|v| base64url::encode(&v.to_bytes_be()));
            // qinv returns &BigInt (signed); extract magnitude bytes.
            jwk.qi = priv_key.qinv().map(|v| {
                let (_sign, bytes) = v.to_bytes_be();
                base64url::encode(&bytes)
            });
        }
    }

    Ok(jwk)
}

// ── EC ─────────────────────────────────────────────────────────────────

fn jwk_to_ec(jwk: &Jwk) -> Result<kryptering::SoftwareKey> {
    let crv = jwk
        .crv
        .as_deref()
        .ok_or_else(|| JoseError::Key("missing crv for EC key".into()))?;

    match crv {
        "P-256" => jwk_to_ec_p256(jwk),
        "P-384" => jwk_to_ec_p384(jwk),
        "P-521" => jwk_to_ec_p521(jwk),
        other => Err(JoseError::Key(format!("unsupported EC curve: {other}"))),
    }
}

fn jwk_to_ec_p256(jwk: &Jwk) -> Result<kryptering::SoftwareKey> {
    use p256::elliptic_curve::sec1::FromEncodedPoint;

    let x_bytes = require(jwk, "x")?;
    let y_bytes = require(jwk, "y")?;

    let coord_len = 32;
    let mut point = vec![0x04u8];
    point.extend(pad_left(&x_bytes, coord_len));
    point.extend(pad_left(&y_bytes, coord_len));

    let encoded_point = p256::EncodedPoint::from_bytes(&point)
        .map_err(|e| JoseError::Key(format!("invalid P-256 point: {e}")))?;
    let public_key: Option<p256::PublicKey> =
        p256::PublicKey::from_encoded_point(&encoded_point).into();
    let public_key =
        public_key.ok_or_else(|| JoseError::Key("P-256 point not on curve".into()))?;
    let verifying_key = p256::ecdsa::VerifyingKey::from(&public_key);

    let private = if jwk.d.is_some() {
        let d_bytes = require(jwk, "d")?;
        let signing_key = p256::ecdsa::SigningKey::from_slice(&d_bytes)
            .map_err(|e| JoseError::Key(format!("invalid P-256 private key: {e}")))?;
        Some(signing_key)
    } else {
        None
    };

    Ok(kryptering::SoftwareKey::EcP256 {
        private,
        public: verifying_key,
    })
}

fn jwk_to_ec_p384(jwk: &Jwk) -> Result<kryptering::SoftwareKey> {
    use p384::elliptic_curve::sec1::FromEncodedPoint;

    let x_bytes = require(jwk, "x")?;
    let y_bytes = require(jwk, "y")?;

    let coord_len = 48;
    let mut point = vec![0x04u8];
    point.extend(pad_left(&x_bytes, coord_len));
    point.extend(pad_left(&y_bytes, coord_len));

    let encoded_point = p384::EncodedPoint::from_bytes(&point)
        .map_err(|e| JoseError::Key(format!("invalid P-384 point: {e}")))?;
    let public_key: Option<p384::PublicKey> =
        p384::PublicKey::from_encoded_point(&encoded_point).into();
    let public_key =
        public_key.ok_or_else(|| JoseError::Key("P-384 point not on curve".into()))?;
    let verifying_key = p384::ecdsa::VerifyingKey::from(&public_key);

    let private = if jwk.d.is_some() {
        let d_bytes = require(jwk, "d")?;
        let signing_key = p384::ecdsa::SigningKey::from_slice(&d_bytes)
            .map_err(|e| JoseError::Key(format!("invalid P-384 private key: {e}")))?;
        Some(signing_key)
    } else {
        None
    };

    Ok(kryptering::SoftwareKey::EcP384 {
        private,
        public: verifying_key,
    })
}

fn jwk_to_ec_p521(jwk: &Jwk) -> Result<kryptering::SoftwareKey> {
    let x_bytes = require(jwk, "x")?;
    let y_bytes = require(jwk, "y")?;

    let coord_len = 66;
    let mut point = vec![0x04u8];
    point.extend(pad_left(&x_bytes, coord_len));
    point.extend(pad_left(&y_bytes, coord_len));

    let verifying_key = p521::ecdsa::VerifyingKey::from_sec1_bytes(&point)
        .map_err(|e| JoseError::Key(format!("invalid P-521 public key: {e}")))?;

    let private = if jwk.d.is_some() {
        let d_bytes = require(jwk, "d")?;
        let signing_key = p521::ecdsa::SigningKey::from_slice(&d_bytes)
            .map_err(|e| JoseError::Key(format!("invalid P-521 private key: {e}")))?;
        Some(signing_key)
    } else {
        None
    };

    Ok(kryptering::SoftwareKey::EcP521 {
        private,
        public: verifying_key,
    })
}

fn ec_p256_to_jwk(
    private: Option<&p256::ecdsa::SigningKey>,
    public: &p256::ecdsa::VerifyingKey,
) -> Result<Jwk> {
    let point = public.to_encoded_point(false);
    let mut jwk = new_jwk("EC");
    jwk.crv = Some("P-256".into());
    jwk.x = Some(base64url::encode(point.x().unwrap()));
    jwk.y = Some(base64url::encode(point.y().unwrap()));
    jwk.d = private.map(|sk| base64url::encode(&sk.to_bytes()));
    Ok(jwk)
}

fn ec_p384_to_jwk(
    private: Option<&p384::ecdsa::SigningKey>,
    public: &p384::ecdsa::VerifyingKey,
) -> Result<Jwk> {
    let point = public.to_encoded_point(false);
    let mut jwk = new_jwk("EC");
    jwk.crv = Some("P-384".into());
    jwk.x = Some(base64url::encode(point.x().unwrap()));
    jwk.y = Some(base64url::encode(point.y().unwrap()));
    jwk.d = private.map(|sk| base64url::encode(&sk.to_bytes()));
    Ok(jwk)
}

fn ec_p521_to_jwk(
    private: Option<&p521::ecdsa::SigningKey>,
    public: &p521::ecdsa::VerifyingKey,
) -> Result<Jwk> {
    let point = public.to_encoded_point(false);
    let mut jwk = new_jwk("EC");
    jwk.crv = Some("P-521".into());
    jwk.x = Some(base64url::encode(point.x().unwrap()));
    jwk.y = Some(base64url::encode(point.y().unwrap()));
    jwk.d = private.map(|sk| base64url::encode(&sk.to_bytes()));
    Ok(jwk)
}

// ── OKP (Ed25519) ──────────────────────────────────────────────────────

fn jwk_to_okp(jwk: &Jwk) -> Result<kryptering::SoftwareKey> {
    let crv = jwk
        .crv
        .as_deref()
        .ok_or_else(|| JoseError::Key("missing crv for OKP key".into()))?;

    if crv != "Ed25519" {
        return Err(JoseError::Key(format!("unsupported OKP curve: {crv}")));
    }

    let x_bytes = require(jwk, "x")?;
    if x_bytes.len() != 32 {
        return Err(JoseError::Key(format!(
            "Ed25519 public key must be 32 bytes, got {}",
            x_bytes.len()
        )));
    }

    let pub_bytes: [u8; 32] = x_bytes
        .try_into()
        .map_err(|_| JoseError::Key("Ed25519 public key length mismatch".into()))?;
    let public = ed25519_dalek::VerifyingKey::from_bytes(&pub_bytes)
        .map_err(|e| JoseError::Key(format!("invalid Ed25519 public key: {e}")))?;

    let private = if jwk.d.is_some() {
        let d_bytes = require(jwk, "d")?;
        if d_bytes.len() != 32 {
            return Err(JoseError::Key(format!(
                "Ed25519 private key must be 32 bytes, got {}",
                d_bytes.len()
            )));
        }
        let secret: [u8; 32] = d_bytes
            .try_into()
            .map_err(|_| JoseError::Key("Ed25519 private key length mismatch".into()))?;
        Some(ed25519_dalek::SigningKey::from_bytes(&secret))
    } else {
        None
    };

    Ok(kryptering::SoftwareKey::Ed25519 { private, public })
}

fn ed25519_to_jwk(
    private: Option<&ed25519_dalek::SigningKey>,
    public: &ed25519_dalek::VerifyingKey,
) -> Result<Jwk> {
    let mut jwk = new_jwk("OKP");
    jwk.crv = Some("Ed25519".into());
    jwk.x = Some(base64url::encode(public.as_bytes()));
    jwk.d = private.map(|sk| base64url::encode(&sk.to_bytes()));
    Ok(jwk)
}

// ── oct (symmetric) ────────────────────────────────────────────────────

fn jwk_to_oct(jwk: &Jwk) -> Result<kryptering::SoftwareKey> {
    let k_bytes = require(jwk, "k")?;

    // If alg is specified, use it to determine key type.
    // Otherwise fall back based on key length.
    if let Some(alg) = jwk.alg.as_deref() {
        if alg.starts_with("HS") {
            return Ok(kryptering::SoftwareKey::Hmac(k_bytes));
        }
        if alg.starts_with('A')
            && (alg.contains("KW") || alg.contains("GCM") || alg.contains("CBC"))
        {
            return Ok(kryptering::SoftwareKey::Aes(k_bytes));
        }
    }

    // Default heuristic: standard AES key lengths -> Aes, otherwise -> Hmac
    match k_bytes.len() {
        16 | 24 | 32 => Ok(kryptering::SoftwareKey::Aes(k_bytes)),
        _ => Ok(kryptering::SoftwareKey::Hmac(k_bytes)),
    }
}

fn oct_to_jwk(bytes: &[u8]) -> Result<Jwk> {
    let mut jwk = new_jwk("oct");
    jwk.k = Some(base64url::encode(bytes));
    Ok(jwk)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── RSA roundtrip ──────────────────────────────────────────────

    #[test]
    fn rsa_generate_to_jwk_roundtrip() {
        let private_key = rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap();
        let public_key = private_key.to_public_key();
        let sw = kryptering::SoftwareKey::Rsa {
            private: Some(private_key),
            public: public_key,
        };

        // Convert to JWK
        let jwk = software_key_to_jwk(&sw).unwrap();
        assert_eq!(jwk.kty, "RSA");
        assert!(jwk.n.is_some());
        assert!(jwk.e.is_some());
        assert!(jwk.d.is_some());
        assert!(jwk.p.is_some());
        assert!(jwk.q.is_some());

        // Convert back
        let sw2 = jwk_to_software_key(&jwk).unwrap();
        match &sw2 {
            kryptering::SoftwareKey::Rsa {
                private,
                public: _,
            } => {
                assert!(private.is_some());
            }
            _ => panic!("expected RSA key"),
        }

        // Sign with original, verify with converted
        use kryptering::HashAlgorithm;
        use kryptering::SignatureAlgorithm;
        use kryptering::Signer as _;
        use kryptering::Verifier as _;
        use kryptering::{SoftwareSigner, SoftwareVerifier};

        let signer = SoftwareSigner::new(
            SignatureAlgorithm::RsaPkcs1v15(HashAlgorithm::Sha256),
            sw,
        )
        .unwrap();
        let data = b"hello world";
        let sig = signer.sign(data).unwrap();

        let verifier = SoftwareVerifier::new(
            SignatureAlgorithm::RsaPkcs1v15(HashAlgorithm::Sha256),
            sw2,
        )
        .unwrap();
        verifier.verify(data, &sig).unwrap();
    }

    #[test]
    fn rsa_public_only_roundtrip() {
        let private_key = rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap();
        let public_key = private_key.to_public_key();
        let sw = kryptering::SoftwareKey::Rsa {
            private: None,
            public: public_key,
        };

        let jwk = software_key_to_jwk(&sw).unwrap();
        assert!(jwk.d.is_none());
        assert!(jwk.p.is_none());

        let sw2 = jwk_to_software_key(&jwk).unwrap();
        match &sw2 {
            kryptering::SoftwareKey::Rsa { private, .. } => {
                assert!(private.is_none());
            }
            _ => panic!("expected RSA key"),
        }
    }

    // ── EC P-256 roundtrip ─────────────────────────────────────────

    #[test]
    fn ec_p256_roundtrip() {
        let signing_key = p256::ecdsa::SigningKey::random(&mut rand::thread_rng());
        let verifying_key = *signing_key.verifying_key();
        let sw = kryptering::SoftwareKey::EcP256 {
            private: Some(signing_key),
            public: verifying_key,
        };

        let jwk = software_key_to_jwk(&sw).unwrap();
        assert_eq!(jwk.kty, "EC");
        assert_eq!(jwk.crv.as_deref(), Some("P-256"));
        assert!(jwk.x.is_some());
        assert!(jwk.y.is_some());
        assert!(jwk.d.is_some());

        let sw2 = jwk_to_software_key(&jwk).unwrap();
        match &sw2 {
            kryptering::SoftwareKey::EcP256 { private, .. } => {
                assert!(private.is_some());
            }
            _ => panic!("expected EcP256 key"),
        }

        // Sign/verify roundtrip
        use kryptering::Signer as _;
        use kryptering::Verifier as _;
        use kryptering::{EcCurve, HashAlgorithm, SignatureAlgorithm};
        use kryptering::{SoftwareSigner, SoftwareVerifier};

        let signer = SoftwareSigner::new(
            SignatureAlgorithm::Ecdsa(EcCurve::P256, HashAlgorithm::Sha256),
            sw,
        )
        .unwrap();
        let data = b"test message";
        let sig = signer.sign(data).unwrap();

        let verifier = SoftwareVerifier::new(
            SignatureAlgorithm::Ecdsa(EcCurve::P256, HashAlgorithm::Sha256),
            sw2,
        )
        .unwrap();
        verifier.verify(data, &sig).unwrap();
    }

    // ── EC P-384 roundtrip ─────────────────────────────────────────

    #[test]
    fn ec_p384_roundtrip() {
        let signing_key = p384::ecdsa::SigningKey::random(&mut rand::thread_rng());
        let verifying_key = *signing_key.verifying_key();
        let sw = kryptering::SoftwareKey::EcP384 {
            private: Some(signing_key),
            public: verifying_key,
        };

        let jwk = software_key_to_jwk(&sw).unwrap();
        assert_eq!(jwk.crv.as_deref(), Some("P-384"));

        let sw2 = jwk_to_software_key(&jwk).unwrap();
        match &sw2 {
            kryptering::SoftwareKey::EcP384 { private, .. } => {
                assert!(private.is_some());
            }
            _ => panic!("expected EcP384 key"),
        }
    }

    // ── EC P-521 roundtrip ─────────────────────────────────────────

    #[test]
    fn ec_p521_roundtrip() {
        let signing_key = p521::ecdsa::SigningKey::random(&mut rand::thread_rng());
        let verifying_key = p521::ecdsa::VerifyingKey::from(&signing_key);
        let sw = kryptering::SoftwareKey::EcP521 {
            private: Some(signing_key),
            public: verifying_key,
        };

        let jwk = software_key_to_jwk(&sw).unwrap();
        assert_eq!(jwk.crv.as_deref(), Some("P-521"));

        let sw2 = jwk_to_software_key(&jwk).unwrap();
        match &sw2 {
            kryptering::SoftwareKey::EcP521 { private, .. } => {
                assert!(private.is_some());
            }
            _ => panic!("expected EcP521 key"),
        }
    }

    // ── Ed25519 roundtrip ──────────────────────────────────────────

    #[test]
    fn ed25519_roundtrip() {
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let verifying_key = signing_key.verifying_key();
        let sw = kryptering::SoftwareKey::Ed25519 {
            private: Some(signing_key),
            public: verifying_key,
        };

        let jwk = software_key_to_jwk(&sw).unwrap();
        assert_eq!(jwk.kty, "OKP");
        assert_eq!(jwk.crv.as_deref(), Some("Ed25519"));
        assert!(jwk.x.is_some());
        assert!(jwk.d.is_some());

        let sw2 = jwk_to_software_key(&jwk).unwrap();
        match &sw2 {
            kryptering::SoftwareKey::Ed25519 { private, .. } => {
                assert!(private.is_some());
            }
            _ => panic!("expected Ed25519 key"),
        }

        // Sign/verify roundtrip
        use kryptering::SignatureAlgorithm;
        use kryptering::Signer as _;
        use kryptering::Verifier as _;
        use kryptering::{SoftwareSigner, SoftwareVerifier};

        let signer = SoftwareSigner::new(SignatureAlgorithm::Ed25519, sw).unwrap();
        let data = b"ed25519 test";
        let sig = signer.sign(data).unwrap();

        let verifier = SoftwareVerifier::new(SignatureAlgorithm::Ed25519, sw2).unwrap();
        verifier.verify(data, &sig).unwrap();
    }

    // ── Symmetric roundtrip ────────────────────────────────────────

    #[test]
    fn hmac_symmetric_roundtrip() {
        let key_bytes = vec![0x42u8; 32];
        let sw = kryptering::SoftwareKey::Hmac(key_bytes.clone());

        let jwk = software_key_to_jwk(&sw).unwrap();
        assert_eq!(jwk.kty, "oct");
        assert!(jwk.k.is_some());

        // Parse back -- no alg set, 32 bytes -> Aes by default heuristic
        // Set alg to HS256 to get Hmac back
        let mut jwk_hmac = jwk.clone();
        jwk_hmac.alg = Some("HS256".into());
        let sw2 = jwk_to_software_key(&jwk_hmac).unwrap();
        match &sw2 {
            kryptering::SoftwareKey::Hmac(bytes) => {
                assert_eq!(bytes, &key_bytes);
            }
            _ => panic!("expected Hmac key"),
        }
    }

    #[test]
    fn aes_symmetric_roundtrip() {
        let key_bytes = vec![0x42u8; 16];
        let sw = kryptering::SoftwareKey::Aes(key_bytes.clone());

        let jwk = software_key_to_jwk(&sw).unwrap();
        assert_eq!(jwk.kty, "oct");

        let sw2 = jwk_to_software_key(&jwk).unwrap();
        match &sw2 {
            kryptering::SoftwareKey::Aes(bytes) => {
                assert_eq!(bytes, &key_bytes);
            }
            _ => panic!("expected Aes key"),
        }
    }

    // ── RFC 7517 Appendix A.1 (RSA public key) ────────────────────

    #[test]
    fn rfc7517_rsa_public_key() {
        let json = r#"{
            "kty": "RSA",
            "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
            "e": "AQAB",
            "alg": "RS256",
            "kid": "2011-04-29"
        }"#;

        let jwk = Jwk::from_json(json).unwrap();
        let sw = jwk_to_software_key(&jwk).unwrap();

        match &sw {
            kryptering::SoftwareKey::Rsa { private, public } => {
                assert!(private.is_none());
                use rsa::traits::PublicKeyParts;
                assert!(public.n().bits() >= 2040);
            }
            _ => panic!("expected RSA key"),
        }
    }

    // ── EC public key parse ────────────────────────────────────────

    #[test]
    fn ec_p256_public_key_parse() {
        let json = r#"{
            "kty": "EC",
            "crv": "P-256",
            "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
            "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
            "kid": "ec-1"
        }"#;

        let jwk = Jwk::from_json(json).unwrap();
        let sw = jwk_to_software_key(&jwk).unwrap();
        match &sw {
            kryptering::SoftwareKey::EcP256 { private, .. } => {
                assert!(private.is_none());
            }
            _ => panic!("expected EcP256 key"),
        }
    }

    // ── Unsupported kty ────────────────────────────────────────────

    #[test]
    fn unsupported_kty_error() {
        let json = r#"{"kty":"unknown"}"#;
        let jwk = Jwk::from_json(json).unwrap();
        let result = jwk_to_software_key(&jwk);
        match result {
            Err(e) => {
                let msg = format!("{e}");
                assert!(msg.contains("unsupported kty"));
            }
            Ok(_) => panic!("expected error for unsupported kty"),
        }
    }
}
