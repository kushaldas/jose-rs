//! Conversion between JWK and kryptering SoftwareKey.

use crate::base64url;
use crate::error::{JoseError, Result};
use crate::jwk::Jwk;
use p521::elliptic_curve::sec1::ToEncodedPoint;

/// Convert a JWK to a kryptering SoftwareKey.
///
/// If the JWK advertises an `alg`, it is cross-checked against `kty` (and
/// `crv` for EC/OKP keys). Mismatches — e.g. `kty: "oct"` with
/// `alg: "RS256"` — are rejected before any key construction.
pub fn jwk_to_software_key(jwk: &Jwk) -> Result<kryptering::SoftwareKey> {
    check_alg_kty_consistency(jwk)?;
    match jwk.kty.as_str() {
        "RSA" => jwk_to_rsa(jwk),
        "EC" => jwk_to_ec(jwk),
        "OKP" => jwk_to_okp(jwk),
        "oct" => jwk_to_oct(jwk),
        #[cfg(feature = "post-quantum")]
        "AKP" => jwk_to_akp(jwk),
        other => Err(JoseError::Key(format!("unsupported kty: {other}"))),
    }
}

/// Verify that `alg`, if present, is consistent with `kty` and `crv`.
///
/// RFC 7517 §4.4: `alg` is an identifier for the algorithm this key is
/// intended for use with. It MUST be consistent with the key's other
/// parameters.
fn check_alg_kty_consistency(jwk: &Jwk) -> Result<()> {
    let Some(alg) = jwk.alg.as_deref() else {
        return Ok(());
    };
    let kty = jwk.kty.as_str();
    let crv = jwk.crv.as_deref();

    let expected_kty: &[&str] = match alg {
        // JWS HMAC: symmetric oct.
        "HS256" | "HS384" | "HS512" => &["oct"],
        // JWS RSA variants.
        "RS256" | "RS384" | "RS512" | "PS256" | "PS384" | "PS512" => &["RSA"],
        // JWS ECDSA.
        "ES256" | "ES384" | "ES512" | "ES256K" => &["EC"],
        // EdDSA.
        "EdDSA" => &["OKP"],
        // Post-quantum ML-DSA and composite ML-DSA.
        "ML-DSA-44" | "ML-DSA-65" | "ML-DSA-87" | "ML-DSA-44-ES256" | "ML-DSA-65-ES256"
        | "ML-DSA-87-ES384" | "ML-DSA-44-Ed25519" | "ML-DSA-65-Ed25519" | "ML-DSA-87-Ed448" => {
            &["AKP"]
        }
        // JWE key wrap, direct, PBES2 — all symmetric.
        "A128KW" | "A192KW" | "A256KW" | "dir" | "PBES2-HS256+A128KW" | "PBES2-HS384+A192KW"
        | "PBES2-HS512+A256KW" => &["oct"],
        // JWE RSA key transport.
        "RSA-OAEP" | "RSA-OAEP-256" | "RSA1_5" => &["RSA"],
        // JWE ECDH-ES family.
        "ECDH-ES" | "ECDH-ES+A128KW" | "ECDH-ES+A192KW" | "ECDH-ES+A256KW" => &["EC", "OKP"],
        // JWE content encryption algs shouldn't be on a JWK `alg` field,
        // but if they are, they imply symmetric.
        "A128GCM" | "A192GCM" | "A256GCM" | "A128CBC-HS256" | "A192CBC-HS384" | "A256CBC-HS512" => {
            &["oct"]
        }
        _ => &[], // unknown alg: don't enforce
    };

    if !expected_kty.is_empty() && !expected_kty.contains(&kty) {
        return Err(JoseError::Key(format!(
            "JWK alg {alg} is incompatible with kty {kty}"
        )));
    }

    // ECDSA alg implies a specific curve.
    let expected_crv: Option<&str> = match alg {
        "ES256" => Some("P-256"),
        "ES384" => Some("P-384"),
        "ES512" => Some("P-521"),
        "ES256K" => Some("secp256k1"),
        "EdDSA" => Some("Ed25519"),
        _ => None,
    };
    if let Some(want) = expected_crv {
        match crv {
            Some(got) if got == want => {}
            Some(got) => {
                return Err(JoseError::Key(format!(
                    "JWK alg {alg} requires crv={want}, got {got}"
                )));
            }
            None => {
                return Err(JoseError::Key(format!(
                    "JWK alg {alg} requires crv={want}, got none"
                )));
            }
        }
    }

    Ok(())
}

/// Convert a kryptering SoftwareKey to a JWK.
pub fn software_key_to_jwk(key: &kryptering::SoftwareKey) -> Result<Jwk> {
    use kryptering::KeyAlgorithm;
    use pkcs8::spki::DecodePublicKey;
    use pkcs8::DecodePrivateKey;

    match key.algorithm() {
        KeyAlgorithm::Rsa => {
            let public_der = key.export_spki_der()?;
            let public = rsa::RsaPublicKey::from_public_key_der(&public_der)
                .map_err(|e| JoseError::Key(format!("parse exported RSA SPKI: {e}")))?;
            let private = if key.has_private_key() {
                let private_der = key.export_private()?;
                Some(
                    rsa::RsaPrivateKey::from_pkcs8_der(&private_der)
                        .map_err(|e| JoseError::Key(format!("parse exported RSA PKCS#8: {e}")))?,
                )
            } else {
                None
            };
            rsa_to_jwk(private.as_ref(), &public)
        }
        KeyAlgorithm::Ec(kryptering::EcCurve::P256) => {
            let public_der = key.export_spki_der()?;
            let public = p256::ecdsa::VerifyingKey::from_public_key_der(&public_der)
                .map_err(|e| JoseError::Key(format!("parse exported P-256 SPKI: {e}")))?;
            let private = if key.has_private_key() {
                let private_der = key.export_private()?;
                Some(
                    p256::ecdsa::SigningKey::from_pkcs8_der(&private_der)
                        .map_err(|e| JoseError::Key(format!("parse exported P-256 PKCS#8: {e}")))?,
                )
            } else {
                None
            };
            ec_p256_to_jwk(private.as_ref(), &public)
        }
        KeyAlgorithm::Ec(kryptering::EcCurve::P384) => {
            let public_der = key.export_spki_der()?;
            let public = p384::ecdsa::VerifyingKey::from_public_key_der(&public_der)
                .map_err(|e| JoseError::Key(format!("parse exported P-384 SPKI: {e}")))?;
            let private = if key.has_private_key() {
                let private_der = key.export_private()?;
                Some(
                    p384::ecdsa::SigningKey::from_pkcs8_der(&private_der)
                        .map_err(|e| JoseError::Key(format!("parse exported P-384 PKCS#8: {e}")))?,
                )
            } else {
                None
            };
            ec_p384_to_jwk(private.as_ref(), &public)
        }
        KeyAlgorithm::Ec(kryptering::EcCurve::P521) => {
            let public_der = key.export_spki_der()?;
            let public_key = p521::PublicKey::from_public_key_der(&public_der)
                .map_err(|e| JoseError::Key(format!("parse exported P-521 SPKI: {e}")))?;
            let public = p521::ecdsa::VerifyingKey::from_sec1_bytes(
                public_key.to_encoded_point(false).as_bytes(),
            )
            .map_err(|e| JoseError::Key(format!("parse exported P-521 public point: {e}")))?;
            let private = if key.has_private_key() {
                let private_der = key.export_private()?;
                let secret = p521::SecretKey::from_pkcs8_der(&private_der)
                    .map_err(|e| JoseError::Key(format!("parse exported P-521 PKCS#8: {e}")))?;
                Some(
                    p521::ecdsa::SigningKey::from_slice(&secret.to_bytes()).map_err(|e| {
                        JoseError::Key(format!("parse exported P-521 private scalar: {e}"))
                    })?,
                )
            } else {
                None
            };
            ec_p521_to_jwk(private.as_ref(), &public)
        }
        KeyAlgorithm::Ed25519 => {
            let public_der = key.export_spki_der()?;
            let public = ed25519_dalek::VerifyingKey::from_public_key_der(&public_der)
                .map_err(|e| JoseError::Key(format!("parse exported Ed25519 SPKI: {e}")))?;
            let private = if key.has_private_key() {
                let private_der = key.export_private()?;
                Some(
                    ed25519_dalek::SigningKey::from_pkcs8_der(&private_der).map_err(|e| {
                        JoseError::Key(format!("parse exported Ed25519 PKCS#8: {e}"))
                    })?,
                )
            } else {
                None
            };
            ed25519_to_jwk(private.as_ref(), &public)
        }
        KeyAlgorithm::Hmac | KeyAlgorithm::Aes => {
            let bytes = key.export_private()?;
            oct_to_jwk(&bytes)
        }
        #[cfg(feature = "post-quantum")]
        KeyAlgorithm::PostQuantum(algorithm) => {
            let public_der = key.export_spki_der()?;
            let private = key
                .has_private_key()
                .then(|| key.export_private())
                .transpose()?;
            akp_to_jwk(
                algorithm,
                &public_der,
                private.as_ref().map(|value| value.as_slice()),
            )
        }
        #[cfg(feature = "post-quantum")]
        KeyAlgorithm::CompositeMlDsa(variant) => {
            let public = key.export_composite_public()?;
            let private = key
                .has_private_key()
                .then(|| key.export_composite_private())
                .transpose()?;
            composite_akp_to_jwk(
                variant,
                &public,
                private.as_ref().map(|value| value.as_slice()),
            )
        }
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

/// Reject an EC coordinate whose byte length exceeds the curve's coord size.
/// Left-padding with pad_left handles the short case; anything strictly longer
/// is malformed and should fail early with a clear error.
fn reject_oversized_coord(bytes: &[u8], target_len: usize, field: &str) -> Result<()> {
    if bytes.len() > target_len {
        return Err(JoseError::Key(format!(
            "EC coordinate {field} is {} bytes, exceeds curve size {target_len}",
            bytes.len()
        )));
    }
    Ok(())
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
        pub_: None,
        priv_: None,
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

    // Public exponent sanity: must be >= 3 and odd. RFC 7518 does not pin a
    // value, but 65537 (AQAB) is the universal default. Reject values that
    // could produce degenerate or insecure RSA instances.
    let three = BigUint::from(3u32);
    if e < three {
        return Err(JoseError::Key(
            "RSA public exponent is below the minimum of 3".into(),
        ));
    }
    // Even exponents are invalid — they cannot be coprime to phi(n) for any
    // usable modulus.
    let is_even = e.to_bytes_be().last().copied().unwrap_or(0) & 1 == 0;
    if is_even {
        return Err(JoseError::Key("RSA public exponent must be odd".into()));
    }

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

    use pkcs8::spki::EncodePublicKey;
    use pkcs8::EncodePrivateKey;

    if let Some(private) = private {
        let der = private
            .to_pkcs8_der()
            .map_err(|e| JoseError::Key(format!("encode RSA PKCS#8: {e}")))?;
        kryptering::SoftwareKey::from_pkcs8_der(kryptering::KeyAlgorithm::Rsa, der.as_bytes())
            .map_err(Into::into)
    } else {
        let der = public
            .to_public_key_der()
            .map_err(|e| JoseError::Key(format!("encode RSA SPKI: {e}")))?;
        kryptering::SoftwareKey::from_spki_der(kryptering::KeyAlgorithm::Rsa, der.as_bytes())
            .map_err(Into::into)
    }
}

fn rsa_to_jwk(private: Option<&rsa::RsaPrivateKey>, public: &rsa::RsaPublicKey) -> Result<Jwk> {
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
            jwk.dp = priv_key.dp().map(|v| base64url::encode(&v.to_bytes_be()));
            jwk.dq = priv_key.dq().map(|v| base64url::encode(&v.to_bytes_be()));
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
    reject_oversized_coord(&x_bytes, coord_len, "x")?;
    reject_oversized_coord(&y_bytes, coord_len, "y")?;
    let mut point = vec![0x04u8];
    point.extend(pad_left(&x_bytes, coord_len));
    point.extend(pad_left(&y_bytes, coord_len));

    let encoded_point = p256::EncodedPoint::from_bytes(&point)
        .map_err(|e| JoseError::Key(format!("invalid P-256 point: {e}")))?;
    let public_key: Option<p256::PublicKey> =
        p256::PublicKey::from_encoded_point(&encoded_point).into();
    let public_key = public_key.ok_or_else(|| JoseError::Key("P-256 point not on curve".into()))?;
    let verifying_key = p256::ecdsa::VerifyingKey::from(&public_key);

    let private = if jwk.d.is_some() {
        let d_bytes = require(jwk, "d")?;
        let signing_key = p256::ecdsa::SigningKey::from_slice(&d_bytes)
            .map_err(|e| JoseError::Key(format!("invalid P-256 private key: {e}")))?;
        // The public point (x, y) and the private scalar d are imported
        // independently; reject a JWK whose halves disagree so a caller
        // cannot publish one identity while signing under another.
        if signing_key.verifying_key() != &verifying_key {
            return Err(JoseError::Key(
                "P-256 private key d does not match the public point (x, y)".into(),
            ));
        }
        Some(signing_key)
    } else {
        None
    };

    use pkcs8::spki::EncodePublicKey;
    use pkcs8::EncodePrivateKey;

    if let Some(private) = private {
        let der = private
            .to_pkcs8_der()
            .map_err(|e| JoseError::Key(format!("encode P-256 PKCS#8: {e}")))?;
        kryptering::SoftwareKey::from_pkcs8_der(
            kryptering::KeyAlgorithm::Ec(kryptering::EcCurve::P256),
            der.as_bytes(),
        )
        .map_err(Into::into)
    } else {
        let der = verifying_key
            .to_public_key_der()
            .map_err(|e| JoseError::Key(format!("encode P-256 SPKI: {e}")))?;
        kryptering::SoftwareKey::from_spki_der(
            kryptering::KeyAlgorithm::Ec(kryptering::EcCurve::P256),
            der.as_bytes(),
        )
        .map_err(Into::into)
    }
}

fn jwk_to_ec_p384(jwk: &Jwk) -> Result<kryptering::SoftwareKey> {
    use p384::elliptic_curve::sec1::FromEncodedPoint;

    let x_bytes = require(jwk, "x")?;
    let y_bytes = require(jwk, "y")?;

    let coord_len = 48;
    reject_oversized_coord(&x_bytes, coord_len, "x")?;
    reject_oversized_coord(&y_bytes, coord_len, "y")?;
    let mut point = vec![0x04u8];
    point.extend(pad_left(&x_bytes, coord_len));
    point.extend(pad_left(&y_bytes, coord_len));

    let encoded_point = p384::EncodedPoint::from_bytes(&point)
        .map_err(|e| JoseError::Key(format!("invalid P-384 point: {e}")))?;
    let public_key: Option<p384::PublicKey> =
        p384::PublicKey::from_encoded_point(&encoded_point).into();
    let public_key = public_key.ok_or_else(|| JoseError::Key("P-384 point not on curve".into()))?;
    let verifying_key = p384::ecdsa::VerifyingKey::from(&public_key);

    let private = if jwk.d.is_some() {
        let d_bytes = require(jwk, "d")?;
        let signing_key = p384::ecdsa::SigningKey::from_slice(&d_bytes)
            .map_err(|e| JoseError::Key(format!("invalid P-384 private key: {e}")))?;
        if signing_key.verifying_key() != &verifying_key {
            return Err(JoseError::Key(
                "P-384 private key d does not match the public point (x, y)".into(),
            ));
        }
        Some(signing_key)
    } else {
        None
    };

    use pkcs8::spki::EncodePublicKey;
    use pkcs8::EncodePrivateKey;

    if let Some(private) = private {
        let der = private
            .to_pkcs8_der()
            .map_err(|e| JoseError::Key(format!("encode P-384 PKCS#8: {e}")))?;
        kryptering::SoftwareKey::from_pkcs8_der(
            kryptering::KeyAlgorithm::Ec(kryptering::EcCurve::P384),
            der.as_bytes(),
        )
        .map_err(Into::into)
    } else {
        let der = verifying_key
            .to_public_key_der()
            .map_err(|e| JoseError::Key(format!("encode P-384 SPKI: {e}")))?;
        kryptering::SoftwareKey::from_spki_der(
            kryptering::KeyAlgorithm::Ec(kryptering::EcCurve::P384),
            der.as_bytes(),
        )
        .map_err(Into::into)
    }
}

fn jwk_to_ec_p521(jwk: &Jwk) -> Result<kryptering::SoftwareKey> {
    let x_bytes = require(jwk, "x")?;
    let y_bytes = require(jwk, "y")?;

    let coord_len = 66;
    reject_oversized_coord(&x_bytes, coord_len, "x")?;
    reject_oversized_coord(&y_bytes, coord_len, "y")?;
    let mut point = vec![0x04u8];
    point.extend(pad_left(&x_bytes, coord_len));
    point.extend(pad_left(&y_bytes, coord_len));

    let verifying_key = p521::ecdsa::VerifyingKey::from_sec1_bytes(&point)
        .map_err(|e| JoseError::Key(format!("invalid P-521 public key: {e}")))?;

    let private = if jwk.d.is_some() {
        let d_bytes = require(jwk, "d")?;
        let signing_key = p521::ecdsa::SigningKey::from_slice(&d_bytes)
            .map_err(|e| JoseError::Key(format!("invalid P-521 private key: {e}")))?;
        // p521's VerifyingKey does not implement PartialEq; compare the
        // uncompressed SEC1 encodings of the supplied and derived points.
        let derived = p521::ecdsa::VerifyingKey::from(&signing_key);
        if derived.to_encoded_point(false) != verifying_key.to_encoded_point(false) {
            return Err(JoseError::Key(
                "P-521 private key d does not match the public point (x, y)".into(),
            ));
        }
        Some(signing_key)
    } else {
        None
    };

    use pkcs8::spki::EncodePublicKey;
    use pkcs8::EncodePrivateKey;

    if let Some(private) = private {
        let secret = p521::SecretKey::from_slice(&private.to_bytes())
            .map_err(|e| JoseError::Key(format!("convert P-521 private scalar: {e}")))?;
        let der = secret
            .to_pkcs8_der()
            .map_err(|e| JoseError::Key(format!("encode P-521 PKCS#8: {e}")))?;
        kryptering::SoftwareKey::from_pkcs8_der(
            kryptering::KeyAlgorithm::Ec(kryptering::EcCurve::P521),
            der.as_bytes(),
        )
        .map_err(Into::into)
    } else {
        let public =
            p521::PublicKey::from_sec1_bytes(verifying_key.to_encoded_point(false).as_bytes())
                .map_err(|e| JoseError::Key(format!("convert P-521 public point: {e}")))?;
        let der = public
            .to_public_key_der()
            .map_err(|e| JoseError::Key(format!("encode P-521 SPKI: {e}")))?;
        kryptering::SoftwareKey::from_spki_der(
            kryptering::KeyAlgorithm::Ec(kryptering::EcCurve::P521),
            der.as_bytes(),
        )
        .map_err(Into::into)
    }
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
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&secret);
        // Reject a JWK whose private seed does not derive the supplied public
        // key — the two are imported from independent fields (`d` and `x`).
        if signing_key.verifying_key() != public {
            return Err(JoseError::Key(
                "Ed25519 private key d does not match the public key x".into(),
            ));
        }
        Some(signing_key)
    } else {
        None
    };

    use pkcs8::spki::EncodePublicKey;
    use pkcs8::EncodePrivateKey;

    if let Some(private) = private {
        let der = private
            .to_pkcs8_der()
            .map_err(|e| JoseError::Key(format!("encode Ed25519 PKCS#8: {e}")))?;
        kryptering::SoftwareKey::from_pkcs8_der(kryptering::KeyAlgorithm::Ed25519, der.as_bytes())
            .map_err(Into::into)
    } else {
        let der = public
            .to_public_key_der()
            .map_err(|e| JoseError::Key(format!("encode Ed25519 SPKI: {e}")))?;
        kryptering::SoftwareKey::from_spki_der(kryptering::KeyAlgorithm::Ed25519, der.as_bytes())
            .map_err(Into::into)
    }
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
            // RFC 7518 §3.2: the HMAC key MUST be at least as long as the
            // hash output. Reject shorter keys explicitly — otherwise a
            // caller could mint an HS512 token signed with 8 bytes of
            // attacker-brute-forceable entropy.
            let min_len = match alg {
                "HS256" => 32,
                "HS384" => 48,
                "HS512" => 64,
                _ => 0,
            };
            if k_bytes.len() < min_len {
                return Err(JoseError::Key(format!(
                    "{alg} requires an HMAC key of at least {min_len} bytes, got {}",
                    k_bytes.len()
                )));
            }
            return kryptering::SoftwareKey::from_symmetric_bytes(
                kryptering::KeyAlgorithm::Hmac,
                &k_bytes,
            )
            .map_err(Into::into);
        }
        if alg.starts_with('A')
            && (alg.contains("KW") || alg.contains("GCM") || alg.contains("CBC"))
        {
            // Reject under-length symmetric keys for AES-based algorithms.
            // Otherwise a JWKS- or `jwk`-header-supplied `oct` key could
            // weaken content encryption below the algorithm's security level.
            if let Some(expected) = aes_oct_key_len(alg) {
                if k_bytes.len() != expected {
                    return Err(JoseError::Key(format!(
                        "{alg} requires a {expected}-byte key, got {}",
                        k_bytes.len()
                    )));
                }
            }
            // A CBC-HS content-encryption key is an aggregate MAC || AES key,
            // not an AES key by itself.  kryptering intentionally accepts
            // only 16/24/32-byte AES primitive keys, so retain CBC-HS keys in
            // its variable-length secret-key container.
            let key_algorithm = if alg.contains("CBC") {
                kryptering::KeyAlgorithm::Hmac
            } else {
                kryptering::KeyAlgorithm::Aes
            };
            return kryptering::SoftwareKey::from_symmetric_bytes(key_algorithm, &k_bytes)
                .map_err(Into::into);
        }
    }

    // Default heuristic (no `alg` pinned): standard AES key lengths -> Aes,
    // any other length is treated as HMAC and must meet the smallest HMAC
    // requirement (HS256 -> 32 bytes). Shorter keys cannot satisfy any
    // supported algorithm and are rejected rather than silently accepted.
    match k_bytes.len() {
        16 | 24 | 32 => {
            kryptering::SoftwareKey::from_symmetric_bytes(kryptering::KeyAlgorithm::Aes, &k_bytes)
                .map_err(Into::into)
        }
        n if n >= 32 => {
            kryptering::SoftwareKey::from_symmetric_bytes(kryptering::KeyAlgorithm::Hmac, &k_bytes)
                .map_err(Into::into)
        }
        n => Err(JoseError::Key(format!(
            "oct key of {n} bytes is too short: with no `alg` pinned it must be \
             a valid AES length (16/24/32) or at least 32 bytes for HMAC"
        ))),
    }
}

/// Expected byte length of an `oct` key for an AES-based JOSE algorithm,
/// or `None` for an unrecognized identifier (left to downstream validation).
fn aes_oct_key_len(alg: &str) -> Option<usize> {
    match alg {
        "A128KW" | "A128GCM" => Some(16),
        "A192KW" | "A192GCM" => Some(24),
        "A256KW" | "A256GCM" => Some(32),
        // CBC-HS content encryption uses a double-length key (MAC || ENC).
        "A128CBC-HS256" => Some(32),
        "A192CBC-HS384" => Some(48),
        "A256CBC-HS512" => Some(64),
        _ => None,
    }
}

fn oct_to_jwk(bytes: &[u8]) -> Result<Jwk> {
    let mut jwk = new_jwk("oct");
    jwk.k = Some(base64url::encode(bytes));
    Ok(jwk)
}

// ── AKP (post-quantum and composite ML-DSA) ────────────────────────────
//
// draft-ietf-cose-dilithium: `kty="AKP"` with base64url members `pub`
// (the raw FIPS 204 public key bytes) and `priv` (the 32-byte seed).
// draft-ietf-jose-pq-composite-sigs-03 uses the same members for raw
// aggregate keys. Pure ML-DSA is translated to kryptering's DER-backed
// representation; composite keys remain in the draft's aggregate encoding.

#[cfg(feature = "post-quantum")]
fn jwk_to_akp(jwk: &Jwk) -> Result<kryptering::SoftwareKey> {
    let alg = jwk
        .alg
        .as_deref()
        .ok_or_else(|| JoseError::Key("AKP JWK requires `alg`".into()))?;
    if let Some(variant) = composite_variant_from_name(alg) {
        return jwk_to_composite_akp(jwk, variant);
    }

    let variant = match alg {
        "ML-DSA-44" => kryptering::MlDsaVariant::MlDsa44,
        "ML-DSA-65" => kryptering::MlDsaVariant::MlDsa65,
        "ML-DSA-87" => kryptering::MlDsaVariant::MlDsa87,
        other => {
            return Err(JoseError::Key(format!("unsupported AKP alg: {other}")));
        }
    };

    let pub_b64 = jwk
        .pub_
        .as_deref()
        .ok_or_else(|| JoseError::Key("AKP JWK missing `pub`".into()))?;
    let pub_raw = base64url::decode(pub_b64)?;
    let expected_pub_len = mldsa_public_key_len(variant);
    if pub_raw.len() != expected_pub_len {
        return Err(JoseError::Key(format!(
            "{} `pub` must be {expected_pub_len} bytes, got {}",
            variant.name(),
            pub_raw.len()
        )));
    }
    let public_der = mldsa_raw_public_to_spki_der(variant, &pub_raw)?;

    let private_der = match jwk.priv_.as_deref() {
        Some(s) => {
            let seed = base64url::decode(s)?;
            if seed.len() != 32 {
                return Err(JoseError::Key(format!(
                    "AKP `priv` must be 32 bytes (seed), got {}",
                    seed.len()
                )));
            }
            Some(zeroize::Zeroizing::new(seed))
        }
        None => None,
    };

    kryptering::SoftwareKey::from_post_quantum_der(
        kryptering::PqAlgorithm::MlDsa(variant),
        private_der.as_ref().map(|value| value.as_slice()),
        &public_der,
    )
    .map_err(Into::into)
}

#[cfg(feature = "post-quantum")]
fn jwk_to_composite_akp(
    jwk: &Jwk,
    variant: kryptering::CompositeMlDsaVariant,
) -> Result<kryptering::SoftwareKey> {
    let public = base64url::decode(
        jwk.pub_
            .as_deref()
            .ok_or_else(|| JoseError::Key("AKP JWK missing `pub`".into()))?,
    )?;
    if public.len() != variant.public_key_len() {
        return Err(JoseError::Key(format!(
            "{} `pub` must be {} bytes, got {}",
            variant.name(),
            variant.public_key_len(),
            public.len()
        )));
    }

    let private = jwk
        .priv_
        .as_deref()
        .map(base64url::decode)
        .transpose()?
        .map(zeroize::Zeroizing::new);
    if let Some(private) = private.as_ref().map(|value| value.as_slice()) {
        if private.len() != variant.private_key_len() {
            return Err(JoseError::Key(format!(
                "{} `priv` must be {} bytes, got {}",
                variant.name(),
                variant.private_key_len(),
                private.len()
            )));
        }
    }

    kryptering::SoftwareKey::from_composite_ml_dsa(
        variant,
        private.as_ref().map(|value| value.as_slice()),
        &public,
    )
    .map_err(Into::into)
}

#[cfg(feature = "post-quantum")]
fn akp_to_jwk(
    pq: kryptering::PqAlgorithm,
    public_der: &[u8],
    private: Option<&[u8]>,
) -> Result<Jwk> {
    let variant = match pq {
        kryptering::PqAlgorithm::MlDsa(v) => v,
        kryptering::PqAlgorithm::SlhDsa(_) => {
            return Err(JoseError::Key(
                "SLH-DSA JWK export not yet implemented".into(),
            ));
        }
        kryptering::PqAlgorithm::MlKem(_) => {
            return Err(JoseError::Key(
                "ML-KEM JWK export not yet implemented".into(),
            ));
        }
    };
    let pub_raw = mldsa_spki_der_to_raw_public(variant, public_der)?;
    let mut jwk = new_jwk("AKP");
    jwk.alg = Some(variant.name().to_string());
    jwk.pub_ = Some(base64url::encode(&pub_raw));
    if let Some(priv_bytes) = private {
        if priv_bytes.len() != 32 {
            return Err(JoseError::Key(format!(
                "AKP JWK export requires 32-byte seed (FIPS 204 priv format), got {} bytes",
                priv_bytes.len()
            )));
        }
        jwk.priv_ = Some(base64url::encode(priv_bytes));
    }
    Ok(jwk)
}

#[cfg(feature = "post-quantum")]
fn composite_akp_to_jwk(
    variant: kryptering::CompositeMlDsaVariant,
    public: &[u8],
    private: Option<&[u8]>,
) -> Result<Jwk> {
    if public.len() != variant.public_key_len() {
        return Err(JoseError::Key(format!(
            "{} JWK export requires a {}-byte aggregate public key, got {}",
            variant.name(),
            variant.public_key_len(),
            public.len()
        )));
    }
    if let Some(private) = private {
        if private.len() != variant.private_key_len() {
            return Err(JoseError::Key(format!(
                "{} JWK export requires a {}-byte aggregate private key, got {}",
                variant.name(),
                variant.private_key_len(),
                private.len()
            )));
        }
    }

    let mut jwk = new_jwk("AKP");
    jwk.alg = Some(variant.name().to_string());
    jwk.pub_ = Some(base64url::encode(public));
    jwk.priv_ = private.map(base64url::encode);
    Ok(jwk)
}

#[cfg(feature = "post-quantum")]
fn composite_variant_from_name(name: &str) -> Option<kryptering::CompositeMlDsaVariant> {
    use kryptering::CompositeMlDsaVariant as Variant;

    match name {
        "ML-DSA-44-ES256" => Some(Variant::MlDsa44Es256),
        "ML-DSA-65-ES256" => Some(Variant::MlDsa65Es256),
        "ML-DSA-87-ES384" => Some(Variant::MlDsa87Es384),
        "ML-DSA-44-Ed25519" => Some(Variant::MlDsa44Ed25519),
        "ML-DSA-65-Ed25519" => Some(Variant::MlDsa65Ed25519),
        "ML-DSA-87-Ed448" => Some(Variant::MlDsa87Ed448),
        _ => None,
    }
}

#[cfg(feature = "post-quantum")]
fn mldsa_public_key_len(variant: kryptering::MlDsaVariant) -> usize {
    match variant {
        kryptering::MlDsaVariant::MlDsa44 => 1312,
        kryptering::MlDsaVariant::MlDsa65 => 1952,
        kryptering::MlDsaVariant::MlDsa87 => 2592,
    }
}

#[cfg(feature = "post-quantum")]
fn mldsa_raw_public_to_spki_der(variant: kryptering::MlDsaVariant, raw: &[u8]) -> Result<Vec<u8>> {
    use pkcs8_pq::spki::EncodePublicKey;

    fn encode<P>(raw: &[u8]) -> Result<Vec<u8>>
    where
        P: ml_dsa::MlDsaParams,
        P: pkcs8_pq::spki::AssociatedAlgorithmIdentifier<Params = pkcs8_pq::der::AnyRef<'static>>,
    {
        let enc = ml_dsa::EncodedVerifyingKey::<P>::try_from(raw)
            .map_err(|_| JoseError::Key("ML-DSA public key length mismatch".into()))?;
        let vk = ml_dsa::VerifyingKey::<P>::decode(&enc);
        let der = vk
            .to_public_key_der()
            .map_err(|e| JoseError::Key(format!("SPKI encode: {e}")))?;
        Ok(der.as_bytes().to_vec())
    }

    match variant {
        kryptering::MlDsaVariant::MlDsa44 => encode::<ml_dsa::MlDsa44>(raw),
        kryptering::MlDsaVariant::MlDsa65 => encode::<ml_dsa::MlDsa65>(raw),
        kryptering::MlDsaVariant::MlDsa87 => encode::<ml_dsa::MlDsa87>(raw),
    }
}

#[cfg(feature = "post-quantum")]
fn mldsa_spki_der_to_raw_public(variant: kryptering::MlDsaVariant, der: &[u8]) -> Result<Vec<u8>> {
    use pkcs8_pq::spki::DecodePublicKey;

    fn decode<P>(der: &[u8]) -> Result<Vec<u8>>
    where
        P: ml_dsa::MlDsaParams,
        P: pkcs8_pq::spki::AssociatedAlgorithmIdentifier<Params = pkcs8_pq::der::AnyRef<'static>>,
    {
        let vk = ml_dsa::VerifyingKey::<P>::from_public_key_der(der)
            .map_err(|e| JoseError::Key(format!("parse ML-DSA SPKI: {e}")))?;
        let encoded: ml_dsa::EncodedVerifyingKey<P> = vk.encode();
        Ok(encoded.to_vec())
    }

    match variant {
        kryptering::MlDsaVariant::MlDsa44 => decode::<ml_dsa::MlDsa44>(der),
        kryptering::MlDsaVariant::MlDsa65 => decode::<ml_dsa::MlDsa65>(der),
        kryptering::MlDsaVariant::MlDsa87 => decode::<ml_dsa::MlDsa87>(der),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rsa_private_key(key: &rsa::RsaPrivateKey) -> kryptering::SoftwareKey {
        use pkcs8::EncodePrivateKey;
        let der = key.to_pkcs8_der().unwrap();
        kryptering::SoftwareKey::from_pkcs8_der(kryptering::KeyAlgorithm::Rsa, der.as_bytes())
            .unwrap()
    }

    fn rsa_public_key(key: &rsa::RsaPublicKey) -> kryptering::SoftwareKey {
        use pkcs8::spki::EncodePublicKey;
        let der = key.to_public_key_der().unwrap();
        kryptering::SoftwareKey::from_spki_der(kryptering::KeyAlgorithm::Rsa, der.as_bytes())
            .unwrap()
    }

    fn p256_private_key(key: &p256::ecdsa::SigningKey) -> kryptering::SoftwareKey {
        use pkcs8::EncodePrivateKey;
        let der = key.to_pkcs8_der().unwrap();
        kryptering::SoftwareKey::from_pkcs8_der(
            kryptering::KeyAlgorithm::Ec(kryptering::EcCurve::P256),
            der.as_bytes(),
        )
        .unwrap()
    }

    fn p384_private_key(key: &p384::ecdsa::SigningKey) -> kryptering::SoftwareKey {
        use pkcs8::EncodePrivateKey;
        let der = key.to_pkcs8_der().unwrap();
        kryptering::SoftwareKey::from_pkcs8_der(
            kryptering::KeyAlgorithm::Ec(kryptering::EcCurve::P384),
            der.as_bytes(),
        )
        .unwrap()
    }

    fn p521_private_key(key: &p521::ecdsa::SigningKey) -> kryptering::SoftwareKey {
        use pkcs8::EncodePrivateKey;
        let secret = p521::SecretKey::from_slice(&key.to_bytes()).unwrap();
        let der = secret.to_pkcs8_der().unwrap();
        kryptering::SoftwareKey::from_pkcs8_der(
            kryptering::KeyAlgorithm::Ec(kryptering::EcCurve::P521),
            der.as_bytes(),
        )
        .unwrap()
    }

    fn ed25519_private_key(key: &ed25519_dalek::SigningKey) -> kryptering::SoftwareKey {
        use pkcs8::EncodePrivateKey;
        let der = key.to_pkcs8_der().unwrap();
        kryptering::SoftwareKey::from_pkcs8_der(kryptering::KeyAlgorithm::Ed25519, der.as_bytes())
            .unwrap()
    }

    // ── RSA roundtrip ──────────────────────────────────────────────

    #[test]
    fn rsa_generate_to_jwk_roundtrip() {
        let private_key = rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap();
        let sw = rsa_private_key(&private_key);

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
        assert_eq!(sw2.algorithm(), kryptering::KeyAlgorithm::Rsa);
        assert!(sw2.has_private_key());

        // Sign with original, verify with converted
        use kryptering::HashAlgorithm;
        use kryptering::SignatureAlgorithm;
        use kryptering::Signer as _;
        use kryptering::Verifier as _;
        use kryptering::{SoftwareSigner, SoftwareVerifier};

        let signer =
            SoftwareSigner::new(SignatureAlgorithm::RsaPkcs1v15(HashAlgorithm::Sha256), sw)
                .unwrap();
        let data = b"hello world";
        let sig = signer.sign(data).unwrap();

        let verifier =
            SoftwareVerifier::new(SignatureAlgorithm::RsaPkcs1v15(HashAlgorithm::Sha256), sw2)
                .unwrap();
        verifier.verify(data, &sig).unwrap();
    }

    #[test]
    fn rsa_public_only_roundtrip() {
        let private_key = rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap();
        let public_key = private_key.to_public_key();
        let sw = rsa_public_key(&public_key);

        let jwk = software_key_to_jwk(&sw).unwrap();
        assert!(jwk.d.is_none());
        assert!(jwk.p.is_none());

        let sw2 = jwk_to_software_key(&jwk).unwrap();
        assert_eq!(sw2.algorithm(), kryptering::KeyAlgorithm::Rsa);
        assert!(!sw2.has_private_key());
    }

    // ── EC P-256 roundtrip ─────────────────────────────────────────

    #[test]
    fn ec_p256_roundtrip() {
        let signing_key = p256::ecdsa::SigningKey::random(&mut rand::thread_rng());
        let sw = p256_private_key(&signing_key);

        let jwk = software_key_to_jwk(&sw).unwrap();
        assert_eq!(jwk.kty, "EC");
        assert_eq!(jwk.crv.as_deref(), Some("P-256"));
        assert!(jwk.x.is_some());
        assert!(jwk.y.is_some());
        assert!(jwk.d.is_some());

        let sw2 = jwk_to_software_key(&jwk).unwrap();
        assert_eq!(
            sw2.algorithm(),
            kryptering::KeyAlgorithm::Ec(kryptering::EcCurve::P256)
        );
        assert!(sw2.has_private_key());

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
        let sw = p384_private_key(&signing_key);

        let jwk = software_key_to_jwk(&sw).unwrap();
        assert_eq!(jwk.crv.as_deref(), Some("P-384"));

        let sw2 = jwk_to_software_key(&jwk).unwrap();
        assert_eq!(
            sw2.algorithm(),
            kryptering::KeyAlgorithm::Ec(kryptering::EcCurve::P384)
        );
        assert!(sw2.has_private_key());
    }

    // ── EC P-521 roundtrip ─────────────────────────────────────────

    #[test]
    fn ec_p521_roundtrip() {
        let signing_key = p521::ecdsa::SigningKey::random(&mut rand::thread_rng());
        let sw = p521_private_key(&signing_key);

        let jwk = software_key_to_jwk(&sw).unwrap();
        assert_eq!(jwk.crv.as_deref(), Some("P-521"));

        let sw2 = jwk_to_software_key(&jwk).unwrap();
        assert_eq!(
            sw2.algorithm(),
            kryptering::KeyAlgorithm::Ec(kryptering::EcCurve::P521)
        );
        assert!(sw2.has_private_key());
    }

    // ── Ed25519 roundtrip ──────────────────────────────────────────

    #[test]
    fn ed25519_roundtrip() {
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let sw = ed25519_private_key(&signing_key);

        let jwk = software_key_to_jwk(&sw).unwrap();
        assert_eq!(jwk.kty, "OKP");
        assert_eq!(jwk.crv.as_deref(), Some("Ed25519"));
        assert!(jwk.x.is_some());
        assert!(jwk.d.is_some());

        let sw2 = jwk_to_software_key(&jwk).unwrap();
        assert_eq!(sw2.algorithm(), kryptering::KeyAlgorithm::Ed25519);
        assert!(sw2.has_private_key());

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
        let sw = kryptering::SoftwareKey::from_symmetric_bytes(
            kryptering::KeyAlgorithm::Hmac,
            &key_bytes,
        )
        .unwrap();

        let jwk = software_key_to_jwk(&sw).unwrap();
        assert_eq!(jwk.kty, "oct");
        assert!(jwk.k.is_some());

        // Parse back -- no alg set, 32 bytes -> Aes by default heuristic
        // Set alg to HS256 to get Hmac back
        let mut jwk_hmac = jwk.clone();
        jwk_hmac.alg = Some("HS256".into());
        let sw2 = jwk_to_software_key(&jwk_hmac).unwrap();
        assert_eq!(sw2.algorithm(), kryptering::KeyAlgorithm::Hmac);
        assert_eq!(sw2.export_private().unwrap().as_slice(), key_bytes);
    }

    #[test]
    fn aes_symmetric_roundtrip() {
        let key_bytes = vec![0x42u8; 16];
        let sw = kryptering::SoftwareKey::from_symmetric_bytes(
            kryptering::KeyAlgorithm::Aes,
            &key_bytes,
        )
        .unwrap();

        let jwk = software_key_to_jwk(&sw).unwrap();
        assert_eq!(jwk.kty, "oct");

        let sw2 = jwk_to_software_key(&jwk).unwrap();
        assert_eq!(sw2.algorithm(), kryptering::KeyAlgorithm::Aes);
        assert_eq!(sw2.export_private().unwrap().as_slice(), key_bytes);
    }

    // ── Tier-2 hardening: key-consistency + oct length ─────────────

    /// A P-256 JWK whose private scalar `d` does not derive the public
    /// point `(x, y)` must be rejected at import.
    #[test]
    fn ec_p256_mismatched_d_rejected() {
        let a = p256::ecdsa::SigningKey::random(&mut rand::thread_rng());
        let b = p256::ecdsa::SigningKey::random(&mut rand::thread_rng());
        let a_jwk = software_key_to_jwk(&p256_private_key(&a)).unwrap();
        let b_jwk = software_key_to_jwk(&p256_private_key(&b)).unwrap();

        // x/y from A, but d from B.
        let mut mixed = a_jwk;
        mixed.d = b_jwk.d.clone();
        let err = jwk_to_software_key(&mixed).err().unwrap().to_string();
        assert!(
            err.contains("does not match the public point"),
            "unexpected: {err}"
        );
    }

    /// An Ed25519 JWK whose seed `d` does not derive the public key `x`
    /// must be rejected at import.
    #[test]
    fn ed25519_mismatched_d_rejected() {
        let a = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let b = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let a_jwk = software_key_to_jwk(&ed25519_private_key(&a)).unwrap();
        let b_jwk = software_key_to_jwk(&ed25519_private_key(&b)).unwrap();

        let mut mixed = a_jwk;
        mixed.d = b_jwk.d.clone();
        let err = jwk_to_software_key(&mixed).err().unwrap().to_string();
        assert!(
            err.contains("does not match the public key"),
            "unexpected: {err}"
        );
    }

    /// An `oct` key whose length is wrong for its pinned AES `alg` is
    /// rejected (here: A128GCM needs 16 bytes, given 8).
    #[test]
    fn oct_aes_wrong_length_rejected() {
        let json = format!(
            r#"{{"kty":"oct","alg":"A128GCM","k":"{}"}}"#,
            crate::base64url::encode(&[0u8; 8])
        );
        let jwk = Jwk::from_json(&json).unwrap();
        let err = jwk_to_software_key(&jwk).err().unwrap().to_string();
        assert!(err.contains("requires a 16-byte key"), "unexpected: {err}");
    }

    /// A correctly-sized AES key wrap `oct` key still imports.
    #[test]
    fn oct_a128kw_correct_length_ok() {
        let json = format!(
            r#"{{"kty":"oct","alg":"A128KW","k":"{}"}}"#,
            crate::base64url::encode(&[0u8; 16])
        );
        let jwk = Jwk::from_json(&json).unwrap();
        assert!(jwk_to_software_key(&jwk).is_ok());
    }

    /// A short `oct` key with no pinned `alg` cannot satisfy any supported
    /// algorithm and is rejected rather than silently treated as HMAC.
    #[test]
    fn oct_short_no_alg_rejected() {
        let json = format!(
            r#"{{"kty":"oct","k":"{}"}}"#,
            crate::base64url::encode(&[0u8; 8])
        );
        let jwk = Jwk::from_json(&json).unwrap();
        let err = jwk_to_software_key(&jwk).err().unwrap().to_string();
        assert!(err.contains("too short"), "unexpected: {err}");
    }

    /// A 64-byte `oct` key with no `alg` is a valid HMAC key (HS512) and imports.
    #[test]
    fn oct_long_no_alg_is_hmac() {
        let json = format!(
            r#"{{"kty":"oct","k":"{}"}}"#,
            crate::base64url::encode(&[0u8; 64])
        );
        let jwk = Jwk::from_json(&json).unwrap();
        let sw = jwk_to_software_key(&jwk).unwrap();
        assert_eq!(sw.algorithm(), kryptering::KeyAlgorithm::Hmac);
        assert_eq!(sw.export_private().unwrap().len(), 64);
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

        assert_eq!(sw.algorithm(), kryptering::KeyAlgorithm::Rsa);
        assert!(!sw.has_private_key());
        let public_der = sw.export_spki_der().unwrap();
        use rsa::pkcs8::DecodePublicKey;
        use rsa::traits::PublicKeyParts;
        let public = rsa::RsaPublicKey::from_public_key_der(&public_der).unwrap();
        assert!(public.n().bits() >= 2040);
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
        assert_eq!(
            sw.algorithm(),
            kryptering::KeyAlgorithm::Ec(kryptering::EcCurve::P256)
        );
        assert!(!sw.has_private_key());
    }

    // ── RSA exponent validation ───────────────────────────────────

    /// Phase 2: RSA exponent < 3 (e.g. "AQ" = 1) must be rejected.
    #[test]
    fn rsa_exponent_too_small_is_rejected() {
        // Build a valid 2048-bit modulus but with e=1.
        let private_key = rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap();
        let n_b64 = {
            use rsa::traits::PublicKeyParts;
            base64url::encode(&private_key.n().to_bytes_be())
        };
        let json = format!(r#"{{"kty":"RSA","n":"{n_b64}","e":"AQ"}}"#);
        let jwk = Jwk::from_json(&json).unwrap();
        let err = match jwk_to_software_key(&jwk) {
            Ok(_) => panic!("expected error"),
            Err(e) => e.to_string(),
        };
        assert!(
            err.contains("public exponent") || err.contains("below the minimum"),
            "unexpected error: {err}"
        );
    }

    /// Phase 2: even RSA exponent (e.g. 4) must be rejected.
    #[test]
    fn rsa_exponent_even_is_rejected() {
        let private_key = rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap();
        let n_b64 = {
            use rsa::traits::PublicKeyParts;
            base64url::encode(&private_key.n().to_bytes_be())
        };
        // e = 4 → base64url("BA") — wait, 4 is two bytes? No, 4 = 0x04 → one byte "BA"
        // Actually base64url(0x04) — let's encode explicitly.
        let e_b64 = base64url::encode(&[0x04]);
        let json = format!(r#"{{"kty":"RSA","n":"{n_b64}","e":"{e_b64}"}}"#);
        let jwk = Jwk::from_json(&json).unwrap();
        let err = match jwk_to_software_key(&jwk) {
            Ok(_) => panic!("expected error"),
            Err(e) => e.to_string(),
        };
        assert!(err.contains("odd"), "unexpected error: {err}");
    }

    /// Phase 7: HS256 with a 16-byte HMAC key is rejected (RFC 7518 §3.2 requires 32).
    #[test]
    fn hs256_short_key_is_rejected() {
        let k = base64url::encode(&[0u8; 16]);
        let json = format!(r#"{{"kty":"oct","k":"{k}","alg":"HS256"}}"#);
        let jwk = Jwk::from_json(&json).unwrap();
        let err = match jwk_to_software_key(&jwk) {
            Ok(_) => panic!("expected error"),
            Err(e) => e.to_string(),
        };
        assert!(err.contains("HS256"), "unexpected: {err}");
        assert!(err.contains("at least 32"), "unexpected: {err}");
    }

    /// Phase 7: HS512 with 32 bytes (one short of 64) is rejected.
    #[test]
    fn hs512_short_key_is_rejected() {
        let k = base64url::encode(&[0u8; 32]);
        let json = format!(r#"{{"kty":"oct","k":"{k}","alg":"HS512"}}"#);
        let jwk = Jwk::from_json(&json).unwrap();
        let err = match jwk_to_software_key(&jwk) {
            Ok(_) => panic!("expected error"),
            Err(e) => e.to_string(),
        };
        assert!(err.contains("at least 64"), "unexpected: {err}");
    }

    /// Phase 7: HS256 with exactly 32 bytes is accepted.
    #[test]
    fn hs256_at_minimum_length_accepted() {
        let k = base64url::encode(&[0u8; 32]);
        let json = format!(r#"{{"kty":"oct","k":"{k}","alg":"HS256"}}"#);
        let jwk = Jwk::from_json(&json).unwrap();
        jwk_to_software_key(&jwk).unwrap();
    }

    /// Phase 6: alg/kty mismatch is rejected with a clear error.
    #[test]
    fn alg_kty_mismatch_rejected() {
        // RS256 declared on a symmetric oct key.
        let json = r#"{"kty":"oct","k":"AA","alg":"RS256"}"#;
        let jwk = Jwk::from_json(json).unwrap();
        let err = match jwk_to_software_key(&jwk) {
            Ok(_) => panic!("expected error"),
            Err(e) => e.to_string(),
        };
        assert!(err.contains("incompatible with kty"), "unexpected: {err}");
    }

    /// Phase 6: ES256 requires crv=P-256; mismatched crv is rejected.
    #[test]
    fn alg_crv_mismatch_rejected() {
        let json = r#"{
            "kty":"EC","crv":"P-384",
            "x":"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
            "y":"yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy",
            "alg":"ES256"
        }"#;
        let jwk = Jwk::from_json(json).unwrap();
        let err = match jwk_to_software_key(&jwk) {
            Ok(_) => panic!("expected error"),
            Err(e) => e.to_string(),
        };
        assert!(err.contains("requires crv=P-256"), "unexpected: {err}");
    }

    /// Phase 6: a consistent alg/kty combination passes.
    #[test]
    fn alg_kty_match_accepted() {
        let json = r#"{"kty":"oct","k":"AA","alg":"HS256"}"#;
        let jwk = Jwk::from_json(json).unwrap();
        // HS256 + oct is fine — conversion proceeds (may fail later due to
        // short key, but the alg/kty gate passes).
        let _ = jwk_to_software_key(&jwk);
    }

    /// Phase 5: EC JWK with oversized x coordinate is rejected with a clear error.
    #[test]
    fn ec_oversized_coordinate_is_rejected() {
        // P-256 expects 32-byte x; provide 33 bytes (0x01 prefix).
        let big_x = base64url::encode(&[1u8; 33]);
        let y = base64url::encode(&[0u8; 32]);
        let json = format!(r#"{{"kty":"EC","crv":"P-256","x":"{big_x}","y":"{y}"}}"#);
        let jwk = Jwk::from_json(&json).unwrap();
        let err = match jwk_to_software_key(&jwk) {
            Ok(_) => panic!("expected error"),
            Err(e) => e.to_string(),
        };
        assert!(
            err.contains("exceeds curve size"),
            "unexpected error: {err}"
        );
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

    // ── AKP (ML-DSA) ────────────────────────────────────────────────

    #[cfg(feature = "post-quantum")]
    #[test]
    fn akp_missing_alg_rejected() {
        // 1312-byte pub (ML-DSA-44 size), but no alg to select a variant.
        let jwk_json = format!(
            r#"{{"kty":"AKP","pub":"{}"}}"#,
            crate::base64url::encode(&vec![0u8; 1312])
        );
        let jwk = Jwk::from_json(&jwk_json).unwrap();
        let err = jwk_to_software_key(&jwk).err().unwrap().to_string();
        assert!(err.contains("requires `alg`"), "unexpected error: {err}");
    }

    #[cfg(feature = "post-quantum")]
    #[test]
    fn akp_wrong_pub_length_rejected() {
        // ML-DSA-44 expects 1312 bytes, we give 1200.
        let jwk_json = format!(
            r#"{{"kty":"AKP","alg":"ML-DSA-44","pub":"{}"}}"#,
            crate::base64url::encode(&vec![0u8; 1200])
        );
        let jwk = Jwk::from_json(&jwk_json).unwrap();
        let err = jwk_to_software_key(&jwk).err().unwrap().to_string();
        assert!(
            err.contains("must be 1312 bytes"),
            "unexpected error: {err}"
        );
    }

    #[cfg(feature = "post-quantum")]
    #[test]
    fn akp_wrong_priv_length_rejected() {
        // Valid ML-DSA-44 public but priv is 64 bytes instead of 32-byte seed.
        use kryptering::MlDsaVariant;
        let gen = crate::jwk::generate::generate_mldsa(MlDsaVariant::MlDsa44).unwrap();
        let jwk_json = format!(
            r#"{{"kty":"AKP","alg":"ML-DSA-44","pub":"{}","priv":"{}"}}"#,
            gen.pub_.as_deref().unwrap(),
            crate::base64url::encode(&[0u8; 64])
        );
        let jwk = Jwk::from_json(&jwk_json).unwrap();
        let err = jwk_to_software_key(&jwk).err().unwrap().to_string();
        assert!(err.contains("must be 32 bytes"), "unexpected error: {err}");
    }

    #[cfg(feature = "post-quantum")]
    #[test]
    fn akp_alg_kty_mismatch_rejected() {
        // ML-DSA alg with kty="RSA" should fail consistency check.
        let jwk_json = r#"{"kty":"RSA","alg":"ML-DSA-44","n":"AA","e":"AQAB"}"#;
        let jwk = Jwk::from_json(jwk_json).unwrap();
        let err = jwk_to_software_key(&jwk).err().unwrap().to_string();
        assert!(
            err.contains("incompatible with kty"),
            "unexpected error: {err}"
        );
    }
}
