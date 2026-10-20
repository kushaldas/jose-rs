//! JWK key generation.

use crate::algorithm::JweEncryption;
use crate::error::{JoseError, Result};
use crate::jwk::convert::software_key_to_jwk;
use crate::jwk::Jwk;
use zeroize::Zeroizing;

fn rng() -> getrandom::rand_core::UnwrapErr<getrandom::SysRng> {
    getrandom::rand_core::UnwrapErr(getrandom::SysRng)
}

/// Generate an RSA key pair as a JWK.
///
/// `bits` is the modulus size in bits (e.g. 2048, 3072, 4096). Must be at
/// at least [`crate::MIN_RSA_BITS`] (2048) per RFC 7518 §3.3 and at most
/// [`crate::MAX_RSA_BITS`] (8192) to bound key-generation work.
pub fn generate_rsa(bits: usize) -> Result<Jwk> {
    use pkcs8::EncodePrivateKey;

    crate::ensure_rsa_bits(bits)?;
    let private_key = rsa::RsaPrivateKey::new(&mut rng(), bits)
        .map_err(|e| JoseError::Key(format!("RSA keygen failed: {e}")))?;
    let der = private_key
        .to_pkcs8_der()
        .map_err(|e| JoseError::Key(format!("RSA PKCS#8 encode failed: {e}")))?;
    let sw =
        kryptering::SoftwareKey::from_pkcs8_der(kryptering::KeyAlgorithm::Rsa, der.as_bytes())?;
    software_key_to_jwk(&sw)
}

/// Generate an EC key pair as a JWK.
///
/// `curve` must be one of `"P-256"`, `"P-384"`, or `"P-521"`.
pub fn generate_ec(curve: &str) -> Result<Jwk> {
    use p256::elliptic_curve::Generate;
    use pkcs8::EncodePrivateKey;

    let sw = match curve {
        "P-256" => {
            let sk = p256::ecdsa::SigningKey::generate_from_rng(&mut rng());
            let der = sk
                .to_pkcs8_der()
                .map_err(|e| JoseError::Key(format!("P-256 PKCS#8 encode failed: {e}")))?;
            kryptering::SoftwareKey::from_pkcs8_der(
                kryptering::KeyAlgorithm::Ec(kryptering::EcCurve::P256),
                der.as_bytes(),
            )?
        }
        "P-384" => {
            let sk = p384::ecdsa::SigningKey::generate_from_rng(&mut rng());
            let der = sk
                .to_pkcs8_der()
                .map_err(|e| JoseError::Key(format!("P-384 PKCS#8 encode failed: {e}")))?;
            kryptering::SoftwareKey::from_pkcs8_der(
                kryptering::KeyAlgorithm::Ec(kryptering::EcCurve::P384),
                der.as_bytes(),
            )?
        }
        "P-521" => {
            let sk = p521::ecdsa::SigningKey::generate_from_rng(&mut rng());
            let secret = p521::SecretKey::from_slice(&sk.to_bytes())
                .map_err(|e| JoseError::Key(format!("P-521 key conversion failed: {e}")))?;
            let der = secret
                .to_pkcs8_der()
                .map_err(|e| JoseError::Key(format!("P-521 PKCS#8 encode failed: {e}")))?;
            kryptering::SoftwareKey::from_pkcs8_der(
                kryptering::KeyAlgorithm::Ec(kryptering::EcCurve::P521),
                der.as_bytes(),
            )?
        }
        other => return Err(JoseError::Key(format!("unsupported EC curve: {other}"))),
    };
    software_key_to_jwk(&sw)
}

/// Generate an Ed25519 key pair as a JWK.
///
/// The key has no `alg` pin. Choose `Ed25519` for the fully specified wire
/// identifier or `EdDSA` for legacy interoperability before one-shot signing.
/// The two identifiers are not interchangeable in a pinned JWK.
///
/// ```
/// use jose_rs::{jwk, jws::compact, JoseHeader, JwsAlgorithm};
/// let mut key = jwk::generate_ed25519()?;
/// key.alg = Some(JwsAlgorithm::Ed25519.as_str().into());
/// let token = compact::sign_with_jwk(&key, b"payload", &JoseHeader::new("Ed25519"))?;
/// assert_eq!(compact::verify_with_jwk(&key.to_public_jwk(), &token)?, b"payload");
/// # Ok::<(), jose_rs::JoseError>(())
/// ```
pub fn generate_ed25519() -> Result<Jwk> {
    use pkcs8::EncodePrivateKey;

    let sk = ed25519_dalek::SigningKey::generate(&mut rng());
    let der = sk
        .to_pkcs8_der()
        .map_err(|e| JoseError::Key(format!("Ed25519 PKCS#8 encode failed: {e}")))?;
    let sw =
        kryptering::SoftwareKey::from_pkcs8_der(kryptering::KeyAlgorithm::Ed25519, der.as_bytes())?;
    software_key_to_jwk(&sw)
}

/// Generate an X25519 key pair as an OKP JWK (RFC 8037 §2).
///
/// The public value is computed from the generated scalar rather than carried
/// alongside it as an independent choice, so the pair this returns always passes
/// the `d`-derives-`x` check that [`crate::jwk::jwk_to_software_key`] enforces on
/// import. That asymmetry is deliberate: the check exists because agreement multiplies
/// with `d` while a JWE publishes `x`, so a JWK with an inconsistent pair would
/// publish one identity and agree with another.
///
/// # Errors
///
/// [`JoseError::Crypto`] if the scalar multiplication fails, which for a random
/// scalar means the degenerate all-zero scalar (probability 2^-255) or a backend
/// refusal of the operation.
///
/// ```
/// # fn main() -> Result<(), jose_rs::JoseError> {
/// let key = jose_rs::jwk::generate_x25519()?;
/// assert_eq!(key.kty, "OKP");
/// assert_eq!(key.crv.as_deref(), Some("X25519"));
/// # Ok(())
/// # }
/// ```
pub fn generate_x25519() -> Result<Jwk> {
    // X25519 clamps the scalar internally, so no masking is applied here; the
    // value must simply be uniformly random and 32 octets long.
    let mut secret = Zeroizing::new([0u8; 32]);
    getrandom::fill(&mut *secret).map_err(|e| {
        JoseError::Crypto(kryptering::Error::Crypto(format!(
            "operating-system randomness failed: {e}"
        )))
    })?;
    let public = kryptering::software::keyagreement::ecdh_x25519(
        &crate::jwk::X25519_BASEPOINT,
        &secret[..],
    )?;
    let sw = kryptering::SoftwareKey::from_x25519(Some(&secret[..]), &public)?;
    software_key_to_jwk(&sw)
}

/// Generate a symmetric (oct) key as a JWK.
///
/// `len` is the key length in bytes (e.g. 16 for AES-128, 32 for AES-256 / HS256).
pub fn generate_symmetric(len: usize) -> Result<Jwk> {
    let mut key_bytes = vec![0u8; len];
    getrandom::fill(&mut key_bytes).map_err(|e| {
        JoseError::Crypto(kryptering::Error::Crypto(format!(
            "operating-system randomness failed: {e}"
        )))
    })?;
    let sw =
        kryptering::SoftwareKey::from_symmetric_bytes(kryptering::KeyAlgorithm::Hmac, &key_bytes)?;
    software_key_to_jwk(&sw)
}

/// Generate a symmetric (oct) key pinned to a specific JOSE algorithm.
///
/// This is the migration path for the JWK-first APIs that require `jwk.alg`
/// to be set explicitly. The returned JWK also pins `use` to `sig` for HMAC
/// algorithms and `enc` for JWE algorithms.
pub fn generate_symmetric_for_alg(alg: &str) -> Result<Jwk> {
    let (len, use_) = match alg {
        "HS256" => (32, "sig"),
        "HS384" => (48, "sig"),
        "HS512" => (64, "sig"),
        "A128KW" | "A128GCM" | "A128GCMKW" => (16, "enc"),
        "A192KW" | "A192GCM" | "A192GCMKW" => (24, "enc"),
        "A256KW" | "A256GCM" | "A256GCMKW" => (32, "enc"),
        "A128CBC-HS256" => (32, "enc"),
        "A192CBC-HS384" => (48, "enc"),
        "A256CBC-HS512" => (64, "enc"),
        "dir" => {
            return Err(JoseError::Key(
                "direct JWE keys depend on `enc`; use generate_direct_symmetric(enc)".into(),
            ))
        }
        other => {
            return Err(JoseError::Key(format!(
                "unsupported symmetric algorithm for key generation: {other}"
            )))
        }
    };

    let mut jwk = generate_symmetric(len)?;
    jwk.alg = Some(alg.into());
    jwk.use_ = Some(use_.into());
    Ok(jwk)
}

/// Generate a symmetric direct-encryption JWK pinned to `alg = "dir"`.
///
/// The key length is derived from the chosen content-encryption algorithm,
/// because direct encryption uses the JWK's `k` bytes as the CEK.
pub fn generate_direct_symmetric(enc: JweEncryption) -> Result<Jwk> {
    let len = enc.cek_size();
    let mut jwk = generate_symmetric(len)?;
    jwk.alg = Some("dir".into());
    jwk.use_ = Some("enc".into());
    Ok(jwk)
}

/// Generate an ML-DSA (FIPS 204) key pair as a JWK with `kty = "AKP"`.
///
/// Returns a JWK carrying:
/// - `alg`: `"ML-DSA-44"` / `"ML-DSA-65"` / `"ML-DSA-87"` (from `variant`)
/// - `pub`: raw FIPS 204 encoded public key bytes (base64url)
/// - `priv`: 32-byte FIPS 204 seed (base64url) — per
///   draft-ietf-cose-dilithium, the seed is the serialized private key.
///
/// Delegates to [`kryptering::generate_ml_dsa`] for the actual key
/// material so the crate keeps a single post-quantum RNG policy
/// (`getrandom::SysRng`, matching the signing path). jose-rs only
/// translates the resulting opaque software key into the AKP JWK wire
/// format. `Jwk::Drop` still zeroizes `priv`, and `SoftwareKey::Drop`
/// still zeroizes the seed, at both sides of the boundary.
#[cfg(feature = "post-quantum")]
pub fn generate_mldsa(variant: kryptering::MlDsaVariant) -> Result<Jwk> {
    let sw = kryptering::generate_ml_dsa(variant).map_err(JoseError::Crypto)?;
    software_key_to_jwk(&sw)
}

/// Generate a composite ML-DSA key pair as an AKP JWK.
///
/// The `pub` and `priv` members contain the aggregate raw encodings from
/// draft-ietf-jose-pq-composite-sigs-03. Both components are generated
/// atomically by kryptering and are bound to the selected composite variant.
#[cfg(feature = "post-quantum")]
pub fn generate_composite_mldsa(variant: kryptering::CompositeMlDsaVariant) -> Result<Jwk> {
    let sw = kryptering::generate_composite_ml_dsa(variant)?;
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
        assert_eq!(sw.algorithm(), kryptering::KeyAlgorithm::Rsa);
        assert!(sw.has_private_key());
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

    #[test]
    fn generate_symmetric_for_alg_sets_alg_and_use() {
        let jwk = generate_symmetric_for_alg("A256KW").unwrap();
        assert_eq!(jwk.alg.as_deref(), Some("A256KW"));
        assert_eq!(jwk.use_.as_deref(), Some("enc"));
        let sw = jwk_to_software_key(&jwk).unwrap();
        assert_eq!(sw.algorithm(), kryptering::KeyAlgorithm::Aes);
        assert_eq!(sw.export_private().unwrap().len(), 32);
    }

    #[test]
    fn generate_cbc_hs_symmetric_roundtrips_aggregate_key() {
        let jwk = generate_symmetric_for_alg("A192CBC-HS384").unwrap();
        assert_eq!(jwk.alg.as_deref(), Some("A192CBC-HS384"));
        assert_eq!(jwk.use_.as_deref(), Some("enc"));
        let sw = jwk_to_software_key(&jwk).unwrap();
        assert_eq!(sw.algorithm(), kryptering::KeyAlgorithm::Hmac);
        assert_eq!(sw.export_private().unwrap().len(), 48);
    }

    #[test]
    fn generate_direct_symmetric_sets_dir_alg() {
        let jwk = generate_direct_symmetric(JweEncryption::A128GCM).unwrap();
        assert_eq!(jwk.alg.as_deref(), Some("dir"));
        assert_eq!(jwk.use_.as_deref(), Some("enc"));
        let sw = jwk_to_software_key(&jwk).unwrap();
        assert_eq!(sw.algorithm(), kryptering::KeyAlgorithm::Aes);
        assert_eq!(sw.export_private().unwrap().len(), 16);
    }

    #[test]
    fn generate_direct_cbc_hs_roundtrips_aggregate_key() {
        let jwk = generate_direct_symmetric(JweEncryption::A256CbcHs512).unwrap();
        assert_eq!(jwk.alg.as_deref(), Some("dir"));
        assert_eq!(jwk.use_.as_deref(), Some("enc"));
        let sw = jwk_to_software_key(&jwk).unwrap();
        assert_eq!(sw.algorithm(), kryptering::KeyAlgorithm::Hmac);
        assert_eq!(sw.export_private().unwrap().len(), 64);
    }

    #[test]
    fn generate_symmetric_for_alg_rejects_dir() {
        let err = generate_symmetric_for_alg("dir").unwrap_err().to_string();
        assert!(
            err.contains("generate_direct_symmetric"),
            "unexpected: {err}"
        );
    }

    #[cfg(feature = "post-quantum")]
    #[test]
    fn generate_mldsa_44() {
        use kryptering::MlDsaVariant;
        let jwk = generate_mldsa(MlDsaVariant::MlDsa44).unwrap();
        assert_eq!(jwk.kty, "AKP");
        assert_eq!(jwk.alg.as_deref(), Some("ML-DSA-44"));

        let pub_bytes = crate::base64url::decode(jwk.pub_.as_ref().unwrap()).unwrap();
        assert_eq!(pub_bytes.len(), 1312, "ML-DSA-44 public key is 1312 bytes");

        let priv_bytes = crate::base64url::decode(jwk.priv_.as_ref().unwrap()).unwrap();
        assert_eq!(priv_bytes.len(), 32, "ML-DSA priv is a 32-byte seed");
    }

    #[cfg(feature = "post-quantum")]
    #[test]
    fn generate_mldsa_65() {
        use kryptering::MlDsaVariant;
        let jwk = generate_mldsa(MlDsaVariant::MlDsa65).unwrap();
        assert_eq!(jwk.alg.as_deref(), Some("ML-DSA-65"));
        let pub_bytes = crate::base64url::decode(jwk.pub_.as_ref().unwrap()).unwrap();
        assert_eq!(pub_bytes.len(), 1952);
    }

    #[cfg(feature = "post-quantum")]
    #[test]
    fn generate_mldsa_87() {
        use kryptering::MlDsaVariant;
        let jwk = generate_mldsa(MlDsaVariant::MlDsa87).unwrap();
        assert_eq!(jwk.alg.as_deref(), Some("ML-DSA-87"));
        let pub_bytes = crate::base64url::decode(jwk.pub_.as_ref().unwrap()).unwrap();
        assert_eq!(pub_bytes.len(), 2592);
    }

    #[cfg(feature = "post-quantum")]
    #[test]
    fn mldsa_jwk_roundtrips_to_software_key() {
        use kryptering::MlDsaVariant;
        let jwk = generate_mldsa(MlDsaVariant::MlDsa44).unwrap();
        let sw = jwk_to_software_key(&jwk).unwrap();
        assert_eq!(
            sw.algorithm(),
            kryptering::KeyAlgorithm::PostQuantum(kryptering::PqAlgorithm::MlDsa(
                MlDsaVariant::MlDsa44
            ))
        );
        assert_eq!(sw.export_private().unwrap().len(), 32);
        assert!(
            sw.export_spki_der().unwrap().len() > 1312,
            "public is SPKI DER, not raw"
        );
    }

    #[cfg(feature = "post-quantum")]
    #[test]
    fn mldsa_jwk_seeds_are_unique() {
        use kryptering::MlDsaVariant;
        let a = generate_mldsa(MlDsaVariant::MlDsa44).unwrap();
        let b = generate_mldsa(MlDsaVariant::MlDsa44).unwrap();
        assert_ne!(a.priv_, b.priv_);
        assert_ne!(a.pub_, b.pub_);
    }
}

/// The EC curves this crate can generate, as a type rather than as a string.
///
/// The point of the enum is what it makes unrepresentable: there is no variant for secp256k1 or
/// a Brainpool curve, so `KeyGeneration::Ec { curve: ... }` cannot *ask* for one and cannot
/// silently fall back to P-256 when a caller typos one. Where a curve name arrives as text,
/// `TryFrom<&str>` converts it and refuses naming what it was given.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EcCurve {
    /// NIST P-256 (`prime256v1`).
    P256,
    /// NIST P-384 (`secp384r1`).
    P384,
    /// NIST P-521 (`secp521r1`).
    P521,
}

impl EcCurve {
    /// The JWK `crv` value, which is also what [`generate_ec`] takes.
    pub fn as_str(self) -> &'static str {
        match self {
            EcCurve::P256 => "P-256",
            EcCurve::P384 => "P-384",
            EcCurve::P521 => "P-521",
        }
    }
}

impl TryFrom<&str> for EcCurve {
    type Error = JoseError;

    /// Accept exactly the three supported names — case-sensitively, no aliases.
    ///
    /// `p256` and `P256` are refused rather than normalized: a caller who means a different
    /// curve than they wrote should find out here, not in a signature failure later.
    fn try_from(value: &str) -> std::result::Result<Self, Self::Error> {
        match value {
            "P-256" => Ok(EcCurve::P256),
            "P-384" => Ok(EcCurve::P384),
            "P-521" => Ok(EcCurve::P521),
            other => Err(JoseError::Key(format!(
                "unsupported EC curve \"{other}\"; this crate generates P-256, P-384 and P-521"
            ))),
        }
    }
}

/// A key to generate, as data.
///
/// The existing per-type functions ([`generate_rsa`], [`generate_ec`], [`generate_ed25519`],
/// [`generate_x25519`], [`generate_symmetric`]) stay available and unchanged; this enum is for
/// callers who carry the choice as configuration — a keystore, a CLI flag, a test matrix — and
/// would otherwise write their own string dispatch.
///
/// It reuses those functions rather than reimplementing them, so every existing rule (the
/// [`MIN_RSA_BITS`](crate::MIN_RSA_BITS) floor, the curve set, the `alg`/`use` pinning) applies
/// here too. There is one addition: [`KeyGeneration::Oct`] accepts only key sizes that JOSE
/// algorithms actually use, because "any length the caller typed" is not a policy.
///
/// There is deliberately **no post-quantum variant**. A variant behind `#[cfg(feature =
/// "post-quantum")]` would make every caller's `match` non-exhaustive depending on a feature
/// they may not control, which is a worse API than the two doors it would have unified;
/// [`generate_mldsa`] remains the entry point for that.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyGeneration {
    /// RSA key pair of the given modulus size in bits; at least 2048.
    Rsa {
        /// Modulus size in bits (2048, 3072, 4096, …).
        bits: usize,
    },
    /// EC key pair on a supported curve.
    Ec {
        /// The curve.
        curve: EcCurve,
    },
    /// Ed25519 key pair.
    Ed25519,
    /// X25519 key pair (key agreement; no signing).
    X25519,
    /// Symmetric key of a JOSE-sized length in bytes.
    Oct {
        /// 16, 24, 32, 48 or 64.
        size: usize,
    },
}

impl KeyGeneration {
    /// The JWK `kty` the generated key will have.
    pub fn key_type(&self) -> &'static str {
        match self {
            KeyGeneration::Rsa { .. } => "RSA",
            KeyGeneration::Ec { .. } => "EC",
            KeyGeneration::Ed25519 | KeyGeneration::X25519 => "OKP",
            KeyGeneration::Oct { .. } => "oct",
        }
    }
}

/// Generate a key described by [`KeyGeneration`].
///
/// ```
/// use jose_rs::jwk::{generate_key, EcCurve, KeyGeneration};
///
/// let key = generate_key(KeyGeneration::Ec {
///     curve: EcCurve::try_from("P-256")?,
/// })?;
/// assert_eq!(key.kty, "EC");
/// assert_eq!(key.crv.as_deref(), Some("P-256"));
///
/// // An unsupported size is refused, not rounded or truncated.
/// let err = generate_key(KeyGeneration::Oct { size: 20 }).unwrap_err();
/// assert!(err.to_string().contains("20"));
/// # Ok::<(), jose_rs::JoseError>(())
/// ```
///
/// # Errors
///
/// [`JoseError::Key`] for an RSA size below the minimum, or an `Oct` size outside
/// 16/24/32/48/64, plus whatever the underlying generator reports.
pub fn generate_key(options: KeyGeneration) -> Result<Jwk> {
    match options {
        KeyGeneration::Rsa { bits } => generate_rsa(bits),
        KeyGeneration::Ec { curve } => generate_ec(curve.as_str()),
        KeyGeneration::Ed25519 => generate_ed25519(),
        KeyGeneration::X25519 => generate_x25519(),
        KeyGeneration::Oct { size } => {
            // The set is what JOSE's own algorithms use: AES-128/192/256 for key management and
            // content encryption, and HMAC-SHA-384/512's MAC key sizes. Anything else would be a
            // key no algorithm in this crate can use, so it is refused by name.
            if !matches!(size, 16 | 24 | 32 | 48 | 64) {
                return Err(JoseError::Key(format!(
                    "symmetric key size {size} bytes is not one this crate can use (16, 24, 32, \
                     48 or 64); generate_symmetric remains available if you deliberately need \
                     another length"
                )));
            }
            generate_symmetric(size)
        }
    }
}

#[cfg(test)]
mod typed_generation_tests {
    use super::*;

    #[test]
    fn curve_names_convert_exactly_or_not_at_all() {
        assert_eq!(EcCurve::try_from("P-256").expect("ok"), EcCurve::P256);
        assert_eq!(EcCurve::try_from("P-384").expect("ok"), EcCurve::P384);
        assert_eq!(EcCurve::try_from("P-521").expect("ok"), EcCurve::P521);
        // No aliases, no case folding: a near-miss is refused with the name it was given.
        for bad in [
            "p-256",
            "P256",
            "secp256k1",
            "brainpoolP256r1",
            "P-384 ",
            "",
        ] {
            let err = EcCurve::try_from(bad).expect_err("must refuse");
            assert!(err.to_string().contains(bad.trim()), "{bad}: {err}");
        }
    }

    #[test]
    fn every_variant_generates_the_key_type_it_promises() {
        let cases = [
            (KeyGeneration::Rsa { bits: 2048 }, "RSA", None),
            (
                KeyGeneration::Ec {
                    curve: EcCurve::P256,
                },
                "EC",
                Some("P-256"),
            ),
            (
                KeyGeneration::Ec {
                    curve: EcCurve::P384,
                },
                "EC",
                Some("P-384"),
            ),
            (KeyGeneration::Ed25519, "OKP", Some("Ed25519")),
            (KeyGeneration::X25519, "OKP", Some("X25519")),
            (KeyGeneration::Oct { size: 32 }, "oct", None),
        ];
        for (options, kty, crv) in cases {
            assert_eq!(options.key_type(), kty);
            let key = generate_key(options).unwrap_or_else(|e| panic!("{options:?}: {e}"));
            assert_eq!(key.kty, kty, "{options:?}");
            assert_eq!(key.crv.as_deref(), crv, "{options:?}");
            // Private material is present for the asymmetric types.
            assert!(
                key.d.is_some() || key.k.is_some() || key.priv_.is_some(),
                "{options:?}: generated a key with no private part"
            );
        }
    }

    #[test]
    fn unsupported_sizes_are_refused_by_name() {
        // Reuses generate_rsa's floor rather than restating a different one.
        let err = generate_key(KeyGeneration::Rsa { bits: 1024 }).expect_err("too small");
        assert!(err.to_string().contains("1024"), "{err}");
        assert!(err.to_string().contains("2048"), "{err}");

        for size in [0usize, 1, 15, 20, 31, 33, 65, 4096] {
            let err = generate_key(KeyGeneration::Oct { size }).expect_err("bad size");
            let message = err.to_string();
            assert!(message.contains(&format!("{size}")), "{size}: {message}");
            assert!(message.contains("generate_symmetric"), "{size}: {message}");
        }
    }
}
