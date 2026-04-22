//! JOSE algorithm identifiers and mapping to kryptering enums.

use crate::error::{JoseError, Result};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// JWS signature algorithms (RFC 7518 §3)
// ---------------------------------------------------------------------------

/// JWS signature algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum JwsAlgorithm {
    /// HMAC using SHA-256
    HS256,
    /// HMAC using SHA-384
    HS384,
    /// HMAC using SHA-512
    HS512,
    /// RSASSA-PKCS1-v1_5 using SHA-256
    RS256,
    /// RSASSA-PKCS1-v1_5 using SHA-384
    RS384,
    /// RSASSA-PKCS1-v1_5 using SHA-512
    RS512,
    /// RSASSA-PSS using SHA-256
    PS256,
    /// RSASSA-PSS using SHA-384
    PS384,
    /// RSASSA-PSS using SHA-512
    PS512,
    /// ECDSA using P-256 and SHA-256
    ES256,
    /// ECDSA using P-384 and SHA-384
    ES384,
    /// ECDSA using P-521 and SHA-512
    ES512,
    /// EdDSA (Ed25519)
    EdDSA,
    /// ECDSA using secp256k1 and SHA-256
    ES256K,
    /// ML-DSA-44 (FIPS 204) — post-quantum digital signature (draft-ietf-cose-dilithium)
    #[cfg(feature = "post-quantum")]
    #[serde(rename = "ML-DSA-44")]
    MlDsa44,
    /// ML-DSA-65 (FIPS 204) — post-quantum digital signature (draft-ietf-cose-dilithium)
    #[cfg(feature = "post-quantum")]
    #[serde(rename = "ML-DSA-65")]
    MlDsa65,
    /// ML-DSA-87 (FIPS 204) — post-quantum digital signature (draft-ietf-cose-dilithium)
    #[cfg(feature = "post-quantum")]
    #[serde(rename = "ML-DSA-87")]
    MlDsa87,
    /// No digital signature (DANGEROUS -- only available with the `deprecated` feature)
    #[cfg(feature = "deprecated")]
    None,
}

#[allow(clippy::should_implement_trait)] // from_str returns JoseError, not FromStr::Err
impl JwsAlgorithm {
    /// Map to the corresponding kryptering signature algorithm.
    ///
    /// Returns `Err` for algorithms that kryptering does not yet support
    /// (ES256K) or that have no meaningful cryptographic operation (None).
    pub fn to_crypto(self) -> Result<kryptering::SignatureAlgorithm> {
        use kryptering::{EcCurve, HashAlgorithm, SignatureAlgorithm};
        match self {
            Self::HS256 => Ok(SignatureAlgorithm::Hmac(HashAlgorithm::Sha256)),
            Self::HS384 => Ok(SignatureAlgorithm::Hmac(HashAlgorithm::Sha384)),
            Self::HS512 => Ok(SignatureAlgorithm::Hmac(HashAlgorithm::Sha512)),
            Self::RS256 => Ok(SignatureAlgorithm::RsaPkcs1v15(HashAlgorithm::Sha256)),
            Self::RS384 => Ok(SignatureAlgorithm::RsaPkcs1v15(HashAlgorithm::Sha384)),
            Self::RS512 => Ok(SignatureAlgorithm::RsaPkcs1v15(HashAlgorithm::Sha512)),
            Self::PS256 => Ok(SignatureAlgorithm::RsaPss(HashAlgorithm::Sha256)),
            Self::PS384 => Ok(SignatureAlgorithm::RsaPss(HashAlgorithm::Sha384)),
            Self::PS512 => Ok(SignatureAlgorithm::RsaPss(HashAlgorithm::Sha512)),
            Self::ES256 => Ok(SignatureAlgorithm::Ecdsa(
                EcCurve::P256,
                HashAlgorithm::Sha256,
            )),
            Self::ES384 => Ok(SignatureAlgorithm::Ecdsa(
                EcCurve::P384,
                HashAlgorithm::Sha384,
            )),
            Self::ES512 => Ok(SignatureAlgorithm::Ecdsa(
                EcCurve::P521,
                HashAlgorithm::Sha512,
            )),
            Self::EdDSA => Ok(SignatureAlgorithm::Ed25519),
            Self::ES256K => Err(JoseError::UnsupportedAlgorithm(
                "ES256K (secp256k1) is not yet supported by kryptering".into(),
            )),
            #[cfg(feature = "post-quantum")]
            Self::MlDsa44 => Ok(SignatureAlgorithm::MlDsa(
                kryptering::MlDsaVariant::MlDsa44,
            )),
            #[cfg(feature = "post-quantum")]
            Self::MlDsa65 => Ok(SignatureAlgorithm::MlDsa(
                kryptering::MlDsaVariant::MlDsa65,
            )),
            #[cfg(feature = "post-quantum")]
            Self::MlDsa87 => Ok(SignatureAlgorithm::MlDsa(
                kryptering::MlDsaVariant::MlDsa87,
            )),
            #[cfg(feature = "deprecated")]
            Self::None => Err(JoseError::UnsupportedAlgorithm(
                "\"none\" algorithm has no cryptographic operation".into(),
            )),
        }
    }

    /// Parse from the `alg` header string.
    pub fn from_str(s: &str) -> Result<Self> {
        match s {
            "HS256" => Ok(Self::HS256),
            "HS384" => Ok(Self::HS384),
            "HS512" => Ok(Self::HS512),
            "RS256" => Ok(Self::RS256),
            "RS384" => Ok(Self::RS384),
            "RS512" => Ok(Self::RS512),
            "PS256" => Ok(Self::PS256),
            "PS384" => Ok(Self::PS384),
            "PS512" => Ok(Self::PS512),
            "ES256" => Ok(Self::ES256),
            "ES384" => Ok(Self::ES384),
            "ES512" => Ok(Self::ES512),
            "EdDSA" => Ok(Self::EdDSA),
            "ES256K" => Ok(Self::ES256K),
            #[cfg(feature = "post-quantum")]
            "ML-DSA-44" => Ok(Self::MlDsa44),
            #[cfg(feature = "post-quantum")]
            "ML-DSA-65" => Ok(Self::MlDsa65),
            #[cfg(feature = "post-quantum")]
            "ML-DSA-87" => Ok(Self::MlDsa87),
            #[cfg(feature = "deprecated")]
            "none" => Ok(Self::None),
            other => Err(JoseError::UnsupportedAlgorithm(other.to_string())),
        }
    }

    /// Return the `alg` header string.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::HS256 => "HS256",
            Self::HS384 => "HS384",
            Self::HS512 => "HS512",
            Self::RS256 => "RS256",
            Self::RS384 => "RS384",
            Self::RS512 => "RS512",
            Self::PS256 => "PS256",
            Self::PS384 => "PS384",
            Self::PS512 => "PS512",
            Self::ES256 => "ES256",
            Self::ES384 => "ES384",
            Self::ES512 => "ES512",
            Self::EdDSA => "EdDSA",
            Self::ES256K => "ES256K",
            #[cfg(feature = "post-quantum")]
            Self::MlDsa44 => "ML-DSA-44",
            #[cfg(feature = "post-quantum")]
            Self::MlDsa65 => "ML-DSA-65",
            #[cfg(feature = "post-quantum")]
            Self::MlDsa87 => "ML-DSA-87",
            #[cfg(feature = "deprecated")]
            Self::None => "none",
        }
    }
}

impl std::fmt::Display for JwsAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// JWE key management algorithms (RFC 7518 §4)
// ---------------------------------------------------------------------------

/// JWE key management algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum JweAlgorithm {
    /// Direct use of a shared symmetric key
    #[serde(rename = "dir")]
    Dir,
    /// AES Key Wrap (128-bit)
    A128KW,
    /// AES Key Wrap (192-bit)
    A192KW,
    /// AES Key Wrap (256-bit)
    A256KW,
    /// RSAES-OAEP using default parameters (SHA-1 — only available with the `deprecated` feature)
    #[cfg(feature = "deprecated")]
    #[serde(rename = "RSA-OAEP")]
    RsaOaep,
    /// RSAES-OAEP using SHA-256 and MGF1 with SHA-256
    #[serde(rename = "RSA-OAEP-256")]
    RsaOaep256,
    /// ECDH-ES
    #[serde(rename = "ECDH-ES")]
    EcdhEs,
    /// ECDH-ES + A128KW
    #[serde(rename = "ECDH-ES+A128KW")]
    EcdhEsA128kw,
    /// ECDH-ES + A192KW
    #[serde(rename = "ECDH-ES+A192KW")]
    EcdhEsA192kw,
    /// ECDH-ES + A256KW
    #[serde(rename = "ECDH-ES+A256KW")]
    EcdhEsA256kw,
    /// PBES2-HS256+A128KW
    #[serde(rename = "PBES2-HS256+A128KW")]
    Pbes2Hs256A128kw,
    /// PBES2-HS384+A192KW
    #[serde(rename = "PBES2-HS384+A192KW")]
    Pbes2Hs384A192kw,
    /// PBES2-HS512+A256KW
    #[serde(rename = "PBES2-HS512+A256KW")]
    Pbes2Hs512A256kw,
}

#[allow(clippy::should_implement_trait)]
impl JweAlgorithm {
    /// Parse from the `alg` header string.
    pub fn from_str(s: &str) -> Result<Self> {
        match s {
            "dir" => Ok(Self::Dir),
            "A128KW" => Ok(Self::A128KW),
            "A192KW" => Ok(Self::A192KW),
            "A256KW" => Ok(Self::A256KW),
            #[cfg(feature = "deprecated")]
            "RSA-OAEP" => Ok(Self::RsaOaep),
            "RSA-OAEP-256" => Ok(Self::RsaOaep256),
            "ECDH-ES" => Ok(Self::EcdhEs),
            "ECDH-ES+A128KW" => Ok(Self::EcdhEsA128kw),
            "ECDH-ES+A192KW" => Ok(Self::EcdhEsA192kw),
            "ECDH-ES+A256KW" => Ok(Self::EcdhEsA256kw),
            "PBES2-HS256+A128KW" => Ok(Self::Pbes2Hs256A128kw),
            "PBES2-HS384+A192KW" => Ok(Self::Pbes2Hs384A192kw),
            "PBES2-HS512+A256KW" => Ok(Self::Pbes2Hs512A256kw),
            other => Err(JoseError::UnsupportedAlgorithm(other.to_string())),
        }
    }

    /// Return the `alg` header string.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Dir => "dir",
            Self::A128KW => "A128KW",
            Self::A192KW => "A192KW",
            Self::A256KW => "A256KW",
            #[cfg(feature = "deprecated")]
            Self::RsaOaep => "RSA-OAEP",
            Self::RsaOaep256 => "RSA-OAEP-256",
            Self::EcdhEs => "ECDH-ES",
            Self::EcdhEsA128kw => "ECDH-ES+A128KW",
            Self::EcdhEsA192kw => "ECDH-ES+A192KW",
            Self::EcdhEsA256kw => "ECDH-ES+A256KW",
            Self::Pbes2Hs256A128kw => "PBES2-HS256+A128KW",
            Self::Pbes2Hs384A192kw => "PBES2-HS384+A192KW",
            Self::Pbes2Hs512A256kw => "PBES2-HS512+A256KW",
        }
    }
}

// ---------------------------------------------------------------------------
// JWE content encryption algorithms (RFC 7518 §5)
// ---------------------------------------------------------------------------

/// JWE content encryption algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum JweEncryption {
    /// AES-CBC using 128-bit key with HMAC SHA-256
    #[serde(rename = "A128CBC-HS256")]
    A128CbcHs256,
    /// AES-CBC using 192-bit key with HMAC SHA-384
    #[serde(rename = "A192CBC-HS384")]
    A192CbcHs384,
    /// AES-CBC using 256-bit key with HMAC SHA-512
    #[serde(rename = "A256CBC-HS512")]
    A256CbcHs512,
    /// AES-GCM using 128-bit key
    A128GCM,
    /// AES-GCM using 192-bit key
    A192GCM,
    /// AES-GCM using 256-bit key
    A256GCM,
}

#[allow(clippy::should_implement_trait)]
impl JweEncryption {
    /// Content Encryption Key size in bytes.
    pub fn cek_size(self) -> usize {
        match self {
            Self::A128CbcHs256 => 32, // 128-bit AES + 128-bit HMAC
            Self::A192CbcHs384 => 48, // 192-bit AES + 192-bit HMAC
            Self::A256CbcHs512 => 64, // 256-bit AES + 256-bit HMAC
            Self::A128GCM => 16,
            Self::A192GCM => 24,
            Self::A256GCM => 32,
        }
    }

    /// Parse from the `enc` header string.
    pub fn from_str(s: &str) -> Result<Self> {
        match s {
            "A128CBC-HS256" => Ok(Self::A128CbcHs256),
            "A192CBC-HS384" => Ok(Self::A192CbcHs384),
            "A256CBC-HS512" => Ok(Self::A256CbcHs512),
            "A128GCM" => Ok(Self::A128GCM),
            "A192GCM" => Ok(Self::A192GCM),
            "A256GCM" => Ok(Self::A256GCM),
            other => Err(JoseError::UnsupportedAlgorithm(other.to_string())),
        }
    }

    /// Return the `enc` header string.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::A128CbcHs256 => "A128CBC-HS256",
            Self::A192CbcHs384 => "A192CBC-HS384",
            Self::A256CbcHs512 => "A256CBC-HS512",
            Self::A128GCM => "A128GCM",
            Self::A192GCM => "A192GCM",
            Self::A256GCM => "A256GCM",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn es256k_from_str() {
        let alg = JwsAlgorithm::from_str("ES256K").unwrap();
        assert_eq!(alg, JwsAlgorithm::ES256K);
    }

    #[test]
    fn es256k_as_str() {
        assert_eq!(JwsAlgorithm::ES256K.as_str(), "ES256K");
    }

    #[test]
    fn es256k_to_crypto_returns_error() {
        let result = JwsAlgorithm::ES256K.to_crypto();
        assert!(result.is_err());
    }

    #[test]
    fn es256k_roundtrip() {
        let alg = JwsAlgorithm::from_str(JwsAlgorithm::ES256K.as_str()).unwrap();
        assert_eq!(alg, JwsAlgorithm::ES256K);
    }

    #[test]
    fn existing_algorithms_to_crypto_still_work() {
        // Verify the signature change didn't break existing algorithms.
        assert!(JwsAlgorithm::HS256.to_crypto().is_ok());
        assert!(JwsAlgorithm::RS256.to_crypto().is_ok());
        assert!(JwsAlgorithm::ES256.to_crypto().is_ok());
        assert!(JwsAlgorithm::EdDSA.to_crypto().is_ok());
    }
}
