//! JOSE Header (shared between JWS and JWE).

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// JOSE Header — the protected header used in JWS and JWE compact serialization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JoseHeader {
    /// Algorithm (`alg`). Required.
    pub alg: String,

    /// Encryption algorithm (`enc`). Used in JWE only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enc: Option<String>,

    /// Key ID (`kid`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,

    /// Type (`typ`), e.g. "JWT".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub typ: Option<String>,

    /// Content Type (`cty`), e.g. "JWT" for nested JWTs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cty: Option<String>,

    /// JWK Set URL (`jku`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jku: Option<String>,

    /// JSON Web Key (`jwk`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwk: Option<Value>,

    /// X.509 URL (`x5u`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5u: Option<String>,

    /// X.509 Certificate Chain (`x5c`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5c: Option<Vec<String>>,

    /// X.509 Certificate SHA-1 Thumbprint (`x5t`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5t: Option<String>,

    /// X.509 Certificate SHA-256 Thumbprint (`x5t#S256`).
    #[serde(rename = "x5t#S256", skip_serializing_if = "Option::is_none")]
    pub x5t_s256: Option<String>,

    /// Critical headers (`crit`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crit: Option<Vec<String>>,

    /// Catch-all for additional header parameters.
    #[serde(flatten)]
    pub extra: std::collections::HashMap<String, Value>,
}

impl JoseHeader {
    /// Create a minimal header with just the `alg` field.
    pub fn new(alg: &str) -> Self {
        Self {
            alg: alg.to_string(),
            enc: None,
            kid: None,
            typ: None,
            cty: None,
            jku: None,
            jwk: None,
            x5u: None,
            x5c: None,
            x5t: None,
            x5t_s256: None,
            crit: None,
            extra: std::collections::HashMap::new(),
        }
    }

    /// Create a JWS header with `alg` and `typ: "JWT"`.
    pub fn jwt(alg: &str) -> Self {
        let mut h = Self::new(alg);
        h.typ = Some("JWT".to_string());
        h
    }

    /// Create a JWS header from a typed algorithm enum. Prevents the
    /// string-typo class of bugs that [`JoseHeader::new`] allows.
    pub fn for_alg(alg: crate::algorithm::JwsAlgorithm) -> Self {
        Self::new(alg.as_str())
    }

    /// Create a JWS header for a JWT (`alg` + `typ: "JWT"`) from a typed
    /// algorithm enum.
    pub fn jwt_for_alg(alg: crate::algorithm::JwsAlgorithm) -> Self {
        let mut h = Self::for_alg(alg);
        h.typ = Some("JWT".to_string());
        h
    }

    /// Create a JWE protected header from typed algorithm enums.
    pub fn for_jwe(
        alg: crate::algorithm::JweAlgorithm,
        enc: crate::algorithm::JweEncryption,
    ) -> Self {
        let mut h = Self::new(alg.as_str());
        h.enc = Some(enc.as_str().to_string());
        h
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::algorithm::{JweAlgorithm, JweEncryption, JwsAlgorithm};

    /// Phase 10: for_alg produces the same alg string as JwsAlgorithm::as_str.
    #[test]
    fn for_alg_matches_as_str() {
        let h = JoseHeader::for_alg(JwsAlgorithm::ES256);
        assert_eq!(h.alg, "ES256");
        assert!(h.typ.is_none());
    }

    /// Phase 10: jwt_for_alg sets alg and typ="JWT".
    #[test]
    fn jwt_for_alg_sets_typ() {
        let h = JoseHeader::jwt_for_alg(JwsAlgorithm::HS256);
        assert_eq!(h.alg, "HS256");
        assert_eq!(h.typ.as_deref(), Some("JWT"));
    }

    /// Phase 10: for_jwe sets both alg and enc.
    #[test]
    fn for_jwe_sets_alg_and_enc() {
        let h = JoseHeader::for_jwe(JweAlgorithm::A256KW, JweEncryption::A256GCM);
        assert_eq!(h.alg, "A256KW");
        assert_eq!(h.enc.as_deref(), Some("A256GCM"));
    }
}
