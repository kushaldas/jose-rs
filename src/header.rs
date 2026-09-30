//! JOSE Header (shared between JWS and JWE).

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::{JoseError, Result};

/// JSON member names produced by the typed fields of [`JoseHeader`].
///
/// [`JoseHeader::extra`] is `#[serde(flatten)]`ed into the same JSON object as
/// the typed fields, and serde does not deduplicate keys on serialization. If
/// `extra` also contains one of these names, the serialized header carries
/// the member twice, e.g. `{"alg":"HS256",...,"alg":"none"}`:
///
/// - sign/encrypt-side checks (`alg` agreement, `crit` policy, ...) only see
///   the typed field, so the duplicate value is never validated;
/// - this crate's decoder rejects the duplicate, but last-key-wins parsers
///   (JavaScript `JSON.parse`, panva/jose, ...) silently take the `extra`
///   value, so peers disagree about `alg`, `enc`, `kid`, `crit`, etc.
///
/// Keep this list in sync with the fields of [`JoseHeader`], using their
/// serialized (renamed) names.
const TYPED_MEMBERS: &[&str] = &[
    "alg", "enc", "kid", "typ", "cty", "jku", "jwk", "x5u", "x5c", "x5t", "x5t#S256", "crit",
];

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
    ///
    /// Must not contain a name that a typed field already serializes (`alg`,
    /// `enc`, `kid`, `crit`, ...): signing and encryption reject such headers
    /// because they would produce an ambiguous duplicate JSON member.
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

    /// Reject a header whose [`extra`](Self::extra) map repeats a member that
    /// a typed field already serializes (see [`TYPED_MEMBERS`]).
    ///
    /// Called by every JWS signing and JWE encryption path before the header
    /// is serialized into the authenticated protected header, so this crate
    /// never emits a header that different JSON parsers read differently.
    ///
    /// # Errors
    ///
    /// Returns [`JoseError::InvalidHeader`] naming the first duplicated member.
    pub(crate) fn ensure_no_duplicate_members(&self) -> Result<()> {
        match TYPED_MEMBERS
            .iter()
            .find(|name| self.extra.contains_key(**name))
        {
            Some(name) => Err(JoseError::InvalidHeader(format!(
                "extra header member {name} duplicates a typed header field"
            ))),
            None => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::algorithm::{JweAlgorithm, JweEncryption, JwsAlgorithm};

    /// `TYPED_MEMBERS` must list exactly the member names the typed fields
    /// serialize to. Populates every typed field and compares the serialized
    /// keys, so adding a field to `JoseHeader` without updating the list fails
    /// here instead of silently reopening the duplicate-member bypass.
    #[test]
    fn typed_members_match_serialized_fields() {
        let header = JoseHeader {
            alg: "HS256".into(),
            enc: Some("A128GCM".into()),
            kid: Some("k".into()),
            typ: Some("JWT".into()),
            cty: Some("JWT".into()),
            jku: Some("https://example.com".into()),
            jwk: Some(serde_json::json!({})),
            x5u: Some("https://example.com".into()),
            x5c: Some(vec!["AA".into()]),
            x5t: Some("AA".into()),
            x5t_s256: Some("AA".into()),
            crit: Some(vec!["b64".into()]),
            extra: Default::default(),
        };
        let value = serde_json::to_value(&header).unwrap();
        let mut serialized: Vec<&str> = value
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        let mut expected = TYPED_MEMBERS.to_vec();
        serialized.sort_unstable();
        expected.sort_unstable();
        assert_eq!(serialized, expected);
    }

    /// Each typed member name in `extra` is rejected; other names are allowed.
    #[test]
    fn ensure_no_duplicate_members_rejects_only_typed_names() {
        for name in TYPED_MEMBERS {
            let mut header = JoseHeader::new("HS256");
            header.extra.insert((*name).into(), Value::Null);
            assert!(matches!(
                header.ensure_no_duplicate_members(),
                Err(JoseError::InvalidHeader(_))
            ));
        }
        let mut header = JoseHeader::new("HS256");
        header.extra.insert("b64".into(), Value::Bool(false));
        header.extra.insert("tenant".into(), Value::Null);
        assert!(header.ensure_no_duplicate_members().is_ok());
    }

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
