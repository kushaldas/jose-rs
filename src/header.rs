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

/// Registered header members that carry or point to key material: `jku`,
/// `jwk`, `x5u` and `x5c` (RFC 7515 §4.1.2-4.1.6, RFC 7516 §4.1.4-4.1.7).
///
/// This crate never selects a key from, or dereferences, these members. A
/// peer might: RFC 8725 §2.9 / §3.10 warn that blindly following `jku` or
/// `x5u` can lead to SSRF, and an inline `jwk` / `x5c` is only as trustworthy
/// as the signer that emitted it. An application that forwards
/// caller-controlled data into a header could otherwise mint tokens carrying
/// attacker-chosen key references under a trusted key. RFC 8725 does not
/// require producers to omit these members; requiring an explicit opt-in is
/// this crate's defensive default
/// (`allow_key_reference_headers` in `jws::compact::SignOptions` or
/// `jwe::JweEncryptOptions`).
///
/// Thumbprints (`x5t`, `x5t#S256`) and `kid` only name a key and are not
/// covered.
pub const KEY_REFERENCE_MEMBERS: &[&str] = &["jku", "jwk", "x5u", "x5c"];

/// Registered header members whose only defined use is JWE (IANA "JSON Web
/// Signature and Encryption Header Parameters" registry, usage location
/// "JWE"):
///
/// - `enc`, `zip`: RFC 7516 §4.1.2, §4.1.3;
/// - `epk`, `apu`, `apv`: ECDH-ES key agreement, RFC 7518 §4.6.1;
/// - `iv`, `tag`: AES-GCM key wrapping, RFC 7518 §4.7.1;
/// - `p2s`, `p2c`: PBES2 key encryption, RFC 7518 §4.8.1.
///
/// JWS signing refuses them. RFC 7516 §9 distinguishes a JWE header from a
/// JWS header by the presence of `enc`, so a signed header carrying it
/// claims to be a JWE; the others describe encryption processing that a JWS
/// never performs.
pub const JWE_ONLY_MEMBERS: &[&str] =
    &["enc", "zip", "epk", "apu", "apv", "iv", "tag", "p2s", "p2c"];

/// Whether `name` is a header parameter defined by RFC 7515, RFC 7516 or
/// RFC 7518 ([`TYPED_MEMBERS`] ∪ [`JWE_ONLY_MEMBERS`]).
///
/// RFC 7515 §4.1.11 forbids producers from listing such names in `crit`.
/// RFC 7797 `b64` is an extension and is not included.
pub(crate) fn is_registered_member(name: &str) -> bool {
    TYPED_MEMBERS.contains(&name) || JWE_ONLY_MEMBERS.contains(&name)
}

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
    /// because they would produce an ambiguous duplicate JSON member. JWE
    /// encryption additionally rejects registered members it does not
    /// implement (`zip`, `b64`, `epk`, `apu`, `apv`, `p2s`, `p2c`, `iv`,
    /// `tag`); JWS signing rejects the JWE-only members
    /// ([`JWE_ONLY_MEMBERS`]).
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

    /// The first [`KEY_REFERENCE_MEMBERS`] entry present in this header.
    ///
    /// Only the typed fields are inspected: `extra` cannot hold these names
    /// once [`ensure_no_duplicate_members`](Self::ensure_no_duplicate_members)
    /// has passed.
    pub(crate) fn key_reference_member(&self) -> Option<&'static str> {
        [
            ("jku", self.jku.is_some()),
            ("jwk", self.jwk.is_some()),
            ("x5u", self.x5u.is_some()),
            ("x5c", self.x5c.is_some()),
        ]
        .into_iter()
        .find_map(|(name, present)| present.then_some(name))
    }

    /// The first [`JWE_ONLY_MEMBERS`] entry present in this header, whether
    /// set through the typed `enc` field or through `extra`.
    pub(crate) fn jwe_only_member(&self) -> Option<&'static str> {
        if self.enc.is_some() {
            return Some("enc");
        }
        JWE_ONLY_MEMBERS
            .iter()
            .copied()
            .find(|name| self.extra.contains_key(*name))
    }

    /// Serialize this header as the base64url-encoded protected header of a
    /// JWS or JWE.
    ///
    /// This is the only path by which the crate turns a caller-supplied
    /// [`JoseHeader`] into authenticated bytes, so every emit-side header
    /// rule lives here and a new signing or encryption path cannot skip it:
    ///
    /// 1. no `extra` member may duplicate a typed field
    ///    ([`ensure_no_duplicate_members`](Self::ensure_no_duplicate_members));
    /// 2. no [`KEY_REFERENCE_MEMBERS`] entry unless `allow_key_references`;
    /// 3. the encoded header must not exceed [`crate::MAX_TOKEN_BYTES`], the
    ///    limit this crate's decoders enforce.
    ///
    /// Algorithm-specific checks (`alg` agreement, `crit`, `b64`, `zip`) stay
    /// with the JWS and JWE callers and must run before this.
    ///
    /// # Errors
    ///
    /// Returns [`JoseError::InvalidHeader`] for a rule violation, or
    /// [`JoseError::Json`] if serialization fails.
    pub(crate) fn to_protected_b64(&self, allow_key_references: bool) -> Result<String> {
        self.ensure_no_duplicate_members()?;
        if !allow_key_references {
            if let Some(name) = self.key_reference_member() {
                return Err(JoseError::InvalidHeader(format!(
                    "{name} in protected header requires allow_key_reference_headers \
                     (key-reference members may be dereferenced by peers)"
                )));
            }
        }
        let encoded = crate::base64url::encode(&serde_json::to_vec(self)?);
        if encoded.len() > crate::MAX_TOKEN_BYTES {
            return Err(JoseError::InvalidHeader(format!(
                "encoded protected header is {} bytes, exceeding MAX_TOKEN_BYTES ({})",
                encoded.len(),
                crate::MAX_TOKEN_BYTES
            )));
        }
        Ok(encoded)
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

    /// RFC 7515 §4.1.11 producer rule: every name registered by RFC 7515,
    /// RFC 7516 or RFC 7518 counts as registered, while extension names,
    /// including RFC 7797 `b64` (which RFC 7797 §6 requires in `crit`), do
    /// not.
    #[test]
    fn registered_members_cover_jose_rfcs_but_not_extensions() {
        for name in TYPED_MEMBERS.iter().chain(JWE_ONLY_MEMBERS) {
            assert!(is_registered_member(name), "{name} not registered");
        }
        for name in ["b64", "etsiU", "sigT", "tenant"] {
            assert!(!is_registered_member(name), "{name} treated as registered");
        }
    }

    /// `jwe_only_member` sees both the typed `enc` field and `extra`
    /// entries (RFC 7516 §9: `enc` marks a JWE header).
    #[test]
    fn jwe_only_member_detects_typed_and_extra_members() {
        assert_eq!(JoseHeader::new("HS256").jwe_only_member(), None);
        let jwe = JoseHeader::for_jwe(JweAlgorithm::Dir, JweEncryption::A128GCM);
        assert_eq!(jwe.jwe_only_member(), Some("enc"));
        for name in JWE_ONLY_MEMBERS.iter().filter(|n| **n != "enc") {
            let mut header = JoseHeader::new("HS256");
            header.extra.insert((*name).into(), Value::Null);
            assert_eq!(header.jwe_only_member(), Some(*name));
        }
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
