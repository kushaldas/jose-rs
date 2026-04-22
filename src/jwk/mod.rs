//! JSON Web Key (JWK) types and serialization (RFC 7517).

pub mod convert;
pub mod generate;
pub mod thumbprint;

pub use convert::{jwk_to_software_key, software_key_to_jwk};
pub use generate::{generate_ec, generate_ed25519, generate_rsa, generate_symmetric};

// Re-export JwkOp at the crate root pattern.

use serde::{Deserialize, Serialize};
use crate::error::{JoseError, Result};

/// A JSON Web Key (RFC 7517).
///
/// The `Debug` implementation redacts the private-key fields (`d`, `p`,
/// `q`, `dp`, `dq`, `qi`, `k`) so accidentally logging a `Jwk` does not
/// spill the private material — any present private component is
/// rendered as `<redacted>`.
#[derive(Clone, Serialize, Deserialize)]
pub struct Jwk {
    /// Key type (`kty`): "RSA", "EC", "oct", "OKP"
    pub kty: String,

    /// Key use (`use`): "sig" or "enc"
    #[serde(rename = "use", skip_serializing_if = "Option::is_none")]
    pub use_: Option<String>,

    /// Key operations (`key_ops`)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_ops: Option<Vec<String>>,

    /// Algorithm (`alg`)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,

    /// Key ID (`kid`)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,

    // RSA parameters
    #[serde(skip_serializing_if = "Option::is_none")]
    pub n: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub e: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub d: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub p: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub q: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dq: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub qi: Option<String>,

    // EC parameters
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crv: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub y: Option<String>,

    // Symmetric key parameter
    #[serde(skip_serializing_if = "Option::is_none")]
    pub k: Option<String>,

    // Catch-all for additional parameters
    #[serde(flatten)]
    pub extra: std::collections::HashMap<String, serde_json::Value>,
}

/// A cryptographic operation a JWK may be authorized to perform
/// (RFC 7517 §4.3 "key_ops" values).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum JwkOp {
    Sign,
    Verify,
    Encrypt,
    Decrypt,
    WrapKey,
    UnwrapKey,
    DeriveKey,
    DeriveBits,
}

impl JwkOp {
    /// RFC 7517 §4.3 operation identifier.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sign => "sign",
            Self::Verify => "verify",
            Self::Encrypt => "encrypt",
            Self::Decrypt => "decrypt",
            Self::WrapKey => "wrapKey",
            Self::UnwrapKey => "unwrapKey",
            Self::DeriveKey => "deriveKey",
            Self::DeriveBits => "deriveBits",
        }
    }

    /// RFC 7517 §4.2 "use" category this operation belongs to.
    /// Returns `"sig"` for sign/verify, `"enc"` otherwise.
    pub fn use_category(self) -> &'static str {
        match self {
            Self::Sign | Self::Verify => "sig",
            _ => "enc",
        }
    }
}

impl std::fmt::Debug for Jwk {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Redact any private-key component that is present, but still show
        // that it existed (so debug output conveys "this is a private key").
        let redact = |opt: &Option<String>| -> Option<&'static str> {
            opt.as_ref().map(|_| "<redacted>")
        };
        f.debug_struct("Jwk")
            .field("kty", &self.kty)
            .field("use_", &self.use_)
            .field("key_ops", &self.key_ops)
            .field("alg", &self.alg)
            .field("kid", &self.kid)
            .field("n", &self.n)
            .field("e", &self.e)
            .field("d", &redact(&self.d))
            .field("p", &redact(&self.p))
            .field("q", &redact(&self.q))
            .field("dp", &redact(&self.dp))
            .field("dq", &redact(&self.dq))
            .field("qi", &redact(&self.qi))
            .field("crv", &self.crv)
            .field("x", &self.x)
            .field("y", &self.y)
            .field("k", &redact(&self.k))
            .field("extra", &self.extra)
            .finish()
    }
}

impl Jwk {
    /// Parse a JWK from a JSON string.
    pub fn from_json(s: &str) -> Result<Self> {
        serde_json::from_str(s).map_err(JoseError::from)
    }

    /// Serialize this JWK to a compact JSON string.
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string(self).map_err(JoseError::from)
    }

    /// Serialize this JWK to a pretty-printed JSON string.
    pub fn to_json_pretty(&self) -> Result<String> {
        serde_json::to_string_pretty(self).map_err(JoseError::from)
    }

    /// Return a copy of this JWK with all private-key components removed.
    ///
    /// Wipes `d`, `p`, `q`, `dp`, `dq`, `qi`, `k`. Public components and
    /// metadata (`kid`, `use`, `alg`, `key_ops`, `extra`) are preserved.
    /// For symmetric (`kty: "oct"`) keys the result has no key material at
    /// all — there is no public companion — which is the correct outcome
    /// if someone tries to publish a symmetric key.
    ///
    /// Use this before serializing a JWK to any audience that should not
    /// see private material (a JWK Set endpoint, logs, error messages).
    pub fn to_public_jwk(&self) -> Jwk {
        Jwk {
            kty: self.kty.clone(),
            use_: self.use_.clone(),
            key_ops: self.key_ops.clone(),
            alg: self.alg.clone(),
            kid: self.kid.clone(),
            n: self.n.clone(),
            e: self.e.clone(),
            d: None,
            p: None,
            q: None,
            dp: None,
            dq: None,
            qi: None,
            crv: self.crv.clone(),
            x: self.x.clone(),
            y: self.y.clone(),
            k: None,
            extra: self.extra.clone(),
        }
    }

    /// Check whether this JWK is authorized for the requested operation
    /// per RFC 7517 §4.2 (`use`) and §4.3 (`key_ops`).
    ///
    /// Rules:
    /// - If `use` is set, it must equal the operation's category
    ///   (`"sig"` for `Sign`/`Verify`, `"enc"` otherwise).
    /// - If `key_ops` is set, the operation's JOSE name must appear in it.
    /// - If both are set, they must be consistent with each other.
    /// - If neither is set, the key is unrestricted.
    ///
    /// Returns `Ok(())` when the operation is permitted. Errors are
    /// `JoseError::Key` with a message identifying which field blocked
    /// the operation.
    pub fn check_op(&self, op: JwkOp) -> Result<()> {
        if let Some(use_) = self.use_.as_deref() {
            if use_ != op.use_category() {
                return Err(JoseError::Key(format!(
                    "JWK `use` is {use_}, not permitted for operation {}",
                    op.as_str()
                )));
            }
        }
        if let Some(ops) = &self.key_ops {
            let name = op.as_str();
            if !ops.iter().any(|o| o == name) {
                return Err(JoseError::Key(format!(
                    "JWK `key_ops` does not include {name}"
                )));
            }
        }
        // If both are set, RFC 7517 §4.3 says they SHOULD be consistent;
        // the two checks above already enforce each independently, which
        // implies consistency at the point where a specific op is checked.
        Ok(())
    }
}

/// A JWK Set (RFC 7517 Section 5).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwkSet {
    pub keys: Vec<Jwk>,
}

impl JwkSet {
    /// Parse a JWK Set from a JSON string.
    pub fn from_json(s: &str) -> Result<Self> {
        serde_json::from_str(s).map_err(JoseError::from)
    }

    /// Serialize this JWK Set to a compact JSON string.
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string(self).map_err(JoseError::from)
    }

    /// Find a key in the set by its `kid`.
    pub fn find_by_kid(&self, kid: &str) -> Option<&Jwk> {
        self.keys.iter().find(|k| k.kid.as_deref() == Some(kid))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 7517 Appendix A.1 -- Example RSA Public Key
    const RSA_JWK_JSON: &str = r#"{
        "kty": "RSA",
        "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
        "e": "AQAB",
        "alg": "RS256",
        "kid": "2011-04-29",
        "use": "sig"
    }"#;

    #[test]
    fn parse_rsa_jwk() {
        let jwk = Jwk::from_json(RSA_JWK_JSON).unwrap();
        assert_eq!(jwk.kty, "RSA");
        assert_eq!(jwk.e.as_deref(), Some("AQAB"));
        assert!(jwk.n.is_some());
        assert_eq!(jwk.alg.as_deref(), Some("RS256"));
        assert_eq!(jwk.kid.as_deref(), Some("2011-04-29"));
        assert_eq!(jwk.use_.as_deref(), Some("sig"));
        // Private fields should be absent
        assert!(jwk.d.is_none());
        assert!(jwk.p.is_none());
    }

    #[test]
    fn parse_jwk_set_and_find_by_kid() {
        let set_json = r#"{
            "keys": [
                {
                    "kty": "EC",
                    "crv": "P-256",
                    "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
                    "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
                    "kid": "ec-key-1"
                },
                {
                    "kty": "RSA",
                    "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
                    "e": "AQAB",
                    "kid": "rsa-key-1"
                }
            ]
        }"#;

        let set = JwkSet::from_json(set_json).unwrap();
        assert_eq!(set.keys.len(), 2);

        let ec = set.find_by_kid("ec-key-1").unwrap();
        assert_eq!(ec.kty, "EC");
        assert_eq!(ec.crv.as_deref(), Some("P-256"));

        let rsa = set.find_by_kid("rsa-key-1").unwrap();
        assert_eq!(rsa.kty, "RSA");

        assert!(set.find_by_kid("nonexistent").is_none());
    }

    #[test]
    fn roundtrip_serialize_deserialize() {
        let jwk = Jwk::from_json(RSA_JWK_JSON).unwrap();
        let json = jwk.to_json().unwrap();
        let jwk2 = Jwk::from_json(&json).unwrap();
        assert_eq!(jwk2.kty, jwk.kty);
        assert_eq!(jwk2.n, jwk.n);
        assert_eq!(jwk2.e, jwk.e);
        assert_eq!(jwk2.kid, jwk.kid);
        assert_eq!(jwk2.alg, jwk.alg);
        assert_eq!(jwk2.use_, jwk.use_);
    }

    #[test]
    fn to_json_pretty() {
        let jwk = Jwk::from_json(RSA_JWK_JSON).unwrap();
        let pretty = jwk.to_json_pretty().unwrap();
        assert!(pretty.contains('\n'));
        // Should still parse back
        let jwk2 = Jwk::from_json(&pretty).unwrap();
        assert_eq!(jwk2.kty, "RSA");
    }

    #[test]
    fn symmetric_key() {
        let json = r#"{"kty":"oct","k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow","kid":"hmac-key"}"#;
        let jwk = Jwk::from_json(json).unwrap();
        assert_eq!(jwk.kty, "oct");
        assert!(jwk.k.is_some());
        assert_eq!(jwk.kid.as_deref(), Some("hmac-key"));
    }

    /// Phase 3: Debug output must redact private-key fields.
    #[test]
    fn debug_redacts_private_fields() {
        let json = r#"{
            "kty": "RSA",
            "n": "publicN",
            "e": "AQAB",
            "d": "SECRET-PRIVATE-D",
            "p": "SECRET-PRIME-P",
            "q": "SECRET-PRIME-Q",
            "kid": "log-leak-test"
        }"#;
        let jwk = Jwk::from_json(json).unwrap();
        let s = format!("{jwk:?}");
        assert!(!s.contains("SECRET-PRIVATE-D"), "d leaked: {s}");
        assert!(!s.contains("SECRET-PRIME-P"), "p leaked: {s}");
        assert!(!s.contains("SECRET-PRIME-Q"), "q leaked: {s}");
        assert!(s.contains("<redacted>"), "expected redaction marker: {s}");
        // Public fields still appear.
        assert!(s.contains("publicN"));
        assert!(s.contains("log-leak-test"));
    }

    /// Phase 6: to_public_jwk strips RSA private components.
    #[test]
    fn to_public_jwk_strips_rsa_private() {
        let json = r#"{
            "kty":"RSA","n":"pubN","e":"AQAB",
            "d":"SECRET-D","p":"SECRET-P","q":"SECRET-Q",
            "dp":"SECRET-DP","dq":"SECRET-DQ","qi":"SECRET-QI",
            "kid":"k1","alg":"RS256"
        }"#;
        let jwk = Jwk::from_json(json).unwrap();
        let pub_jwk = jwk.to_public_jwk();
        assert!(pub_jwk.d.is_none());
        assert!(pub_jwk.p.is_none());
        assert!(pub_jwk.q.is_none());
        assert!(pub_jwk.dp.is_none());
        assert!(pub_jwk.dq.is_none());
        assert!(pub_jwk.qi.is_none());
        // Public components preserved.
        assert_eq!(pub_jwk.n.as_deref(), Some("pubN"));
        assert_eq!(pub_jwk.e.as_deref(), Some("AQAB"));
        assert_eq!(pub_jwk.kid.as_deref(), Some("k1"));
        assert_eq!(pub_jwk.alg.as_deref(), Some("RS256"));
        // The serialized form must not contain any SECRET-* string.
        let s = pub_jwk.to_json().unwrap();
        assert!(!s.contains("SECRET"), "private leaked: {s}");
    }

    /// Phase 6: to_public_jwk strips EC d (private scalar).
    #[test]
    fn to_public_jwk_strips_ec_private() {
        let json = r#"{
            "kty":"EC","crv":"P-256",
            "x":"pubX","y":"pubY","d":"SECRET-D","kid":"ec1"
        }"#;
        let jwk = Jwk::from_json(json).unwrap();
        let pub_jwk = jwk.to_public_jwk();
        assert!(pub_jwk.d.is_none());
        assert_eq!(pub_jwk.x.as_deref(), Some("pubX"));
        assert_eq!(pub_jwk.y.as_deref(), Some("pubY"));
    }

    /// Phase 6: to_public_jwk on OKP strips d, keeps x.
    #[test]
    fn to_public_jwk_strips_okp_private() {
        let json = r#"{
            "kty":"OKP","crv":"Ed25519",
            "x":"pubX","d":"SECRET-D"
        }"#;
        let jwk = Jwk::from_json(json).unwrap();
        let pub_jwk = jwk.to_public_jwk();
        assert!(pub_jwk.d.is_none());
        assert_eq!(pub_jwk.x.as_deref(), Some("pubX"));
    }

    /// Phase 6: to_public_jwk on oct strips k entirely (symmetric keys have
    /// no public companion).
    #[test]
    fn to_public_jwk_strips_oct() {
        let json = r#"{"kty":"oct","k":"SECRET","kid":"h1"}"#;
        let jwk = Jwk::from_json(json).unwrap();
        let pub_jwk = jwk.to_public_jwk();
        assert!(pub_jwk.k.is_none());
        assert_eq!(pub_jwk.kid.as_deref(), Some("h1"));
    }

    /// Phase 6: use="sig" permits Verify but not Encrypt.
    #[test]
    fn use_sig_permits_verify_blocks_encrypt() {
        let jwk = Jwk::from_json(
            r#"{"kty":"RSA","n":"AA","e":"AQAB","use":"sig"}"#,
        )
        .unwrap();
        jwk.check_op(JwkOp::Verify).unwrap();
        let err = jwk.check_op(JwkOp::Encrypt).unwrap_err().to_string();
        assert!(err.contains("`use` is sig"), "unexpected: {err}");
    }

    /// Phase 6: use="enc" permits Encrypt but not Sign.
    #[test]
    fn use_enc_permits_encrypt_blocks_sign() {
        let jwk = Jwk::from_json(
            r#"{"kty":"oct","k":"AA","use":"enc"}"#,
        )
        .unwrap();
        jwk.check_op(JwkOp::Encrypt).unwrap();
        let err = jwk.check_op(JwkOp::Sign).unwrap_err().to_string();
        assert!(err.contains("`use` is enc"), "unexpected: {err}");
    }

    /// Phase 6: key_ops narrows to specific operations.
    #[test]
    fn key_ops_restricts_to_listed_operations() {
        let jwk = Jwk::from_json(
            r#"{"kty":"RSA","n":"AA","e":"AQAB","key_ops":["verify"]}"#,
        )
        .unwrap();
        jwk.check_op(JwkOp::Verify).unwrap();
        let err = jwk.check_op(JwkOp::Sign).unwrap_err().to_string();
        assert!(err.contains("key_ops"), "unexpected: {err}");
    }

    /// Phase 6: when neither use nor key_ops is set, all ops are allowed.
    #[test]
    fn no_restriction_allows_everything() {
        let jwk = Jwk::from_json(r#"{"kty":"oct","k":"AA"}"#).unwrap();
        jwk.check_op(JwkOp::Sign).unwrap();
        jwk.check_op(JwkOp::Verify).unwrap();
        jwk.check_op(JwkOp::Encrypt).unwrap();
        jwk.check_op(JwkOp::WrapKey).unwrap();
    }

    /// Phase 6: conflicting use + key_ops is caught (sig + key_ops:["encrypt"]).
    #[test]
    fn inconsistent_use_and_key_ops_both_block() {
        // use=sig says only sig ops. key_ops=["encrypt"] says only encrypt.
        // Any op chosen is blocked by at least one constraint.
        let jwk = Jwk::from_json(
            r#"{"kty":"oct","k":"AA","use":"sig","key_ops":["encrypt"]}"#,
        )
        .unwrap();
        // Verify is a sig-op but not in key_ops → blocked by key_ops.
        assert!(jwk.check_op(JwkOp::Verify).is_err());
        // Encrypt is in key_ops but use=sig → blocked by use.
        assert!(jwk.check_op(JwkOp::Encrypt).is_err());
    }

    /// Phase 3: symmetric key `k` is also redacted in Debug.
    #[test]
    fn debug_redacts_symmetric_key() {
        let json = r#"{"kty":"oct","k":"SECRET-SYMMETRIC-KEY"}"#;
        let jwk = Jwk::from_json(json).unwrap();
        let s = format!("{jwk:?}");
        assert!(!s.contains("SECRET-SYMMETRIC-KEY"), "k leaked: {s}");
        assert!(s.contains("<redacted>"));
    }

    #[test]
    fn extra_fields_preserved() {
        let json = r#"{"kty":"oct","k":"dGVzdA","custom_field":"custom_value"}"#;
        let jwk = Jwk::from_json(json).unwrap();
        assert_eq!(
            jwk.extra.get("custom_field").and_then(|v| v.as_str()),
            Some("custom_value")
        );
        // Roundtrip preserves extra field
        let json2 = jwk.to_json().unwrap();
        assert!(json2.contains("custom_field"));
    }
}
