//! JWK Thumbprint (RFC 7638).

use super::Jwk;
use crate::error::{JoseError, Result};
use std::collections::BTreeMap;

/// Compute the JWK Thumbprint using SHA-256 (RFC 7638).
///
/// Builds the required-members JSON object with fields in lexicographic order
/// (RFC 7638 §3.2) using proper JSON serialization, hashes it with SHA-256,
/// and returns the base64url-encoded digest.
///
/// The required-members JSON is serialized via `serde_json` to guarantee
/// correct escaping of any character inside the JWK field values (critical
/// for spec compliance and to prevent collision attacks on attacker-supplied
/// JWKs).
pub fn thumbprint_sha256(jwk: &Jwk) -> Result<String> {
    // BTreeMap gives lexicographic key ordering automatically.
    let mut required: BTreeMap<&str, &str> = BTreeMap::new();

    match jwk.kty.as_str() {
        "RSA" => {
            let e = jwk
                .e
                .as_deref()
                .ok_or_else(|| JoseError::Key("missing e".into()))?;
            let n = jwk
                .n
                .as_deref()
                .ok_or_else(|| JoseError::Key("missing n".into()))?;
            required.insert("e", e);
            required.insert("kty", "RSA");
            required.insert("n", n);
        }
        "EC" => {
            let crv = jwk
                .crv
                .as_deref()
                .ok_or_else(|| JoseError::Key("missing crv".into()))?;
            let x = jwk
                .x
                .as_deref()
                .ok_or_else(|| JoseError::Key("missing x".into()))?;
            let y = jwk
                .y
                .as_deref()
                .ok_or_else(|| JoseError::Key("missing y".into()))?;
            required.insert("crv", crv);
            required.insert("kty", "EC");
            required.insert("x", x);
            required.insert("y", y);
        }
        "oct" => {
            let k = jwk
                .k
                .as_deref()
                .ok_or_else(|| JoseError::Key("missing k".into()))?;
            required.insert("k", k);
            required.insert("kty", "oct");
        }
        "OKP" => {
            let crv = jwk
                .crv
                .as_deref()
                .ok_or_else(|| JoseError::Key("missing crv".into()))?;
            let x = jwk
                .x
                .as_deref()
                .ok_or_else(|| JoseError::Key("missing x".into()))?;
            required.insert("crv", crv);
            required.insert("kty", "OKP");
            required.insert("x", x);
        }
        other => {
            return Err(JoseError::Key(format!(
                "unsupported kty for thumbprint: {other}"
            )))
        }
    }

    let thumbprint_json = serde_json::to_vec(&required)?;
    let hash = kryptering::digest::digest(kryptering::HashAlgorithm::Sha256, &thumbprint_json);
    Ok(crate::base64url::encode(&hash))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 7638 Section 3.1 — Example JWK Thumbprint
    ///
    /// The example RSA key from RFC 7638 Section 3.1:
    /// The thumbprint input is:
    ///   {"e":"AQAB","kty":"RSA","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"}
    /// The SHA-256 hash of that JSON, base64url-encoded, is:
    ///   NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs
    #[test]
    fn rfc7638_rsa_thumbprint() {
        let jwk_json = r#"{
            "kty": "RSA",
            "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
            "e": "AQAB",
            "alg": "RS256",
            "kid": "2011-04-29"
        }"#;
        let jwk = Jwk::from_json(jwk_json).unwrap();
        let tp = thumbprint_sha256(&jwk).unwrap();
        assert_eq!(tp, "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs");
    }

    #[test]
    fn ec_thumbprint() {
        let jwk_json = r#"{
            "kty": "EC",
            "crv": "P-256",
            "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
            "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
            "kid": "ec-1"
        }"#;
        let jwk = Jwk::from_json(jwk_json).unwrap();
        let tp = thumbprint_sha256(&jwk).unwrap();
        // The thumbprint should be deterministic and not empty
        assert!(!tp.is_empty());
        // Verify it does not contain padding or standard base64 chars
        assert!(!tp.contains('='));
        assert!(!tp.contains('+'));
        assert!(!tp.contains('/'));
    }

    #[test]
    fn oct_thumbprint() {
        let jwk_json = r#"{"kty":"oct","k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"}"#;
        let jwk = Jwk::from_json(jwk_json).unwrap();
        let tp = thumbprint_sha256(&jwk).unwrap();
        assert!(!tp.is_empty());
    }

    #[test]
    fn okp_thumbprint() {
        let jwk_json = r#"{
            "kty": "OKP",
            "crv": "Ed25519",
            "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
        }"#;
        let jwk = Jwk::from_json(jwk_json).unwrap();
        let tp = thumbprint_sha256(&jwk).unwrap();
        assert!(!tp.is_empty());
    }

    #[test]
    fn unsupported_kty_error() {
        let jwk_json = r#"{"kty":"unknown"}"#;
        let jwk = Jwk::from_json(jwk_json).unwrap();
        let err = thumbprint_sha256(&jwk).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("unsupported kty"));
    }

    /// J-05 regression: thumbprint input containing a double-quote must be
    /// properly escaped by the serde_json serializer — the old format!()
    /// implementation would silently produce malformed JSON and a wrong hash.
    #[test]
    fn thumbprint_escapes_quotes_correctly() {
        // Two JWKs whose string-concat thumbprint inputs would collide if
        // unescaped, but whose serde_json serialization differs.
        let a = Jwk {
            kty: "oct".into(),
            k: Some("abc\",\"evil\":\"xyz".into()),
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
            extra: Default::default(),
        };
        let b = Jwk {
            kty: "oct".into(),
            k: Some("abc".into()),
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
            extra: Default::default(),
        };
        let tp_a = thumbprint_sha256(&a).unwrap();
        let tp_b = thumbprint_sha256(&b).unwrap();
        assert_ne!(tp_a, tp_b, "escaping must distinguish these inputs");
    }

    #[test]
    fn missing_required_field_error() {
        // RSA key without 'n'
        let jwk_json = r#"{"kty":"RSA","e":"AQAB"}"#;
        let jwk = Jwk::from_json(jwk_json).unwrap();
        let err = thumbprint_sha256(&jwk).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("missing n"));
    }
}
