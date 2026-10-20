//! JWK Thumbprint (RFC 7638).

use super::Jwk;
use crate::error::{JoseError, Result};
use std::collections::BTreeMap;

/// Supported thumbprint hashes. SHA-256 remains the default.
///
/// This deliberately excludes legacy hashes even when the crate's
/// `deprecated` feature is enabled. The hash choice must be agreed by the
/// application; a bare thumbprint does not encode its algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum ThumbprintHash {
    /// SHA-256 (32-byte digest).
    #[default]
    Sha256,
    /// SHA-384 (48-byte digest).
    Sha384,
    /// SHA-512 (64-byte digest).
    Sha512,
}

/// Compute the JWK Thumbprint using SHA-256 (RFC 7638).
///
/// Equivalent to [`thumbprint`] with [`ThumbprintHash::Sha256`]. This
/// compatibility entry point retains its existing output and error behavior.
pub fn thumbprint_sha256(jwk: &Jwk) -> Result<String> {
    thumbprint(jwk, ThumbprintHash::Sha256)
}

/// Compute a base64url-encoded JWK thumbprint with an explicit SHA-2 hash.
///
/// Hashes the UTF-8 JSON representation of the required members, ordered
/// lexicographically (RFC 7638). Private asymmetric material and optional
/// metadata do not contribute. For AKP keys, `alg` is a required member and
/// does contribute; for octet keys, the secret `k` member contributes.
///
/// The required-members JSON is serialized via `serde_json` to guarantee
/// correct escaping. This identifies the supplied representation; it does not
/// validate key material, authorize operations, or establish trust in a key.
///
/// # Errors
///
/// Returns an error for unsupported key types, missing required members,
/// serialization failures, or backend digest errors.
///
/// # Examples
///
/// ```
/// use jose_rs::jwk::{self, thumbprint::{thumbprint, thumbprint_sha256, ThumbprintHash}};
/// let key = jwk::generate_ed25519()?;
/// assert_eq!(thumbprint(&key, ThumbprintHash::default())?, thumbprint_sha256(&key)?);
/// let sha384 = thumbprint(&key, ThumbprintHash::Sha384)?;
/// assert_eq!(sha384.len(), 64); // Unpadded base64url of 48 bytes.
/// # Ok::<(), jose_rs::JoseError>(())
/// ```
pub fn thumbprint(jwk: &Jwk, hash: ThumbprintHash) -> Result<String> {
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
        // draft-ietf-cose-dilithium: AKP thumbprint canonicalises
        // {alg, kty, pub} in lexicographic order. Unlike the other key
        // types, `alg` is required because AKP is generic across
        // post-quantum algorithms and `alg` is what distinguishes them.
        "AKP" => {
            let alg = jwk
                .alg
                .as_deref()
                .ok_or_else(|| JoseError::Key("missing alg".into()))?;
            let pub_ = jwk
                .pub_
                .as_deref()
                .ok_or_else(|| JoseError::Key("missing pub".into()))?;
            required.insert("alg", alg);
            required.insert("kty", "AKP");
            required.insert("pub", pub_);
        }
        other => {
            return Err(JoseError::Key(format!(
                "unsupported kty for thumbprint: {other}"
            )))
        }
    }

    let thumbprint_json = serde_json::to_vec(&required)?;
    let algorithm = match hash {
        ThumbprintHash::Sha256 => kryptering::HashAlgorithm::Sha256,
        ThumbprintHash::Sha384 => kryptering::HashAlgorithm::Sha384,
        ThumbprintHash::Sha512 => kryptering::HashAlgorithm::Sha512,
    };
    let hash = kryptering::digest::digest(algorithm, &thumbprint_json)?;
    Ok(crate::base64url::encode(&hash))
}

/// The URI prefix registered by RFC 9278 §3.
pub const THUMBPRINT_URI_PREFIX: &str = "urn:ietf:params:oauth:jwk-thumbprint";

impl ThumbprintHash {
    /// The IANA "Named Information Hash Algorithm Registry" **Hash Name String** for this
    /// digest, which is what RFC 9278 §4 requires in a thumbprint URI.
    ///
    /// Note the hyphen: the registry name is `sha-256`, not `sha256`. Both spellings are in
    /// circulation in JOSE code — `jose`'s own *algorithm argument* is `sha256` while the URI it
    /// emits is `sha-256` — and the interop test pins that our output agrees with the URI form
    /// byte for byte.
    pub fn hash_name(self) -> &'static str {
        match self {
            ThumbprintHash::Sha256 => "sha-256",
            ThumbprintHash::Sha384 => "sha-384",
            ThumbprintHash::Sha512 => "sha-512",
        }
    }

    /// The digest length in bytes.
    pub fn digest_len(self) -> usize {
        match self {
            ThumbprintHash::Sha256 => 32,
            ThumbprintHash::Sha384 => 48,
            ThumbprintHash::Sha512 => 64,
        }
    }

    /// The length of the unpadded base64url encoding of this digest.
    pub fn encoded_len(self) -> usize {
        (self.digest_len() * 4).div_ceil(3)
    }

    /// The registry name back to a hash, exactly (no case folding, no aliases).
    ///
    /// RFC 9278 §4 says a URI whose hash identifier is not in the registry is not considered
    /// valid, so unrecognised names are refused rather than passed through; the refusal lists
    /// what is accepted.
    pub fn from_hash_name(name: &str) -> Option<ThumbprintHash> {
        match name {
            "sha-256" => Some(ThumbprintHash::Sha256),
            "sha-384" => Some(ThumbprintHash::Sha384),
            "sha-512" => Some(ThumbprintHash::Sha512),
            _ => None,
        }
    }
}

/// Build the JWK Thumbprint URI for a key (RFC 9278).
///
/// ```
/// use jose_rs::jwk::{self, thumbprint::{thumbprint_uri, ThumbprintHash}};
///
/// let key = jwk::generate_ed25519()?;
/// let uri = thumbprint_uri(&key, ThumbprintHash::Sha256)?;
/// assert!(uri.starts_with("urn:ietf:params:oauth:jwk-thumbprint:sha-256:"));
/// # Ok::<(), jose_rs::JoseError>(())
/// ```
///
/// SHA-256 remains the default where the caller does not choose [`ThumbprintHash::Sha384`] or
/// [`ThumbprintHash::Sha512`], matching RFC 9278 §5's mandatory-to-implement algorithm.
///
/// # Errors
///
/// As [`thumbprint`]: the key must have the required members for its type.
pub fn thumbprint_uri(jwk: &Jwk, hash: ThumbprintHash) -> Result<String> {
    Ok(format!(
        "{THUMBPRINT_URI_PREFIX}:{}:{}",
        hash.hash_name(),
        thumbprint(jwk, hash)?
    ))
}

/// [`thumbprint_uri`] with SHA-256, the RFC 9278 §5 mandatory algorithm.
pub fn thumbprint_uri_sha256(jwk: &Jwk) -> Result<String> {
    thumbprint_uri(jwk, ThumbprintHash::Sha256)
}

/// A parsed JWK Thumbprint URI (RFC 9278).
///
/// Holding one of these instead of a `&str` means the prefix, the registry spelling of the hash
/// identifier and the thumbprint's length have all been checked. That is the whole reason the
/// type exists: RFC 9278 §4 puts the burden of detecting a bad hash identifier on the
/// application, and an application that gets it wrong compares a SHA-256 thumbprint against a
/// value that was never one.
///
/// ```
/// use jose_rs::jwk::{self, thumbprint::JwkThumbprintUri};
///
/// let key = jwk::generate_ec("P-256")?;
/// let text = jose_rs::jwk::thumbprint::thumbprint_uri_sha256(&key)?;
/// let uri = JwkThumbprintUri::parse(&text)?;
/// assert!(uri.matches(&key)?);
/// # Ok::<(), jose_rs::JoseError>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct JwkThumbprintUri {
    hash: ThumbprintHash,
    thumbprint: String,
}

impl JwkThumbprintUri {
    /// Parse and validate a thumbprint URI.
    ///
    /// # Errors
    ///
    /// [`JoseError::InvalidToken`] when the prefix is absent, the hash identifier is not one of
    /// `sha-256`/`sha-384`/`sha-512`, the thumbprint is not unpadded base64url, or its decoded
    /// length does not match the named digest (the last check is what stops a truncated or
    /// wrong-digest value being accepted as "the same shape").
    pub fn parse(uri: &str) -> Result<Self> {
        // The prefix is followed by a colon, which belongs to it: without it the first
        // segment parsed as empty and every valid URI was refused.
        let Some(rest) = uri.strip_prefix(&format!("{THUMBPRINT_URI_PREFIX}:")) else {
            return Err(JoseError::InvalidToken(format!(
                "not a JWK Thumbprint URI: expected the RFC 9278 prefix \
                 \"{THUMBPRINT_URI_PREFIX}:…\" and found \"{}\"",
                uri.chars().take(48).collect::<String>()
            )));
        };
        let Some((name, value)) = rest.split_once(':') else {
            return Err(JoseError::InvalidToken(
                "JWK Thumbprint URI must be prefix:hash-identifier:thumbprint; this one has no \
                 hash identifier"
                    .into(),
            ));
        };
        let Some(hash) = ThumbprintHash::from_hash_name(name) else {
            return Err(JoseError::InvalidToken(format!(
                "JWK Thumbprint URI names hash identifier \"{name}\", which is not one of the \
                 registry values this crate accepts (sha-256, sha-384, sha-512); RFC 9278 §4 says \
                 such a URI is not valid, so it is refused rather than passed through"
            )));
        };
        if value.is_empty() {
            return Err(JoseError::InvalidToken(
                "JWK Thumbprint URI ends where the thumbprint value should begin".into(),
            ));
        }
        let decoded = crate::base64url::decode(value).map_err(|e| {
            JoseError::InvalidToken(format!(
                "JWK Thumbprint URI carries a thumbprint that is not unpadded base64url: {e}"
            ))
        })?;
        if decoded.len() != hash.digest_len() {
            return Err(JoseError::InvalidToken(format!(
                "JWK Thumbprint URI says {name} but its thumbprint is {} bytes, and a {name} \
                 digest is {}",
                decoded.len(),
                hash.digest_len()
            )));
        }
        Ok(Self {
            hash,
            thumbprint: value.to_string(),
        })
    }

    /// Build one directly from a key, without going through text.
    pub fn from_jwk(jwk: &Jwk, hash: ThumbprintHash) -> Result<Self> {
        Ok(Self {
            hash,
            thumbprint: thumbprint(jwk, hash)?,
        })
    }

    /// The named hash algorithm.
    pub fn hash(&self) -> ThumbprintHash {
        self.hash
    }

    /// The base64url thumbprint value, without prefix or identifier.
    pub fn thumbprint(&self) -> &str {
        &self.thumbprint
    }

    /// Render back to URI text. Round-trips with [`JwkThumbprintUri::parse`].
    pub fn to_uri(&self) -> String {
        format!(
            "{THUMBPRINT_URI_PREFIX}:{}:{}",
            self.hash.hash_name(),
            self.thumbprint
        )
    }

    /// Does this URI name the thumbprint of `jwk` under the algorithm the URI itself names?
    ///
    /// This is a comparison, not an authorization decision: it says a key and a URI agree, which
    /// is useful for the `kid`-less case, and it says nothing about whether either should be
    /// trusted. RFC 9278 §7's own advice applies — if the URI is an identifier someone presented,
    /// what binds it to a key is how it was conveyed, not this check.
    pub fn matches(&self, jwk: &Jwk) -> Result<bool> {
        Ok(thumbprint(jwk, self.hash)? == self.thumbprint)
    }
}

impl std::fmt::Display for JwkThumbprintUri {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_uri())
    }
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
            pub_: None,
            priv_: None,
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
            pub_: None,
            priv_: None,
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

    #[cfg(feature = "post-quantum")]
    #[test]
    fn akp_thumbprint_deterministic_and_depends_on_alg() {
        use kryptering::MlDsaVariant;
        let jwk = crate::jwk::generate::generate_mldsa(MlDsaVariant::MlDsa65).unwrap();

        // Deterministic: same JWK hashes to the same thumbprint twice.
        let tp1 = thumbprint_sha256(&jwk).unwrap();
        let tp2 = thumbprint_sha256(&jwk).unwrap();
        assert_eq!(tp1, tp2);
        assert!(!tp1.is_empty());
        assert!(!tp1.contains('='));

        // Changing alg changes the thumbprint (alg is a required member).
        let mut modified = jwk.clone();
        modified.alg = Some("ML-DSA-87".into());
        let tp_modified = thumbprint_sha256(&modified).unwrap();
        assert_ne!(tp1, tp_modified);
    }

    #[cfg(feature = "post-quantum")]
    #[test]
    fn akp_thumbprint_requires_alg_and_pub() {
        let without_alg = Jwk {
            kty: "AKP".into(),
            pub_: Some("AA".into()),
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
            priv_: None,
            extra: Default::default(),
        };
        let err = thumbprint_sha256(&without_alg).unwrap_err().to_string();
        assert!(err.contains("missing alg"), "unexpected: {err}");

        let without_pub = Jwk {
            kty: "AKP".into(),
            alg: Some("ML-DSA-44".into()),
            use_: None,
            key_ops: None,
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
        };
        let err = thumbprint_sha256(&without_pub).unwrap_err().to_string();
        assert!(err.contains("missing pub"), "unexpected: {err}");
    }

    #[test]
    fn uri_hash_identifiers_are_the_registry_names() {
        // RFC 9278 §4: the IANA "Hash Name String" values, hyphen included.
        assert_eq!(ThumbprintHash::Sha256.hash_name(), "sha-256");
        assert_eq!(ThumbprintHash::Sha384.hash_name(), "sha-384");
        assert_eq!(ThumbprintHash::Sha512.hash_name(), "sha-512");
        for hash in [
            ThumbprintHash::Sha256,
            ThumbprintHash::Sha384,
            ThumbprintHash::Sha512,
        ] {
            assert_eq!(
                ThumbprintHash::from_hash_name(hash.hash_name()),
                Some(hash),
                "round trip"
            );
            // Encoded lengths: 4/3 of the digest, minus padding.
            assert_eq!(
                hash.encoded_len(),
                thumbprint(&crate::jwk::generate_ed25519().expect("key"), hash)
                    .expect("thumbprint")
                    .len()
            );
        }
        assert_eq!(ThumbprintHash::default(), ThumbprintHash::Sha256);
    }

    #[test]
    fn uri_builds_and_parses_back() {
        let key = crate::jwk::generate_ec("P-256").expect("key");
        let text = thumbprint_uri_sha256(&key).expect("uri");
        assert!(text.starts_with("urn:ietf:params:oauth:jwk-thumbprint:sha-256:"));
        // The value part is the plain thumbprint, unchanged.
        let value = text.rsplit(':').next().expect("value");
        assert_eq!(value, thumbprint_sha256(&key).expect("tp"));

        let parsed = JwkThumbprintUri::parse(&text).expect("parse");
        assert_eq!(parsed.hash(), ThumbprintHash::Sha256);
        assert_eq!(parsed.thumbprint(), value);
        assert_eq!(parsed.to_uri(), text);
        assert_eq!(parsed.to_string(), text);
        assert!(parsed.matches(&key).expect("compare"));

        // A different key does not match, so `matches` is not vacuous.
        let other = crate::jwk::generate_ec("P-256").expect("other");
        assert!(!parsed.matches(&other).expect("compare"));

        // And the digest named in the URI is the one used to compare: a SHA-512 URI cannot be
        // satisfied by a SHA-256 value even if both are handed the same key.
        let sha512 = JwkThumbprintUri::from_jwk(&key, ThumbprintHash::Sha512).expect("512");
        assert!(!sha512.thumbprint().starts_with(value));
        assert!(sha512.matches(&key).expect("compare"));
    }

    #[test]
    fn uri_parser_refuses_every_way_it_can_be_wrong() {
        let key = crate::jwk::generate_ed25519().expect("key");
        let good = thumbprint_uri_sha256(&key).expect("uri");
        let value = good.rsplit(':').next().expect("value");

        // No prefix.
        let err =
            JwkThumbprintUri::parse(&format!("urn:example:sha-256:{value}")).expect_err("pfx");
        assert!(err.to_string().contains("prefix"), "{err}");

        // Missing hash identifier.
        let err =
            JwkThumbprintUri::parse("urn:ietf:params:oauth:jwk-thumbprint:").expect_err("no hash");
        assert!(err.to_string().contains("hash identifier"), "{err}");

        // A hash identifier that is not in the registry — including the unhyphenated spelling
        // that appears in some JOSE APIs, and the upper-case form.
        for bad in ["sha256", "SHA-256", "sha-3", "sha-256 ", ""] {
            let err = JwkThumbprintUri::parse(&format!(
                "urn:ietf:params:oauth:jwk-thumbprint:{bad}:{value}"
            ))
            .expect_err("identifier");
            assert!(err.to_string().contains("registry"), "{bad}: {err}");
        }

        // Right identifier, wrong digest length (a truncated value).
        let short: String = value.chars().take(40).collect();
        let err = JwkThumbprintUri::parse(&format!(
            "urn:ietf:params:oauth:jwk-thumbprint:sha-256:{short}"
        ))
        .expect_err("short");
        let message = err.to_string();
        assert!(message.contains("30 bytes"), "{message}");
        assert!(message.contains("32"), "{message}");

        // A 48-byte value under sha-256 is refused too, rather than "close enough".
        let other = thumbprint(&key, ThumbprintHash::Sha384).expect("384");
        let err = JwkThumbprintUri::parse(&format!(
            "urn:ietf:params:oauth:jwk-thumbprint:sha-256:{other}"
        ))
        .expect_err("wrong digest size");
        assert!(err.to_string().contains("48 bytes"), "{err}");

        // Padding is not base64url-narrow.
        let err = JwkThumbprintUri::parse(&format!(
            "urn:ietf:params:oauth:jwk-thumbprint:sha-256:{value}="
        ))
        .expect_err("padding");
        assert!(err.to_string().contains("base64url"), "{err}");

        // Empty value.
        let err = JwkThumbprintUri::parse("urn:ietf:params:oauth:jwk-thumbprint:sha-256:")
            .expect_err("empty");
        assert!(err.to_string().contains("thumbprint value"), "{err}");
    }
}
