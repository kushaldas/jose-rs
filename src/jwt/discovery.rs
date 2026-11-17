//! Explicit untrusted inspection for application-owned key discovery.
use super::{Claims, Validation};
use crate::{
    jwk::{selection::SelectionPolicy, JwkSet},
    Authenticated, JoseError, JoseHeader, Result,
};

/// Validate raw discovery JSON without normalizing nested objects into Values.
/// A selector may extract keys from any claim, so matching just `jwks` leaves
/// alternate claim names and array positions open to the same parser differential.
fn ensure_unique_members(bytes: &[u8]) -> Result<()> {
    struct UniqueJson;

    impl<'de> serde::Deserialize<'de> for UniqueJson {
        fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            struct UniqueVisitor;

            impl<'de> serde::de::Visitor<'de> for UniqueVisitor {
                type Value = UniqueJson;

                fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    f.write_str("JSON with unique object members")
                }

                fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
                where
                    A: serde::de::MapAccess<'de>,
                {
                    let mut seen = std::collections::HashSet::new();
                    while let Some(name) = map.next_key::<String>()? {
                        // Compare decoded names before reading their values, including
                        // escaped equivalents. Prevent key-policy confusion from JSON
                        // parser differentials (RFC 7517 §4).
                        if !seen.insert(name.clone()) {
                            return Err(serde::de::Error::custom(format!(
                                "duplicate JSON member {name}"
                            )));
                        }
                        map.next_value::<UniqueJson>()?;
                    }
                    Ok(UniqueJson)
                }

                fn visit_seq<A>(self, mut seq: A) -> std::result::Result<Self::Value, A::Error>
                where
                    A: serde::de::SeqAccess<'de>,
                {
                    while seq.next_element::<UniqueJson>()?.is_some() {}
                    Ok(UniqueJson)
                }

                fn visit_bool<E>(self, _: bool) -> std::result::Result<Self::Value, E> {
                    Ok(UniqueJson)
                }

                fn visit_i64<E>(self, _: i64) -> std::result::Result<Self::Value, E> {
                    Ok(UniqueJson)
                }

                fn visit_u64<E>(self, _: u64) -> std::result::Result<Self::Value, E> {
                    Ok(UniqueJson)
                }

                fn visit_f64<E>(self, _: f64) -> std::result::Result<Self::Value, E> {
                    Ok(UniqueJson)
                }

                fn visit_str<E>(self, _: &str) -> std::result::Result<Self::Value, E> {
                    Ok(UniqueJson)
                }

                fn visit_unit<E>(self) -> std::result::Result<Self::Value, E> {
                    Ok(UniqueJson)
                }
            }

            deserializer.deserialize_any(UniqueVisitor)
        }
    }

    // Streaming validation retains serde_json's recursion limit and EOF check.
    // Numeric values are only traversed; the real Claims parse keeps their exact
    // arbitrary-precision representation. The token-size check has already run.
    serde_json::from_slice::<UniqueJson>(bytes)
        .map(|_| ())
        .map_err(|err| JoseError::InvalidClaims(err.to_string()))
}

/// A bounded JWT inspected solely to discover candidate verification keys.
///
/// Header and claims are **untrusted**. Never use them for authorization,
/// routing privileged operations, or unrestricted URL fetching (RFC 8725 §3.10).
/// Possession of an embedded key proves no issuer identity. The original token
/// is retained privately, so later verification never authenticates reserialized
/// claims. Debug deliberately omits the token and untrusted payload.
#[derive(Clone)]
pub struct UnverifiedJwt {
    token: String,
    header: JoseHeader,
    claims: Claims,
}

impl std::fmt::Debug for UnverifiedJwt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UnverifiedJwt").finish_non_exhaustive()
    }
}

impl UnverifiedJwt {
    /// Inspect a compact, base64url-encoded JWT for key discovery only.
    ///
    /// Applies normal token bounds and rejects duplicate members at every payload
    /// object depth before normalization. Selectors may read nested key metadata
    /// from any claim. Unlike ordinary claim parsing, discovery cannot safely
    /// collapse those duplicates. Parsing does not validate signatures, claim
    /// policy, or trust in any key reference.
    ///
    /// # Errors
    ///
    /// Returns [`JoseError::InvalidToken`] for bad compact shape or size,
    /// [`JoseError::InvalidClaims`] for ambiguous or malformed payload JSON,
    /// [`JoseError::Json`] for malformed header JSON, or [`JoseError::Base64`]
    /// for noncanonical encoding.
    /// RFC 7797 unencoded JWT payloads are refused.
    pub fn parse(token: &str) -> Result<Self> {
        let header = crate::jws::compact::decode_header(token)?;
        let mut parts = token.split('.');
        let _ = parts.next();
        let payload = parts
            .next()
            .ok_or_else(|| JoseError::InvalidToken("expected 3 parts".into()))?;
        let signature = parts
            .next()
            .ok_or_else(|| JoseError::InvalidToken("expected 3 parts".into()))?;
        if parts.next().is_some() || signature.is_empty() {
            return Err(JoseError::InvalidToken(
                "expected 3 nonempty signed JWT parts".into(),
            ));
        }
        if header.extra.get("b64") == Some(&serde_json::Value::Bool(false)) {
            return Err(JoseError::InvalidToken(
                "JWT payload must be base64url encoded".into(),
            ));
        }
        crate::base64url::decode(signature)?;
        let payload = crate::base64url::decode(payload)?;
        ensure_unique_members(&payload)?;
        let claims = Claims::from_json_bytes(&payload)?;
        Ok(Self {
            token: token.to_owned(),
            header,
            claims,
        })
    }

    /// Read the **untrusted** header to discover a key; it conveys no identity.
    pub fn header(&self) -> &JoseHeader {
        &self.header
    }

    /// Read **untrusted** claims solely for application-owned key discovery.
    pub fn claims(&self) -> &Claims {
        &self.claims
    }

    /// Verify the original token with a bounded key set, then validate claims.
    ///
    /// Uses [`SelectionPolicy::default`], including its candidate ceiling.
    /// Async applications may discover keys between parsing and this call.
    /// No network access or issuer trust is supplied by this method.
    ///
    /// # Errors
    ///
    /// Propagates selection, signature and claims-policy failures from
    /// [`super::decode_with_jwkset_policy_authenticated`].
    pub fn verify_with(
        &self,
        set: &JwkSet,
        validation: &Validation,
    ) -> Result<Authenticated<Claims>> {
        self.verify_with_policy(set, validation, &SelectionPolicy::default())
    }

    /// Verify the original token with an explicit key-selection policy.
    ///
    /// # Errors
    ///
    /// Propagates selection, signature and claim errors from
    /// [`super::decode_with_jwkset_policy_authenticated`].
    pub fn verify_with_policy(
        &self,
        set: &JwkSet,
        validation: &Validation,
        policy: &SelectionPolicy,
    ) -> Result<Authenticated<Claims>> {
        super::decode_with_jwkset_policy_authenticated(set, &self.token, validation, policy)
    }
}

/// Discover embedded keys from untrusted claims, then verify the original JWT.
///
/// The selector is synchronous and called once; use [`UnverifiedJwt`] when key
/// discovery needs async I/O. Self-signature verifies possession, **not** issuer
/// identity or authority. Callers supply any external trust policy separately.
/// The returned claims are parsed from the verified payload, not the selector's
/// input. Candidate attempts are bounded by [`SelectionPolicy::default`].
///
/// ```
/// use jose_rs::{jwk::{self, JwkSet}, jwt::{self, Claims, Validation}, JoseHeader};
/// let mut key = jwk::generate_ed448()?;
/// key.alg = Some("Ed448".into());
/// let mut claims = Claims::default();
/// claims.extra.insert("jwks".into(), serde_json::json!({"keys":[key.to_public_jwk()]}));
/// let token = jwt::encode_with_jwk(&key, &JoseHeader::new("Ed448"), &claims)?;
/// let verified = jwt::decode_self_signed(&token, &Validation::new(), |untrusted| {
///     JwkSet::from_json(&untrusted.extra["jwks"].to_string())
/// })?;
/// assert_eq!(verified.value, claims);
/// # Ok::<(), jose_rs::JoseError>(())
/// ```
///
/// # Errors
///
/// Propagates inspection errors from [`UnverifiedJwt::parse`], selector errors,
/// and bounded verification/claims-policy errors from [`UnverifiedJwt::verify_with`].
pub fn decode_self_signed<F>(
    token: &str,
    validation: &Validation,
    select_keys: F,
) -> Result<Authenticated<Claims>>
where
    F: FnOnce(&Claims) -> Result<JwkSet>,
{
    let inspected = UnverifiedJwt::parse(token)?;
    let set = select_keys(inspected.claims())?;
    inspected.verify_with(&set, validation)
}
