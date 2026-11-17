//! Explicit untrusted inspection for application-owned key discovery.
use super::{Claims, Validation};
use crate::{
    jwk::{selection::SelectionPolicy, JwkSet},
    Authenticated, JoseError, JoseHeader, Result,
};

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
    /// Applies normal token bounds and duplicate-member checks. Parsing does
    /// not validate signatures, claim policy, or trust in any key reference.
    ///
    /// # Errors
    ///
    /// Returns [`JoseError::InvalidToken`] for bad compact shape or size,
    /// [`JoseError::InvalidClaims`] for ambiguous claims, [`JoseError::Json`]
    /// for malformed JSON, or [`JoseError::Base64`] for noncanonical encoding.
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
        let claims = Claims::from_json_bytes(&crate::base64url::decode(payload)?)?;
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
