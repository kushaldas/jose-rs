//! JWT Validation configuration (RFC 7519).

use crate::algorithm::JwsAlgorithm;
use crate::error::{JoseError, Result};
use crate::header::JoseHeader;
use crate::jwt::claims::Claims;
use std::time::{SystemTime, UNIX_EPOCH};

/// Validation configuration for JWT decoding.
#[derive(Debug, Clone)]
pub struct Validation {
    /// Required issuer. If set, `iss` claim must match.
    pub issuer: Option<String>,
    /// Required audience. If set, `aud` claim must contain this value.
    pub audience: Option<String>,
    /// Required subject. If set, `sub` claim must match.
    pub subject: Option<String>,
    /// Required `typ` header value (RFC 8725 §3.11). If set, the JWS
    /// protected header's `typ` field must equal this string.
    pub required_typ: Option<String>,
    /// Maximum acceptable age (seconds) between the `iat` claim and now.
    /// If set and `iat` is present, tokens older than this are rejected.
    pub max_age: Option<u64>,
    /// Allow-list of JwsAlgorithm values. If non-empty, the token's
    /// header `alg` must map to one of these. Empty means no restriction
    /// beyond the verifier-algorithm binding.
    pub allowed_algorithms: Vec<JwsAlgorithm>,
    /// Clock skew tolerance in seconds (default: 60).
    pub leeway: u64,
    /// Whether to validate `exp` claim (default: true).
    pub validate_exp: bool,
    /// Whether to validate `nbf` claim (default: true).
    pub validate_nbf: bool,
    /// Whether to reject tokens whose `iat` is in the future (default: true).
    pub validate_iat_not_future: bool,
}

impl Default for Validation {
    fn default() -> Self {
        Self {
            issuer: None,
            audience: None,
            subject: None,
            required_typ: None,
            max_age: None,
            allowed_algorithms: Vec::new(),
            leeway: 60,
            validate_exp: true,
            validate_nbf: true,
            validate_iat_not_future: true,
        }
    }
}

impl Validation {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_issuer(mut self, issuer: impl Into<String>) -> Self {
        self.issuer = Some(issuer.into());
        self
    }

    pub fn with_audience(mut self, audience: impl Into<String>) -> Self {
        self.audience = Some(audience.into());
        self
    }

    /// Require the `sub` claim to equal this value.
    pub fn with_subject(mut self, subject: impl Into<String>) -> Self {
        self.subject = Some(subject.into());
        self
    }

    pub fn with_leeway(mut self, seconds: u64) -> Self {
        self.leeway = seconds;
        self
    }

    /// Require the protected header's `typ` field to equal this string
    /// (RFC 8725 §3.11). Prevents JWT-in-different-context confusion —
    /// e.g. an OpenID ID Token being accepted where a service-to-service
    /// JWT was expected.
    pub fn with_typ(mut self, typ: impl Into<String>) -> Self {
        self.required_typ = Some(typ.into());
        self
    }

    /// Reject tokens older than `seconds` when `iat` is present.
    /// Bounds replay windows on long-lived tokens.
    pub fn with_max_age(mut self, seconds: u64) -> Self {
        self.max_age = Some(seconds);
        self
    }

    /// Restrict the set of permitted JWS algorithms. Defence in depth on
    /// top of the verifier-binding enforced at the JWS layer. An empty
    /// list means no additional restriction.
    pub fn with_allowed_algorithms(mut self, algs: Vec<JwsAlgorithm>) -> Self {
        self.allowed_algorithms = algs;
        self
    }

    /// Validate claims against this configuration.
    ///
    /// Header-bound checks (`typ`, `allowed_algorithms`) are skipped when
    /// no header is available. Callers that have the protected header
    /// should prefer [`Validation::validate_with_header`].
    pub fn validate(&self, claims: &Claims) -> Result<()> {
        self.validate_internal(claims, None)
    }

    /// Validate claims AND the protected header together. Enables the
    /// header-bound checks configured by [`Validation::with_typ`] and
    /// [`Validation::with_allowed_algorithms`].
    pub fn validate_with_header(&self, claims: &Claims, header: &JoseHeader) -> Result<()> {
        self.validate_internal(claims, Some(header))
    }

    fn validate_internal(&self, claims: &Claims, header: Option<&JoseHeader>) -> Result<()> {
        // Header-bound checks (run first — fail fast on a mis-typed token).
        if let Some(h) = header {
            if let Some(required_typ) = &self.required_typ {
                match &h.typ {
                    Some(t) if t == required_typ => {}
                    _ => {
                        return Err(JoseError::InvalidHeader(format!(
                            "expected typ={required_typ}, got {:?}",
                            h.typ
                        )))
                    }
                }
            }
            if !self.allowed_algorithms.is_empty() {
                let alg = JwsAlgorithm::from_str(&h.alg)?;
                if !self.allowed_algorithms.contains(&alg) {
                    return Err(JoseError::UnsupportedAlgorithm(format!(
                        "alg {} is not in the caller's allow-list",
                        h.alg
                    )));
                }
            }
        }

        // If the system clock is before 1970 something is very wrong — fail closed.
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| JoseError::InvalidClaims("system clock is before UNIX_EPOCH".into()))?
            .as_secs();

        // Check expiration — use saturating_add so an attacker-controlled exp
        // near u64::MAX cannot wrap and falsely satisfy the comparison.
        if self.validate_exp {
            if let Some(exp) = claims.exp {
                if now > exp.saturating_add(self.leeway) {
                    return Err(JoseError::Expired);
                }
            }
        }

        // Check not-before — saturating_add prevents overflow at the high end.
        if self.validate_nbf {
            if let Some(nbf) = claims.nbf {
                if now.saturating_add(self.leeway) < nbf {
                    return Err(JoseError::NotYetValid);
                }
            }
        }

        // Reject future-dated iat (attacker-controlled or clock-skewed issuer).
        if self.validate_iat_not_future {
            if let Some(iat) = claims.iat {
                if iat > now.saturating_add(self.leeway) {
                    return Err(JoseError::InvalidClaims("iat is in the future".into()));
                }
            }
        }

        // Enforce max token age relative to iat.
        if let (Some(max_age), Some(iat)) = (self.max_age, claims.iat) {
            // now - iat > max_age + leeway → too old.
            // Use saturating to handle any edge cases.
            if now > iat.saturating_add(max_age).saturating_add(self.leeway) {
                return Err(JoseError::Expired);
            }
        }

        // Check issuer
        if let Some(ref required_iss) = self.issuer {
            match &claims.iss {
                Some(iss) if iss == required_iss => {}
                _ => return Err(JoseError::InvalidIssuer),
            }
        }

        // Check audience
        if let Some(ref required_aud) = self.audience {
            match &claims.aud {
                Some(aud) if aud.contains(required_aud) => {}
                _ => return Err(JoseError::InvalidAudience),
            }
        }

        // Check subject
        if let Some(ref required_sub) = self.subject {
            match &claims.sub {
                Some(sub) if sub == required_sub => {}
                _ => return Err(JoseError::InvalidClaims("subject mismatch".into())),
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    /// Phase 5: typ header mismatch is rejected.
    #[test]
    fn typ_mismatch_rejected() {
        let mut header = JoseHeader::new("HS256");
        header.typ = Some("JWT".into());
        let mut claims = Claims::default();
        claims.exp = Some(now() + 3600);

        let validation = Validation::new().with_typ("at+jwt");
        let err = validation
            .validate_with_header(&claims, &header)
            .unwrap_err()
            .to_string();
        assert!(err.contains("at+jwt"), "unexpected: {err}");
    }

    /// Phase 5: missing typ when required is rejected.
    #[test]
    fn typ_missing_when_required() {
        let header = JoseHeader::new("HS256"); // typ unset
        let mut claims = Claims::default();
        claims.exp = Some(now() + 3600);

        let validation = Validation::new().with_typ("JWT");
        assert!(validation.validate_with_header(&claims, &header).is_err());
    }

    /// Phase 5: typ match succeeds.
    #[test]
    fn typ_match_accepted() {
        let mut header = JoseHeader::new("HS256");
        header.typ = Some("JWT".into());
        let mut claims = Claims::default();
        claims.exp = Some(now() + 3600);

        let validation = Validation::new().with_typ("JWT");
        validation.validate_with_header(&claims, &header).unwrap();
    }

    /// Phase 5: allowed_algorithms rejects an unlisted alg.
    #[test]
    fn alg_allow_list_rejects_unlisted() {
        let header = JoseHeader::new("HS256");
        let mut claims = Claims::default();
        claims.exp = Some(now() + 3600);

        let validation = Validation::new().with_allowed_algorithms(vec![JwsAlgorithm::RS256]);
        let err = validation
            .validate_with_header(&claims, &header)
            .unwrap_err()
            .to_string();
        assert!(err.contains("allow-list"), "unexpected: {err}");
    }

    /// Phase 5: allowed_algorithms accepts a listed alg.
    #[test]
    fn alg_allow_list_accepts_listed() {
        let header = JoseHeader::new("HS256");
        let mut claims = Claims::default();
        claims.exp = Some(now() + 3600);

        let validation = Validation::new()
            .with_allowed_algorithms(vec![JwsAlgorithm::HS256, JwsAlgorithm::RS256]);
        validation.validate_with_header(&claims, &header).unwrap();
    }

    /// Phase 5: iat too old vs max_age is rejected.
    #[test]
    fn max_age_rejects_old_iat() {
        let mut claims = Claims::default();
        claims.iat = Some(now() - 3600); // issued 1h ago

        let validation = Validation::new().with_max_age(60); // 60s cap
        let err = validation.validate(&claims).unwrap_err();
        assert!(matches!(err, JoseError::Expired));
    }

    /// Phase 5: iat within max_age is accepted.
    #[test]
    fn max_age_accepts_recent_iat() {
        let mut claims = Claims::default();
        claims.iat = Some(now() - 10); // 10s ago

        let validation = Validation::new().with_max_age(60);
        validation.validate(&claims).unwrap();
    }

    /// Phase 5: iat in the future (beyond leeway) is rejected.
    #[test]
    fn iat_in_future_rejected() {
        let mut claims = Claims::default();
        claims.iat = Some(now() + 3600); // 1h in the future

        let validation = Validation::new(); // default 60s leeway
        let err = validation.validate(&claims).unwrap_err().to_string();
        assert!(err.contains("future"), "unexpected: {err}");
    }

    /// Phase 5: iat slightly in the future (within leeway) is accepted.
    #[test]
    fn iat_within_leeway_accepted() {
        let mut claims = Claims::default();
        claims.iat = Some(now() + 30); // 30s in the future, within 60s leeway

        let validation = Validation::new();
        validation.validate(&claims).unwrap();
    }

    /// Phase 5: with_subject builder and subject check.
    #[test]
    fn with_subject_builder_and_check() {
        let mut claims = Claims::default();
        claims.sub = Some("alice".into());
        claims.exp = Some(now() + 3600);

        let v = Validation::new().with_subject("alice");
        v.validate(&claims).unwrap();

        let v_wrong = Validation::new().with_subject("bob");
        assert!(v_wrong.validate(&claims).is_err());
    }

    /// J-12 regression: exp near u64::MAX with a non-zero leeway must not
    /// overflow into a small number (which would previously cause spurious
    /// Expired errors for far-future tokens).
    #[test]
    fn exp_near_u64_max_does_not_wrap() {
        let mut claims = Claims::default();
        claims.exp = Some(u64::MAX - 1);
        let validation = Validation::new().with_leeway(60);
        // Far-future exp must not be reported as expired.
        validation.validate(&claims).unwrap();
    }

    /// J-12 regression: nbf near u64::MAX with leeway must not overflow either.
    #[test]
    fn nbf_near_u64_max_does_not_wrap() {
        let mut claims = Claims::default();
        claims.nbf = Some(u64::MAX - 1);
        let validation = Validation::new().with_leeway(60);
        // nbf in the far future means not-yet-valid — expected error, not a panic.
        let err = validation.validate(&claims).unwrap_err();
        assert!(matches!(err, JoseError::NotYetValid));
    }
}
