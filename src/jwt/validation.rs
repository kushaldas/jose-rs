//! JWT Validation configuration (RFC 7519).

use crate::error::{JoseError, Result};
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
    /// Clock skew tolerance in seconds (default: 60).
    pub leeway: u64,
    /// Whether to validate `exp` claim (default: true).
    pub validate_exp: bool,
    /// Whether to validate `nbf` claim (default: true).
    pub validate_nbf: bool,
}

impl Default for Validation {
    fn default() -> Self {
        Self {
            issuer: None,
            audience: None,
            subject: None,
            leeway: 60,
            validate_exp: true,
            validate_nbf: true,
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

    pub fn with_leeway(mut self, seconds: u64) -> Self {
        self.leeway = seconds;
        self
    }

    /// Validate claims against this configuration.
    pub fn validate(&self, claims: &Claims) -> Result<()> {
        // If the system clock is before 1970 something is very wrong — fail closed.
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| {
                JoseError::InvalidClaims("system clock is before UNIX_EPOCH".into())
            })?
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
