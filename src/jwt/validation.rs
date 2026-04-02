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
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Check expiration
        if self.validate_exp {
            if let Some(exp) = claims.exp {
                if now > exp + self.leeway {
                    return Err(JoseError::Expired);
                }
            }
        }

        // Check not-before
        if self.validate_nbf {
            if let Some(nbf) = claims.nbf {
                if now + self.leeway < nbf {
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
