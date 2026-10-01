//! JWT Claims Set (RFC 7519 Section 4).

use super::NumericDate;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// JWT Claims Set (RFC 7519 Section 4).
///
/// Registered claims are typed fields; custom claims go in `extra`.
/// Dates use [`NumericDate`] to preserve fractional seconds. Integer Rust
/// assignments use `Some(seconds.into())`. Parse original JSON directly into
/// `Claims` to avoid precision already lost in an intermediate floating-point
/// value. Serialization normalizes numeric spelling without rounding values.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Claims {
    /// Issuer (`iss`)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,

    /// Subject (`sub`)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,

    /// Audience (`aud`) — can be a single string or array of strings
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<Audience>,

    /// Expiration Time (`exp`) — NumericDate (seconds since epoch)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exp: Option<NumericDate>,

    /// Not Before (`nbf`) — NumericDate
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nbf: Option<NumericDate>,

    /// Issued At (`iat`) — NumericDate
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iat: Option<NumericDate>,

    /// JWT ID (`jti`)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,

    /// Custom claims
    #[serde(flatten)]
    pub extra: std::collections::HashMap<String, Value>,
}

/// Audience can be a single string or an array of strings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Audience {
    /// A single audience string.
    Single(String),
    /// Multiple acceptable audience strings.
    Multiple(Vec<String>),
}

impl Audience {
    /// Check if this audience contains the given value.
    pub fn contains(&self, value: &str) -> bool {
        match self {
            Self::Single(s) => s == value,
            Self::Multiple(v) => v.iter().any(|s| s == value),
        }
    }
}
