//! JWT Claims Set (RFC 7519 Section 4).

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// JWT Claims Set (RFC 7519 Section 4).
///
/// Registered claims are typed fields; custom claims go in `extra`.
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<u64>,

    /// Not Before (`nbf`) — NumericDate
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nbf: Option<u64>,

    /// Issued At (`iat`) — NumericDate
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat: Option<u64>,

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
    Single(String),
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
