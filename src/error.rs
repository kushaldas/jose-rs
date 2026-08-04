//! Error and result types for JOSE operations.

/// Errors produced by JOSE operations.
#[derive(Debug, thiserror::Error)]
pub enum JoseError {
    /// A cryptographic backend operation failed.
    #[error("cryptographic error: {0}")]
    Crypto(#[from] kryptering::Error),

    /// A serialized JOSE token is malformed or fails structural validation.
    #[error("invalid token format: {0}")]
    InvalidToken(String),

    /// A JOSE protected header is malformed or violates configured policy.
    #[error("invalid header: {0}")]
    InvalidHeader(String),

    /// JWT claims are malformed or violate configured validation policy.
    #[error("invalid claims: {0}")]
    InvalidClaims(String),

    /// The requested or encoded JOSE algorithm is unsupported.
    #[error("unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),

    /// Key material is malformed, incomplete, or incompatible with an operation.
    #[error("key error: {0}")]
    Key(String),

    /// JWT validation found that the token has expired.
    #[error("token expired")]
    Expired,

    /// JWT validation found that the token is not valid yet.
    #[error("token not yet valid")]
    NotYetValid,

    /// The JWT issuer does not match the configured issuer.
    #[error("invalid issuer")]
    InvalidIssuer,

    /// The JWT audience does not contain the configured audience.
    #[error("invalid audience")]
    InvalidAudience,

    /// JSON serialization or deserialization failed.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Base64url decoding failed.
    #[error("base64 decode error: {0}")]
    Base64(String),
}

/// Result type returned by `jose-rs` operations.
pub type Result<T> = std::result::Result<T, JoseError>;
