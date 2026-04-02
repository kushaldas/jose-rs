/// Errors produced by JOSE operations.
#[derive(Debug, thiserror::Error)]
pub enum JoseError {
    #[error("cryptographic error: {0}")]
    Crypto(#[from] kryptering::Error),

    #[error("invalid token format: {0}")]
    InvalidToken(String),

    #[error("invalid header: {0}")]
    InvalidHeader(String),

    #[error("invalid claims: {0}")]
    InvalidClaims(String),

    #[error("unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),

    #[error("key error: {0}")]
    Key(String),

    #[error("token expired")]
    Expired,

    #[error("token not yet valid")]
    NotYetValid,

    #[error("invalid issuer")]
    InvalidIssuer,

    #[error("invalid audience")]
    InvalidAudience,

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("base64 decode error: {0}")]
    Base64(String),
}

pub type Result<T> = std::result::Result<T, JoseError>;
