#![forbid(unsafe_code)]

pub mod algorithm;
pub mod base64url;
pub mod error;
pub mod header;
pub mod jwe;
pub mod jwk;
pub mod jws;
pub mod jwt;

pub use algorithm::{JweAlgorithm, JweEncryption, JwsAlgorithm};
pub use error::{JoseError, Result};
pub use header::JoseHeader;

/// Minimum RSA modulus size in bits required by RFC 7518 §3.3 / §4.2.
pub const MIN_RSA_BITS: usize = 2048;
