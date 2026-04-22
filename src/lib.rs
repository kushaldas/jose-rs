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

/// Maximum token length (in bytes) accepted by the JWS and JWE decoders.
///
/// Caps memory allocation from an attacker-supplied oversized token — the
/// decoders refuse any input longer than this before any base64url or
/// JSON decoding runs. Set to 1 MiB, which comfortably exceeds any
/// realistic JOSE token (RFC 7519 §2 notes that JWTs are compact
/// precisely to fit HTTP Authorization headers, URLs, and POST bodies).
pub const MAX_TOKEN_BYTES: usize = 1024 * 1024;
