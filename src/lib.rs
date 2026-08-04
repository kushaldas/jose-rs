//! Pure-Rust JSON Object Signing and Encryption (JOSE) primitives.
//!
//! The crate provides JSON Web Signature (JWS), JSON Web Encryption (JWE),
//! JSON Web Key (JWK), and JSON Web Token (JWT) APIs backed by software keys
//! and optional PKCS#11 keys. Algorithms are represented by typed enums, and
//! higher-level JWK APIs bind key metadata to signing, verification,
//! encryption, and decryption operations.
//!
//! Optional crate features enable post-quantum algorithms, deprecated JOSE
//! algorithms needed for legacy interoperability, and PKCS#11 support.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod algorithm;
pub mod base64url;
/// Error and result types returned by JOSE operations.
pub mod error;
pub mod header;
pub mod jwe;
pub mod jwk;
/// JSON Web Signature compact and JSON serialization APIs.
pub mod jws;
pub mod jwt;

pub use algorithm::{JweAlgorithm, JweEncryption, JwsAlgorithm};
pub use error::{JoseError, Result};
pub use header::JoseHeader;
pub use jwk::JwkOp;

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
