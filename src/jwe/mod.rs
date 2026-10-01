//! JWE (JSON Web Encryption) -- RFC 7516.
//!
//! Supports compact serialization with these key management algorithms:
//! - `dir` -- direct use of a shared symmetric key as the CEK
//! - `A128KW`, `A192KW`, `A256KW` -- AES Key Wrap (RFC 3394)
//! - `RSA-OAEP`, `RSA-OAEP-256` -- RSA-OAEP key transport
//!
//! And these content encryption algorithms:
//! - `A128GCM`, `A192GCM`, `A256GCM` -- AES-GCM
//! - `A128CBC-HS256`, `A192CBC-HS384`, `A256CBC-HS512` -- AES-CBC with HMAC

pub mod compact;

/// Shared content-encryption implementation (crate-private).
mod content;
/// Shared envelope parsing, header policy and key management (crate-private).
mod internal;

pub use compact::{
    decrypt, decrypt_with_jwk, decrypt_with_options, encrypt, encrypt_with_header,
    encrypt_with_header_options, encrypt_with_jwk, encrypt_with_jwk_header,
    encrypt_with_jwk_header_options, JweDecryptOptions, JweEncryptOptions,
};
