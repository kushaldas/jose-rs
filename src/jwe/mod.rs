//! JWE (JSON Web Encryption) -- RFC 7516.
//!
//! Two serializations are available over one shared policy core:
//!
//! - [`compact`] -- the five-part dotted Compact Serialization (RFC 7516 §7.1)
//! - [`json`] -- the single-recipient Flattened JSON Serialization
//!   (RFC 7516 §7.2.2), with all header parameters protected
//!
//! Both use the same header validation, the same decryption-time algorithm
//! allow-list, the same exact plaintext-size limit, the same key-management
//! rules and the same content ciphers, so neither serialization is a
//! weaker path than the other.
//!
//! Key management algorithms:
//! - `dir` -- direct use of a shared symmetric key as the CEK
//! - `A128KW`, `A192KW`, `A256KW` -- AES Key Wrap (RFC 3394)
//! - `RSA-OAEP`, `RSA-OAEP-256` -- RSA-OAEP key transport
//!
//! Content encryption algorithms:
//! - `A128GCM`, `A192GCM`, `A256GCM` -- AES-GCM
//! - `A128CBC-HS256`, `A192CBC-HS384`, `A256CBC-HS512` -- AES-CBC with HMAC
//!
//! Not implemented, and refused by name rather than ignored: the General JSON
//! Serialization (`recipients`), external additional authenticated data
//! (`aad`), and the unprotected header members (`unprotected`, `header`) --
//! see ADR 0011, ADR 0012, ADR 0013 and ADR 0014. Compression (`zip`) is not
//! implemented either.

pub mod compact;
pub mod json;

/// Shared content-encryption implementation (crate-private).
mod content;
/// Shared envelope parsing, header policy and key management (crate-private).
mod internal;

pub use compact::{
    decrypt, decrypt_with_jwk, decrypt_with_options, encrypt, encrypt_with_header,
    encrypt_with_header_options, encrypt_with_jwk, encrypt_with_jwk_header,
    encrypt_with_jwk_header_options, JweDecryptOptions, JweEncryptOptions,
};
