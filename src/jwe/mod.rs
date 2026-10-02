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
//! - `ECDH-ES` -- direct ECDH key agreement (RFC 7518 §4.6): the CEK is agreed
//!   with one recipient, the ephemeral key is generated per message and published
//!   as `epk` in the protected header, and nothing is conveyed as the encrypted
//!   key. Needs a JWK (a curve and coordinates are not something `&[u8]` can
//!   carry) and provides **no origin authentication** -- see ADR 0016/0017.
//!
//! Content encryption algorithms:
//! - `A128GCM`, `A192GCM`, `A256GCM` -- AES-GCM
//! - `A128CBC-HS256`, `A192CBC-HS384`, `A256CBC-HS512` -- AES-CBC with HMAC
//!
//! External additional authenticated data (`aad`) and the unprotected header
//! members (`unprotected`, `header`) are read under the policies in ADR 0012
//! and ADR 0013; this crate emits neither unprotected parameters nor anything
//! it cannot itself decrypt.
//!
//! The General JSON Serialization (`recipients`, multiple recipients sharing one
//! ciphertext) is read and produced through [`general`]; decryption there is
//! always scoped to one recipient the caller names, because the header the
//! content tag is validated under is per-recipient (ADR 0014).
//!
//! Not implemented, and refused by name rather than ignored: content
//! compression (`zip`), which this crate cannot decrypt and therefore will not
//! emit; and key agreement addressing more than one recipient of a general JWE,
//! which needs one `epk` per recipient and has nowhere authenticated to put it
//! (ADR 0018). The agreement modes themselves — `ECDH-ES` (ADR 0017) and
//! `ECDH-ES+A128KW`/`+A192KW`/`+A256KW` (ADR 0018) — are implemented, in the
//! compact and flattened serializations, through
//! [`crate::jwk::agreement`] (ADR 0016).

pub mod compact;
pub mod general;
pub mod json;

/// Shared content-encryption implementation (crate-private).
mod content;
/// Shared envelope parsing, header policy and key management (crate-private).
///
/// `pub(crate)` rather than `private` so that the key-agreement boundary in
/// [`crate::jwk::agreement`] can run the derivation policy (JOSE's Concat KDF)
/// that the JWE algorithms themselves use — one implementation of RFC 7518
/// §4.6.2, not one per caller. It is not part of the public API.
pub(crate) mod internal;

pub use compact::{
    decrypt, decrypt_with_jwk, decrypt_with_options, encrypt, encrypt_with_header,
    encrypt_with_header_options, encrypt_with_jwk, encrypt_with_jwk_header,
    encrypt_with_jwk_header_options, JweDecryptOptions, JweEncryptOptions,
};
