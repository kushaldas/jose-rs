//! JSON Web Signature (JWS) signing, verification, and certificate binding.
//!
//! [`crate::jws::compact`] implements RFC 7515 Compact Serialization,
//! [`crate::jws::json`] implements Flattened and General JSON Serialization,
//! and [`crate::jws::x5`] provides helpers for binding protected headers to
//! X.509 certificates.

pub mod compact;
pub mod json;
pub mod x5;

pub use compact::{
    decode_header, sign, sign_with_options, verify, verify_with_options, SignOptions,
    VerifyOptions, LIB_UNDERSTOOD_CRIT,
};
