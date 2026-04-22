//! Base64url encoding/decoding (RFC 4648 §5, no padding).
//!
//! RFC 7515, 7516, and 7519 mandate unpadded base64url for all JOSE fields.
//! This module rejects padded input on decode to align with the spec and
//! avoid accepting two distinct encodings of the same byte string.

use crate::error::{JoseError, Result};
use base64::Engine;

const ENGINE: base64::engine::GeneralPurpose = base64::engine::GeneralPurpose::new(
    &base64::alphabet::URL_SAFE,
    base64::engine::GeneralPurposeConfig::new()
        .with_decode_padding_mode(base64::engine::DecodePaddingMode::RequireNone)
        .with_encode_padding(false),
);

/// Encode bytes to base64url (no padding).
pub fn encode(data: &[u8]) -> String {
    ENGINE.encode(data)
}

/// Decode base64url string to bytes. Padding is rejected (RFC 7515).
pub fn decode(s: &str) -> Result<Vec<u8>> {
    ENGINE
        .decode(s)
        .map_err(|e| JoseError::Base64(format!("{e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let data = b"hello world";
        let encoded = encode(data);
        assert!(!encoded.contains('='), "should have no padding");
        assert!(!encoded.contains('+'), "should use URL-safe alphabet");
        assert!(!encoded.contains('/'), "should use URL-safe alphabet");
        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    /// J-13 regression: padded input is rejected (RFC 7515 mandates unpadded).
    #[test]
    fn rejects_padding() {
        // URL_SAFE engine emits padding; URL_SAFE_NO_PAD does not.
        let padded = base64::engine::general_purpose::URL_SAFE.encode(b"test");
        assert!(padded.ends_with('='));
        let result = decode(&padded);
        assert!(
            result.is_err(),
            "padded base64url must be rejected, got {result:?}"
        );
    }

    #[test]
    fn empty() {
        assert_eq!(encode(b""), "");
        assert_eq!(decode("").unwrap(), b"");
    }
}
