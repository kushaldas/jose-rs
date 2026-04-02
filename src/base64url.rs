//! Base64url encoding/decoding (RFC 4648 §5, no padding).

use crate::error::{JoseError, Result};
use base64::Engine;

const ENGINE: base64::engine::GeneralPurpose = base64::engine::GeneralPurpose::new(
    &base64::alphabet::URL_SAFE,
    base64::engine::GeneralPurposeConfig::new()
        .with_decode_padding_mode(base64::engine::DecodePaddingMode::Indifferent)
        .with_encode_padding(false),
);

/// Encode bytes to base64url (no padding).
pub fn encode(data: &[u8]) -> String {
    ENGINE.encode(data)
}

/// Decode base64url string to bytes (accepts with or without padding).
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

    #[test]
    fn accepts_padding() {
        // Should accept input with padding too
        let encoded = base64::engine::general_purpose::URL_SAFE.encode(b"test");
        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded, b"test");
    }

    #[test]
    fn empty() {
        assert_eq!(encode(b""), "");
        assert_eq!(decode("").unwrap(), b"");
    }
}
