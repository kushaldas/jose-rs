#![no_main]

use libfuzzer_sys::fuzz_target;

// RFC 7638 thumbprint computation over attacker-supplied JWKs.
// The phase-1 fix replaced string-concat with serde_json — but the
// serializer still has to handle every JWK field value.
fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        if let Ok(jwk) = jose_rs::jwk::Jwk::from_json(s) {
            let _ = jose_rs::jwk::thumbprint::thumbprint_sha256(&jwk);
        }
    }
});
