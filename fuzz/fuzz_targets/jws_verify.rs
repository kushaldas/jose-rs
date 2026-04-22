#![no_main]

use libfuzzer_sys::fuzz_target;

// Full JWS verify pipeline with a fixed HMAC verifier. The fuzzer's job
// is to find panics / UB — not to break the HMAC. A successful
// verification is fine (and expected for the first few well-formed
// inputs the fuzzer discovers); we just want no crashes.
fuzz_target!(|data: &[u8]| {
    use kryptering::{HashAlgorithm, SignatureAlgorithm, SoftwareKey, SoftwareVerifier};

    let key = SoftwareKey::Hmac(b"fuzz-key-at-least-thirty-two-bytes!".to_vec());
    let verifier = match SoftwareVerifier::new(
        SignatureAlgorithm::Hmac(HashAlgorithm::Sha256),
        key,
    ) {
        Ok(v) => v,
        Err(_) => return,
    };

    if let Ok(s) = std::str::from_utf8(data) {
        let _ = jose_rs::jws::compact::verify(&verifier, s);
    }
});
