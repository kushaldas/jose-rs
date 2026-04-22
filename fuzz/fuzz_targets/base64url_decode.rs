#![no_main]

use libfuzzer_sys::fuzz_target;

// Feed arbitrary bytes as the "encoded" string. base64url::decode must
// handle any input without panicking, regardless of length, alphabet, or
// padding state.
fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = jose_rs::base64url::decode(s);
    }
});
