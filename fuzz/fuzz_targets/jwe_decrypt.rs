#![no_main]

use libfuzzer_sys::fuzz_target;

// JWE decrypt pipeline with a fixed 32-byte CEK in `dir` mode. The
// MAX_TOKEN_BYTES cap bounds memory; beyond that, the decoder must
// handle any input without panicking.
fuzz_target!(|data: &[u8]| {
    let cek = [0x42u8; 32];
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = jose_rs::jwe::decrypt(&cek, s);
    }
});
