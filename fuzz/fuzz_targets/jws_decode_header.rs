#![no_main]

use libfuzzer_sys::fuzz_target;

// decode_header is called before any verification as part of the
// alg-binding check, so it sees attacker-controlled tokens. Must never
// panic regardless of the input.
fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = jose_rs::jws::compact::decode_header(s);
    }
});
