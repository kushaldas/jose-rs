#![no_main]

use libfuzzer_sys::fuzz_target;

// decode_unverified parses header + claims without touching crypto —
// exactly the code path that receives attacker-controlled JSON payloads
// early. Must never panic.
fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        #[allow(deprecated)]
        let _ = jose_rs::jwt::decode_unverified(s);
    }
});
