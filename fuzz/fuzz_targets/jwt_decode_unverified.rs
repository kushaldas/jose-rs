#![no_main]

use libfuzzer_sys::fuzz_target;

// Exercise legacy inspection and the new key-discovery inspection path,
// including bounded verification with embedded candidate keys. None of these
// untrusted inputs may panic; successful self-verification implies no issuer trust.
fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        #[allow(deprecated)]
        let _ = jose_rs::jwt::decode_unverified(s);
        if let Ok(inspected) = jose_rs::jwt::UnverifiedJwt::parse(s) {
            let _ = inspected.header();
            if let Some(value) = inspected.claims().extra.get("jwks") {
                if let Ok(set) = jose_rs::jwk::JwkSet::from_json_with_limits(
                    &value.to_string(),
                    &jose_rs::jwk::selection::SetLimits::default(),
                ) {
                    let _ = inspected.verify_with(&set, &jose_rs::jwt::Validation::new());
                }
            }
        }
    }
});
