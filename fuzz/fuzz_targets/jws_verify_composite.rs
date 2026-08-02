#![no_main]

use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

// Exercise attacker-controlled compact JWS parsing and aggregate signature
// splitting with a fixed ML-DSA-44-Ed25519 public AKP key.
fn jwk() -> &'static jose_rs::jwk::Jwk {
    static CELL: OnceLock<jose_rs::jwk::Jwk> = OnceLock::new();
    CELL.get_or_init(|| {
        jose_rs::jwk::generate_composite_mldsa(kryptering::CompositeMlDsaVariant::MlDsa44Ed25519)
            .expect("composite key generation must succeed")
            .to_public_jwk()
    })
}

fuzz_target!(|data: &[u8]| {
    if let Ok(token) = std::str::from_utf8(data) {
        let _ = jose_rs::jws::compact::verify_with_jwk(jwk(), token);
    }
});
