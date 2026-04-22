#![no_main]

use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

// Full JWS verify pipeline for ML-DSA-44 (FIPS 204). The fuzzer feeds
// arbitrary bytes in as a compact JWS and we call verify_with_jwk with a
// fixed keypair. The target is meant to surface panics / UB in the AKP
// JWK parse path, the raw↔SPKI public-key conversion, or the post-quantum
// sign/verify dispatch — not to break the signature scheme itself.
//
// ML-DSA-44 (not -65/-87) is picked deliberately: it has the smallest
// expanded signing key (fits comfortably in libFuzzer's default stack) and
// the fastest verify, so throughput is highest.

fn jwk() -> &'static jose_rs::jwk::Jwk {
    static CELL: OnceLock<jose_rs::jwk::Jwk> = OnceLock::new();
    CELL.get_or_init(|| {
        jose_rs::jwk::generate_mldsa(kryptering::MlDsaVariant::MlDsa44)
            .expect("generate_mldsa must succeed with a valid RNG")
    })
}

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = jose_rs::jws::compact::verify_with_jwk(jwk(), s);
    }
});
