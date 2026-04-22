#![no_main]

use libfuzzer_sys::fuzz_target;

// JWK JSON parser: attacker-controlled input in practice (jku fetches,
// JWK Set endpoints, inline jwk header). Must not panic on any byte
// sequence — malformed input should return JoseError, not crash.
fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        if let Ok(jwk) = jose_rs::jwk::Jwk::from_json(s) {
            // Exercise downstream paths that may trip on malformed JWKs.
            let _ = jose_rs::jwk::jwk_to_software_key(&jwk);
            let _ = jose_rs::jwk::thumbprint::thumbprint_sha256(&jwk);
            let _ = jwk.to_public_jwk();
            // All JwkOp variants — check_op is pure validation over
            // use / key_ops and must not panic.
            for op in [
                jose_rs::JwkOp::Sign,
                jose_rs::JwkOp::Verify,
                jose_rs::JwkOp::Encrypt,
                jose_rs::JwkOp::Decrypt,
                jose_rs::JwkOp::WrapKey,
                jose_rs::JwkOp::UnwrapKey,
                jose_rs::JwkOp::DeriveKey,
                jose_rs::JwkOp::DeriveBits,
            ] {
                let _ = jwk.check_op(op);
            }
        }
    }
});
