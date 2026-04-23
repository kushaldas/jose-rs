//! JWT signing and verification with ML-DSA (post-quantum, FIPS 204).
//!
//! Run: cargo run --example jwt_ml_dsa --features post-quantum
//!
//! This example generates a fresh ML-DSA-65 keypair, signs a JWT, derives
//! the public companion via `to_public_jwk()`, and verifies the token
//! using only the public key. It exercises the full AKP (Algorithm Key
//! Pair) wire format per `draft-ietf-cose-dilithium`.

use jose_rs::jwt::{Claims, Validation};
use jose_rs::JoseHeader;
use std::time::{SystemTime, UNIX_EPOCH};

fn main() -> jose_rs::Result<()> {
    // 1. Generate a fresh ML-DSA-65 keypair as a JWK.
    //    The resulting JWK carries:
    //      kty  = "AKP"
    //      alg  = "ML-DSA-65"
    //      pub  = raw FIPS 204 public key bytes (base64url, 1952 bytes)
    //      priv = 32-byte FIPS 204 seed (base64url)
    let private_jwk = jose_rs::jwk::generate_mldsa(kryptering::MlDsaVariant::MlDsa65)?;
    println!(
        "Generated {} key ({} kty, pub = {} raw bytes, priv = 32-byte seed)",
        private_jwk.alg.as_deref().unwrap_or("?"),
        private_jwk.kty,
        jose_rs::base64url::decode(private_jwk.pub_.as_deref().unwrap())?.len(),
    );

    // 2. Sign a JWT via the JWK-first API.
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_secs();
    let claims = Claims {
        iss: Some("ml-dsa-issuer".into()),
        sub: Some("alice".into()),
        exp: Some(now + 600),
        ..Default::default()
    };

    let header = JoseHeader::jwt("ML-DSA-65");
    let token = jose_rs::jwt::encode_with_jwk(&private_jwk, &header, &claims)?;
    println!(
        "JWT signed with ML-DSA-65 ({} bytes total, sig ≈ 3309 bytes)",
        token.len()
    );
    println!("{}…\n", &token[..80]);

    // 3. Derive the public companion. `to_public_jwk()` drops `priv` and
    //    keeps `pub` — exactly the shape you would publish in a JWK Set.
    let public_jwk = private_jwk.to_public_jwk();
    assert!(public_jwk.priv_.is_none(), "priv must be stripped");
    assert!(public_jwk.pub_.is_some(), "pub must survive");

    // 4. Verify using only the public JWK.
    let validation = Validation::new().with_issuer("ml-dsa-issuer");
    let decoded = jose_rs::jwt::decode_with_jwk(&public_jwk, &token, &validation)?;
    println!("Verified with ML-DSA-65 public key:");
    println!("  iss: {:?}", decoded.iss);
    println!("  sub: {:?}", decoded.sub);
    println!("  exp: {:?}", decoded.exp);

    Ok(())
}
