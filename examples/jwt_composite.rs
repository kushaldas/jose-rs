//! JWT signing and verification with ML-DSA-65-Ed25519.
//!
//! Run: cargo run --example jwt_composite --features post-quantum

use jose_rs::jwt::{Claims, Validation};
use jose_rs::JoseHeader;
use kryptering::CompositeMlDsaVariant;
use std::time::{SystemTime, UNIX_EPOCH};

fn main() -> jose_rs::Result<()> {
    let variant = CompositeMlDsaVariant::MlDsa65Ed25519;
    let private_jwk = jose_rs::jwk::generate_composite_mldsa(variant)?;
    let public_jwk = private_jwk.to_public_jwk();

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_secs();
    let claims = Claims {
        iss: Some("composite-issuer".into()),
        sub: Some("alice".into()),
        exp: Some(now + 600),
        ..Default::default()
    };

    let header = JoseHeader::jwt(variant.name());
    let token = jose_rs::jwt::encode_with_jwk(&private_jwk, &header, &claims)?;
    let decoded = jose_rs::jwt::decode_with_jwk(
        &public_jwk,
        &token,
        &Validation::new().with_issuer("composite-issuer"),
    )?;

    assert_eq!(decoded.sub.as_deref(), Some("alice"));
    println!(
        "Verified {} JWT with a {}-byte aggregate signature",
        variant.name(),
        variant.signature_len()
    );
    Ok(())
}
