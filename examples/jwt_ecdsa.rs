//! JWT signing with ES256 (ECDSA P-256) and verification with the public key.
//!
//! Prerequisite: cargo run --example generate_keys
//! Run: cargo run --example jwt_ecdsa

use jose_rs::jwt::{Claims, Validation};
use jose_rs::{JoseHeader, JwsAlgorithm};
use std::time::{SystemTime, UNIX_EPOCH};

fn load_jwk(path: &str) -> jose_rs::jwk::Jwk {
    let json = std::fs::read_to_string(path)
        .unwrap_or_else(|_| panic!("Key file not found: {path}\nRun `cargo run --example generate_keys` first."));
    jose_rs::jwk::Jwk::from_json(&json).expect("invalid JWK")
}

fn main() -> jose_rs::Result<()> {
    let private_jwk = load_jwk("examples/keys/ec-private.jwk");
    let private_key = jose_rs::jwk::jwk_to_software_key(&private_jwk)?;
    let algo = JwsAlgorithm::ES256.to_crypto()?;
    let signer = kryptering::SoftwareSigner::new(algo, private_key)?;

    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let mut claims = Claims::default();
    claims.iss = Some("mobile-app".into());
    claims.sub = Some("device-abc123".into());
    claims.exp = Some(now + 300); // 5 minutes
    claims.iat = Some(now);

    let header = JoseHeader::jwt("ES256");
    let token = jose_rs::jwt::encode(&signer, &header, &claims)?;
    println!("JWT signed with ES256 ({} bytes)", token.len());
    println!("{}\n", &token[..80]);

    // Verify with public key
    let public_jwk = load_jwk("examples/keys/ec-public.jwk");
    let public_key = jose_rs::jwk::jwk_to_software_key(&public_jwk)?;
    let verifier = kryptering::SoftwareVerifier::new(algo, public_key)?;

    let validation = Validation::new().with_issuer("mobile-app");
    let decoded = jose_rs::jwt::decode(&verifier, &token, &validation)?;
    println!("Verified with EC public key:");
    println!("  iss: {:?}", decoded.iss);
    println!("  sub: {:?}", decoded.sub);

    Ok(())
}
