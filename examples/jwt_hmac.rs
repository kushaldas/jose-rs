//! JWT signing and verification with HMAC-SHA256.
//!
//! Prerequisite: cargo run --example generate_keys
//! Run: cargo run --example jwt_hmac

use jose_rs::jwt::{Claims, Validation};
use jose_rs::{JoseHeader, JwsAlgorithm};
use std::time::{SystemTime, UNIX_EPOCH};

fn load_jwk(path: &str) -> jose_rs::jwk::Jwk {
    let json = std::fs::read_to_string(path)
        .unwrap_or_else(|_| panic!("Key file not found: {path}\nRun `cargo run --example generate_keys` first."));
    jose_rs::jwk::Jwk::from_json(&json).expect("invalid JWK")
}

fn main() -> jose_rs::Result<()> {
    let jwk = load_jwk("examples/keys/hmac.jwk");
    let key = jose_rs::jwk::jwk_to_software_key(&jwk)?;
    let algo = JwsAlgorithm::HS256.to_crypto()?;
    // Load the key twice since SoftwareKey is not Clone
    let key2 = jose_rs::jwk::jwk_to_software_key(&jwk)?;
    let signer = kryptering::SoftwareSigner::new(algo, key)?;
    let verifier = kryptering::SoftwareVerifier::new(algo, key2)?;

    // Build claims
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let mut claims = Claims::default();
    claims.iss = Some("example-service".into());
    claims.sub = Some("user-42".into());
    claims.iat = Some(now);
    claims.exp = Some(now + 3600);

    // Sign
    let header = JoseHeader::jwt("HS256");
    let token = jose_rs::jwt::encode(&signer, &header, &claims)?;
    println!("JWT token:\n{token}\n");

    // Verify
    let validation = Validation::new().with_issuer("example-service");
    let decoded = jose_rs::jwt::decode(&verifier, &token, &validation)?;
    println!("Verified claims:");
    println!("  iss: {:?}", decoded.iss);
    println!("  sub: {:?}", decoded.sub);
    println!("  exp: {:?}", decoded.exp);

    Ok(())
}
