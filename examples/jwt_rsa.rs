//! JWT signing with RS256 (private key) and verification with the public key.
//!
//! Prerequisite: cargo run --example generate_keys
//! Run: cargo run --example jwt_rsa

use jose_rs::jwt::{Audience, Claims, Validation};
use jose_rs::{JoseHeader, JwsAlgorithm};
use std::time::{SystemTime, UNIX_EPOCH};

fn load_jwk(path: &str) -> jose_rs::jwk::Jwk {
    let json = std::fs::read_to_string(path)
        .unwrap_or_else(|_| panic!("Key file not found: {path}\nRun `cargo run --example generate_keys` first."));
    jose_rs::jwk::Jwk::from_json(&json).expect("invalid JWK")
}

fn main() -> jose_rs::Result<()> {
    // Load private key for signing
    let private_jwk = load_jwk("examples/keys/rsa-private.jwk");
    let private_key = jose_rs::jwk::jwk_to_software_key(&private_jwk)?;
    let algo = JwsAlgorithm::RS256.to_crypto()?;
    let signer = kryptering::SoftwareSigner::new(algo, private_key)?;

    // Build claims
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let mut claims = Claims::default();
    claims.iss = Some("auth.example.com".into());
    claims.sub = Some("user@example.com".into());
    claims.aud = Some(Audience::Single("api.example.com".into()));
    claims.exp = Some(now + 3600);
    claims.iat = Some(now);

    // Sign
    let header = JoseHeader::jwt("RS256");
    let token = jose_rs::jwt::encode(&signer, &header, &claims)?;
    println!("JWT signed with RS256 ({} bytes)", token.len());
    println!("{}\n", &token[..80]);

    // Load public key for verification
    let public_jwk = load_jwk("examples/keys/rsa-public.jwk");
    let public_key = jose_rs::jwk::jwk_to_software_key(&public_jwk)?;
    let verifier = kryptering::SoftwareVerifier::new(algo, public_key)?;

    let validation = Validation::new()
        .with_issuer("auth.example.com")
        .with_audience("api.example.com");
    let decoded = jose_rs::jwt::decode(&verifier, &token, &validation)?;
    println!("Verified with public key:");
    println!("  iss: {:?}", decoded.iss);
    println!("  sub: {:?}", decoded.sub);
    println!("  aud: {:?}", decoded.aud);

    Ok(())
}
