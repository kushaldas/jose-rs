//! Nested JWT — a signed JWT encrypted inside a JWE.
//!
//! Signs a JWT with Ed25519, then encrypts it with AES Key Wrap + AES-GCM.
//! On the receiving side, decrypts the JWE then verifies the inner JWT.
//!
//! Prerequisite: cargo run --example generate_keys
//! Run: cargo run --example nested_jwt

use jose_rs::jwt::{Claims, Validation};
use jose_rs::{JoseHeader, JweAlgorithm, JweEncryption, JwsAlgorithm};
use std::time::{SystemTime, UNIX_EPOCH};

fn load_jwk(path: &str) -> jose_rs::jwk::Jwk {
    let json = std::fs::read_to_string(path)
        .unwrap_or_else(|_| panic!("Key file not found: {path}\nRun `cargo run --example generate_keys` first."));
    jose_rs::jwk::Jwk::from_json(&json).expect("invalid JWK")
}

fn main() -> jose_rs::Result<()> {
    // Load signing key (Ed25519)
    let ed_jwk = load_jwk("examples/keys/ed25519-private.jwk");
    let ed_key = jose_rs::jwk::jwk_to_software_key(&ed_jwk)?;
    let sign_algo = JwsAlgorithm::EdDSA.to_crypto()?;
    let signer = kryptering::SoftwareSigner::new(sign_algo, ed_key)?;

    // Load encryption key (AES-256 for key wrapping)
    let aes_jwk = load_jwk("examples/keys/aes.jwk");
    let aes_key = jose_rs::jwk::jwk_to_software_key(&aes_jwk)?;
    let kek = match &aes_key {
        kryptering::SoftwareKey::Aes(bytes) => bytes.clone(),
        kryptering::SoftwareKey::Hmac(bytes) => bytes.clone(),
        _ => panic!("expected symmetric key"),
    };

    // Build claims
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let mut claims = Claims::default();
    claims.iss = Some("secure-service".into());
    claims.sub = Some("confidential-user".into());
    claims.exp = Some(now + 3600);
    claims.extra.insert("role".into(), serde_json::json!("admin"));

    // Sign then encrypt (nested JWT)
    let jws_header = JoseHeader::jwt("EdDSA");
    let token = jose_rs::jwt::encode_nested(
        &signer,
        &jws_header,
        &claims,
        &kek,
        JweAlgorithm::A256KW,
        JweEncryption::A256GCM,
    )?;
    println!("Nested JWT (sign + encrypt):");
    println!("  Outer: JWE with A256KW + A256GCM");
    println!("  Inner: JWS with EdDSA");
    println!("  Token: {} bytes\n", token.len());

    // Decrypt then verify (on the receiving side)
    let ed_pub_jwk = load_jwk("examples/keys/ed25519-public.jwk");
    let ed_pub_key = jose_rs::jwk::jwk_to_software_key(&ed_pub_jwk)?;
    let verifier = kryptering::SoftwareVerifier::new(sign_algo, ed_pub_key)?;

    let validation = Validation::new().with_issuer("secure-service");
    let decoded = jose_rs::jwt::decode_nested(&kek, &verifier, &token, &validation)?;
    println!("Decrypted and verified:");
    println!("  iss:  {:?}", decoded.iss);
    println!("  sub:  {:?}", decoded.sub);
    println!("  role: {:?}", decoded.extra.get("role"));

    Ok(())
}
