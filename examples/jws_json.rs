//! JWS JSON serialization — flattened and general (multi-signature).
//!
//! Prerequisite: cargo run --example generate_keys
//! Run: cargo run --example jws_json

use jose_rs::JoseHeader;

fn load_jwk(path: &str) -> jose_rs::jwk::Jwk {
    let json = std::fs::read_to_string(path)
        .unwrap_or_else(|_| panic!("Key file not found: {path}\nRun `cargo run --example generate_keys` first."));
    jose_rs::jwk::Jwk::from_json(&json).expect("invalid JWK")
}

fn main() -> jose_rs::Result<()> {
    let payload = b"This payload is signed with JWS JSON serialization.";

    // -- Flattened JWS JSON (single signature) --
    let ec_jwk = load_jwk("examples/keys/ec-private.jwk");
    let ec_key = jose_rs::jwk::jwk_to_software_key(&ec_jwk)?;
    let ec_algo = jose_rs::JwsAlgorithm::ES256.to_crypto()?;
    let ec_signer = kryptering::SoftwareSigner::new(ec_algo, ec_key)?;

    let header = JoseHeader::new("ES256");
    let flattened = jose_rs::jws::json::sign_flattened(&ec_signer, payload, &header)?;
    let flattened_json = serde_json::to_string_pretty(&flattened).unwrap();
    println!("=== Flattened JWS JSON ===\n{flattened_json}\n");

    // Verify flattened
    let ec_pub_jwk = load_jwk("examples/keys/ec-public.jwk");
    let ec_pub_key = jose_rs::jwk::jwk_to_software_key(&ec_pub_jwk)?;
    let ec_verifier = kryptering::SoftwareVerifier::new(ec_algo, ec_pub_key)?;
    let verified = jose_rs::jws::json::verify_flattened(&ec_verifier, &flattened)?;
    println!("Flattened verified: {}\n", std::str::from_utf8(&verified).unwrap());

    // -- General JWS JSON (two signatures: EC + Ed25519) --
    let ed_jwk = load_jwk("examples/keys/ed25519-private.jwk");
    let ed_key = jose_rs::jwk::jwk_to_software_key(&ed_jwk)?;
    let ed_algo = jose_rs::JwsAlgorithm::EdDSA.to_crypto()?;
    let ed_signer = kryptering::SoftwareSigner::new(ed_algo, ed_key)?;

    let ec_header = JoseHeader::new("ES256");
    let ed_header = JoseHeader::new("EdDSA");
    let signers: Vec<(&dyn kryptering::Signer, &JoseHeader)> = vec![
        (&ec_signer, &ec_header),
        (&ed_signer, &ed_header),
    ];
    let general = jose_rs::jws::json::sign_general(&signers, payload)?;
    let general_json = serde_json::to_string_pretty(&general).unwrap();
    println!("=== General JWS JSON (2 signatures) ===\n{general_json}\n");

    // Verify with either key
    let verified = jose_rs::jws::json::verify_general(&ec_verifier, &general)?;
    println!("General verified with EC key: {}", std::str::from_utf8(&verified).unwrap());

    Ok(())
}
