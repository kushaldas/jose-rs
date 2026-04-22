//! JWE encryption with RSA-OAEP-256 key transport + AES-256-GCM content encryption.
//!
//! Encrypts with the RSA public key, decrypts with the RSA private key.
//!
//! Prerequisite: cargo run --example generate_keys
//! Run: cargo run --example jwe_rsa_oaep

use jose_rs::{JweAlgorithm, JweEncryption};

fn load_jwk(path: &str) -> jose_rs::jwk::Jwk {
    let json = std::fs::read_to_string(path)
        .unwrap_or_else(|_| panic!("Key file not found: {path}\nRun `cargo run --example generate_keys` first."));
    jose_rs::jwk::Jwk::from_json(&json).expect("invalid JWK")
}

fn main() -> jose_rs::Result<()> {
    let plaintext = b"Top secret data encrypted with RSA-OAEP + AES-256-GCM.";
    println!("Plaintext: {}", std::str::from_utf8(plaintext).unwrap());

    // Load RSA public key for encryption
    let pub_jwk = load_jwk("examples/keys/rsa-public.jwk");
    let pub_key = jose_rs::jwk::jwk_to_software_key(&pub_jwk)?;
    let pub_der = match &pub_key {
        kryptering::SoftwareKey::Rsa { public, .. } => {
            use rsa::pkcs8::EncodePublicKey;
            public.to_public_key_der()
                .map_err(|e| jose_rs::JoseError::Key(format!("DER encode: {e}")))?
                .to_vec()
        }
        _ => panic!("expected RSA key"),
    };

    // Encrypt with RSA-OAEP-256 (SHA-1 OAEP is deprecated; use SHA-256 OAEP by default).
    let token = jose_rs::jwe::encrypt(
        &pub_der,
        plaintext,
        JweAlgorithm::RsaOaep256,
        JweEncryption::A256GCM,
    )?;
    println!("\nJWE token ({} bytes)", token.len());

    // Load RSA private key for decryption
    let priv_jwk = load_jwk("examples/keys/rsa-private.jwk");
    let priv_key = jose_rs::jwk::jwk_to_software_key(&priv_jwk)?;
    let priv_der = match &priv_key {
        kryptering::SoftwareKey::Rsa { private: Some(pk), .. } => {
            use rsa::pkcs8::EncodePrivateKey;
            pk.to_pkcs8_der()
                .map_err(|e| jose_rs::JoseError::Key(format!("DER encode: {e}")))?
                .to_bytes()
                .to_vec()
        }
        _ => panic!("expected RSA private key"),
    };

    // Decrypt
    let decrypted = jose_rs::jwe::decrypt(&priv_der, &token)?;
    println!("Decrypted: {}", std::str::from_utf8(&decrypted).unwrap());
    assert_eq!(decrypted, plaintext);

    Ok(())
}
