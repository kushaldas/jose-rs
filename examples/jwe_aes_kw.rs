//! JWE encryption with AES-256 Key Wrap + AES-128-GCM content encryption.
//!
//! Prerequisite: cargo run --example generate_keys
//! Run: cargo run --example jwe_aes_kw

use jose_rs::{JweAlgorithm, JweEncryption};

fn load_jwk(path: &str) -> jose_rs::jwk::Jwk {
    let json = std::fs::read_to_string(path).unwrap_or_else(|_| {
        panic!("Key file not found: {path}\nRun `cargo run --example generate_keys` first.")
    });
    jose_rs::jwk::Jwk::from_json(&json).expect("invalid JWK")
}

fn main() -> jose_rs::Result<()> {
    // Load AES key (used as Key Encryption Key)
    let jwk = load_jwk("examples/keys/aes.jwk");
    let key = jose_rs::jwk::jwk_to_software_key(&jwk)?;
    let kek = match &key {
        kryptering::SoftwareKey::Aes(bytes) => bytes.clone(),
        kryptering::SoftwareKey::Hmac(bytes) => bytes.clone(),
        _ => panic!("expected symmetric key"),
    };

    let plaintext = b"This is a secret message encrypted with AES Key Wrap.";
    println!("Plaintext: {}", std::str::from_utf8(plaintext).unwrap());

    // Encrypt
    let token = jose_rs::jwe::encrypt(
        &kek,
        plaintext,
        JweAlgorithm::A256KW,
        JweEncryption::A128GCM,
    )?;
    println!(
        "\nJWE token ({} bytes):\n{}...{}\n",
        token.len(),
        &token[..60],
        &token[token.len() - 20..]
    );

    // Decrypt
    let decrypted = jose_rs::jwe::decrypt(&kek, &token)?;
    println!("Decrypted: {}", std::str::from_utf8(&decrypted).unwrap());
    assert_eq!(decrypted, plaintext);

    Ok(())
}
