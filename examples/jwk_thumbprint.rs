//! JWK Thumbprint computation (RFC 7638).
//!
//! Computes the SHA-256 thumbprint for each key type.
//!
//! Prerequisite: cargo run --example generate_keys
//! Run: cargo run --example jwk_thumbprint

fn load_jwk(path: &str) -> jose_rs::jwk::Jwk {
    let json = std::fs::read_to_string(path)
        .unwrap_or_else(|_| panic!("Key file not found: {path}\nRun `cargo run --example generate_keys` first."));
    jose_rs::jwk::Jwk::from_json(&json).expect("invalid JWK")
}

fn main() -> jose_rs::Result<()> {
    let keys = [
        ("RSA", "examples/keys/rsa-public.jwk"),
        ("EC P-256", "examples/keys/ec-public.jwk"),
        ("Ed25519", "examples/keys/ed25519-public.jwk"),
        ("HMAC", "examples/keys/hmac.jwk"),
    ];

    println!("JWK Thumbprints (SHA-256, base64url):\n");
    for (name, path) in keys {
        let jwk = load_jwk(path);
        let thumbprint = jose_rs::jwk::thumbprint::thumbprint_sha256(&jwk)?;
        println!("  {name:10} {thumbprint}");
    }

    Ok(())
}
