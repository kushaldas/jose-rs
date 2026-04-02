//! Generate test keys and save them as JWK files.
//!
//! Run this first to create the key files used by all other examples:
//!   cargo run --example generate_keys
//!
//! Creates:
//!   examples/keys/rsa-private.jwk    RSA 2048 private key
//!   examples/keys/rsa-public.jwk     RSA 2048 public key
//!   examples/keys/ec-private.jwk     EC P-256 private key
//!   examples/keys/ec-public.jwk      EC P-256 public key
//!   examples/keys/ed25519-private.jwk  Ed25519 private key
//!   examples/keys/ed25519-public.jwk   Ed25519 public key
//!   examples/keys/hmac.jwk           256-bit HMAC symmetric key
//!   examples/keys/aes.jwk            256-bit AES symmetric key

use jose_rs::jwk;

fn main() -> jose_rs::Result<()> {
    let dir = "examples/keys";
    std::fs::create_dir_all(dir).expect("failed to create keys directory");

    // RSA 2048
    println!("Generating RSA 2048 key pair...");
    let rsa = jwk::generate_rsa(2048)?;
    std::fs::write(format!("{dir}/rsa-private.jwk"), rsa.to_json_pretty()?).unwrap();
    let mut rsa_pub = rsa;
    rsa_pub.d = None;
    rsa_pub.p = None;
    rsa_pub.q = None;
    rsa_pub.dp = None;
    rsa_pub.dq = None;
    rsa_pub.qi = None;
    std::fs::write(format!("{dir}/rsa-public.jwk"), rsa_pub.to_json_pretty()?).unwrap();
    println!("  -> {dir}/rsa-private.jwk, {dir}/rsa-public.jwk");

    // EC P-256
    println!("Generating EC P-256 key pair...");
    let ec = jwk::generate_ec("P-256")?;
    std::fs::write(format!("{dir}/ec-private.jwk"), ec.to_json_pretty()?).unwrap();
    let mut ec_pub = ec;
    ec_pub.d = None;
    std::fs::write(format!("{dir}/ec-public.jwk"), ec_pub.to_json_pretty()?).unwrap();
    println!("  -> {dir}/ec-private.jwk, {dir}/ec-public.jwk");

    // Ed25519
    println!("Generating Ed25519 key pair...");
    let ed = jwk::generate_ed25519()?;
    std::fs::write(format!("{dir}/ed25519-private.jwk"), ed.to_json_pretty()?).unwrap();
    let mut ed_pub = ed;
    ed_pub.d = None;
    std::fs::write(format!("{dir}/ed25519-public.jwk"), ed_pub.to_json_pretty()?).unwrap();
    println!("  -> {dir}/ed25519-private.jwk, {dir}/ed25519-public.jwk");

    // HMAC (256-bit symmetric)
    println!("Generating 256-bit HMAC key...");
    let mut hmac = jwk::generate_symmetric(32)?;
    hmac.alg = Some("HS256".into());
    hmac.use_ = Some("sig".into());
    std::fs::write(format!("{dir}/hmac.jwk"), hmac.to_json_pretty()?).unwrap();
    println!("  -> {dir}/hmac.jwk");

    // AES (256-bit symmetric)
    println!("Generating 256-bit AES key...");
    let aes = jwk::generate_symmetric(32)?;
    std::fs::write(format!("{dir}/aes.jwk"), aes.to_json_pretty()?).unwrap();
    println!("  -> {dir}/aes.jwk");

    println!("\nAll keys generated. Run other examples now.");
    Ok(())
}
