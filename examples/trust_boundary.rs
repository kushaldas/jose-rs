//! The trust boundary, in four short acts (plan L4).
//!
//! Run with `cargo run --example trust_boundary`.
//!
//! Everything this program prints about a document comes from one of two places, and the
//! whole point is that they are not the same place: the bytes a signature covered, and the
//! bytes that merely travelled with it.

use jose_rs::jwe::json as jwe_json;
use jose_rs::jwk::{self, Jwk};
use jose_rs::jws::json as jws_json;
use jose_rs::jws::SignOptions;
use jose_rs::{ErrorCategory, JoseHeader};
use serde_json::{json, Map};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut signing_key = jwk::generate_ec("P-256")?;
    signing_key.alg = Some("ES256".into());

    // ---------------------------------------------------------------------
    // 1. A verified document hands back the header it authenticated.
    // ---------------------------------------------------------------------
    let mut header = JoseHeader::new("ES256");
    header.kid = Some("real-key".into());
    header.typ = Some("application/jose+json".into());

    let mut flattened = jws_json::sign_flattened_with_jwk_opts(
        &signing_key,
        br#"{"sub":"alice"}"#,
        &header,
        Some(json!({"comment": "in the clear"})),
        &SignOptions::new(),
    )?;

    let outcome = jws_json::verify_flattened_with_jwk_authenticated(&signing_key, &flattened)?;
    println!(
        "verified payload      : {}",
        String::from_utf8_lossy(&outcome.value)
    );
    println!("authenticated kid     : {:?}", outcome.kid());
    println!("authenticated typ     : {:?}", outcome.protected.typ);
    println!("unauthenticated       : {:?}", outcome.unprotected);
    println!();

    // ---------------------------------------------------------------------
    // 2. An on-path attacker rewrites the unprotected member. Nothing about the
    //    authenticated view changes — because the type never merges the two.
    // ---------------------------------------------------------------------
    flattened.header = Some(json!({
        "kid": "attacker-key",
        "alg": "HS256",
        "comment": "please use my key",
    }));
    let outcome = jws_json::verify_flattened_with_jwk_authenticated(&signing_key, &flattened)?;
    println!("after the rewrite:");
    println!(
        "  authenticated kid   : {:?}   <- still the signed one",
        outcome.kid()
    );
    println!("  offered (unsigned)  : {:?}", outcome.unprotected[0]);
    println!(
        "  had this been read as authority, the document would have been \
         re-verified under an attacker-chosen alg/kid"
    );
    println!();

    // ---------------------------------------------------------------------
    // 3. Our serializer refuses to emit the ambiguity in the first place.
    // ---------------------------------------------------------------------
    let refused = jws_json::sign_flattened_with_jwk_opts(
        &signing_key,
        b"x",
        &header,
        // `kid` already lives in the protected header: emitting it twice would make one
        // document two documents, and readers disagree about which member wins.
        Some(json!({"kid": "duplicate"})),
        &SignOptions::new(),
    );
    match refused {
        Err(err) => println!(
            "serializer refusal    : {err}  [{}]",
            describe(err.category())
        ),
        Ok(_) => println!("serializer refusal    : UNEXPECTEDLY ACCEPTED"),
    }
    println!();

    // ---------------------------------------------------------------------
    // 4. Errors are classified coarsely, on purpose.
    // ---------------------------------------------------------------------
    let wrong_key = jwk::generate_ed25519()?;
    let mut wrong_key_jwk: Jwk = wrong_key;
    wrong_key_jwk.alg = Some("EdDSA".into());

    let token = jose_rs::jws::compact::sign_with_jwk(&signing_key, b"payload", &header)?;
    let tampered = {
        let mut parts: Vec<String> = token.split('.').map(str::to_string).collect();
        let mut sig = jose_rs::base64url::decode(&parts[2])?;
        let last = sig.len() - 1;
        sig[last] ^= 0x01;
        parts[2] = jose_rs::base64url::encode(&sig);
        parts.join(".")
    };

    for (label, err) in [
        (
            "signature did not verify",
            jose_rs::jws::compact::verify_with_jwk(&signing_key, &tampered).unwrap_err(),
        ),
        (
            "wrong key supplied",
            jose_rs::jws::compact::verify_with_jwk(&wrong_key_jwk, &token).unwrap_err(),
        ),
        (
            "capability not built",
            jose_rs::JwsAlgorithm::from_str("ES256K")?
                .to_crypto()
                .unwrap_err(),
        ),
        ("malformed document", {
            jose_rs::jws::compact::decode_header("!!!.Q.a").unwrap_err()
        }),
    ] {
        println!(
            "{label:26} : {:?}{}",
            err.category(),
            if err.is_authentication_failure() {
                "  (counts as an authentication failure)"
            } else {
                ""
            }
        );
    }
    println!();
    println!(
        "Note the two rows that are NOT separated: whether an integrity check failed or a \
         backend refused the input on the way there is deliberately merged, because that \
         distinction is a probeable oracle."
    );

    // And a JWE, where unauthenticated metadata lives in two places at once.
    println!();
    let encryption_key = {
        let mut k = jwk::generate_ec("P-256")?;
        k.alg = Some("ECDH-ES+A256KW".into());
        k.extra.insert("use".into(), serde_json::json!("enc"));
        k
    };
    let mut jwe = jwe_json::encrypt_flattened_with_jwk_header(
        &encryption_key,
        JoseHeader::for_jwe(
            jose_rs::JweAlgorithm::EcdhEsA256kw,
            jose_rs::JweEncryption::A256GCM,
        ),
        b"top secret",
        jose_rs::JweEncryption::A256GCM,
    )?;
    // Graft two cleartext members, as an on-path observer would.
    jwe.unprotected = Some(Map::from_iter([(
        "note".to_string(),
        json!("shared, in the clear"),
    )]));
    jwe.header = Some(Map::from_iter([("alg".to_string(), json!("FAKE-ALG"))]));

    let outcome = jwe_json::decrypt_flattened_with_jwk_authenticated(&encryption_key, &jwe)?;
    println!(
        "jwe plaintext           : {}",
        String::from_utf8_lossy(&outcome.value)
    );
    println!("jwe authenticated alg : {}", outcome.algorithm());
    println!(
        "jwe cleartext metadata  : {} object(s), none of it authoritative",
        outcome.unprotected.len()
    );
    Ok(())
}

fn describe(category: ErrorCategory) -> &'static str {
    match category {
        ErrorCategory::UnsupportedCapability => "unsupported capability",
        ErrorCategory::InvalidStructure => "invalid structure",
        ErrorCategory::PolicyRejection => "policy rejection",
        ErrorCategory::AuthenticationFailure => "authentication failure",
        ErrorCategory::KeyMaterial => "key material",
        ErrorCategory::Cryptographic => "cryptographic",
        ErrorCategory::Encoding => "encoding",
        // The enum is `#[non_exhaustive]`: new categories may be added without a breaking
        // change, so downstream matches must carry an arm like this one.
        _ => "other",
    }
}
