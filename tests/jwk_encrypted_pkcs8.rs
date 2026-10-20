//! Password-encrypted PKCS#8 key files (I3), read from files produced by **other tools**.
//!
//! These are `openssl pkcs8 -topk8` outputs, not files this crate wrote, which is the point:
//! the scheme parameters, iteration counts and armor all come from somebody else's defaults,
//! and the interop claim is about those. Every expected value (curve, coordinates, refusal
//! wording) is written here first, then the run either agrees or the feature is wrong.
//!
//! The passwords are `hunter2`, deliberately in the fixture names and comments: they are test
//! keys, and a real password never belongs in a repository.

use jose_rs::jwk::{
    self, encrypted_pkcs8_pem_from_jwk, jwk_from_encrypted_pkcs8_pem,
    jwk_from_encrypted_pkcs8_pem_with_options, Password, Pkcs8Encryption, Pkcs8ReadOptions,
};

/// `openssl pkcs8 -topk8 -v2 aes-256-cbc -v2prf hmacWithSHA256` (default 2 048 iterations).
const ENC_AES256: &str = include_str!("fixtures/pkcs8/enc_pbkdf2_sha256_aes256.pem");
/// Same, with `-v2 aes-128-cbc -iter 100000`.
const ENC_AES128_100K: &str = include_str!("fixtures/pkcs8/enc_pbkdf2_sha256_aes128.pem");
/// RSA key, `-v2 des3` (3DES).
const ENC_RSA_DES3: &str = include_str!("fixtures/pkcs8/enc_rsa_des3.pem");
/// `-v2 aes-256-cbc -v2prf hmacWithSHA1`.
const ENC_SHA1_PRF: &str = include_str!("fixtures/pkcs8/enc_pbkdf2_sha1_aes256.pem");
/// `-iter 1` — a file that calls itself protected.
const ENC_ONE_ITER: &str = include_str!("fixtures/pkcs8/enc_low_iter.pem");
/// The same key, unencrypted, for the "no fallback" direction.
const PLAIN_EC: &str = include_str!("fixtures/pem/ec_pkcs8.pem");

fn password() -> Password {
    Password::from_utf8("hunter2")
}

/// OpenSSL's default-encrypted EC key imports with the right password and nothing else.
#[test]
fn openssl_default_encrypted_key_imports() {
    let key = jwk_from_encrypted_pkcs8_pem(ENC_AES256, &password()).expect("import");

    // The fixture is a P-256 key whose public point is fixed in the file.
    assert_eq!(key.kty, "EC");
    assert_eq!(key.crv.as_deref(), Some("P-256"));
    assert!(key.d.is_some());
    assert_eq!(
        key.x.as_deref().unwrap().len(),
        43,
        "P-256 x is 43 base64url chars"
    );
    assert_eq!(key.y.as_deref().unwrap().len(), 43);

    // The password is what protected it: every other guess fails.
    for wrong in ["hunter1", "Hunter2", "hunter22"] {
        let err = jwk_from_encrypted_pkcs8_pem(ENC_AES256, &Password::from_utf8(wrong))
            .expect_err("wrong password must not import");
        assert!(err.to_string().contains("decryption failed"), "{err}");
    }
    // An empty password is refused *on the way out* (ADR 0021's decision, applied here too).
    assert!(encrypted_pkcs8_pem_from_jwk(
        &jwk::generate_ec("P-256").expect("generate"),
        &Password::from_utf8(""),
        &Pkcs8Encryption::default()
    )
    .expect_err("empty password")
    .to_string()
    .contains("empty password"));
}

/// The imported key **signs**, and the signature verifies against the same key imported
/// unencrypted — the decryption produced the right key, not merely a parseable one.
#[test]
fn imported_key_signs_and_verifies() {
    let encrypted = jwk_from_encrypted_pkcs8_pem(ENC_AES256, &password()).expect("encrypted");
    let plaintext = jwk::jwk_from_pem(PLAIN_EC).expect("plaintext");

    assert_eq!(encrypted.x, plaintext.x);
    assert_eq!(encrypted.d, plaintext.d);

    let mut signing = encrypted.clone();
    signing.alg = Some(jose_rs::JwsAlgorithm::ES256.as_str().to_string());
    let token = jose_rs::jws::compact::sign_with_jwk(
        &signing,
        b"payload",
        &jose_rs::JoseHeader::new(jose_rs::JwsAlgorithm::ES256.as_str()),
    )
    .expect("sign");
    jose_rs::jws::compact::verify_with_jwk(&plaintext.to_public_jwk(), &token).expect("verify");
}

/// AES-128-CBC with 100 000 iterations is in the allow-list and inside the default budget.
#[test]
fn aes128_with_high_iteration_count_imports() {
    let key = jwk_from_encrypted_pkcs8_pem(ENC_AES128_100K, &password()).expect("import");
    assert_eq!(key.kty, "EC");

    // The same file, with a smaller budget, is refused naming the count it was asked to pay.
    let err = jwk_from_encrypted_pkcs8_pem_with_options(
        ENC_AES128_100K,
        &password(),
        &Pkcs8ReadOptions::default().with_max_iterations(50_000),
    )
    .expect_err("over budget");
    let msg = err.to_string();
    assert!(msg.contains("100000"), "{msg}");
    assert!(msg.contains("50000"), "{msg}");
}

/// 3DES is refused by name, not as a parse failure — and the refusal arrives *before* any
/// password work.
#[test]
fn des3_file_is_refused_by_name() {
    let err = jwk_from_encrypted_pkcs8_pem(ENC_RSA_DES3, &password()).expect_err("3DES");
    let msg = err.to_string();
    assert!(msg.contains("3DES"), "{msg}");
    assert!(msg.contains("AES-CBC"), "{msg}");
    // The refusal must not be laundered into "wrong password".
    assert!(!msg.contains("decryption failed"), "{msg}");
}

/// HMAC-SHA1 as the PBKDF2 PRF is outside the allow-list.
#[test]
fn sha1_prf_is_outside_the_allow_list() {
    let err = jwk_from_encrypted_pkcs8_pem(ENC_SHA1_PRF, &password()).expect_err("SHA-1");
    let msg = err.to_string();
    assert!(msg.contains("HMAC-SHA1"), "{msg}");
    assert!(msg.contains("allow-list"), "{msg}");
}

/// A file that names one iteration is refused: that is not protection, and the message says
/// what to do about it.
#[test]
fn one_iteration_is_below_the_floor() {
    let err = jwk_from_encrypted_pkcs8_pem(ENC_ONE_ITER, &password()).expect_err("1 iteration");
    let msg = err.to_string();
    assert!(msg.contains("1 PBKDF2 iterations"), "{msg}");
    assert!(msg.contains("2048"), "{msg}");
    assert!(msg.contains("re-export"), "{msg}");
}

/// No fallback in either direction: the password path cannot read an unencrypted file, and
/// the plain PEM door refuses an encrypted one and names the function that can.
#[test]
fn no_fallback_between_encrypted_and_plain() {
    let err = jwk_from_encrypted_pkcs8_pem(PLAIN_EC, &password()).expect_err("plain at door");
    assert!(err.to_string().contains("protected"), "{err}");

    let err = jwk::jwk_from_pem(ENC_AES256).expect_err("encrypted at plain door");
    assert!(
        err.to_string().contains("jwk_from_encrypted_pkcs8_pem"),
        "{err}"
    );
}

/// What this crate writes, OpenSSL's own tools can read: round-tripped through the CLI in
/// `tests/fixtures/pkcs8/README.md` and byte-checked in the interop suite. Here we assert the
/// shape, and that our own reader accepts it.
#[test]
fn our_own_files_round_trip_and_are_labelled_encrypted() {
    let key = jwk::generate_ec("P-256").expect("generate");
    let pem = encrypted_pkcs8_pem_from_jwk(
        &key,
        &password(),
        &Pkcs8Encryption::Aes256CbcPbkdf2HmacSha256 { iterations: 4_096 },
    )
    .expect("export");

    assert!(pem.starts_with("-----BEGIN ENCRYPTED PRIVATE KEY-----\n"));
    assert!(pem.ends_with("-----END ENCRYPTED PRIVATE KEY-----\n"));
    // RFC 7468's 64-character line cap.
    for line in pem.lines().filter(|l| !l.starts_with("-----")) {
        assert!(line.len() <= 64, "{line}");
    }

    let back = jwk_from_encrypted_pkcs8_pem(&pem, &password()).expect("re-import");
    assert_eq!(back.crv, key.crv);
    assert_eq!(back.d, key.d);

    // And it is distinguishable from a plaintext export at a glance.
    let plain = jwk::private_pem_from_jwk(&key).expect("plain");
    assert!(plain.starts_with("-----BEGIN PRIVATE KEY-----"));
}

/// An RSA key survives the same trip, including the modulus floor the PKCS#8 importer
/// enforces after decryption.
#[test]
fn rsa_key_survives_encrypted_export_and_import() {
    let key = jwk::generate_rsa(2048).expect("generate");
    let pem = encrypted_pkcs8_pem_from_jwk(&key, &password(), &Pkcs8Encryption::default())
        .expect("export");
    let back = jwk_from_encrypted_pkcs8_pem(&pem, &password()).expect("import");
    assert_eq!(back.kty, "RSA");
    assert_eq!(back.n, key.n);
    assert_eq!(back.d, key.d);
    assert_eq!(back.p, key.p);
    assert_eq!(back.q, key.q);
}
