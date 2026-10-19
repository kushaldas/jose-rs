//! Password-based key management (`PBES2-HS256+A128KW`, `+HS384+A192KW`,
//! `+HS512+A256KW`, RFC 7518 §4.8).
//!
//! The last key-management family in RFC 7518. Its difference is not the cryptography —
//! PBKDF2 and AES-KW are both already in this crate — but the *input*: a password, which
//! is low-entropy, is supplied by a human, and is only ever the input to a derivation. So
//! these tests are mostly about the boundaries that follows from:
//!
//! * a password is not a key, in either direction. Handing one to `A128KW` is refused, and
//!   so is handing a *key* to a PBES2 message — the second is the dangerous one, because
//!   key bytes are bytes and would derive successfully;
//! * `p2s` and `p2c` are KDF inputs, so they are read from the integrity-protected header
//!   only and generated here (a peer that chose the salt chooses the derived key);
//! * `p2c` names how much CPU the *recipient* spends, so the work budget is enforced
//!   before any derivation — a refusal must be free, not a bill;
//! * and the RFC 7520 §5.3 message decrypts. That vector is the independent check: it was
//!   produced by neither this implementation nor its peers, and it pins the salt
//!   construction (`UTF8(alg) || 0x00 || Salt Input`), the hash/iteration pairing, and the
//!   AES-KW step in one 380-octet assertion.
//!
//! Iteration counts in these tests are the minimum the crate allows (1 000), not the
//! default it emits (100 000). Integration tests run in the unoptimized profile, where
//! PBKDF2 is orders of magnitude slower than the release-mode numbers the budget was
//! chosen from; the default path gets its own dedicated test.

use jose_rs::algorithm::{JweAlgorithm, JweEncryption};
use jose_rs::jwe::{
    compact, general, json, JweDecryptOptions, JweEncryptOptions, Password,
    PBES2_DEFAULT_ITERATIONS,
};
use jose_rs::JoseHeader;

/// 1 000 iterations: the floor the crate accepts, and the reason these tests finish in
/// seconds rather than minutes in the test profile.
const FAST: u32 = 1_000;

const PBES2: [JweAlgorithm; 3] = [
    JweAlgorithm::Pbes2Hs256A128kw,
    JweAlgorithm::Pbes2Hs384A192kw,
    JweAlgorithm::Pbes2Hs512A256kw,
];

fn alg_name(alg: JweAlgorithm) -> &'static str {
    alg.as_str()
}

fn encrypt(alg: JweAlgorithm, enc: JweEncryption, password: &Password, plaintext: &[u8]) -> String {
    compact::encrypt_with_password_options(
        password,
        plaintext,
        alg,
        enc,
        &JweEncryptOptions::new().with_pbes2_iterations(FAST),
    )
    .unwrap_or_else(|e| panic!("{} with {enc:?}: {e}", alg_name(alg)))
}

/// The protected header of a compact token, decoded.
fn header_of(token: &str) -> serde_json::Value {
    let bytes = jose_rs::base64url::decode(token.split('.').next().unwrap()).unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

/// Rebuild a compact token with an edited protected header.
fn with_header(token: &str, header: &serde_json::Value) -> String {
    format!(
        "{}.{}",
        jose_rs::base64url::encode(&serde_json::to_vec(header).unwrap()),
        token.split('.').skip(1).collect::<Vec<_>>().join(".")
    )
}

#[test]
fn every_pbes2_algorithm_round_trips_in_both_serializations() {
    let password = Password::from_utf8("correct horse battery staple");
    for alg in PBES2 {
        for enc in [
            JweEncryption::A128GCM,
            JweEncryption::A256GCM,
            JweEncryption::A128CbcHs256,
        ] {
            let token = encrypt(alg, enc, &password, b"password-based, still authenticated");
            assert_eq!(
                compact::decrypt_with_password(&password, &token)
                    .unwrap_or_else(|e| panic!("{} with {enc:?}: {e}", alg_name(alg))),
                b"password-based, still authenticated"
            );

            let flat = json::encrypt_flattened_with_password_options(
                &password,
                b"flattened too",
                alg,
                enc,
                &JweEncryptOptions::new().with_pbes2_iterations(FAST),
            )
            .unwrap();
            // Both members sit in the protected header, where they are authenticated.
            let protected = header_of(&flat.protected.clone().unwrap());
            assert!(protected.get("p2s").is_some(), "{alg:?}: {protected}");
            assert_eq!(protected["p2c"], serde_json::json!(FAST));
            assert_eq!(
                json::decrypt_flattened_with_password(&password, &flat).unwrap(),
                b"flattened too"
            );
        }
    }
}

#[test]
fn the_rfc_7520_pbes2_message_decrypts() {
    // RFC 7520 §5.3: PBES2-HS512+A256KW with A128CBC-HS256, password from Figure 96,
    // salt input from Figure 99, 8192 iterations. Assembled from the RFC's own figures,
    // so this asserts the salt construction (UTF8(alg) || 0x00 || Salt Input), the
    // HMAC-SHA-512 PRF, the 32-octet derived key and the RFC 3394 wrap together. A
    // derivation that disagreed anywhere would fail the wrap's integrity check.
    let header_b64 = "eyJhbGciOiJQQkVTMi1IUzUxMitBMjU2S1ciLCJwMnMiOiI4UTFTemluYXNSM3hjaFl6NlpaY0hBIiwicDJjIjo4MTkyLCJjdHkiOiJqd2stc2V0K2pzb24iLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0";
    let encrypted_key = "d3qNhUWfqheyPp4H8sjOWsDYajoej4c5Je6rlUtFPWdgtURtmeDV1g";
    let iv = "VBiCzVHNoLiR3F4V82uoTQ";
    let ciphertext = "23i-Tb1AV4n0WKVSSgcQrdg6GRqsUKxjruHXYsTHAJLZ2nsnGIX86vMXqIi6IRsfywCRFzLxEcZBRnTvG3nhzPk0GDD7FMyXhUHpDjEYCNA_XOmzg8yZR9oyjo6lTF6si4q9FZ2EhzgFQCLO_6h5EVg3vR75_hkBsnuoqoM3dwejXBtIodN84PeqMb6asmas_dpSsz7H10fC5ni9xIz424givB1YLldF6exVmL93R3fOoOJbmk2GBQZL_SEGllv2cQsBgeprARsaQ7Bq99tT80coH8ItBjgV08AtzXFFsx9qKvC982KLKdPQMTlVJKkqtV4Ru5LEVpBZXBnZrtViSOgyg6AiuwaS-rCrcD_ePOGSuxvgtrokAKYPqmXUeRdjFJwafkYEkiuDCV9vWGAi1DH2xTafhJwcmywIyzi4BqRpmdn_N-zl5tuJYyuvKhjKv6ihbsV_k1hJGPGAxJ6wUpmwC4PTQ2izEm0TuSE8oMKdTw8V3kobXZ77ulMwDs4p";
    let tag = "0HlwodAhOCILG5SQ2LQ9dg";
    let token = [header_b64, encrypted_key, iv, ciphertext, tag].join(".");

    // Figure 96, with the two "\xe2\x80\x93" sequences it spells out replaced by the
    // character they encode — and this is also the test that the UTF-8 encoding
    // RFC 7518 §4.8 requires is what actually gets derived over.
    let password = Password::from_utf8("entrap_o\u{2013}peter_long\u{2013}credit_tun");
    let plaintext = compact::decrypt_with_password(&password, &token).expect("RFC 7520 §5.3");

    // Figure 95: the JWK Set the RFC chose as its payload.
    let expected = br#"{"keys":[{"kty":"oct","kid":"77c7e2b8-6e13-45cf-8672-617b5b45243a","use":"enc","alg":"A128GCM","k":"XctOhJAkA-pD9Lh7ZgW_2A"},{"kty":"oct","kid":"81b20965-8332-43d9-a468-82160ad91ac8","use":"enc","alg":"A128KW","k":"GZy6sIZ6wl9NJOKB-jnmVQ"},{"kty":"oct","kid":"18ec08e1-bfa9-4d95-b205-2b4dd1d4321d","use":"enc","alg":"A256GCMKW","k":"qC57l_uxcm7Nm3K-ct4GFjx8tM1U8CZ0NLBvdQstiS8"}]}"#;
    assert_eq!(plaintext, expected);

    // The same password with a hyphen instead of the en dash derives a different key —
    // §4.8 says UTF-8, and this is what a "just normalize the password" helper would
    // break.
    let hyphen = Password::from_utf8("entrap_o-peter_long-credit_tun");
    assert!(compact::decrypt_with_password(&hyphen, &token).is_err());
}

#[test]
fn the_wrong_password_fails_out_loud() {
    let password = Password::from_utf8("the right one");
    let token = encrypt(
        JweAlgorithm::Pbes2Hs256A128kw,
        JweEncryption::A128GCM,
        &password,
        b"x",
    );
    for wrong in ["the wrong one", "The right one", "the right one "] {
        let err = compact::decrypt_with_password(&Password::from_utf8(wrong), &token)
            .unwrap_err()
            .to_string();
        // Named as a password problem, not a generic crypto failure: this is the one
        // key-management path where "the wrap did not authenticate" means something
        // specific, and RFC 3394's wrap gives us the certainty to say it.
        assert!(
            err.to_lowercase().contains("wrong password"),
            "{wrong:?}: {err}"
        );
    }
}

#[test]
fn the_members_are_mandatory_and_typed() {
    let password = Password::from_utf8("x");
    let token = encrypt(
        JweAlgorithm::Pbes2Hs512A256kw,
        JweEncryption::A128GCM,
        &password,
        b"x",
    );

    for (member, value, expected) in [
        // Absent, in either direction.
        ("p2s", None, "p2s"),
        ("p2c", None, "p2c"),
        // Wrong types: `p2c` is "a positive JSON integer" (§4.8.1.2), not a number-ish
        // value coerced into one.
        ("p2s", Some(serde_json::json!(16)), "base64url string"),
        (
            "p2c",
            Some(serde_json::json!("8192")),
            "positive JSON integer",
        ),
        (
            "p2c",
            Some(serde_json::json!(8192.0)),
            "positive JSON integer",
        ),
        ("p2c", Some(serde_json::json!(-1)), "positive JSON integer"),
        ("p2c", Some(serde_json::json!(0)), "iteration floor"),
        // Too short a salt: §4.8.1.1's own minimum.
        (
            "p2s",
            Some(serde_json::json!(jose_rs::base64url::encode(&[1u8; 4]))),
            "8 or more octets",
        ),
    ] {
        let mut header = header_of(&token);
        let described = format!("{value:?}");
        match value {
            None => {
                header.as_object_mut().unwrap().remove(member);
            }
            Some(v) => {
                header[member] = v;
            }
        }
        let edited = with_header(&token, &header);
        let err = compact::decrypt_with_password(&password, &edited)
            .unwrap_err()
            .to_string();
        assert!(
            err.to_lowercase().contains(&expected.to_lowercase()),
            "{member} = {described}: {err}"
        );
    }
}

#[test]
fn the_work_budget_is_applied_before_any_derivation() {
    // `p2c` is chosen by the sender and paid by the recipient, so an unbounded accepted
    // count is a one-message denial of service. The refusal has to be free: checking the
    // count *after* deriving would be the bug, not the fix.
    let password = Password::from_utf8("x");
    for alg in PBES2 {
        let token = encrypt(alg, JweEncryption::A128GCM, &password, b"x");
        let started = std::time::Instant::now();
        let err = compact::decrypt_with_password_options(
            &password,
            &token,
            &JweDecryptOptions::new(PBES2.to_vec(), vec![JweEncryption::A128GCM])
                .with_pbes2_max_iterations(999),
        )
        .unwrap_err()
        .to_string();
        let elapsed = started.elapsed();
        assert!(err.contains("work budget"), "{alg:?}: {err}");
        // 1 000 iterations of PBKDF2 in the unoptimized test profile is milliseconds at
        // worst; a refusal that derived first would take visibly longer.
        assert!(
            elapsed < std::time::Duration::from_millis(500),
            "{alg:?}: refusing cost {elapsed:?}, which means it derived first"
        );
    }
}

#[test]
fn the_default_iteration_count_is_the_documented_one_and_is_overridable() {
    let password = Password::from_utf8("x");
    let token = compact::encrypt_with_password(
        &password,
        b"x",
        JweAlgorithm::Pbes2Hs256A128kw,
        JweEncryption::A128GCM,
    )
    .unwrap();
    let header = header_of(&token);
    assert_eq!(header["p2c"], serde_json::json!(PBES2_DEFAULT_ITERATIONS));

    // And a sender who chooses a count is heard.
    let chosen = compact::encrypt_with_password_options(
        &password,
        b"x",
        JweAlgorithm::Pbes2Hs256A128kw,
        JweEncryption::A128GCM,
        &JweEncryptOptions::new().with_pbes2_iterations(2048),
    )
    .unwrap();
    assert_eq!(header_of(&chosen)["p2c"], serde_json::json!(2048));
    // Readable at a budget that permits it, refused at one that does not.
    assert_eq!(
        compact::decrypt_with_password_options(
            &password,
            &chosen,
            &JweDecryptOptions::new(PBES2.to_vec(), vec![JweEncryption::A128GCM])
                .with_pbes2_max_iterations(2048),
        )
        .unwrap(),
        b"x"
    );

    let flat = json::encrypt_flattened_with_password_options(
        &password,
        b"x",
        JweAlgorithm::Pbes2Hs256A128kw,
        JweEncryption::A128GCM,
        &JweEncryptOptions::new().with_pbes2_iterations(2048),
    )
    .unwrap();
    let err = json::decrypt_flattened_with_password_options(
        &password,
        &flat,
        &JweDecryptOptions::new(PBES2.to_vec(), vec![JweEncryption::A128GCM])
            .with_pbes2_max_iterations(2047),
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("budget") && err.contains("2048"), "{err}");

    let header = JoseHeader::for_jwe(JweAlgorithm::Pbes2Hs256A128kw, JweEncryption::A128GCM);
    let general = general::encrypt_general_with_passwords_options(
        &header,
        &[&password],
        b"x",
        JweAlgorithm::Pbes2Hs256A128kw,
        JweEncryption::A128GCM,
        &JweEncryptOptions::new().with_pbes2_iterations(2048),
    )
    .unwrap();
    let err = general::decrypt_general_with_password_options(
        &password,
        &general,
        0,
        &JweDecryptOptions::new(PBES2.to_vec(), vec![JweEncryption::A128GCM])
            .with_pbes2_max_iterations(2047),
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("budget") && err.contains("2048"), "{err}");

    // Below the floor, the *emit* side refuses: a message nobody else will read is worse
    // than an error, and this crate does not write what it will not accept.
    let err = compact::encrypt_with_password_options(
        &password,
        b"x",
        JweAlgorithm::Pbes2Hs256A128kw,
        JweEncryption::A128GCM,
        &JweEncryptOptions::new().with_pbes2_iterations(999),
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("minimum of 1000"), "{err}");
}

#[test]
fn password_json_decrypt_bounds_a_directly_constructed_protected_header() {
    let password = Password::from_utf8("x");
    let mut flat = json::encrypt_flattened_with_password_options(
        &password,
        b"x",
        JweAlgorithm::Pbes2Hs256A128kw,
        JweEncryption::A128GCM,
        &JweEncryptOptions::new().with_pbes2_iterations(FAST),
    )
    .unwrap();
    flat.protected = Some("A".repeat(jose_rs::MAX_TOKEN_BYTES + 1));

    let err = json::decrypt_flattened_with_password(&password, &flat)
        .unwrap_err()
        .to_string();
    assert!(err.contains("MAX_TOKEN_BYTES"), "{err}");
}

#[test]
fn the_salt_is_fresh_and_cannot_be_supplied() {
    let password = Password::from_utf8("same password every time");
    let first = encrypt(
        JweAlgorithm::Pbes2Hs256A128kw,
        JweEncryption::A128GCM,
        &password,
        b"x",
    );
    let second = encrypt(
        JweAlgorithm::Pbes2Hs256A128kw,
        JweEncryption::A128GCM,
        &password,
        b"x",
    );
    let (a, b) = (header_of(&first), header_of(&second));
    let salt = jose_rs::base64url::decode(a["p2s"].as_str().unwrap()).unwrap();
    assert_eq!(salt.len(), 16, "the RFC requires 8 or more; peers use 16");
    assert_ne!(
        a["p2s"], b["p2s"],
        "a repeated salt means two messages under one derived key"
    );
    assert_ne!(
        first.split('.').nth(1).unwrap(),
        second.split('.').nth(1).unwrap()
    );

    // And neither member is the caller's to choose: `p2s` is a nonce and `p2c` is a
    // budget the recipient pays.
    for member in ["p2s", "p2c"] {
        let mut header =
            JoseHeader::for_jwe(JweAlgorithm::Pbes2Hs256A128kw, JweEncryption::A128GCM);
        header.extra.insert(
            member.into(),
            if member == "p2s" {
                serde_json::json!(jose_rs::base64url::encode(&[9u8; 16]))
            } else {
                serde_json::json!(4096)
            },
        );
        let err = compact::encrypt_with_password_header(
            &password,
            header,
            b"x",
            JweAlgorithm::Pbes2Hs256A128kw,
            JweEncryption::A128GCM,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains(member), "{member}: {err}");
    }
}

#[test]
fn a_password_is_not_a_key_in_either_direction() {
    let password = Password::from_utf8("a perfectly good passphrase");

    // Password into a key algorithm: refused, because `A128KW` would use these bytes
    // directly as a key-encryption key, and a passphrase has none of the entropy that
    // assumes.
    for alg in [
        JweAlgorithm::A128KW,
        JweAlgorithm::Dir,
        JweAlgorithm::A128Gcmkw,
        JweAlgorithm::RsaOaep256,
        JweAlgorithm::EcdhEs,
    ] {
        let err = compact::encrypt_with_password(&password, b"x", alg, JweEncryption::A128GCM)
            .unwrap_err()
            .to_string();
        assert!(
            err.to_lowercase().contains("does not use a password"),
            "{alg:?}: {err}"
        );
    }

    // Key into a password algorithm: the direction that actually matters, because key
    // bytes *are* bytes and would derive successfully into the wrong key. A 32-octet
    // symmetric key read as a PBES2 message would "work" while meaning something
    // completely different.
    let token = encrypt(
        JweAlgorithm::Pbes2Hs256A128kw,
        JweEncryption::A128GCM,
        &password,
        b"do not read me as a password",
    );
    let key_bytes = [0x42u8; 32];
    let err = compact::decrypt(&key_bytes, &token)
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("derives its key from a password") || err.contains("needs one"),
        "{err}"
    );
}

#[test]
fn a_message_naming_a_non_password_algorithm_gets_no_password() {
    // A password carries no `alg`, so the pin cannot come from the secret. It comes from
    // the family gate instead: `dir`, AES-KW and the rest are refused before the
    // password is offered to anything that would use its bytes as a key.
    let key: jose_rs::jwk::Jwk = serde_json::from_value(serde_json::json!({
        "kty": "oct",
        "k": jose_rs::base64url::encode(&[7u8; 16]),
        "alg": "A128KW",
        "use": "enc",
    }))
    .unwrap();
    let token = compact::encrypt_with_jwk(&key, b"x", JweEncryption::A128GCM).unwrap();
    let err = compact::decrypt_with_password(&Password::from_utf8("x"), &token)
        .unwrap_err()
        .to_string();
    assert!(err.contains("not a password-based algorithm"), "{err}");
}

#[test]
fn unprotected_p2s_and_p2c_are_refused_at_parse_time() {
    // The rule is ADR 0013's, and PBES2 is where it earns its keep: these two values are
    // the derivation's inputs, so a peer that positions them unauthenticated picks the
    // salt the password is mixed with — the primitive behind any offline dictionary
    // attack that has to beat a precomputed table.
    let password = Password::from_utf8("x");
    let flat = json::encrypt_flattened_with_password_options(
        &password,
        b"x",
        JweAlgorithm::Pbes2Hs256A128kw,
        JweEncryption::A128GCM,
        &JweEncryptOptions::new().with_pbes2_iterations(FAST),
    )
    .unwrap();
    let mut value: serde_json::Value = serde_json::from_str(&flat.to_json().unwrap()).unwrap();
    let protected: serde_json::Value = serde_json::from_slice(
        &jose_rs::base64url::decode(value["protected"].as_str().unwrap()).unwrap(),
    )
    .unwrap();
    value["header"] = serde_json::json!({"p2s": protected["p2s"], "p2c": protected["p2c"]});
    value["protected"] = serde_json::json!(jose_rs::base64url::encode(
        &serde_json::to_vec(&serde_json::json!({
            "alg": "PBES2-HS256+A128KW",
            "enc": "A128GCM"
        }))
        .unwrap()
    ));
    let err = json::FlattenedJwe::from_json(&value.to_string())
        .unwrap_err()
        .to_string();
    assert!(err.contains("integrity protected"), "{err}");
}

#[test]
fn an_empty_password_is_refused_on_the_emit_side_only() {
    let empty = Password::from_utf8("");
    assert!(empty.is_empty());
    let err = compact::encrypt_with_password(
        &empty,
        b"x",
        JweAlgorithm::Pbes2Hs256A128kw,
        JweEncryption::A128GCM,
    )
    .unwrap_err()
    .to_string();
    // An unset secret and an empty one look identical here, which is the whole reason.
    assert!(err.contains("empty password"), "{err}");

    // Reading is not refused on that ground: a peer's message is not judged by the shape
    // of its secret, and the wrap's integrity check decides the question anyway.
    let token = compact::encrypt_with_password_options(
        &Password::from_utf8("something"),
        b"x",
        JweAlgorithm::Pbes2Hs256A128kw,
        JweEncryption::A128GCM,
        &JweEncryptOptions::new().with_pbes2_iterations(FAST),
    )
    .unwrap();
    assert!(compact::decrypt_with_password(&empty, &token).is_err());
}

#[test]
fn several_recipients_are_refused_with_the_reason() {
    // Each recipient's password derives a different KEK, so each needs its own `p2s` and
    // `p2c` — and a recipient element has no protected header to put them in.
    let a = Password::from_utf8("first passphrase");
    let header = JoseHeader::for_jwe(JweAlgorithm::Pbes2Hs256A128kw, JweEncryption::A128GCM);
    let err = general::encrypt_general_with_passwords(
        &header,
        &[&a, &Password::from_utf8("second passphrase")],
        b"two recipients",
        JweAlgorithm::Pbes2Hs256A128kw,
        JweEncryption::A128GCM,
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("p2s and p2c"), "{err}");
    assert!(err.contains("protected"), "{err}");
}

#[test]
fn oct_key_material_cannot_stand_in_for_a_password() {
    // The shape a library migrating from `oct` keys would try: an `oct` JWK whose `k`
    // holds the passphrase, offered to the PBES2 path. Refused, and the reason is that
    // the same JWK is also perfectly acceptable to `A128KW` — one secret, two incompatible
    // security arguments, which is a confusion rather than a convenience.
    let jwk: jose_rs::jwk::Jwk = serde_json::from_value(serde_json::json!({
        "kty": "oct",
        "k": jose_rs::base64url::encode(b"my passphrase"),
        "alg": "PBES2-HS256+A128KW",
        "use": "enc",
    }))
    .unwrap();
    let err = compact::encrypt_with_jwk(&jwk, b"x", JweEncryption::A128GCM)
        .unwrap_err()
        .to_string();
    assert!(err.to_lowercase().contains("password"), "{err}");
}
