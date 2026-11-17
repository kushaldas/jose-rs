//! Blocking non-default PBES2 iteration vectors, independent of runtime ratios.
//!
//! Generated with Python 3 `hashlib.pbkdf2_hmac` (OpenSSL) and cryptography 50.0.2:
//! `kek = pbkdf2_hmac(hash, password, alg.encode() + b"\x00" + salt, count, dklen)`.
//! RFC 3394 wrapping uses `aes_key_wrap(kek, bytes([0x42]) * 32)`; A256GCM uses
//! `AESGCM(cek).encrypt(bytes([0x24]) * 12, plaintext, protected.encode())`.
//! Protected JSON is `json.dumps(header, sort_keys=True, separators=(",", ":"))`,
//! then unpadded base64url. The fixed salt, password and plaintext are below.
//! All values are public test inputs; fixed CEKs/nonces are only fixture data.
//!
//! Both iteration counts differ from the default/RFC vector's 8 192. The oracle
//! is pinned against independent fixed KEKs, then used outside the JOSE glue to
//! unwrap and authenticate newly emitted tokens. A shared producer/consumer bug
//! cannot hide behind a same-library round trip.
use aes_gcm::{
    aead::{AeadInOut, KeyInit, Nonce, Tag},
    Aes256Gcm,
};
use jose_rs::{
    base64url,
    jwe::{compact, JweDecryptOptions, JweEncryptOptions, Password},
    JweAlgorithm, JweEncryption,
};
use kryptering::{AesKeySize, HashAlgorithm, KeyWrapAlgorithm};
use zeroize::Zeroizing;

const PASSWORD: &[u8] = b"budget-invariant";
const SALT: &[u8] = b"0123456789abcdef";
const PLAINTEXT: &[u8] = b"non-default p2c interoperability";

struct Fixture {
    alg: JweAlgorithm,
    hash: HashAlgorithm,
    size: AesKeySize,
    iterations: u32,
    kek: &'static str,
    token: &'static str,
}

const FIXTURES: &[Fixture] = &[
    Fixture {
        alg: JweAlgorithm::Pbes2Hs256A128kw,
        hash: HashAlgorithm::Sha256,
        size: AesKeySize::Aes128,
        iterations: 1000,
        kek: "6x1B2WaVua3JvmxcztGw5w",
        token: "eyJhbGciOiJQQkVTMi1IUzI1NitBMTI4S1ciLCJlbmMiOiJBMjU2R0NNIiwicDJjIjoxMDAwLCJwMnMiOiJNREV5TXpRMU5qYzRPV0ZpWTJSbFpnIn0.fjRoMjUYcpSTlXZqK94D0xjJ1mzveBp5-hEtKnJoW_G3BwC73Bgu2w.JCQkJCQkJCQkJCQk.e_6qbI2joF9ThFaKzQDwhgWVRxXExCAIwsWuMzqsk2o.ifuEV4qqZdm0_LrYbP8eTg",
    },
    Fixture {
        alg: JweAlgorithm::Pbes2Hs256A128kw,
        hash: HashAlgorithm::Sha256,
        size: AesKeySize::Aes128,
        iterations: 2048,
        kek: "B0Kr8yvjA-qf8cc8k37WPA",
        token: "eyJhbGciOiJQQkVTMi1IUzI1NitBMTI4S1ciLCJlbmMiOiJBMjU2R0NNIiwicDJjIjoyMDQ4LCJwMnMiOiJNREV5TXpRMU5qYzRPV0ZpWTJSbFpnIn0.04bT-NpY0cJjdPie0fi0XUMOcewBfeyqrvUWA8WZj3uXsiaR2lbi2Q.JCQkJCQkJCQkJCQk.e_6qbI2joF9ThFaKzQDwhgWVRxXExCAIwsWuMzqsk2o.PwFF4aZAfsGwLF68rckjpA",
    },
    Fixture {
        alg: JweAlgorithm::Pbes2Hs384A192kw,
        hash: HashAlgorithm::Sha384,
        size: AesKeySize::Aes192,
        iterations: 1000,
        kek: "q1Hygug8KKj0KIdJF6Yw-Xj3l-d8jLsP",
        token: "eyJhbGciOiJQQkVTMi1IUzM4NCtBMTkyS1ciLCJlbmMiOiJBMjU2R0NNIiwicDJjIjoxMDAwLCJwMnMiOiJNREV5TXpRMU5qYzRPV0ZpWTJSbFpnIn0.mn3S0tHTF5XlrTQDauMjD_Ep_JyU7DvIYqTGermiPxPkwjE3l5VahA.JCQkJCQkJCQkJCQk.e_6qbI2joF9ThFaKzQDwhgWVRxXExCAIwsWuMzqsk2o.efftWA9AKfU2uPSrRB1Kiw",
    },
    Fixture {
        alg: JweAlgorithm::Pbes2Hs384A192kw,
        hash: HashAlgorithm::Sha384,
        size: AesKeySize::Aes192,
        iterations: 2048,
        kek: "MSY4wD1hX3jWH0lH5Jbnt8rUxKBwx7hM",
        token: "eyJhbGciOiJQQkVTMi1IUzM4NCtBMTkyS1ciLCJlbmMiOiJBMjU2R0NNIiwicDJjIjoyMDQ4LCJwMnMiOiJNREV5TXpRMU5qYzRPV0ZpWTJSbFpnIn0.yVfohqzVQPbGM7hLEuJ7g5ltwZK7mAGA700cZ5EFFxiUWn5kr-A1mA.JCQkJCQkJCQkJCQk.e_6qbI2joF9ThFaKzQDwhgWVRxXExCAIwsWuMzqsk2o.zw0s7iOqMu0yaBDPhSt3YQ",
    },
    Fixture {
        alg: JweAlgorithm::Pbes2Hs512A256kw,
        hash: HashAlgorithm::Sha512,
        size: AesKeySize::Aes256,
        iterations: 1000,
        kek: "qEhiZpCh-Ga9Um4VomWmXUvX4iJvKqmTZK--z_PFQaw",
        token: "eyJhbGciOiJQQkVTMi1IUzUxMitBMjU2S1ciLCJlbmMiOiJBMjU2R0NNIiwicDJjIjoxMDAwLCJwMnMiOiJNREV5TXpRMU5qYzRPV0ZpWTJSbFpnIn0.mZrcGJlDg2Bf6tCEC8YRqSTSUsaziZ_h3JJigK7xFS1ooCRKQh8xWA.JCQkJCQkJCQkJCQk.e_6qbI2joF9ThFaKzQDwhgWVRxXExCAIwsWuMzqsk2o.YNUeELQFibS10oLWHZwanQ",
    },
    Fixture {
        alg: JweAlgorithm::Pbes2Hs512A256kw,
        hash: HashAlgorithm::Sha512,
        size: AesKeySize::Aes256,
        iterations: 2048,
        kek: "ecbJxI86qFhgypftUTf5p1FCFEom6pEsNjMZcXvtf7o",
        token: "eyJhbGciOiJQQkVTMi1IUzUxMitBMjU2S1ciLCJlbmMiOiJBMjU2R0NNIiwicDJjIjoyMDQ4LCJwMnMiOiJNREV5TXpRMU5qYzRPV0ZpWTJSbFpnIn0.zYwE5IiayLhFWSh8hxIyIa5GhIgLNtWT8QP-jyrv4tnSqOUk9PHYKw.JCQkJCQkJCQkJCQk.e_6qbI2joF9ThFaKzQDwhgWVRxXExCAIwsWuMzqsk2o.1i_fppjvkqyxAmay3Kondw",
    },
];

/// Reference assembly of the public PBKDF2 inputs, without any JOSE KDF helper.
fn oracle(fixture: &Fixture, salt_input: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut salt = fixture.alg.as_str().as_bytes().to_vec();
    salt.push(0);
    salt.extend_from_slice(salt_input);
    Zeroizing::new(
        kryptering::kdf::pbkdf2_derive(
            PASSWORD,
            &kryptering::kdf::Pbkdf2Params {
                hash: fixture.hash,
                salt,
                iteration_count: fixture.iterations,
                key_length: fixture.size.key_len(),
            },
        )
        .unwrap(),
    )
}

#[test]
fn oracle_matches_independent_python_kek_vectors() {
    for fixture in FIXTURES {
        assert_eq!(
            base64url::encode(&oracle(fixture, SALT)),
            fixture.kek,
            "{:?} / {}",
            fixture.alg,
            fixture.iterations
        );
    }
}

#[test]
fn decrypts_independent_non_default_iteration_tokens() {
    let password = Password::from_bytes(PASSWORD);
    for fixture in FIXTURES {
        let options = JweDecryptOptions::new(vec![fixture.alg], vec![JweEncryption::A256GCM])
            .with_pbes2_max_iterations(fixture.iterations);
        let plaintext = compact::decrypt_with_password_options(&password, fixture.token, &options)
            .unwrap_or_else(|error| panic!("{:?} / {}: {error}", fixture.alg, fixture.iterations));
        assert_eq!(plaintext, PLAINTEXT);
    }
}

#[test]
fn newly_emitted_tokens_use_the_advertised_non_default_iteration_count() {
    let password = Password::from_bytes(PASSWORD);
    for fixture in FIXTURES {
        let token = compact::encrypt_with_password_options(
            &password,
            PLAINTEXT,
            fixture.alg,
            JweEncryption::A256GCM,
            &JweEncryptOptions::new().with_pbes2_iterations(fixture.iterations),
        )
        .unwrap();
        let header = compact::decode_header(&token).unwrap();
        assert_eq!(
            header.extra["p2c"].as_u64(),
            Some(u64::from(fixture.iterations))
        );
        let salt = base64url::decode(header.extra["p2s"].as_str().unwrap()).unwrap();
        let kek = oracle(fixture, &salt);
        let parts: Vec<_> = token.split('.').collect();
        let wrapped = base64url::decode(parts[1]).unwrap();
        let cek = Zeroizing::new(
            kryptering::keywrap::unwrap(KeyWrapAlgorithm::AesKw(fixture.size), &kek, &wrapped)
                .unwrap_or_else(|error| {
                    panic!(
                        "{:?} / {} independent unwrap: {error}",
                        fixture.alg, fixture.iterations
                    )
                }),
        );
        let iv = base64url::decode(parts[2]).unwrap();
        let mut payload = Zeroizing::new(base64url::decode(parts[3]).unwrap());
        let tag = base64url::decode(parts[4]).unwrap();
        Aes256Gcm::new_from_slice(&cek)
            .unwrap()
            .decrypt_inout_detached(
                &Nonce::<Aes256Gcm>::try_from(iv.as_slice()).unwrap(),
                parts[0].as_bytes(),
                (&mut payload[..]).into(),
                &Tag::<Aes256Gcm>::try_from(tag.as_slice()).unwrap(),
            )
            .unwrap();
        assert_eq!(&payload[..], PLAINTEXT);
    }
}
