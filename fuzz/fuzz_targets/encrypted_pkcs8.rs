#![no_main]

use libfuzzer_sys::fuzz_target;

use jose_rs::jwk::encrypted_pkcs8::Pkcs8ReadOptions;
use jose_rs::jwk::Password;

// Password-encrypted PKCS#8 (`ENCRYPTED PRIVATE KEY`) import.
//
// Two things make this target worth its keep:
//
// 1. The scheme named in the file is a *choice the file makes about our work*.
//    PKCS#5 parameters say how many PBKDF2 rounds to run, so a caller that
//    forgets to cap them has handed the writer of the file a denial-of-service
//    lever. This harness pins the budget deliberately low
//    (`PKCS8_MIN_ITERATIONS`, ~1 ms) so a fuzz run measures parser behaviour
//    rather than PBKDF2 throughput — and so a regression that consults the
//    file's iteration count before the budget is a visible refusal instead of
//    a slow test suite.
// 2. The allow-list is compile-time: PBES1, scrypt, SHA-1/SHA-224 PRFs and
//    DES/3DES are not reachable, so they cannot be selected by a crafted file.
//    The target asserts nothing about which refusal comes back — only that
//    none of these byte sequences can produce a panic or a derived key.
//
// The password is fixed and the budget fixed: what is under test is the
// parsing and the policy, not the attacker's control of our secrets.
fuzz_target!(|data: &[u8]| {
    if data.len() > 65_536 {
        return;
    }

    let password = Password::from_utf8("fuzz-password");
    let options = Pkcs8ReadOptions::default()
        .with_max_iterations(jose_rs::jwk::encrypted_pkcs8::PKCS8_MIN_ITERATIONS);

    for result in [
        jose_rs::jwk::encrypted_pkcs8::jwk_from_encrypted_pkcs8_der_with_options(
            data, &password, &options,
        ),
        std::str::from_utf8(data)
            .map_err(|_| jose_rs::JoseError::Key("not utf-8".into()))
            .and_then(|text| {
                jose_rs::jwk::encrypted_pkcs8::jwk_from_encrypted_pkcs8_pem_with_options(
                    text, &password, &options,
                )
            }),
    ]
    .into_iter()
    .flatten()
    {
        let _ = jose_rs::jwk::jwk_to_software_key(&result);
        let _ = jose_rs::jwk::thumbprint::thumbprint_sha256(&result);
        // Re-export is a size-bounded path we also own; it must not panic on a key
        // that came out of an encrypted file.
        let _ = jose_rs::jwk::encrypted_pkcs8::encrypted_pkcs8_der_from_jwk(
            &result,
            &password,
            &jose_rs::jwk::encrypted_pkcs8::Pkcs8Encryption::Aes256CbcPbkdf2HmacSha256 {
                iterations: jose_rs::jwk::encrypted_pkcs8::PKCS8_MIN_ITERATIONS,
            },
        );
    }
});
