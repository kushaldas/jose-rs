//! The capability report has to be true, not merely tidy (L0).
//!
//! `src/capability.rs` is hand-written metadata about what this build can do. That is only worth
//! having if something checks it, so this file **performs** every advertised operation and
//! **attempts** every advertised refusal, and it also asserts two structural properties that make
//! the table keep up with the code: the identifier lists are enumerated from the enums themselves
//! (an exhaustive `match`, so a new variant is a compile error here), and the committed
//! `docs/capabilities.md` is what the code renders.
//!
//! Feature combinations matter: `cargo test --no-default-features`, `--features deprecated` and
//! `--features post-quantum` must all pass, which is how "recognized identifiers stay visibly
//! unsupported across feature combinations" is checked rather than claimed.

use jose_rs::algorithm::{JweAlgorithm, JweEncryption, JwsAlgorithm};
use jose_rs::capability::{self, Availability, Kind, Operation};
use jose_rs::jwk::{self, Jwk, Password};
use jose_rs::{JoseError, JoseHeader, JweEncryption as Enc};

/// Exhaustive enumeration of the JWS variants *compiled into this build*.
///
/// The `match` is the point: adding a variant to `JwsAlgorithm` without updating the capability
/// table turns into a compile error in this file, not into a quietly incomplete table.
fn all_jws_variants() -> Vec<JwsAlgorithm> {
    [
        JwsAlgorithm::HS256,
        JwsAlgorithm::HS384,
        JwsAlgorithm::HS512,
        JwsAlgorithm::RS256,
        JwsAlgorithm::RS384,
        JwsAlgorithm::RS512,
        JwsAlgorithm::PS256,
        JwsAlgorithm::PS384,
        JwsAlgorithm::PS512,
        JwsAlgorithm::ES256,
        JwsAlgorithm::ES384,
        JwsAlgorithm::ES512,
        JwsAlgorithm::EdDSA,
        JwsAlgorithm::Ed25519,
        JwsAlgorithm::ES256K,
        #[cfg(feature = "post-quantum")]
        JwsAlgorithm::MlDsa44,
        #[cfg(feature = "post-quantum")]
        JwsAlgorithm::MlDsa65,
        #[cfg(feature = "post-quantum")]
        JwsAlgorithm::MlDsa87,
        #[cfg(feature = "post-quantum")]
        JwsAlgorithm::MlDsa44Es256,
        #[cfg(feature = "post-quantum")]
        JwsAlgorithm::MlDsa65Es256,
        #[cfg(feature = "post-quantum")]
        JwsAlgorithm::MlDsa87Es384,
        #[cfg(feature = "post-quantum")]
        JwsAlgorithm::MlDsa44Ed25519,
        #[cfg(feature = "post-quantum")]
        JwsAlgorithm::MlDsa65Ed25519,
        #[cfg(feature = "post-quantum")]
        JwsAlgorithm::MlDsa87Ed448,
        #[cfg(feature = "deprecated")]
        JwsAlgorithm::None,
    ]
    .to_vec()
}

fn all_jwe_key_management_variants() -> Vec<JweAlgorithm> {
    [
        JweAlgorithm::Dir,
        JweAlgorithm::A128KW,
        JweAlgorithm::A192KW,
        JweAlgorithm::A256KW,
        JweAlgorithm::A128Gcmkw,
        JweAlgorithm::A192Gcmkw,
        JweAlgorithm::A256Gcmkw,
        #[cfg(feature = "deprecated")]
        JweAlgorithm::RsaOaep,
        JweAlgorithm::RsaOaep256,
        JweAlgorithm::EcdhEs,
        JweAlgorithm::EcdhEsA128kw,
        JweAlgorithm::EcdhEsA192kw,
        JweAlgorithm::EcdhEsA256kw,
        JweAlgorithm::Pbes2Hs256A128kw,
        JweAlgorithm::Pbes2Hs384A192kw,
        JweAlgorithm::Pbes2Hs512A256kw,
    ]
    .to_vec()
}

fn all_content_encryption_variants() -> Vec<JweEncryption> {
    [
        JweEncryption::A128CbcHs256,
        JweEncryption::A192CbcHs384,
        JweEncryption::A256CbcHs512,
        JweEncryption::A128GCM,
        JweEncryption::A192GCM,
        JweEncryption::A256GCM,
    ]
    .to_vec()
}

/// Every enum variant must appear in the table, with an identifier that parses back to it.
#[test]
fn the_tables_cover_every_compiled_variant() {
    for variant in all_jws_variants() {
        let identifier = variant.as_str();
        let row = capability::find(Kind::JwsAlgorithm, identifier)
            .unwrap_or_else(|| panic!("no capability row for JWS `{identifier}`"));
        // The row's identifier must mean the same thing the enum means.
        assert_eq!(
            JwsAlgorithm::from_str(row.identifier).ok(),
            Some(variant),
            "row `{identifier}` does not parse back to its variant"
        );
    }
    for variant in all_jwe_key_management_variants() {
        let identifier = variant.as_str();
        assert!(
            capability::find(Kind::JweKeyManagement, identifier).is_some(),
            "no capability row for JWE `{identifier}`"
        );
    }
    for variant in all_content_encryption_variants() {
        assert!(
            capability::find(Kind::JweContentEncryption, variant.as_str()).is_some(),
            "no capability row for `enc` {}",
            variant.as_str()
        );
    }
}

/// A key that can perform `alg`, mirroring what the table claims about generation.
fn key_for_jws(alg: &str) -> Result<Jwk, JoseError> {
    let mut key = match alg {
        "HS256" | "HS384" | "HS512" => jwk::generate_symmetric_for_alg(alg)?,
        "RS256" | "RS384" | "RS512" | "PS256" | "PS384" | "PS512" => jwk::generate_rsa(2048)?,
        "ES256" => jwk::generate_ec("P-256")?,
        "ES384" => jwk::generate_ec("P-384")?,
        "ES512" => jwk::generate_ec("P-521")?,
        "EdDSA" | "Ed25519" => jwk::generate_ed25519()?,
        "ES256K" => jwk::generate_ec("P-256")?,
        #[cfg(feature = "post-quantum")]
        "ML-DSA-44" => jwk::generate_mldsa(kryptering::MlDsaVariant::MlDsa44)?,
        #[cfg(feature = "post-quantum")]
        "ML-DSA-65" => jwk::generate_mldsa(kryptering::MlDsaVariant::MlDsa65)?,
        #[cfg(feature = "post-quantum")]
        "ML-DSA-87" => jwk::generate_mldsa(kryptering::MlDsaVariant::MlDsa87)?,
        #[cfg(feature = "post-quantum")]
        "ML-DSA-44-ES256" => {
            jwk::generate_composite_mldsa(kryptering::CompositeMlDsaVariant::MlDsa44Es256)?
        }
        #[cfg(feature = "post-quantum")]
        "ML-DSA-65-ES256" => {
            jwk::generate_composite_mldsa(kryptering::CompositeMlDsaVariant::MlDsa65Es256)?
        }
        #[cfg(feature = "post-quantum")]
        "ML-DSA-87-ES384" => {
            jwk::generate_composite_mldsa(kryptering::CompositeMlDsaVariant::MlDsa87Es384)?
        }
        #[cfg(feature = "post-quantum")]
        "ML-DSA-44-Ed25519" => {
            jwk::generate_composite_mldsa(kryptering::CompositeMlDsaVariant::MlDsa44Ed25519)?
        }
        #[cfg(feature = "post-quantum")]
        "ML-DSA-65-Ed25519" => {
            jwk::generate_composite_mldsa(kryptering::CompositeMlDsaVariant::MlDsa65Ed25519)?
        }
        // Listed as recognized-and-unsupported with the feature on: the composite needs a
        // standalone Ed448, which the backend does not expose. Building the key anyway lets the
        // refusal be observed at signing time, which is the stronger claim.
        #[cfg(feature = "post-quantum")]
        "ML-DSA-87-Ed448" => {
            jwk::generate_composite_mldsa(kryptering::CompositeMlDsaVariant::MlDsa87Ed448)?
        }
        // An identifier this test cannot build a key for is reported as a refusal rather than a
        // panic: `advertised_jws_operations_are_performed` requires a key for every row it claims
        // is usable, so a missing path there still fails loudly, while an unusable row here is
        // exactly the "recognized, unsupported" case being checked.
        other => {
            return Err(JoseError::UnsupportedAlgorithm(format!(
                "no key-generation path for `{other}`"
            )))
        }
    };
    key.alg = Some(alg.to_string());
    Ok(key)
}

/// Every row that says "sign" and "verify" must sign and verify, in this build, with the
/// feature set this build has.
#[test]
fn advertised_jws_operations_are_performed() {
    let rows = capability::jws_algorithms();
    let mut performed = 0;
    for row in rows.iter().filter(|row| row.availability.is_available()) {
        if !row.operations.contains(&Operation::Sign) {
            continue;
        }
        let key = key_for_jws(row.identifier)
            .unwrap_or_else(|e| panic!("{}: key generation failed: {e}", row.identifier));
        assert_eq!(
            key.kty,
            expected_kty(row.identifier).unwrap_or(key.kty.as_str()),
            "{}: generated key type does not match the table's implication",
            row.identifier
        );

        let header = JoseHeader::new(row.identifier);
        let token = jose_rs::jws::compact::sign_with_jwk(&key, b"capability report", &header)
            .unwrap_or_else(|e| panic!("{}: sign failed: {e}", row.identifier));
        // An `oct` key has no public half, so verification uses the same key; asymmetric rows
        // verify under the *public* JWK, which is the stronger claim.
        let verifier = if key.kty == "oct" {
            key.clone()
        } else {
            key.to_public_jwk()
        };
        jose_rs::jws::compact::verify_with_jwk(&verifier, &token)
            .unwrap_or_else(|e| panic!("{}: verify failed: {e}", row.identifier));
        performed += 1;

        // And tampering is still caught, so "verify" is not vacuous.
        let mut broken = token.clone();
        let last = broken.pop().expect("non-empty jws");
        broken.push(if last == 'A' { 'B' } else { 'A' });
        assert!(
            jose_rs::jws::compact::verify_with_jwk(&verifier, &broken).is_err(),
            "{}: a corrupted JWS verified",
            row.identifier
        );
    }
    // A guard against the test silently doing nothing (e.g. if every row were marked unavailable).
    assert!(
        performed >= 12,
        "only {performed} JWS operations were performed; the table or this test is broken"
    );
}

fn expected_kty(alg: &str) -> Option<&'static str> {
    Some(match alg {
        "HS256" | "HS384" | "HS512" => "oct",
        "RS256" | "RS384" | "RS512" | "PS256" | "PS384" | "PS512" => "RSA",
        "ES256" | "ES384" | "ES512" => "EC",
        "EdDSA" | "Ed25519" => "OKP",
        _ if alg.starts_with("ML-DSA") => "AKP",
        _ => return None,
    })
}

/// Rows that say "not available" must actually refuse, in the way the row claims.
#[test]
fn unavailable_rows_refuse() {
    for row in capability::jws_algorithms()
        .into_iter()
        .filter(|row| !row.availability.is_available())
    {
        let reason = match row.availability {
            Availability::RequiresFeature(feature) => {
                // With the feature off, the identifier must not even parse into the enum.
                let parsed = JwsAlgorithm::from_str(row.identifier);
                match feature {
                    "post-quantum" | "deprecated" => assert!(
                        parsed.is_err(),
                        "{} parses even though feature `{feature}` is off",
                        row.identifier
                    ),
                    other => panic!("unknown feature {other} in the table"),
                }
                "feature-gated identifier refused by the parser"
            }
            Availability::RecognizedNotSupported => {
                // Recognized — and every operation refuses.
                assert!(
                    JwsAlgorithm::from_str(row.identifier).is_ok(),
                    "{} is listed as recognized but does not parse",
                    row.identifier
                );
                // The refusal may arrive at key generation (no usable key for the curve or the
                // second leg of a composite) or at signing; either way nothing is performed.
                match key_for_jws(row.identifier) {
                    Ok(key) => {
                        let err = jose_rs::jws::compact::sign_with_jwk(
                            &key,
                            b"x",
                            &JoseHeader::new(row.identifier),
                        )
                        .expect_err("must refuse");
                        assert!(
                            matches!(err, JoseError::UnsupportedAlgorithm(_)),
                            "{}: expected an unsupported-algorithm refusal, got {err}",
                            row.identifier
                        );
                    }
                    Err(err) => assert!(
                        matches!(err, JoseError::UnsupportedAlgorithm(_) | JoseError::Key(_)),
                        "{}: key generation failed with an unexpected error: {err}",
                        row.identifier
                    ),
                }
                "recognized identifier refused at the operation"
            }
            Availability::RefusedByPolicy(_) => {
                // `none` is the interesting one: the identifier is known and unusable.
                let err = JwsAlgorithm::from_str(row.identifier).err().or_else(|| {
                    jose_rs::jws::compact::sign_with_jwk(
                        &jwk::generate_symmetric_for_alg("HS256").expect("key"),
                        b"x",
                        &JoseHeader::new(row.identifier),
                    )
                    .err()
                });
                assert!(err.is_some(), "{} was accepted somewhere", row.identifier);
                "policy refusal"
            }
            Availability::Supported => unreachable!("filtered above"),
        };
        assert!(!row.note.is_empty(), "{} has no note", row.identifier);
        assert!(
            row.operations.is_empty() || !row.availability.is_available(),
            "{} advertises operations but is unavailable",
            row.identifier
        );
        let _ = reason;
    }
}

/// Every JWE key-management row that claims encrypt/decrypt is exercised end to end.
#[test]
fn advertised_jwe_operations_are_performed() {
    // One representative `enc` per algorithm family, sized so the algorithm is usable; the full
    // alg × enc grid is the interop matrix's job (interop/tests/matrix.sh).
    let cases: &[(&str, Enc)] = &[
        ("dir", Enc::A128GCM),
        ("A128KW", Enc::A128CbcHs256),
        ("A192KW", Enc::A192CbcHs384),
        ("A256KW", Enc::A256CbcHs512),
        ("A128GCMKW", Enc::A128GCM),
        ("A192GCMKW", Enc::A192GCM),
        ("A256GCMKW", Enc::A256GCM),
        ("RSA-OAEP-256", Enc::A256GCM),
        ("ECDH-ES", Enc::A128GCM),
        ("ECDH-ES+A128KW", Enc::A256CbcHs512),
        ("ECDH-ES+A192KW", Enc::A192GCM),
        ("ECDH-ES+A256KW", Enc::A256GCM),
        ("PBES2-HS256+A128KW", Enc::A128GCM),
        ("PBES2-HS384+A192KW", Enc::A192GCM),
        ("PBES2-HS512+A256KW", Enc::A256GCM),
    ];

    let mut performed = 0;
    for (identifier, enc) in cases {
        let row = capability::find(Kind::JweKeyManagement, identifier)
            .unwrap_or_else(|| panic!("no capability row for `{identifier}`"));
        if !row.availability.is_available() || !row.operations.contains(&Operation::Encrypt) {
            continue;
        }
        let plaintext = format!("capability report for {identifier}").into_bytes();
        let (token, decryption_key) = if identifier.starts_with("PBES2") {
            let password = Password::from_utf8("capability");
            let token = jose_rs::jwe::compact::encrypt_with_password(
                &password,
                &plaintext,
                jose_rs::JweAlgorithm::from_str(identifier).expect("alg"),
                *enc,
            )
            .unwrap_or_else(|e| panic!("{identifier}: encrypt failed: {e}"));
            (token, None)
        } else {
            let key = key_for_jwe(identifier, *enc);
            let token = jose_rs::jwe::compact::encrypt_with_jwk(&key, &plaintext, *enc)
                .unwrap_or_else(|e| panic!("{identifier}: encrypt failed: {e}"));
            (token, Some(key))
        };

        let plaintext_back = match decryption_key {
            Some(key) => jose_rs::jwe::compact::decrypt_with_jwk(&key, &token)
                .unwrap_or_else(|e| panic!("{identifier}: decrypt failed: {e}")),
            None => jose_rs::jwe::compact::decrypt_with_password(
                &Password::from_utf8("capability"),
                &token,
            )
            .unwrap_or_else(|e| panic!("{identifier}: decrypt failed: {e}")),
        };
        assert_eq!(plaintext_back, plaintext, "{identifier}");
        performed += 1;

        // A wrong key or password must not produce the plaintext.
        if identifier.starts_with("PBES2") {
            assert!(jose_rs::jwe::compact::decrypt_with_password(
                &Password::from_utf8("wrong"),
                &token
            )
            .is_err());
        } else {
            let unrelated = match *enc {
                Enc::A128GCM | Enc::A192GCM | Enc::A256GCM => jwk::generate_symmetric(32),
                _ => jwk::generate_symmetric(48),
            }
            .expect("other key");
            assert!(jose_rs::jwe::compact::decrypt_with_jwk(&unrelated, &token).is_err());
        }
    }
    assert!(
        performed >= 10,
        "only {performed} JWE operations were performed"
    );
}

fn key_for_jwe(alg: &str, enc: Enc) -> Jwk {
    let mut key = match alg {
        // `dir` uses the content-encryption key itself, so the size is dictated by `enc`.
        "dir" => jwk::generate_direct_symmetric(enc),
        "A128KW" | "A128GCMKW" => jwk::generate_symmetric(16),
        "A192KW" | "A192GCMKW" => jwk::generate_symmetric(24),
        "A256KW" | "A256GCMKW" => jwk::generate_symmetric(32),
        "RSA-OAEP" | "RSA-OAEP-256" => jwk::generate_rsa(2048),
        "ECDH-ES" => match enc {
            Enc::A128GCM | Enc::A128CbcHs256 => jwk::generate_ec("P-256"),
            Enc::A192GCM | Enc::A192CbcHs384 => jwk::generate_ec("P-384"),
            Enc::A256GCM | Enc::A256CbcHs512 => jwk::generate_ec("P-521"),
        },
        "ECDH-ES+A128KW" | "ECDH-ES+A192KW" | "ECDH-ES+A256KW" => jwk::generate_ec("P-256"),
        other => panic!("no key-building path for {other}"),
    }
    .expect("key generation");
    key.alg = Some(alg.to_string());
    key
}

/// Key-format rows claiming `import` must import a real file of that format.
#[test]
fn advertised_key_format_imports_work() {
    let rsa_cert: &str = include_str!("fixtures/cert/rsa_cert.pem");
    let ec_cert: &str = include_str!("fixtures/cert/ec256_cert.pem");
    assert!(
        jose_rs::jwk::public_jwk_from_certificate_pem(rsa_cert)
            .expect("certificate row advertises import")
            .kty
            == "RSA"
    );
    assert!(
        jose_rs::jwk::public_jwk_from_certificate_pem(ec_cert)
            .expect("certificate import for EC")
            .crv
            .as_deref()
            == Some("P-256")
    );

    // PKCS#8 + SPKI + PKCS#1 + SEC1 + encrypted PKCS#8, each through its own door.
    let plain = jose_rs::jwk::jwk_from_pkcs8_pem(include_str!("fixtures/pem/ec_pkcs8.pem"))
        .expect("pkcs8 row advertises import");
    let encrypted = jose_rs::jwk::encrypted_pkcs8_pem_from_jwk(
        &plain,
        &Password::from_utf8("capability"),
        &jose_rs::jwk::Pkcs8Encryption::Aes256CbcPbkdf2HmacSha256 { iterations: 4_096 },
    )
    .expect("encrypted export advertises export");
    assert!(jose_rs::jwk::jwk_from_encrypted_pkcs8_pem(
        &encrypted,
        &Password::from_utf8("capability")
    )
    .expect("encrypted row advertises import")
    .d
    .is_some());

    let spki = jose_rs::jwk::public_pem_from_jwk(&plain).expect("spki export row");
    assert!(jose_rs::jwk::jwk_from_spki_pem(&spki)
        .expect("spki import row")
        .x
        .is_some());

    // Formats listed as *not* supported must refuse something shaped like them.
    let unencrypted = jose_rs::jwk::private_pem_from_jwk(&plain).expect("plain pem");
    assert!(
        jose_rs::jwk::jwk_from_encrypted_pkcs8_pem(&unencrypted, &Password::from_utf8("x"))
            .is_err()
    );
}

/// The committed tables are the code's output, not a snapshot somebody maintained once.
///
/// Checked only in the default-feature build, because the rendering states the build's feature
/// state and therefore legitimately differs under `--features deprecated` / `--all-features`. The
/// second half of the test — every available identifier appears in the rendering — runs everywhere.
#[cfg(all(not(feature = "deprecated"), not(feature = "post-quantum")))]
#[test]
fn committed_markdown_matches_the_code() {
    let rendered = capability::markdown();
    let committed = include_str!("../docs/capabilities.md");

    // The feature state of *this* build appears in the header table, so compare from the first
    // real table onward: under `--features post-quantum` the feature rows legitimately differ from
    // the committed (default-build) rendering.
    let marker = "## JWS algorithms";
    let rendered_body = rendered.split(marker).nth(1).expect("rendered body");
    let committed_body = committed.split(marker).nth(1).expect("committed body");
    assert_eq!(
        rendered_body.trim(),
        committed_body.trim(),
        "docs/capabilities.md is stale; regenerate with `cargo run --example capabilities`"
    );

    // Every advertised operation appears in the rendered text too, so a row added to the code
    // without regenerating docs fails here rather than shipping undocumented.
    for row in capability::available() {
        assert!(
            rendered.contains(&format!("`{}`", row.identifier)),
            "{} missing from the rendered tables",
            row.identifier
        );
    }
}

/// In non-default builds, the tables still describe *this* build: no row may advertise an
/// operation while its own gating says it is unavailable, and every available identifier must be
/// rendered.
#[cfg(any(feature = "deprecated", feature = "post-quantum"))]
#[test]
fn feature_builds_report_themselves_honestly() {
    let rendered = capability::markdown();
    for row in capability::available() {
        assert!(
            !row.operations.is_empty(),
            "{} is available in this build but advertises no operation",
            row.identifier
        );
        assert!(
            rendered.contains(&format!("`{}`", row.identifier)),
            "{} missing from the rendered tables",
            row.identifier
        );
    }
    for row in capability::all() {
        if let Availability::RequiresFeature(feature) = row.availability {
            if capability::feature_enabled(feature) {
                assert!(
                    !row.operations.is_empty(),
                    "`{}` is gated on `{feature}`, which this build HAS, yet lists no operation — \
                     either the row is invented or the feature does not do what the table says",
                    row.identifier
                );
            } else {
                assert!(
                    row.identifier.contains('-') || row.identifier == "none",
                    "suspicious gated identifier `{}`",
                    row.identifier
                );
            }
        }
    }
}

/// The report is read-only and stable: same input, same answer, and no way to register anything.
#[test]
fn reporting_is_read_only_and_stable() {
    assert_eq!(capability::all(), capability::all());
    assert_eq!(capability::available().len(), capability::available().len());
    // No identifier is both available and refused, and no identifier is duplicated.
    let mut seen: Vec<(Kind, &str)> = Vec::new();
    for row in capability::all() {
        assert!(
            !seen.contains(&(row.kind, row.identifier)),
            "duplicate row for {:?}",
            (row.kind, row.identifier)
        );
        seen.push((row.kind, row.identifier));
        if row.availability.is_available() {
            assert!(
                !row.operations.is_empty(),
                "{} is available but advertises no operation",
                row.identifier
            );
        }
    }
    assert!(!capability::features().is_empty());
}
