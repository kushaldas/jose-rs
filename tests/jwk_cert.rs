//! Public-key extraction from X.509 certificates (I4).
//!
//! Two claims are tested, and they are deliberately far apart:
//!
//! 1. **The right key comes out.** For every fixture, the extracted JWK must equal the JWK
//!    obtained from `openssl x509 -pubkey` — a different tool's encoder — and the key must
//!    *verify a signature* made by the certificate's own private key. A walk that lands on the
//!    wrong element can produce a parseable JWK; it cannot produce one that verifies.
//! 2. **Nothing is validated.** A certificate with its signature bytes flipped yields the same
//!    key, and that is asserted as correct behaviour. The API's name and rustdoc promise a key,
//!    not an identity, and a test is the only place that promise can be pinned.
//!
//! The refusals are the third part: DER-only parsing (stricter than OpenSSL, matching
//! `cryptography`), unsupported key types named clearly, and no reading of a chain's first
//! block as if it were the leaf.

use jose_rs::jwk::{
    self, public_jwk_from_certificate_der, public_jwk_from_certificate_pem,
    thumbprint::thumbprint_sha256, Jwk,
};
use jose_rs::{JoseHeader, JwsAlgorithm};

const RSA_CERT_PEM: &str = include_str!("fixtures/cert/rsa_cert.pem");
const RSA_CERT_DER: &[u8] = include_bytes!("fixtures/cert/rsa_cert.der");
const RSA_SPKI_PEM: &str = include_str!("fixtures/cert/rsa_spki.pem");
const RSA_KEY_PEM: &str = include_str!("fixtures/cert/rsa_key.pem");
const EC256_CERT_PEM: &str = include_str!("fixtures/cert/ec256_cert.pem");
const EC256_SPKI_PEM: &str = include_str!("fixtures/cert/ec256_spki.pem");
const EC256_KEY_PEM: &str = include_str!("fixtures/cert/ec256_key.pem");
const EC384_CERT_PEM: &str = include_str!("fixtures/cert/ec384_cert.pem");
const EC384_SPKI_PEM: &str = include_str!("fixtures/cert/ec384_spki.pem");
const EC384_KEY_PEM: &str = include_str!("fixtures/cert/ec384_key.pem");
const ED_CERT_PEM: &str = include_str!("fixtures/cert/ed_cert.pem");
const ED_SPKI_PEM: &str = include_str!("fixtures/cert/ed_spki.pem");
const ED_KEY_PEM: &str = include_str!("fixtures/cert/ed_key.pem");

const CERT_V1: &str = include_str!("fixtures/cert/rsa_cert_v1.pem");
const CERT_DECOY: &str = include_str!("fixtures/cert/rsa_cert_decoy.pem");
const DECOY_SPKI: &str = include_str!("fixtures/cert/rsa2_spki.pem");
const CERT_BER_INNER: &str = include_str!("fixtures/cert/rsa_cert_ber_inner.pem");
const CERT_BER_OUTER: &str = include_str!("fixtures/cert/rsa_cert_ber_outer.pem");
const CERT_TRUNCATED: &str = include_str!("fixtures/cert/rsa_cert_truncated.pem");
const CERT_TAMPERED: &str = include_str!("fixtures/cert/rsa_cert_tampered.pem");
const CHAIN: &str = include_str!("fixtures/cert/chain.pem");
const DSA_CERT: &str = include_str!("fixtures/cert/dsa_cert.pem");
const BRAINPOOL_CERT: &str = include_str!("fixtures/cert/bp_cert.pem");
const PSS_SPKI_CERT: &str = include_str!("fixtures/cert/rsa_pss_spki.pem");

/// Extract from PEM and DER and compare against OpenSSL's own SPKI encoding of the same cert.
fn assert_matches_spki(cert_pem: &str, spki_pem: &str, fixture: &str) {
    let from_cert = public_jwk_from_certificate_pem(cert_pem)
        .unwrap_or_else(|e| panic!("{fixture}: extraction failed: {e}"));
    let from_spki = jwk::jwk_from_spki_pem(spki_pem).expect("openssl spki imports");

    // Same key, by thumbprint (the canonical JWK fingerprint) rather than by field-by-field
    // comparison, so the claim is "the same key" and not "the same JSON shape".
    assert_eq!(
        thumbprint_sha256(&from_cert).expect("thumbprint"),
        thumbprint_sha256(&from_spki).expect("thumbprint"),
        "{fixture}: extracted key differs from openssl's SPKI"
    );
    // A certificate's key is public by definition.
    assert!(
        from_cert.d.is_none(),
        "{fixture}: private material appeared"
    );
    assert!(from_cert.kid.is_none(), "{fixture}: invented kid");
}

#[test]
fn rsa_ec_and_ed25519_certificates_yield_their_subject_keys() {
    assert_matches_spki(RSA_CERT_PEM, RSA_SPKI_PEM, "rsa");
    assert_matches_spki(EC256_CERT_PEM, EC256_SPKI_PEM, "ec P-256");
    assert_matches_spki(EC384_CERT_PEM, EC384_SPKI_PEM, "ec P-384");
    assert_matches_spki(ED_CERT_PEM, ED_SPKI_PEM, "ed25519");

    let rsa = public_jwk_from_certificate_pem(RSA_CERT_PEM).expect("rsa");
    assert_eq!(rsa.kty, "RSA");
    let ec = public_jwk_from_certificate_pem(EC256_CERT_PEM).expect("ec");
    assert_eq!((ec.kty.as_str(), ec.crv.as_deref()), ("EC", Some("P-256")));
    let ed = public_jwk_from_certificate_pem(ED_CERT_PEM).expect("ed");
    assert_eq!(
        (ed.kty.as_str(), ed.crv.as_deref()),
        ("OKP", Some("Ed25519"))
    );
}

#[test]
fn der_and_pem_doors_agree() {
    let from_der = public_jwk_from_certificate_der(RSA_CERT_DER).expect("der");
    let from_pem = public_jwk_from_certificate_pem(RSA_CERT_PEM).expect("pem");
    assert_eq!(
        thumbprint_sha256(&from_der).expect("t1"),
        thumbprint_sha256(&from_pem).expect("t2")
    );
}

/// The strongest check in this file: a signature made by the certificate's *private* key
/// verifies under the key extracted from the certificate. Landing on the wrong element of the
/// DER — the issuer's key, a decoy, an extension — could still parse; it could not verify.
#[test]
fn extracted_keys_verify_signatures_from_the_certificate_keys() {
    let cases: [(&str, &str, JwsAlgorithm); 4] = [
        (RSA_KEY_PEM, RSA_CERT_PEM, JwsAlgorithm::RS256),
        (EC256_KEY_PEM, EC256_CERT_PEM, JwsAlgorithm::ES256),
        (EC384_KEY_PEM, EC384_CERT_PEM, JwsAlgorithm::ES384),
        (ED_KEY_PEM, ED_CERT_PEM, JwsAlgorithm::EdDSA),
    ];
    for (key_pem, cert_pem, alg) in cases {
        let mut signing = jwk::jwk_from_pem(key_pem).expect("private key imports");
        signing.alg = Some(alg.as_str().to_string());
        let jws = jose_rs::jws::compact::sign_with_jwk(
            &signing,
            b"signed for the certificate test",
            &JoseHeader::new(alg.as_str()),
        )
        .expect("sign");

        let from_cert = public_jwk_from_certificate_pem(cert_pem).expect("extract");
        jose_rs::jws::compact::verify_with_jwk(&from_cert, &jws)
            .unwrap_or_else(|e| panic!("{alg:?}: verify failed: {e}"));

        // And a key that is *not* the certificate's refuses, so the check above is not vacuous.
        let other = jwk::generate_ec("P-256").expect("generate");
        assert!(jose_rs::jws::compact::verify_with_jwk(&other, &jws).is_err());
    }
}

/// A version-1-shaped certificate has no `[0] version` element, which shifts every later index.
/// Reading positionally means this must be handled, not guessed.
#[test]
fn a_version_one_certificate_reads_the_same_key() {
    let v1 = public_jwk_from_certificate_pem(CERT_V1).expect("v1 cert");
    let v3 = public_jwk_from_certificate_pem(RSA_CERT_PEM).expect("v3 cert");
    assert_eq!(
        thumbprint_sha256(&v1).expect("t1"),
        thumbprint_sha256(&v3).expect("t2")
    );
}

/// A second, perfectly valid SPKI is hidden in a private extension of this certificate. A
/// reader that *searches* for a public key finds the decoy; a positional reader does not.
#[test]
fn a_decoy_public_key_in_an_extension_is_not_the_subject_key() {
    let from_cert = public_jwk_from_certificate_pem(CERT_DECOY).expect("extract");
    let decoy = jwk::jwk_from_spki_pem(DECOY_SPKI).expect("decoy spki");
    let real = public_jwk_from_certificate_pem(RSA_CERT_PEM).expect("real cert");

    assert_eq!(
        thumbprint_sha256(&from_cert).expect("a"),
        thumbprint_sha256(&real).expect("b"),
        "the extension decoy must not displace the real subject key"
    );
    assert_ne!(
        thumbprint_sha256(&from_cert).expect("a"),
        thumbprint_sha256(&decoy).expect("c"),
        "the decoy must actually be a different key, or this test proves nothing"
    );
}

/// Extraction is not validation: a corrupted signature leaves the extracted key unchanged.
#[test]
fn extraction_does_not_validate_the_certificate_signature() {
    let tampered = public_jwk_from_certificate_pem(CERT_TAMPERED).expect("extract");
    let intact = public_jwk_from_certificate_pem(RSA_CERT_PEM).expect("extract");
    assert_eq!(
        thumbprint_sha256(&tampered).expect("t"),
        thumbprint_sha256(&intact).expect("i"),
        "flipping signature bytes must not change which key is presented"
    );
    // ...while `openssl verify` would reject that file. This asymmetry is the whole reason the
    // function is named `public_jwk_from_*` and not `verify_*`.
}

/// DER only, as RFC 5280 Appendix A.1 defines it. OpenSSL accepts both of these files;
/// `cryptography` refuses them, and so do we — naming the length form rather than "corrupt".
#[test]
fn indefinite_length_certificates_are_refused_by_name() {
    for (name, fixture) in [("inner", CERT_BER_INNER), ("outer", CERT_BER_OUTER)] {
        let err = public_jwk_from_certificate_pem(fixture)
            .expect_err("{name}: indefinite lengths must be refused");
        assert!(
            err.to_string().contains("indefinite length"),
            "{name}: {err}"
        );
    }
}

#[test]
fn truncated_and_mislabelled_inputs_are_refused() {
    let err = public_jwk_from_certificate_pem(CERT_TRUNCATED).expect_err("truncated");
    let message = err.to_string();
    assert!(
        message.contains("truncated") || message.contains("ended"),
        "{message}"
    );

    // A private key is not a certificate, in either direction.
    let err = public_jwk_from_certificate_pem(RSA_KEY_PEM).expect_err("private key at cert door");
    assert!(err.to_string().contains("CERTIFICATE"), "{err}");

    // And `jwk_from_pem` refuses a certificate, pointing at this module.
    let err = jwk::jwk_from_pem(RSA_CERT_PEM).expect_err("cert at jwk door");
    assert!(
        err.to_string().contains("public_jwk_from_certificate_pem"),
        "{err}"
    );
}

/// A file holding a chain is refused with the count: which certificate a caller means is their
/// decision, and quietly reading block one would present the wrong key without an error.
#[test]
fn a_certificate_chain_is_refused_with_a_block_count() {
    let err = public_jwk_from_certificate_pem(CHAIN).expect_err("two blocks");
    assert!(err.to_string().contains("2"), "{err}");
}

/// Unsupported and restricted algorithms fail clearly rather than producing a wrong-shaped key.
#[test]
fn unsupported_and_restricted_algorithms_are_named() {
    let err = public_jwk_from_certificate_pem(DSA_CERT).expect_err("DSA");
    let message = err.to_string();
    assert!(
        message.contains("DSA") || message.contains("algorithm") || message.contains("OID"),
        "{message}"
    );

    // Brainpool: a real, valid certificate on a curve this crate does not support.
    let err = public_jwk_from_certificate_pem(BRAINPOOL_CERT).expect_err("brainpool");
    let message = err.to_string();
    assert!(
        message.contains("curve") || message.contains("OID"),
        "{message}"
    );

    // An SPKI that names id-RSASSA-PSS: refused, and `cryptography` refuses it too.
    let err = public_jwk_from_certificate_pem(PSS_SPKI_CERT).expect_err("pss params");
    assert!(!err.to_string().is_empty());
}

#[test]
fn extracted_keys_carry_no_metadata_invented_for_them() {
    let key: Jwk = public_jwk_from_certificate_pem(EC256_CERT_PEM).expect("extract");
    assert!(key.use_.is_none());
    assert!(key.alg.is_none());
}
