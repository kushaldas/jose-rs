//! X25519 agreement keys in JWE (`kty: OKP`, `crv: X25519`; RFC 8037 §2, §5).
//!
//! X25519 is the second key type `ECDH-ES` accepts, and it exercises parts of the
//! agreement path the P-curves do not:
//!
//! * the public value is a **bare 32-octet u-coordinate** — no SEC1 prefix, no
//!   second coordinate — so both the encoding the sender publishes and the one
//!   the recipient validates have a different shape;
//! * the key type is `OKP`, whose curves split into signing (Ed25519, Ed448) and
//!   agreement (X25519, X448) families, and only one of the four is available
//!   here — so the refusals have to be specific enough that a caller with an
//!   Ed25519 key does not conclude that "OKP is broken";
//! * the backend import takes `d` and `x` as independent values, so this crate
//!   must check that `d` derives `x` before it will agree with a key while
//!   publishing a different one (the check itself is covered in
//!   `jwk_agreement.rs`; here it is covered where it matters, on a JWE path).
//!
//! RFC 8037 Appendix A.6 publishes an X25519 ECDH-ES computation, but stops at the
//! shared secret without a ciphertext, so the wire-level cross-implementation
//! checks for this curve are the interop suite (panva and jwcrypto both implement
//! it) and the crypto-level check is in `jwk_agreement.rs`.

use jose_rs::algorithm::{JweAlgorithm, JweEncryption};
use jose_rs::jwe::{compact, json};
use jose_rs::jwk::Jwk;
use jose_rs::JoseHeader;

/// An X25519 recipient key pinned to `alg`.
fn recipient(alg: &str) -> Jwk {
    let mut key = jose_rs::jwk::generate_x25519().unwrap();
    key.alg = Some(alg.into());
    key.use_ = Some("enc".into());
    key
}

/// The `epk` member of a compact token's protected header.
fn epk_of(token: &str) -> serde_json::Value {
    let bytes = jose_rs::base64url::decode(token.split('.').next().unwrap()).unwrap();
    serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()["epk"].clone()
}

#[test]
fn every_agreement_algorithm_round_trips_over_x25519() {
    for alg in [
        "ECDH-ES",
        "ECDH-ES+A128KW",
        "ECDH-ES+A192KW",
        "ECDH-ES+A256KW",
    ] {
        let key = recipient(alg);
        for enc in [
            JweEncryption::A128GCM,
            JweEncryption::A256GCM,
            JweEncryption::A128CbcHs256,
            JweEncryption::A256CbcHs512,
        ] {
            let token = compact::encrypt_with_jwk(&key, b"x25519 agreement", enc)
                .unwrap_or_else(|e| panic!("{alg} with {enc:?}: {e}"));
            assert_eq!(
                compact::decrypt_with_jwk(&key, &token)
                    .unwrap_or_else(|e| panic!("{alg} with {enc:?}: {e}")),
                b"x25519 agreement"
            );

            let flat = json::encrypt_flattened_with_jwk(&key, b"x25519 agreement", enc).unwrap();
            assert_eq!(
                json::decrypt_flattened_with_jwk(&key, &flat).unwrap(),
                b"x25519 agreement"
            );
        }
    }
}

#[test]
fn the_epk_is_an_okp_public_value_with_nothing_extra() {
    // RFC 8037 §2: an OKP public key is `kty`, `crv` and `x` — no `y`, and no
    // private component. RFC 7518 §4.6.1.1 makes the second rule absolute for
    // `epk`.
    for alg in ["ECDH-ES", "ECDH-ES+A256KW"] {
        let key = recipient(alg);
        let token = compact::encrypt_with_jwk(&key, b"x", JweEncryption::A128GCM).unwrap();
        let epk = epk_of(&token);
        assert_eq!(epk["kty"], "OKP");
        assert_eq!(epk["crv"], "X25519");
        assert_eq!(
            epk.as_object().unwrap().keys().collect::<Vec<_>>(),
            vec!["crv", "kty", "x"],
            "{alg}: an X25519 epk carries exactly its public value"
        );
        let x = jose_rs::base64url::decode(epk["x"].as_str().unwrap()).unwrap();
        assert_eq!(x.len(), 32, "the u-coordinate, unprefixed");
    }
}

#[test]
fn an_x25519_sender_publishes_a_key_it_actually_agreed_with() {
    // The published `epk` must be the public half of the key the sender used, so
    // the recipient's own X25519 multiplication reproduces the content key. If `d`
    // and `x` ever diverged on this path, the recipient would derive from `x`
    // while the sender had multiplied with `d`, and every message would fail to
    // authenticate — which is why the mismatch is refused rather than tolerated.
    let key = recipient("ECDH-ES");
    let token = compact::encrypt_with_jwk(&key, b"matched pair", JweEncryption::A256GCM).unwrap();
    assert_eq!(
        compact::decrypt_with_jwk(&key, &token).unwrap(),
        b"matched pair"
    );

    // A JWK whose published half does not belong to its secret half cannot be used
    // to *recover* anything. Encrypting to it is fine and correct — a sender
    // consumes only the public value, and whoever holds the `d` matching that `x`
    // can read the message — so the refusal belongs on the receiving side, where
    // the pair would actually be multiplied out.
    let mut mismatched = jose_rs::jwk::generate_x25519().unwrap();
    mismatched.alg = Some("ECDH-ES".into());
    mismatched.use_ = Some("enc".into());
    let other = jose_rs::jwk::generate_x25519().unwrap();
    mismatched.x = other.x.clone();

    let against_mismatched =
        compact::encrypt_with_jwk(&mismatched, b"x", JweEncryption::A128GCM).is_ok();
    assert!(
        against_mismatched,
        "encryption consumes the recipient's public value only"
    );
    let token = compact::encrypt_with_jwk(&mismatched, b"x", JweEncryption::A128GCM).unwrap();
    let err = compact::decrypt_with_jwk(&mismatched, &token)
        .unwrap_err()
        .to_string();
    assert!(err.contains("does not match the public key x"), "{err}");

    // And the same key arriving as the message's peer value is refused too.
    let mut peer_is_private = jose_rs::jwk::generate_x25519().unwrap();
    peer_is_private.alg = Some("ECDH-ES".into());
    let ok_token =
        compact::encrypt_with_jwk(&peer_is_private, b"x", JweEncryption::A128GCM).unwrap();
    let header = jose_rs::base64url::decode(ok_token.split('.').next().unwrap()).unwrap();
    let mut header: serde_json::Value = serde_json::from_slice(&header).unwrap();
    // Hand the recipient a *private* `epk`, which is a protocol error regardless
    // of curve (RFC 7518 §4.6.1.1).
    header["epk"] = serde_json::json!({
        "kty": "OKP", "crv": "X25519",
        "x": peer_is_private.x.clone(), "d": peer_is_private.d.clone(),
    });
    let forged = format!(
        "{}.{}",
        jose_rs::base64url::encode(&serde_json::to_vec(&header).unwrap()),
        ok_token.split('.').skip(1).collect::<Vec<_>>().join(".")
    );
    let err = compact::decrypt_with_jwk(&peer_is_private, &forged)
        .unwrap_err()
        .to_string();
    assert!(err.contains("public material only"), "{err}");
}

#[test]
fn curves_cannot_be_mixed_across_an_ecdh_message() {
    // An X25519 recipient offered a P-256 message (and the reverse): agreement is
    // defined within one curve, so this is a refusal rather than a garbage key.
    let x25519 = recipient("ECDH-ES");
    let mut p256 = jose_rs::jwk::generate_ec("P-256").unwrap();
    p256.alg = Some("ECDH-ES".into());
    p256.use_ = Some("enc".into());

    let x_message = compact::encrypt_with_jwk(&x25519, b"x", JweEncryption::A128GCM).unwrap();
    let err = compact::decrypt_with_jwk(&p256, &x_message)
        .unwrap_err()
        .to_string();
    assert!(err.contains("curve"), "{err}");

    let p_message = compact::encrypt_with_jwk(&p256, b"x", JweEncryption::A128GCM).unwrap();
    let err = compact::decrypt_with_jwk(&x25519, &p_message)
        .unwrap_err()
        .to_string();
    assert!(err.contains("curve"), "{err}");
}

#[test]
fn a_signing_okp_key_is_refused_by_name() {
    // Ed25519 is the other OKP curve in wide use, and it is a signing curve: the
    // refusal has to say so, because "OKP is not supported" would send a caller
    // off to replace a key that was fine for its own purpose.
    // `alg` is pinned to an agreement algorithm so the refusal is about the curve:
    // without a pin the API refuses earlier, on the missing algorithm.
    let mut key = jose_rs::jwk::generate_ed25519().unwrap();
    key.alg = Some("ECDH-ES".into());
    key.use_ = Some("enc".into());
    let err = compact::encrypt_with_jwk(&key, b"x", JweEncryption::A128GCM)
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("Ed25519") && err.contains("signing curve"),
        "{err}"
    );

    // X448 is an agreement curve — just not one this backend can do — so it gets
    // its own wording rather than the signing-curve message.
    let mut x448 = key.clone();
    x448.kty = "OKP".into();
    x448.crv = Some("X448".into());
    let err = compact::encrypt_with_jwk(&x448, b"x", JweEncryption::A128GCM)
        .unwrap_err()
        .to_string();
    assert!(err.contains("X448"), "{err}");
    assert!(!err.contains("signing curve"), "{err}");
}

#[test]
fn a_key_pinned_for_signing_cannot_be_an_x25519_recipient() {
    // The curve is right and the material is right; the key's own statement is
    // not. RFC 7517 §4.2/§4.3, enforced identically for every agreement curve.
    // A key pinned to a signature algorithm never reaches the agreement boundary
    // at all: the JWE entry point cannot even name it as a key-management
    // algorithm, which is the earliest and clearest place to say no.
    let mut key = jose_rs::jwk::generate_x25519().unwrap();
    key.alg = Some("EdDSA".into());
    key.use_ = Some("enc".into());
    let err = compact::encrypt_with_jwk(&key, b"x", JweEncryption::A128GCM)
        .unwrap_err()
        .to_string();
    assert!(err.contains("EdDSA"), "{err}");

    let mut key = jose_rs::jwk::generate_x25519().unwrap();
    key.alg = Some("ECDH-ES".into());
    key.use_ = Some("sig".into());
    let err = compact::encrypt_with_jwk(&key, b"x", JweEncryption::A128GCM)
        .unwrap_err()
        .to_string();
    assert!(err.contains("`use` is sig"), "{err}");
}

#[test]
fn party_values_and_wrapping_still_apply_to_x25519() {
    // The KDF is shared with the P-curves: same AlgorithmID rules, same
    // apu/apv validation, same KEK lengths. Asserted here so an X25519 path that
    // quietly skipped a step shows up as a failure rather than an untested branch.
    let key = recipient("ECDH-ES+A128KW");
    let mut header = JoseHeader::for_jwe(JweAlgorithm::EcdhEsA128kw, JweEncryption::A256GCM);
    header
        .extra
        .insert("apu".into(), serde_json::json!("QWxpY2U"));
    header.extra.insert("apv".into(), serde_json::json!("Qm9i"));
    let token =
        compact::encrypt_with_jwk_header(&key, header, b"party info", JweEncryption::A256GCM)
            .unwrap();
    assert_eq!(
        compact::decrypt_with_jwk(&key, &token).unwrap(),
        b"party info",
        "the same party values derive the same KEK on both sides"
    );
    // A256GCM's 32-octet CEK under a 16-octet KEK: RFC 3394's 8-octet integrity
    // block makes the wrapped length report which length was used for what.
    let wrapped = jose_rs::base64url::decode(token.split('.').nth(1).unwrap()).unwrap();
    assert_eq!(wrapped.len(), 40);

    for (apu, apv) in [("QWxpY2U", "QWxpY2U"), ("!!", "Qm9i")] {
        let mut header = JoseHeader::for_jwe(JweAlgorithm::EcdhEs, JweEncryption::A128GCM);
        header.extra.insert("apu".into(), serde_json::json!(apu));
        header.extra.insert("apv".into(), serde_json::json!(apv));
        assert!(
            compact::encrypt_with_jwk_header(
                &recipient("ECDH-ES"),
                header,
                b"x",
                JweEncryption::A128GCM
            )
            .is_err(),
            "{apu}/{apv}"
        );
    }
}

#[test]
fn an_x25519_message_cannot_be_read_by_a_p_curve_key_and_back() {
    // Stronger than the curve-mismatch test above: same algorithm, same enc, both
    // keys pinned correctly for ECDH-ES — the only difference is the curve, which
    // is the one thing the message does not get to choose.
    for alg in ["ECDH-ES", "ECDH-ES+A256KW"] {
        let x = recipient(alg);
        let mut ec = jose_rs::jwk::generate_ec("P-521").unwrap();
        ec.alg = Some(alg.into());
        ec.use_ = Some("enc".into());

        let from_x = compact::encrypt_with_jwk(&x, b"x", JweEncryption::A128GCM).unwrap();
        assert!(compact::decrypt_with_jwk(&ec, &from_x).is_err());
        let from_ec = compact::encrypt_with_jwk(&ec, b"x", JweEncryption::A128GCM).unwrap();
        assert!(compact::decrypt_with_jwk(&x, &from_ec).is_err());
    }
}
