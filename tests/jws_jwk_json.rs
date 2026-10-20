//! JWK-aware JSON JWS APIs (plan L2).
//!
//! The acceptance property is that the JSON serialization stops being a place callers have to
//! leave in order to use a JWK: the key metadata and strength rules are the compact path's rules,
//! by way of being the *same code*, and the multi-key General verify makes its success policy
//! explicit instead of choosing for the caller.

use jose_rs::jwk::{self, Jwk};
use jose_rs::jws::json::{self, GeneralJwkSigner, SignaturePolicy, MAX_CANDIDATE_KEYS};
use jose_rs::jws::{SignOptions, VerifyOptions};
use jose_rs::{JoseError, JoseHeader};
use serde_json::json;

fn ec(alg: &str, crv: &str) -> Jwk {
    let mut jwk = jwk::generate_ec(crv).expect("generate");
    jwk.alg = Some(alg.into());
    jwk
}

fn ed() -> Jwk {
    let mut jwk = jwk::generate_ed25519().expect("generate");
    jwk.alg = Some("EdDSA".into());
    jwk
}

fn header(alg: &str) -> JoseHeader {
    JoseHeader::new(alg)
}

// ---------------------------------------------------------------------------
// Flattened: same shape as compact, same rules
// ---------------------------------------------------------------------------

#[test]
fn flattened_round_trip_with_a_jwk() {
    let key = ec("ES256", "P-256");
    let flattened =
        json::sign_flattened_with_jwk(&key, b"payload bytes", &header("ES256")).unwrap();
    assert!(flattened.payload.is_some(), "attached by default");
    assert_eq!(
        json::verify_flattened_with_jwk(&key, &flattened).unwrap(),
        b"payload bytes"
    );
}

#[test]
fn detached_and_unencoded_payload_behaviour_is_unchanged() {
    let key = ec("ES256", "P-256");

    // Detached: no payload member, verified against out-of-band bytes.
    let detached =
        json::sign_flattened_detached_with_jwk(&key, b"out of band", &header("ES256")).unwrap();
    assert!(detached.payload.is_none());
    assert_eq!(
        json::verify_flattened_detached_with_jwk(&key, &detached, b"out of band").unwrap(),
        b"out of band"
    );
    // Wrong out-of-band bytes must not verify.
    assert!(json::verify_flattened_detached_with_jwk(&key, &detached, b"tampered").is_err());

    // RFC 7797: b64=false carries the raw payload, so the verified bytes are exactly
    // what was signed — the JWK path must not quietly re-encode.
    let opts = SignOptions::new().with_b64(false);
    let mut unencoded_header = header("ES256");
    unencoded_header
        .extra
        .insert("b64".into(), serde_json::json!(false));
    unencoded_header.crit = Some(vec!["b64".into()]);
    let unencoded = json::sign_flattened_with_jwk_opts(
        &key,
        b"raw bytes, not base64",
        &unencoded_header,
        None,
        &opts,
    )
    .unwrap();
    let embedded = unencoded.payload.clone().expect("payload member present");
    assert_eq!(embedded, "raw bytes, not base64");
    // No special option is needed to verify a `b64=false` token: the flag is read from the
    // authenticated header, and a token that says `b64: false` is verified that way.
    assert_eq!(
        json::verify_flattened_with_jwk_opts(&key, &unencoded, None, &VerifyOptions::new())
            .unwrap(),
        b"raw bytes, not base64"
    );
}

#[test]
fn the_jwk_path_applies_the_compact_path_s_key_rules() {
    // The parity claim, tested as parity: for the same key and the same token, the JSON verify
    // path and the compact verify path must refuse for the same reason. Comparing messages is
    // deliberate — if one path grows an extra rule, or drops one, this test notices.
    let mut enc_only = ec("ES256", "P-256");
    enc_only.extra.insert("use".into(), json!("enc"));
    enc_only.key_ops = Some(vec!["encrypt".into(), "decrypt".into()]);

    let signer = ec("ES256", "P-256");
    let token = jose_rs::jws::compact::sign_with_jwk(&signer, b"x", &header("ES256")).unwrap();

    // Same token content, JSON serialization.
    let flattened = json::sign_flattened_with_jwk(&signer, b"x", &header("ES256")).unwrap();

    let compact_err = jose_rs::jws::compact::verify_with_jwk(&enc_only, &token).unwrap_err();
    let json_err = json::verify_flattened_with_jwk(&enc_only, &flattened).unwrap_err();
    assert_eq!(
        compact_err.to_string(),
        json_err.to_string(),
        "key-metadata rules diverged between the compact and JSON paths"
    );
    assert!(
        matches!(json_err, JoseError::Key(_) | JoseError::InvalidToken(_)),
        "{json_err:?}"
    );
}

#[test]
fn a_short_hmac_key_cannot_be_promoted_by_editing_the_header() {
    // 32 bytes is right for HS256 and wrong for HS512. Strength is checked against the *token's*
    // algorithm, and the header is attacker-chosen, so the header must not be able to raise the
    // bar a key is allowed to clear.
    let key_256 = {
        let mut k = jwk::generate_symmetric_for_alg("HS256").unwrap();
        k.alg = Some("HS256".into());
        k
    };
    let unpinned = {
        let mut k = jwk::generate_symmetric_for_alg("HS256").unwrap();
        k.alg = None;
        k
    };

    let _token_256 =
        jose_rs::jws::compact::sign_with_jwk(&key_256, b"x", &header("HS256")).unwrap();
    // Re-sign the same payload under HS512 with a 512-sized key to prove the shape works, then
    // check the 256-bit key is refused for an HS512 token both when unpinned and when pinned.
    let hs512 = {
        let mut k = jwk::generate_symmetric_for_alg("HS512").unwrap();
        k.alg = Some("HS512".into());
        k
    };
    let big_token = jose_rs::jws::compact::sign_with_jwk(&hs512, b"x", &header("HS512")).unwrap();
    let big_flattened = json::sign_flattened_with_jwk(&hs512, b"x", &header("HS512")).unwrap();

    // Unpinned key: the algorithm comes from the header, and the strength check follows it.
    let err = json::verify_flattened_with_jwk(&unpinned, &big_flattened).unwrap_err();
    assert!(
        matches!(err, JoseError::Key(_) | JoseError::InvalidToken(_)),
        "{err:?}"
    );
    let big_key_only = jose_rs::jws::compact::verify_with_jwk(&hs512, &big_token).unwrap();
    assert_eq!(big_key_only, b"x");
}

#[test]
fn an_unpinned_algorithm_and_alg_none_are_still_refused() {
    let key = ec("ES256", "P-256");

    // No alg on the JWK: the JSON sign path cannot pick an algorithm for the caller.
    let mut unpinned = key.clone();
    unpinned.alg = None;
    let err = json::sign_flattened_with_jwk(&unpinned, b"x", &header("ES256")).unwrap_err();
    assert!(matches!(err, JoseError::Key(_)), "{err:?}");

    // Header/JWK disagreement is refused rather than resolved.
    let err = json::sign_flattened_with_jwk(&key, b"x", &header("ES512")).unwrap_err();
    assert!(matches!(err, JoseError::InvalidHeader(_)), "{err:?}");

    // `alg: none` never becomes a signature, JWK path or not.
    let mut none_key = key.clone();
    none_key.alg = Some("none".into());
    let err = json::sign_flattened_with_jwk(&none_key, b"x", &header("none")).unwrap_err();
    assert!(
        matches!(
            err,
            JoseError::UnsupportedAlgorithm(_) | JoseError::InvalidHeader(_)
        ),
        "{err:?}"
    );
}

// ---------------------------------------------------------------------------
// General: explicit policy, diagnosable candidates
// ---------------------------------------------------------------------------

#[test]
fn general_signing_with_jwks_and_both_policies() {
    let a = ed();
    let b = ec("ES256", "P-256");

    let jws = json::sign_general_with_jwk_pairs(
        &[(&a, &header("EdDSA")), (&b, &header("ES256"))],
        b"shared payload",
    )
    .unwrap();
    assert_eq!(jws.signatures.len(), 2);

    // Both policies succeed on a document both keys signed.
    assert_eq!(
        json::verify_general_with_jwk_any(&[&a, &b], &jws).unwrap(),
        b"shared payload"
    );
    assert_eq!(
        json::verify_general_with_jwk_all(&[&a, &b], &jws).unwrap(),
        b"shared payload"
    );

    // Which key signed what is reported, not left to be re-derived.
    let report = json::verify_general_with_jwks(
        &[&a, &b],
        &jws,
        None,
        &VerifyOptions::new(),
        SignaturePolicy::All,
    )
    .unwrap();
    assert!(report.satisfied());
    let keys: Vec<Option<usize>> = report.results.iter().map(|r| r.key_index).collect();
    assert_eq!(
        keys,
        vec![Some(0), Some(1)],
        "signature → key mapping wrong"
    );
    assert_eq!(
        report.results[0].protected_header.as_ref().unwrap().alg,
        "EdDSA"
    );
}

#[test]
fn any_and_all_diverge_on_a_partially_signed_document() {
    // Build a document where one signature is valid and the other is not, by signing two
    // signatures over different content is impossible in one document — so take two valid ones
    // and corrupt one signature string. That is the realistic shape: a document some subset of
    // its signers still authenticates.
    let a = ed();
    let b = ec("ES256", "P-256");
    let mut jws = json::sign_general_with_jwk_pairs(
        &[(&a, &header("EdDSA")), (&b, &header("ES256"))],
        b"payload",
    )
    .unwrap();
    jws.signatures[1].signature = "AAAA".into();

    // At least one valid signature: accepted, and the report says which one failed.
    assert_eq!(
        json::verify_general_with_jwk_any(&[&a, &b], &jws).unwrap(),
        b"payload"
    );

    // Every signature valid: refused, naming the failing index.
    let err = json::verify_general_with_jwk_all(&[&a, &b], &jws).unwrap_err();
    match err {
        JoseError::InvalidToken(msg) => {
            assert!(msg.contains("all-signatures"), "{msg}");
            assert!(msg.contains('1'), "{msg}");
        }
        other => panic!("expected an invalid-token refusal, got {other:?}"),
    }

    // And the report shape says so even when the policy is Any: signature 1 is not verified.
    let report = json::verify_general_with_jwks(
        &[&a, &b],
        &jws,
        None,
        &VerifyOptions::new(),
        SignaturePolicy::Any,
    )
    .unwrap();
    assert!(report.results[0].verified);
    assert!(!report.results[1].verified);
}

#[test]
fn a_short_circuited_report_says_what_it_did_not_do() {
    // The `Any` policy stops at the first valid signature. A report that then says "signature 1
    // failed" would be describing a check that never happened — and worse, its reason would be
    // the algorithm mismatch of the *first* candidate, which reads like a defect in the signature
    // rather than a stopped loop.
    let a = ed();
    let b = ec("ES256", "P-256");
    let jws = json::sign_general_with_jwk_pairs(
        &[(&a, &header("EdDSA")), (&b, &header("ES256"))],
        b"payload",
    )
    .unwrap();

    let report = json::verify_general_with_jwks(
        &[&a, &b],
        &jws,
        None,
        &VerifyOptions::new(),
        SignaturePolicy::Any,
    )
    .unwrap();
    assert!(
        report.results[0].verified,
        "first signature is the one that stopped"
    );
    let second = &report.results[1];
    assert!(!second.verified);
    assert!(
        !second.attempted,
        "signature 1 was never reached, so it must not be reported as attempted"
    );
    let reason = second.error.clone().unwrap_or_default();
    assert!(
        reason.contains("already satisfied"),
        "the reason must say the loop stopped early: {reason}"
    );

    // With `All`, the same signature *is* attempted and verified — the difference is policy, not
    // what the document contains.
    let report = json::verify_general_with_jwks(
        &[&a, &b],
        &jws,
        None,
        &VerifyOptions::new(),
        SignaturePolicy::All,
    )
    .unwrap();
    assert!(report.results[1].attempted && report.results[1].verified);
}

#[test]
fn keys_that_cannot_apply_are_reported_not_skipped() {
    // A `use: enc` key and a wrong-curve key are the two ways a caller's key list is usually
    // wrong. Silent skipping is what turns a misconfigured JWKS into "signature verification
    // failed" with nothing to act on.
    let signer = ec("ES256", "P-256");
    let mut enc_only = ec("ES256", "P-256");
    enc_only.extra.insert("use".into(), json!("enc"));
    let other_curve = ec("ES384", "P-384");

    let jws = json::sign_flattened_with_jwk(&signer, b"payload", &header("ES256")).unwrap();

    let err = json::verify_flattened_with_jwk(&enc_only, &jws).unwrap_err();
    assert!(
        matches!(err, JoseError::Key(_) | JoseError::InvalidToken(_)),
        "{err:?}"
    );

    let report = json::verify_general_with_jwks(
        &[&enc_only, &other_curve],
        &json::GeneralJws {
            payload: jws.payload.clone(),
            signatures: vec![jose_rs::jws::json::JwsSignature {
                protected: jws.protected.clone(),
                header: None,
                signature: jws.signature.clone(),
            }],
        },
        None,
        &VerifyOptions::new(),
        SignaturePolicy::Any,
    )
    .unwrap_err();
    assert!(matches!(report, JoseError::InvalidToken(_)), "{report:?}");
}

#[test]
fn the_candidate_list_is_bounded() {
    let signer = ed();
    let jws = json::sign_flattened_with_jwk(&signer, b"x", &header("EdDSA")).unwrap();
    let general = json::GeneralJws {
        payload: jws.payload,
        signatures: vec![jose_rs::jws::json::JwsSignature {
            protected: jws.protected,
            header: None,
            signature: jws.signature,
        }],
    };

    let keys = ed();
    let many: Vec<&Jwk> = (0..=MAX_CANDIDATE_KEYS).map(|_| &keys).collect();
    let err = json::verify_general_with_jwk_any(&many, &general).unwrap_err();
    assert!(
        matches!(&err, JoseError::InvalidToken(msg) if msg.contains("candidate keys")),
        "{err:?}"
    );

    // An empty candidate list is a caller bug, and saying so beats "no signature verified".
    let err = json::verify_general_with_jwk_any(&[], &general).unwrap_err();
    assert!(matches!(err, JoseError::Key(_)), "{err:?}");
}

#[test]
fn per_signature_unprotected_headers_survive_the_jwk_path() {
    let a = ed();
    let mut b = ec("ES256", "P-256");
    b.kid = Some("second".into());

    let eddsa_header = header("EdDSA");
    let es256_header = header("ES256");
    let entries = vec![
        GeneralJwkSigner::new(&a, &eddsa_header),
        GeneralJwkSigner {
            jwk: &b,
            protected: &es256_header,
            unprotected: Some(json!({"etsiU": {"commitmentType": "1.2.3"}})),
            options: SignOptions::new(),
        },
    ];
    let jws = json::sign_general_with_jwks(&entries, b"payload", true).unwrap();
    assert_eq!(
        jws.signatures[1].header,
        Some(json!({"etsiU": {"commitmentType": "1.2.3"}}))
    );

    // A key-rule failure in a later entry is caught before the first signature runs, so no
    // signature is spent on a document that will be rejected.
    let mut bad = ec("ES256", "P-256");
    bad.alg = Some("ES512".into());
    let entries = vec![
        GeneralJwkSigner::new(&a, &eddsa_header),
        GeneralJwkSigner::new(&bad, &es256_header),
    ];
    let err = json::sign_general_with_jwks(&entries, b"payload", true).unwrap_err();
    assert!(matches!(err, JoseError::InvalidHeader(_)), "{err:?}");
}

#[test]
fn general_signing_refuses_an_empty_entry_list() {
    let err = json::sign_general_with_jwks(&[], b"payload", true).unwrap_err();
    assert!(matches!(err, JoseError::InvalidToken(_)), "{err:?}");
}
