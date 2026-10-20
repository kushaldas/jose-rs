//! The key-agreement boundary (`jose_rs::jwk::agreement`) — RFC 7518 §4.6
//! vectors and policy.
//!
//! Two things are pinned here. First, that the crypto is *right*: RFC 7518
//! Appendix C publishes a complete ECDH-ES computation — both keys with their
//! private parts, the resulting shared secret `Z`, every Concat KDF parameter,
//! and the derived key — so agreement and derivation are checked against the
//! RFC's own numbers rather than against this implementation's opinion.
//!
//! Second, that the boundary refuses the mistakes that matter: a signing key
//! used for agreement, a public-only key asked to be the private half, a peer
//! key carrying a private component, two curves multiplied together, an
//! off-curve peer point, and `apu` equal to `apv`.

use jose_rs::jwk::agreement::{agreement_key, peer_key, AgreementCurve};
use jose_rs::jwk::Jwk;
use serde_json::json;

/// RFC 7518 §C: Alice's ephemeral key, private part included.
const ALICE: &str = r#"{
  "kty": "EC", "crv": "P-256",
  "x": "gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0",
  "y": "SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps",
  "d": "0_NxaRPUMQoAJt50Gz8YiTr8gRTwyEaCumd-MToTmIo"
}"#;

/// RFC 7518 §C: Bob's static key, private part included.
const BOB: &str = r#"{
  "kty": "EC", "crv": "P-256",
  "x": "weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ",
  "y": "e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck",
  "d": "VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw"
}"#;

/// RFC 7518 §C: the shared secret `Z` the RFC states explicitly.
const Z: [u8; 32] = [
    158, 86, 217, 29, 129, 113, 53, 211, 114, 131, 66, 131, 191, 132, 38, 156, 251, 49, 110, 163,
    218, 128, 106, 72, 246, 218, 167, 121, 140, 254, 144, 196,
];

/// RFC 7518 §C: the derived key, base64url-encoded, for `A128GCM` with
/// `apu` = "Alice" and `apv` = "Bob".
const DERIVED_B64U: &str = "VqqN6vgjbSBcIijNcacQGg";

/// `apu` = base64url("Alice"), `apv` = base64url("Bob").
const APU: &str = "QWxpY2U";
const APV: &str = "Qm9i";

fn jwk(text: &str) -> Jwk {
    serde_json::from_str(text).unwrap()
}

/// Remove the private component, leaving a public-only JWK (what `epk` carries).
fn public_only(jwk: &Jwk) -> Jwk {
    let mut public = jwk.clone();
    public.d = None;
    public
}

fn json_jwk(mut object: serde_json::Value) -> Jwk {
    if object.get("key_ops").is_none() {
        object["key_ops"] = serde_json::json!(["deriveKey"]);
    }
    serde_json::from_value(object).unwrap()
}

#[test]
fn rfc_7518_appendix_c_shared_secret_is_reproduced() {
    let alice = agreement_key(&jwk(ALICE)).unwrap();
    let bob_peer = peer_key(&public_only(&jwk(BOB))).unwrap();

    assert_eq!(alice.curve(), AgreementCurve::P256);
    assert_eq!(alice.agree(&bob_peer).unwrap().as_slice(), &Z[..]);

    // Agreement is symmetric, which is the whole point of it: Bob, holding his
    // private key and Alice's published `epk`, computes the same Z.
    let bob = agreement_key(&jwk(BOB)).unwrap();
    let alice_peer = peer_key(&public_only(&jwk(ALICE))).unwrap();
    assert_eq!(bob.agree(&alice_peer).unwrap().as_slice(), &Z[..]);
}

#[test]
fn rfc_7518_appendix_c_derived_key_is_reproduced() {
    let alice = agreement_key(&jwk(ALICE)).unwrap();
    let bob_peer = peer_key(&public_only(&jwk(BOB))).unwrap();

    // Direct key agreement: AlgorithmID is the ASCII `enc` value, keydatalen is
    // the CEK size for A128GCM (128 bits).
    let derived = alice
        .derive_key(&bob_peer, "A128GCM", Some(APU), Some(APV), 16)
        .unwrap();
    assert_eq!(
        jose_rs::base64url::encode(&derived),
        DERIVED_B64U,
        "the Concat KDF OtherInfo must be byte-identical to RFC 7518 §4.6.2's"
    );

    // Every one of those inputs is domain-separating: changing any of them must
    // change the key, or the KDF is not doing its job.
    for (alg_id, apu, apv) in [
        ("A256GCM", Some(APU), Some(APV)),
        ("A128GCM", None, Some(APV)),
        ("A128GCM", Some(APU), None),
        ("A128GCM", Some(APV), Some(APU)),
        ("A128GCM", Some(APU), Some(APV)),
    ] {
        let other = alice
            .derive_key(
                &bob_peer,
                alg_id,
                apu,
                apv,
                if alg_id == "A256GCM" { 32 } else { 16 },
            )
            .unwrap();
        if (alg_id, apu, apv) != ("A128GCM", Some(APU), Some(APV)) {
            assert_ne!(
                other.as_slice(),
                derived.as_slice(),
                "{alg_id}/{apu:?}/{apv:?}"
            );
        }
        assert_eq!(other.len(), if alg_id == "A256GCM" { 32 } else { 16 });
    }
}

#[test]
fn agreement_works_on_every_supported_curve() {
    for crv in ["P-256", "P-384", "P-521"] {
        let a = jose_rs::jwk::generate_ec(crv).unwrap();
        let b = jose_rs::jwk::generate_ec(crv).unwrap();
        let a_key = agreement_key(&a).unwrap();
        let b_key = agreement_key(&b).unwrap();

        let z_ab = a_key.agree(&peer_key(&public_only(&b)).unwrap()).unwrap();
        let z_ba = b_key.agree(&peer_key(&public_only(&a)).unwrap()).unwrap();
        assert_eq!(
            z_ab.as_slice(),
            z_ba.as_slice(),
            "{crv}: agreement is not symmetric"
        );
        assert_eq!(z_ab.len(), a_key.curve().coord_len());

        // And the derived key is stable across the two directions, which is what
        // lets a sender and a recipient who never exchanged a key wrap agree on
        // one CEK.
        let k1 = a_key
            .derive_key(
                &peer_key(&public_only(&b)).unwrap(),
                "A128GCM",
                None,
                None,
                16,
            )
            .unwrap();
        let k2 = b_key
            .derive_key(
                &peer_key(&public_only(&a)).unwrap(),
                "A128GCM",
                None,
                None,
                16,
            )
            .unwrap();
        assert_eq!(k1.as_slice(), k2.as_slice(), "{crv}: derived keys disagree");
    }
}

#[test]
fn a_signing_key_cannot_become_an_agreement_key() {
    // Same curve, same material, wrong operation: `key_ops` says sign.
    let signing = json!({
        "kty": "EC", "crv": "P-256",
        "x": "weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ",
        "y": "e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck",
        "d": "VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw",
        "key_ops": ["sign"],
    });
    let err = agreement_key(&serde_json::from_value(signing).unwrap())
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("`key_ops` does not include deriveKey"),
        "{err}"
    );

    // `use: "sig"` is the coarser statement of the same thing.
    let signing = json!({
        "kty": "EC", "crv": "P-256",
        "x": "weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ",
        "y": "e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck",
        "d": "VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw",
        "use": "sig",
    });
    let err = agreement_key(&serde_json::from_value(signing).unwrap())
        .unwrap_err()
        .to_string();
    assert!(err.contains("`use` is sig"), "{err}");

    // An `alg` pin naming a signature algorithm is refused even without any
    // `use`/`key_ops`, because the pin is the key's own statement of purpose.
    let pinned = json!({
        "kty": "EC", "crv": "P-256",
        "x": "weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ",
        "y": "e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck",
        "d": "VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw",
        "alg": "ES256",
    });
    let err = agreement_key(&serde_json::from_value(pinned).unwrap())
        .unwrap_err()
        .to_string();
    assert!(err.contains("not a key-agreement algorithm"), "{err}");

    // An agreement pin, in contrast, is accepted — and this is what lets a JWK
    // be usable for ECDH-ES without the caller repeating the algorithm.
    let pinned = json!({
        "kty": "EC", "crv": "P-256",
        "x": "weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ",
        "y": "e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck",
        "d": "VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw",
        "alg": "ECDH-ES+A128KW",
        "key_ops": ["deriveKey"],
    });
    assert!(agreement_key(&serde_json::from_value(pinned).unwrap()).is_ok());
}

#[test]
fn the_two_halves_are_not_interchangeable() {
    // A public-only JWK cannot be the private half of an agreement.
    let public = public_only(&jwk(BOB));
    let err = agreement_key(&public).unwrap_err().to_string();
    assert!(err.contains("public-only JWK is a peer key"), "{err}");

    // And a peer carrying a private component is a protocol error, not a
    // courtesy: `epk` is supposed to be public.
    let with_private = jwk(ALICE);
    let err = peer_key(&with_private).unwrap_err().to_string();
    assert!(err.contains("private component"), "{err}");
}

#[test]
fn curves_cannot_be_multiplied_together() {
    let p256 = json!({
        "kty": "EC", "crv": "P-256",
        "x": "weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ",
        "y": "e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck",
        "d": "VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw",
        "key_ops": ["deriveKey"],
    });
    let own = agreement_key(&serde_json::from_value(p256).unwrap()).unwrap();
    let p384 = jose_rs::jwk::generate_ec("P-384").unwrap();
    let peer = peer_key(&public_only(&p384)).unwrap();

    // A P-256 scalar against a P-384 point is refused rather than computed:
    // a lax implementation would produce a shared secret neither party means.
    let err = own.agree(&peer).unwrap_err().to_string();
    assert!(err.contains("curve mismatch"), "{err}");
}

#[test]
fn peer_points_are_validated_not_trusted() {
    // A `y` that is not on the curve. The coordinates have the right shape, so
    // only real validation catches it — and it must be caught, because an
    // off-curve point is the classic way to leak a private scalar.
    let mut bogus: serde_json::Value = serde_json::from_str(ALICE).unwrap();
    bogus["d"] = serde_json::Value::Null;
    bogus["x"] = serde_json::json!("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    bogus["y"] = serde_json::json!("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    let err = peer_key(&serde_json::from_value::<Jwk>(bogus).unwrap())
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("point") || err.contains("curve") || err.contains("invalid"),
        "{err}"
    );

    // Coordinates longer than the field are refused before any arithmetic.
    let mut oversized: serde_json::Value = serde_json::from_str(ALICE).unwrap();
    oversized["d"] = serde_json::Value::Null;
    oversized["x"] = serde_json::json!(
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    );
    let err = peer_key(&serde_json::from_value::<Jwk>(oversized).unwrap())
        .unwrap_err()
        .to_string();
    assert!(err.contains("exceeds curve size"), "{err}");
}

#[test]
fn unsupported_key_types_are_named_at_the_boundary() {
    for (object, expected) in [
        (
            serde_json::json!({"kty": "oct", "k": "AAECAwQFBgcICQoLDA0ODw"}),
            "cannot perform key agreement",
        ),
        (
            serde_json::json!({"kty": "RSA", "n": "AA", "e": "AQAB"}),
            "cannot perform key agreement",
        ),
        (
            serde_json::json!({"kty": "OKP", "crv": "Ed25519", "x": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"}),
            "not a key-agreement curve",
        ),
        (
            serde_json::json!({"kty": "OKP", "crv": "X448", "x": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gYgICAgICAgICAgICAgAgICAg"}),
            "cannot perform key agreement with this backend",
        ),
        (
            serde_json::json!({"kty": "EC", "crv": "P-600", "x": "AA", "y": "AA"}),
            "not supported for key agreement",
        ),
    ] {
        let key = json_jwk(object);
        let err = agreement_key(&key).unwrap_err().to_string();
        assert!(err.contains(expected), "{expected} — got {err}");
    }
}

#[test]
fn apu_and_apv_must_differ() {
    // RFC 7518 §4.6.2: "The 'apu' and 'apv' Header Parameter values MUST be
    // distinct, when used." Two parties with the same identity value is a
    // derivation bug that would silently bind both sides to the same info.
    let alice = agreement_key(&jwk(ALICE)).unwrap();
    let bob_peer = peer_key(&public_only(&jwk(BOB))).unwrap();
    let err = alice
        .derive_key(&bob_peer, "A128GCM", Some(APU), Some(APU), 16)
        .unwrap_err()
        .to_string();
    assert!(err.contains("apu and apv must be distinct"), "{err}");

    // A malformed `apu` is a structural error, not a derivation with garbage.
    let err = alice
        .derive_key(&bob_peer, "A128GCM", Some("not!base64url"), None, 16)
        .unwrap_err()
        .to_string();
    assert!(!err.is_empty(), "{err}");

    // Absent on one side is fine — and differs from the empty string, which the
    // KDF encodes as length 0 either way, so both are accepted deliberately.
    assert!(alice
        .derive_key(&bob_peer, "A128GCM", None, Some(APV), 16)
        .is_ok());
}

#[test]
fn an_agreement_key_publishes_its_own_public_value() {
    // The sender has to put its ephemeral public key in `epk`; the encoding the
    // boundary hands back is the one agreement consumes, so a sender cannot
    // publish a point that its own recipient would reject as malformed.
    let alice = agreement_key(&jwk(ALICE)).unwrap();
    let public = alice.public_bytes();
    assert_eq!(public[0], 0x04);
    assert_eq!(public.len(), 65);
    let expected_x =
        jose_rs::base64url::decode("gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0").unwrap();
    assert_eq!(&public[1..33], &expected_x[..]);
}

// ---------------------------------------------------------------------------
// X25519 (RFC 8037 §2, Appendix A.6)
// ---------------------------------------------------------------------------

/// RFC 8037 A.6: the recipient's public key. Only the public half is published,
/// which is exactly the shape an `epk` or a recipient entry has.
const X25519_BOB: &str = r#"{
  "kty": "OKP", "crv": "X25519", "kid": "Bob",
  "x": "3p7bfXt9wbTTW2HC7OQ1Nz-DQ8hbeGdNrfx-FG-IK08"
}"#;

/// RFC 8037 A.6: the ephemeral key pair — the secret is printed in hex by the
/// RFC, and so is the public value derived from it.
const X25519_EPHEMERAL: &str = r#"{
  "kty": "OKP", "crv": "X25519",
  "x": "hSDwCYkwp1R0i33ctD73Wg2_Og0mOBr066SpjqqbTmo",
  "d": "dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo"
}"#;

/// RFC 8037 A.6: the shared secret both sides compute, printed explicitly.
const X25519_Z: [u8; 32] = [
    0x4a, 0x5d, 0x9d, 0x5b, 0xa4, 0xce, 0x2d, 0xe1, 0x72, 0x8e, 0x3b, 0xf4, 0x80, 0x35, 0x0f, 0x25,
    0xe0, 0x7e, 0x21, 0xc9, 0x47, 0xd1, 0x9e, 0x33, 0x76, 0xf0, 0x9b, 0x3c, 0x1e, 0x16, 0x17, 0x42,
];

#[test]
fn x25519_rfc_8037_a6_shared_secret() {
    // The RFC prints both the ephemeral secret and the Z it produces against
    // Bob's public key, so this is agreement checked against the standard rather
    // than against symmetry with ourselves.
    let own = agreement_key(&jwk(X25519_EPHEMERAL)).unwrap();
    let peer = peer_key(&jwk(X25519_BOB)).unwrap();
    assert_eq!(own.curve(), AgreementCurve::X25519);
    assert_eq!(peer.curve(), AgreementCurve::X25519);
    assert_eq!(own.agree(&peer).unwrap().as_slice(), &X25519_Z[..]);
}

#[test]
fn an_x25519_public_value_is_the_bare_u_coordinate() {
    // No SEC1 prefix, no second coordinate: 32 octets, matching the JWK.
    let own = agreement_key(&jwk(X25519_EPHEMERAL)).unwrap();
    let public = own.public_bytes();
    assert_eq!(public.len(), 32);
    let expected =
        jose_rs::base64url::decode("hSDwCYkwp1R0i33ctD73Wg2_Og0mOBr066SpjqqbTmo").unwrap();
    assert_eq!(public, &expected[..]);
}

#[test]
fn an_x25519_jwk_whose_d_does_not_derive_x_is_refused() {
    // The reason X25519 import is not simply "two base64url strings handed to the
    // backend": agreement multiplies with `d` while the message publishes `x`, so
    // an inconsistent pair publishes one identity and agrees with another key.
    let mut mismatched = jwk(X25519_EPHEMERAL);
    let other = jose_rs::jwk::generate_x25519().unwrap();
    mismatched.x = other.x.clone();
    let err = agreement_key(&mismatched).unwrap_err().to_string();
    assert!(err.contains("does not match the public key x"), "{err}");

    // Same refusal on the peer side, where the check is on the value alone:
    // there is no `d` to disagree with, so the refusal there is about shape.
    let mut peer = jwk(X25519_BOB);
    peer.x = Some("AAA".into());
    assert!(peer_key(&peer).is_err());
}

#[test]
fn x25519_round_trips_in_both_directions() {
    // RFC 8037 A.6 publishes only one side's private value, so the reverse
    // direction is checked with a generated pair instead.
    let recipient = jose_rs::jwk::generate_x25519().unwrap();
    let sender = jose_rs::jwk::generate_x25519().unwrap();

    let forward = agreement_key(&sender)
        .unwrap()
        .derive_key(
            &peer_key(&recipient.to_public_jwk()).unwrap(),
            "ECDH-ES",
            None,
            None,
            32,
        )
        .unwrap();
    let backward = agreement_key(&recipient)
        .unwrap()
        .derive_key(
            &peer_key(&sender.to_public_jwk()).unwrap(),
            "ECDH-ES",
            None,
            None,
            32,
        )
        .unwrap();
    assert_eq!(forward.as_slice(), backward.as_slice());
    assert_eq!(forward.len(), 32);
}

#[test]
fn a_low_order_x25519_peer_value_is_refused() {
    // The X25519 equivalent of an off-curve point: an all-zero u-coordinate is a
    // small-order group element, and multiplying it out yields the identity
    // element — a shared secret of all zeros, which an attacker knows. Refused by
    // the primitive, and the boundary must surface that rather than deriving from
    // it.
    let mut small_order = jwk(X25519_BOB);
    small_order.x = Some(jose_rs::base64url::encode(&[0u8; 32]));
    let peer = peer_key(&small_order).expect("shape is well-formed; the refusal is algebraic");
    let own = agreement_key(&jwk(X25519_EPHEMERAL)).unwrap();
    let err = own.agree(&peer).unwrap_err().to_string();
    assert!(
        err.to_lowercase().contains("low-order") || err.to_lowercase().contains("identity"),
        "{err}"
    );
}

#[test]
fn a_public_only_x25519_key_is_a_peer_not_an_agreement_key() {
    let public = jwk(X25519_BOB);
    assert!(peer_key(&public).is_ok());
    let err = agreement_key(&public).unwrap_err().to_string();
    assert!(err.contains("private scalar"), "{err}");
}
