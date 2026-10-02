//! JWK Thumbprint URIs (RFC 9278) and typed key generation (L5).
//!
//! The URI is a *format* claim, so it is tested against the RFC's own example string rather than
//! against this crate's output: RFC 9278 §6 publishes the complete URI for the RFC 7638 §3.1
//! example key, and this file asserts byte equality with it. The parsing side is tested by
//! breaking the URI in every way it can be broken.
//!
//! Typed generation is tested for the thing it exists to prevent: an unsupported option must be
//! refused by name, never rounded, defaulted, or quietly substituted.

use jose_rs::jwk::thumbprint::{
    thumbprint, thumbprint_sha256, thumbprint_uri, thumbprint_uri_sha256, JwkThumbprintUri,
    ThumbprintHash, THUMBPRINT_URI_PREFIX,
};
use jose_rs::jwk::{generate_key, EcCurve, Jwk, KeyGeneration};

/// The RFC 7638 §3.1 example key, verbatim.
const RFC7638_JWK: &str = r#"{
  "kty": "RSA",
  "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
  "e": "AQAB",
  "alg": "RS256",
  "kid": "2011-04-29"
}"#;

/// RFC 9278 §6, quoted exactly.
const RFC9278_EXAMPLE_URI: &str =
    "urn:ietf:params:oauth:jwk-thumbprint:sha-256:NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs";

#[test]
fn the_rfc_own_example_uri_is_reproduced_byte_for_byte() {
    let key = Jwk::from_json(RFC7638_JWK).expect("rfc vector parses");
    assert_eq!(
        thumbprint_sha256(&key).expect("thumbprint"),
        "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
    );
    assert_eq!(
        thumbprint_uri_sha256(&key).expect("uri"),
        RFC9278_EXAMPLE_URI,
        "the RFC's example URI is the format under test"
    );

    let parsed =
        JwkThumbprintUri::parse(RFC9278_EXAMPLE_URI).expect("the RFC's own example must parse");
    assert_eq!(parsed.hash(), ThumbprintHash::Sha256);
    assert_eq!(
        parsed.thumbprint(),
        "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
    );
    assert_eq!(parsed.to_uri(), RFC9278_EXAMPLE_URI);
    assert!(parsed.matches(&key).expect("compare"));
}

#[test]
fn sha256_stays_the_default_and_the_other_digests_are_available() {
    let key = jose_rs::jwk::generate_ec("P-256").expect("generate");
    // Default == SHA-256, and the URI says so.
    let default_uri = thumbprint_uri(&key, ThumbprintHash::default()).expect("uri");
    assert_eq!(default_uri, thumbprint_uri_sha256(&key).expect("explicit"));
    assert!(default_uri.starts_with(&format!("{THUMBPRINT_URI_PREFIX}:sha-256:")));

    // Each digest carries its own identifier, and its value has its own length.
    for (hash, identifier, encoded_len) in [
        (ThumbprintHash::Sha256, "sha-256", 43),
        (ThumbprintHash::Sha384, "sha-384", 64),
        (ThumbprintHash::Sha512, "sha-512", 86),
    ] {
        let uri = thumbprint_uri(&key, hash).expect("uri");
        assert!(uri.contains(&format!(":{identifier}:")), "{uri}");
        let value = uri.rsplit(':').next().expect("value");
        assert_eq!(value.len(), encoded_len, "{identifier}");
        assert_eq!(value, thumbprint(&key, hash).expect("thumbprint"));
        // Round trip through the parser, which validates the length against the identifier.
        let parsed = JwkThumbprintUri::parse(&uri).unwrap_or_else(|e| panic!("{identifier}: {e}"));
        assert_eq!(parsed.hash(), hash);
        assert!(parsed.matches(&key).expect("compare"));
    }
}

#[test]
fn a_uri_names_the_digest_it_was_computed_with() {
    let key = jose_rs::jwk::generate_ec("P-384").expect("generate");
    let sha256 =
        JwkThumbprintUri::parse(&thumbprint_uri_sha256(&key).expect("uri")).expect("parse");
    let sha512 =
        JwkThumbprintUri::parse(&thumbprint_uri(&key, ThumbprintHash::Sha512).expect("uri"))
            .expect("parse");

    assert_ne!(sha256.thumbprint(), sha512.thumbprint());
    assert!(sha256.matches(&key).expect("m") && sha512.matches(&key).expect("m"));

    // A key that is not this one matches neither, so `matches` is a real comparison.
    let other = jose_rs::jwk::generate_ec("P-384").expect("generate");
    assert!(!sha256.matches(&other).expect("m"));
    assert!(!sha512.matches(&other).expect("m"));
}

#[test]
fn malformed_uris_are_refused_naming_what_was_wrong() {
    let key = jose_rs::jwk::generate_ed25519().expect("generate");
    let good = thumbprint_uri_sha256(&key).expect("uri");
    let value = good.rsplit(':').next().expect("value");

    // Wrong or missing prefix.
    for bad in [
        format!("urn:ietf:params:oauth:jwk-thumb-print:sha-256:{value}"),
        format!("jwk-thumbprint:sha-256:{value}"),
        String::from("urn:ietf:params:oauth:jwk-thumbprint"),
    ] {
        let err = JwkThumbprintUri::parse(&bad).expect_err("prefix");
        assert!(err.to_string().contains("prefix"), "{bad}: {err}");
    }

    // Identifiers outside the IANA registry — including the unhyphenated and upper-case forms
    // that appear in neighbouring APIs. RFC 9278 §4 makes detecting this the application's job,
    // and this crate's answer is to refuse while listing what it accepts.
    for identifier in ["sha256", "SHA-256", "sha-3", "md5", "sha-256 "] {
        let uri = format!("{THUMBPRINT_URI_PREFIX}:{identifier}:{value}");
        let err = JwkThumbprintUri::parse(&uri).expect_err("identifier");
        let message = err.to_string();
        assert!(message.contains("registry"), "{identifier}: {message}");
        assert!(
            message.contains("sha-256, sha-384, sha-512"),
            "{identifier}"
        );
    }

    // Right identifier, digest that is not that size.
    let sha384 = thumbprint(&key, ThumbprintHash::Sha384).expect("384");
    let err = JwkThumbprintUri::parse(&format!("{THUMBPRINT_URI_PREFIX}:sha-256:{sha384}"))
        .expect_err("wrong size");
    assert!(err.to_string().contains("48 bytes"), "{err}");

    // A 40-character value decodes to 30 bytes: a length that is decodable but is not a SHA-256
    // digest, which the length check (not the base64 check) must catch.
    let truncated: String = value.chars().take(40).collect();
    let err = JwkThumbprintUri::parse(&format!("{THUMBPRINT_URI_PREFIX}:sha-256:{truncated}"))
        .expect_err("truncated");
    assert!(err.to_string().contains("30 bytes"), "{err}");

    // 41 characters is not even a base64 length, and says so differently.
    let odd: String = value.chars().take(41).collect();
    let err = JwkThumbprintUri::parse(&format!("{THUMBPRINT_URI_PREFIX}:sha-256:{odd}"))
        .expect_err("odd length");
    assert!(err.to_string().contains("base64url"), "{err}");

    // Not base64url-narrow at all.
    for junk in [
        "",
        " ",
        "abc=",
        "a_b-c+d",
        "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs\n",
    ] {
        let uri = format!("{THUMBPRINT_URI_PREFIX}:sha-256:{junk}");
        assert!(
            JwkThumbprintUri::parse(&uri).is_err(),
            "{junk:?} must be refused"
        );
    }
}

#[test]
fn from_jwk_and_from_text_agree() {
    for options in [
        KeyGeneration::Ed25519,
        KeyGeneration::X25519,
        KeyGeneration::Ec {
            curve: EcCurve::P256,
        },
        KeyGeneration::Oct { size: 32 },
    ] {
        let key = generate_key(options).expect("generate");
        let from_key = JwkThumbprintUri::from_jwk(&key, ThumbprintHash::Sha256).expect("from key");
        let text = thumbprint_uri_sha256(&key).expect("text");
        assert_eq!(from_key.to_uri(), text, "{options:?}");
        assert_eq!(
            JwkThumbprintUri::parse(&text).expect("parse"),
            from_key,
            "{options:?}"
        );
    }
}

// ---------------------------------------------------------------- typed generation

#[test]
fn typed_generation_reuses_the_existing_generators_rules() {
    // Same rules as the string-based doors: the RSA floor, the supported curve set.
    let err = generate_key(KeyGeneration::Rsa { bits: 512 }).expect_err("below floor");
    assert!(err.to_string().contains("2048"), "{err}");

    let key = generate_key(KeyGeneration::Rsa { bits: 2048 }).expect("rsa");
    assert_eq!(key.kty, "RSA");
    assert!(key.n.is_some() && key.e.is_some() && key.d.is_some());

    // Curve conversion is exact, so the enum cannot be pointed at an unsupported curve even by
    // text: the refusal names what was given.
    for bad in ["secp256k1", "P-600", "brainpoolP256r1", "p-256"] {
        let err = EcCurve::try_from(bad).expect_err("must refuse");
        assert!(err.to_string().contains(bad), "{bad}: {err}");
    }
    let err = EcCurve::try_from("P-256 ").expect_err("trailing space");
    assert!(err.to_string().contains("unsupported EC curve"), "{err}");
}

#[test]
fn symmetric_sizes_are_the_ones_jose_can_use() {
    for size in [16usize, 24, 32, 48, 64] {
        let key = generate_key(KeyGeneration::Oct { size }).expect("generate");
        assert_eq!(key.kty, "oct");
        let k = key.k.clone().expect("k present");
        // Unpadded base64url length for `size` bytes.
        assert_eq!(k.len(), (size * 4).div_ceil(3), "{size}");
    }
    for size in [0usize, 8, 20, 65, 128] {
        let err = generate_key(KeyGeneration::Oct { size }).expect_err("refuse");
        assert!(
            err.to_string().contains(&format!("{size}")),
            "{size}: {err}"
        );
    }
}

#[test]
fn generated_keys_are_usable_not_merely_parseable() {
    // A generated key must actually sign and verify, so the typed layer cannot be a JSON shim.
    let mut signing = generate_key(KeyGeneration::Ed25519).expect("generate");
    signing.alg = Some(jose_rs::JwsAlgorithm::EdDSA.as_str().to_string());
    let jws = jose_rs::jws::compact::sign_with_jwk(
        &signing,
        b"typed generation",
        &jose_rs::JoseHeader::new(jose_rs::JwsAlgorithm::EdDSA.as_str()),
    )
    .expect("sign");
    jose_rs::jws::compact::verify_with_jwk(&signing.to_public_jwk(), &jws).expect("verify");

    let agreement = generate_key(KeyGeneration::X25519).expect("x25519");
    assert_eq!(agreement.crv.as_deref(), Some("X25519"));
}
