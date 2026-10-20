//! SEC1 (RFC 5915) EC private-key import — I2.
//!
//! SEC1 is what `openssl ec -traditional` writes: the scalar, and optionally the curve and
//! the public point. The optional parts are the whole story — a file can carry a scalar with
//! no curve at all, can carry a curve as a full domain-parameter block instead of a name, and
//! can carry a public point that belongs to a different key. Each of those is a refusal here,
//! and each refusal exists because the alternative is *guessing*: a guessed curve turns a
//! P-256 secret into a P-384 one, and a borrowed public point produces a JWK whose public half
//! verifies nothing.
//!
//! Fixtures are OpenSSL's own output, plus variants built by rebuilding the outer SEQUENCE
//! from its own members — dropping one, or swapping one for the same-tagged member of a
//! different key — so every variant is well-formed DER that makes exactly one wrong claim.

use jose_rs::jwk::Jwk;
use jose_rs::jwk::{self, pem};
use jose_rs::jws::compact;
use jose_rs::JoseHeader;

fn thumbprint(key: &Jwk) -> String {
    jwk::thumbprint::thumbprint_sha256(key).expect("thumbprint")
}

/// Re-import a PEM document through the DER entry point, to check dispatch and the DER path.
fn der_of(text: &str) -> Vec<u8> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let body: String = text
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();
    let mut bits = 0u32;
    let mut acc = 0u32;
    let mut out = Vec::new();
    for byte in body.bytes() {
        if byte == b'=' {
            break;
        }
        let value = ALPHABET
            .iter()
            .position(|c| *c == byte)
            .unwrap_or_else(|| panic!("not base64: {}", byte as char)) as u32;
        acc = (acc << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    out
}

#[test]
fn every_supported_curve_round_trips_and_matches_its_pkcs8_form() {
    // (SEC1 fixture, PKCS#8 fixture) for each curve this crate reads.
    for (sec1_text, pkcs8_text, curve) in [
        (EC_SEC1, EC_PKCS8, "P-256"),
        (EC_P_384_SEC1, EC_P_384_PKCS8, "P-384"),
        (EC_P_521_SEC1, EC_P_521_PKCS8, "P-521"),
    ] {
        let from_sec1 = pem::jwk_from_pem(sec1_text)
            .unwrap_or_else(|e| panic!("{curve} SEC1 import failed: {e}"));
        let from_pkcs8 = pem::jwk_from_pkcs8_pem(pkcs8_text).expect("PKCS#8 import");
        assert_eq!(from_sec1.crv.as_deref(), Some(curve), "{curve}");
        assert_eq!(from_sec1.d, from_pkcs8.d, "{curve}: same scalar");
        assert_eq!(from_sec1.x, from_pkcs8.x, "{curve}: same public x");
        assert_eq!(from_sec1.y, from_pkcs8.y, "{curve}: same public y");
        assert_eq!(
            from_sec1.to_json().unwrap(),
            from_pkcs8.to_json().unwrap(),
            "{curve}: both formats produce one JWK"
        );
        // The plan's acceptance criterion, stated over the canonical JWK.
        assert_eq!(
            thumbprint(&from_sec1),
            thumbprint(&from_pkcs8),
            "{curve}: matching thumbprints across equivalent import formats"
        );
    }
}

#[test]
fn a_key_imported_from_sec1_signs_and_verifies_against_its_spki_half() {
    let mut private = pem::jwk_from_pem(EC_SEC1).expect("SEC1 imports");
    private.alg = Some("ES256".into());
    let public = pem::jwk_from_spki_pem(EC_SPKI).expect("SPKI imports");
    let token =
        compact::sign_with_jwk(&private, b"sec1 interop", &JoseHeader::new("ES256")).expect("sign");
    assert_eq!(
        compact::verify_with_jwk(&public, &token).unwrap(),
        b"sec1 interop",
        "a file from one tool works against a file from another"
    );
}

#[test]
fn a_scalar_with_no_curve_is_refused_rather_than_guessed() {
    // `parameters` is OPTIONAL. Trying each supported curve until one accepts the scalar is
    // the tempting implementation, and it would read a P-256 secret as a P-384 key.
    let err = pem::jwk_from_pem(EC_SEC1_NO_PARAMS)
        .unwrap_err()
        .to_string();
    assert!(err.contains("no curve parameters"), "{err}");
    assert!(err.contains("guessing"), "{err}");
}

#[test]
fn explicit_curve_parameters_are_refused_by_name() {
    // RFC 5915 allows the full domain-parameter block. Matching it to the nearest named curve
    // would import a key whose curve is *asserted by the file* — an anomalous or unsafely
    // generated curve is exactly what an attacker wants accepted. OpenSSL's own
    // `-param_enc explicit` output is the fixture.
    let err = pem::jwk_from_pem(EC256_EXPLICIT_ONLY)
        .unwrap_err()
        .to_string();
    assert!(err.contains("explicit curve parameters"), "{err}");
    assert!(err.contains("named"), "{err}");
}

#[test]
fn a_borrowed_public_point_is_refused() {
    // A's scalar with B's public point: both are valid on their own, and the pair is a key
    // whose public half belongs to someone else.
    let err = pem::jwk_from_pem(EC_SEC1_OTHER_POINT)
        .unwrap_err()
        .to_string();
    assert!(err.contains("P-256"), "{err}");
    assert!(
        err.contains("public point") || err.contains("embedded public point"),
        "{err}"
    );
    // Sanity: B's own file imports, so the refusal above is about the pairing.
    assert!(pem::jwk_from_pem(EC_B_SEC1).is_ok());
}

#[test]
fn scalars_outside_the_group_order_are_refused() {
    // Zero and the order itself are both outside [1, n−1]; neither is a usable secret, and
    // one of them (n) is congruent to 0, which would make every signature identical.
    for (text, what) in [
        (EC_SEC1_ZERO_SCALAR, "zero scalar"),
        (EC_SEC1_SCALAR_EQ_N, "scalar equal to n"),
    ] {
        let err = pem::jwk_from_pem(text).unwrap_err().to_string();
        assert!(err.contains("[1, n-1]"), "{what}: {err}");
    }
}

#[test]
fn the_sec1_and_pkcs8_doors_do_not_open_into_each_other() {
    assert!(jwk::jwk_from_sec1_der(&der_of(EC_SEC1)).is_ok());
    assert!(
        jwk::jwk_from_sec1_der(&der_of(EC_PKCS8)).is_err(),
        "PKCS#8 is not SEC1: reading it as such would reinterpret the bytes"
    );
    assert!(jwk::jwk_from_pkcs8_der(&der_of(EC_SEC1)).is_err());
    // Trailing bytes after the DER are refused rather than ignored.
    let mut extended = der_of(EC_SEC1);
    extended.push(0x00);
    assert!(jwk::jwk_from_sec1_der(&extended).is_err());
}

#[test]
fn an_unsupported_named_curve_is_refused_by_oid() {
    // The refusal has to say which curve it could not place, so a caller with a Brainpool or
    // secp256k1 key knows that is the problem rather than assuming the file is corrupt.
    // Built by swapping P-256's curve OID for secp256k1's (1.3.132.0.10).
    let secp256k1_oid: &[u8] = &[0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x0A];
    let mutated = swap_parameters(EC_SEC1, secp256k1_oid);
    let err = pem::jwk_from_pem(&mutated).unwrap_err().to_string();
    assert!(err.contains("unsupported SEC1 curve OID"), "{err}");
    assert!(err.contains("P-256, P-384 and P-521"), "{err}");
}

/// Rebuild a SEC1 document with its `parameters [0]` member replaced, keeping the armor
/// shape intact. Used to ask "what if the curve were a different one?".
fn swap_parameters(text: &str, new_parameters: &[u8]) -> String {
    let der = der_of(text);
    let (body, header) = sequence_body(&der);
    let mut pieces: Vec<(u8, Vec<u8>)> = Vec::new();
    let mut rest = body;
    while !rest.is_empty() {
        let tag = rest[0];
        let (&len_byte, after_tag) = rest[1..].split_first().unwrap();
        let (len, head) = if len_byte & 0x80 == 0 {
            (len_byte as usize, 2)
        } else {
            let octets = (len_byte & 0x7f) as usize;
            let len = after_tag[..octets]
                .iter()
                .fold(0usize, |a, b| (a << 8) | *b as usize);
            (len, 2 + octets)
        };
        pieces.push((tag, rest[head..head + len].to_vec()));
        rest = &rest[head + len..];
    }
    let rebuilt: Vec<(u8, Vec<u8>)> = pieces
        .iter()
        .map(|(tag, value)| {
            if *tag == 0xa0 {
                (*tag, new_parameters.to_vec())
            } else {
                (*tag, value.clone())
            }
        })
        .collect();
    let _ = header;
    let mut inner = Vec::new();
    for (tag, value) in rebuilt {
        inner.push(tag);
        if value.len() > 127 {
            let octets = len_octets(value.len());
            inner.push(0x80 | octets as u8);
            inner.extend_from_slice(&value.len().to_be_bytes()[8 - octets..]);
        } else {
            inner.push(value.len() as u8);
        }
        inner.extend_from_slice(&value);
    }
    let mut out = vec![0x30];
    if inner.len() > 127 {
        let octets = len_octets(inner.len());
        out.push(0x80 | octets as u8);
        out.extend_from_slice(&inner.len().to_be_bytes()[8 - octets..]);
    } else {
        out.push(inner.len() as u8);
    }
    out.extend_from_slice(&inner);
    let b64 = base64(&out);
    let wrapped: Vec<&str> = b64
        .as_bytes()
        .chunks(64)
        .map(|chunk| std::str::from_utf8(chunk).unwrap())
        .collect();
    format!(
        "-----BEGIN EC PRIVATE KEY-----\n{}\n-----END EC PRIVATE KEY-----\n",
        wrapped.join("\n")
    )
}

/// The body of a top-level `SEQUENCE`, and the size of its header.
fn sequence_body(der: &[u8]) -> (&[u8], usize) {
    assert_eq!(der[0], 0x30, "outer SEQUENCE");
    let first = der[1];
    if first & 0x80 == 0 {
        let len = first as usize;
        return (&der[2..2 + len], 2);
    }
    let octets = (first & 0x7f) as usize;
    let len = der[2..2 + octets]
        .iter()
        .fold(0usize, |a, b| (a << 8) | *b as usize);
    (&der[2 + octets..2 + octets + len], 2 + octets)
}

/// How many octets a DER length needs.
fn len_octets(len: usize) -> usize {
    match len {
        0..=0xFF => 1,
        0x100..=0xFFFF => 2,
        _ => 3,
    }
}

/// Base64 without pulling a decoder dependency into an integration test.
fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let mut buf = [0u8; 4];
        buf[1..1 + chunk.len()].copy_from_slice(chunk);
        let n = u32::from_be_bytes(buf) & 0x00ff_ffff;
        out.push(ALPHABET[(n >> 18) as usize] as char);
        out.push(ALPHABET[(n >> 12) as usize & 0x3f] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[(n >> 6) as usize & 0x3f] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[n as usize & 0x3f] as char
        } else {
            '='
        });
    }
    out
}

#[test]
fn pkcs8_and_sec1_imports_of_one_key_sign_identically() {
    // The strongest form of "equivalent import formats": the two files produce byte-identical
    // signatures for the same payload, because they are the same key in every member.
    let from_sec1 = pem::jwk_from_pem(EC_SEC1).unwrap();
    let from_pkcs8 = pem::jwk_from_pkcs8_pem(EC_PKCS8).unwrap();
    let header = JoseHeader::new("ES256");
    let mut a = from_sec1.clone();
    let mut b = from_pkcs8.clone();
    a.alg = Some("ES256".into());
    b.alg = Some("ES256".into());
    let t1 = compact::sign_with_jwk(&a, b"same key", &header).unwrap();
    let t2 = compact::sign_with_jwk(&b, b"same key", &header).unwrap();
    assert_eq!(t1, t2, "one key, two files, one signature");
}

const EC_SEC1: &str = r#"
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIBCba6yVutpga89oP4ZLtIFX8yExTbYuLWU/H9bt3n9KoAoGCCqGSM49
AwEHoUQDQgAEhpSXMpL642ZH3sli8VMdpTidFOhVa3GESAAqlYVY5HuC85MTw7fi
TP6eXAHUlWv1Oqhz56/UidVT3ncg0Nc3iA==
-----END EC PRIVATE KEY-----
"#;

const EC_P_384_SEC1: &str = r#"
-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDBUQ6Khnfk2i4Rko218bjmktw43qXQjxdp91clkXwpBSa8Zd26fLL/N
KvamvW4LzligBwYFK4EEACKhZANiAATkc4pCqUfz7b6w8hfQa88myxS3RrzcIJMs
zi96ikKZOhQlOwZQRlKUR2aAMkMIx49zokr8foFyIC3Fdfphhr72dcRP2TdRUwFA
Xe9A+Ig73st6FareK4xSU2zv9eP3zKI=
-----END EC PRIVATE KEY-----
"#;

const EC_P_521_SEC1: &str = r#"
-----BEGIN EC PRIVATE KEY-----
MIHcAgEBBEIBZPyaBORW8cHuDh/z/yjtMcKzmEUDghoVivlweLAtKShBHYM19JHW
CPw5tNg20c6CmirOH+55PwkNo7AZhO36mzSgBwYFK4EEACOhgYkDgYYABAE5ob5P
AL8YEvzEH2Lo9MXfCDOXYOGGr24iIHcANnkLbGhK6CzVHW6i8C4TDEI7od89DQ9z
xarFnH8FUz8h4fSt7ADxRpoYwr+3rErAw7YglQy67NsH90dz/ZGWPltn47FhZaRe
DVikg9SnC95lbc/cnByhLOE/A/1ab+3LC3O7r/LynA==
-----END EC PRIVATE KEY-----
"#;

const EC_SEC1_NO_PARAMS: &str = r#"
-----BEGIN EC PRIVATE KEY-----
MGsCAQEEIBCba6yVutpga89oP4ZLtIFX8yExTbYuLWU/H9bt3n9KoUQDQgAEhpSX
MpL642ZH3sli8VMdpTidFOhVa3GESAAqlYVY5HuC85MTw7fiTP6eXAHUlWv1Oqhz
56/UidVT3ncg0Nc3iA==
-----END EC PRIVATE KEY-----
"#;

const EC_SEC1_OTHER_POINT: &str = r#"
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIBCba6yVutpga89oP4ZLtIFX8yExTbYuLWU/H9bt3n9KoAoGCCqGSM49
AwEHoUQDQgAEwbGxN1iFH037VPN0+AktcCqAqBubK3zOOVw/slFPcBBjyraa/bJm
6kZa5RAek0DxiloVxuPl19YmPXbsXLOfog==
-----END EC PRIVATE KEY-----
"#;

const EC_SEC1_ZERO_SCALAR: &str = r#"
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAoAoGCCqGSM49
AwEHoUQDQgAEhpSXMpL642ZH3sli8VMdpTidFOhVa3GESAAqlYVY5HuC85MTw7fi
TP6eXAHUlWv1Oqhz56/UidVT3ncg0Nc3iA==
-----END EC PRIVATE KEY-----
"#;

const EC_SEC1_SCALAR_EQ_N: &str = r#"
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIP////8AAAAA//////////+85vqtpxeehPO5ysL8YyVRoAoGCCqGSM49
AwEHoUQDQgAEhpSXMpL642ZH3sli8VMdpTidFOhVa3GESAAqlYVY5HuC85MTw7fi
TP6eXAHUlWv1Oqhz56/UidVT3ncg0Nc3iA==
-----END EC PRIVATE KEY-----
"#;

const EC256_EXPLICIT_ONLY: &str = r#"
-----BEGIN EC PRIVATE KEY-----
MIIBaAIBAQQgnxn1oUN96HPG7FqujfEiiOJ/od4YiFWnUi/librR3TSggfowgfcC
AQEwLAYHKoZIzj0BAQIhAP////8AAAABAAAAAAAAAAAAAAAA////////////////
MFsEIP////8AAAABAAAAAAAAAAAAAAAA///////////////8BCBaxjXYqjqT57Pr
vVV2mIa8ZR0GsMxTsPY7zjw+J9JgSwMVAMSdNgiG5wSTamZ44ROdJreBn36QBEEE
axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpZP40Li/hp/m47n60p8D54W
K84zV2sxXs7LtkBoN79R9QIhAP////8AAAAA//////////+85vqtpxeehPO5ysL8
YyVRAgEBoUQDQgAE9w7cmjnZR99dgfq0z2P4Zx82MYdUnvyRMENn5i09zTKXdDRy
2/whsZ17ltViWdiVJxwoJjHPEPUMZ2jdrJlnZA==
-----END EC PRIVATE KEY-----
"#;

const EC_PKCS8: &str = r#"
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgEJtrrJW62mBrz2g/
hku0gVfzITFNti4tZT8f1u3ef0qhRANCAASGlJcykvrjZkfeyWLxUx2lOJ0U6FVr
cYRIACqVhVjke4LzkxPDt+JM/p5cAdSVa/U6qHPnr9SJ1VPedyDQ1zeI
-----END PRIVATE KEY-----
"#;

const EC_P_384_PKCS8: &str = r#"
-----BEGIN PRIVATE KEY-----
MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDBUQ6Khnfk2i4Rko218
bjmktw43qXQjxdp91clkXwpBSa8Zd26fLL/NKvamvW4LzlihZANiAATkc4pCqUfz
7b6w8hfQa88myxS3RrzcIJMszi96ikKZOhQlOwZQRlKUR2aAMkMIx49zokr8foFy
IC3Fdfphhr72dcRP2TdRUwFAXe9A+Ig73st6FareK4xSU2zv9eP3zKI=
-----END PRIVATE KEY-----
"#;

const EC_P_521_PKCS8: &str = r#"
-----BEGIN PRIVATE KEY-----
MIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIBZPyaBORW8cHuDh/z
/yjtMcKzmEUDghoVivlweLAtKShBHYM19JHWCPw5tNg20c6CmirOH+55PwkNo7AZ
hO36mzShgYkDgYYABAE5ob5PAL8YEvzEH2Lo9MXfCDOXYOGGr24iIHcANnkLbGhK
6CzVHW6i8C4TDEI7od89DQ9zxarFnH8FUz8h4fSt7ADxRpoYwr+3rErAw7YglQy6
7NsH90dz/ZGWPltn47FhZaReDVikg9SnC95lbc/cnByhLOE/A/1ab+3LC3O7r/Ly
nA==
-----END PRIVATE KEY-----
"#;

const EC_SPKI: &str = r#"
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEhpSXMpL642ZH3sli8VMdpTidFOhV
a3GESAAqlYVY5HuC85MTw7fiTP6eXAHUlWv1Oqhz56/UidVT3ncg0Nc3iA==
-----END PUBLIC KEY-----
"#;

const EC_B_SEC1: &str = r#"
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIJQx4m6cIrxIumVqkwKBiY1P4ONBLkMGzoOmHd1V1QufoAoGCCqGSM49
AwEHoUQDQgAEwbGxN1iFH037VPN0+AktcCqAqBubK3zOOVw/slFPcBBjyraa/bJm
6kZa5RAek0DxiloVxuPl19YmPXbsXLOfog==
-----END EC PRIVATE KEY-----
"#;
