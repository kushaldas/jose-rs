//! PKCS#1 (RFC 8017 §A.1.2) RSA import — I1.
//!
//! PKCS#1 is the RSA-only older sibling of PKCS#8: what `openssl genrsa` writes by default,
//! what `id_rsa` carries. It states no algorithm because there is only one, and it can carry
//! things a JWK has nowhere to put — a third prime factor, CRT members that disagree with
//! the key they belong to. The fixtures are OpenSSL's own output plus variants produced by
//! flipping a single interior octet of one INTEGER, which keeps the DER well-formed and
//! changes exactly one claim the file makes about itself.
//!
//! The rule under test is that **decoding is not validation**. Every import is rebuilt from
//! its parts and checked against itself before anything is returned.

use jose_rs::jwk::Jwk;
use jose_rs::jwk::{self, pem};
use jose_rs::jws::compact;
use jose_rs::JoseHeader;

fn import_private(text: &str) -> Result<Jwk, jose_rs::JoseError> {
    pem::jwk_from_pem(text)
}

#[test]
fn openssl_pkcs1_private_imports_and_matches_its_pkcs8_form() {
    let from_pkcs1 = pem::jwk_from_pem(RSA_PKCS1).expect("OpenSSL's PKCS#1 imports");
    let from_pkcs8 = pem::jwk_from_pkcs8_pem(RSA_PKCS8).expect("the same key as PKCS#8");
    assert_eq!(
        from_pkcs1.d, from_pkcs8.d,
        "the private part is the same number"
    );
    assert_eq!(
        from_pkcs1.to_json().unwrap(),
        from_pkcs8.to_json().unwrap(),
        "and so is every other member: both paths normalize to the same JWK"
    );
    // RFC 7638 thumbprints across equivalent import formats: the acceptance criterion,
    // stated over the canonical JWK rather than the file bytes.
    assert_eq!(
        jwk::thumbprint::thumbprint_sha256(&from_pkcs1).unwrap(),
        jwk::thumbprint::thumbprint_sha256(&from_pkcs8).unwrap()
    );
}

#[test]
fn openssl_pkcs1_public_imports_and_matches_its_spki_form() {
    let from_pkcs1 = pem::jwk_from_pem(RSA_PUB_PKCS1).expect("PKCS#1 public imports");
    let from_spki = pem::jwk_from_spki_pem(RSA_SPKI).expect("SPKI public imports");
    assert_eq!(from_pkcs1.to_json().unwrap(), from_spki.to_json().unwrap());
    assert!(
        from_pkcs1.d.is_none(),
        "a public import has no private part"
    );
    assert_eq!(
        jwk::thumbprint::thumbprint_sha256(&from_pkcs1).unwrap(),
        jwk::thumbprint::thumbprint_sha256(&from_spki).unwrap()
    );
}

#[test]
fn a_key_imported_from_pkcs1_signs_and_verifies_against_its_spki_half() {
    // The end-to-end statement: a file one tool wrote is usable against a file another
    // tool wrote, not merely parseable by both.
    let mut private = import_private(RSA_PKCS1).expect("imports");
    private.alg = Some("RS256".into());
    let public = pem::jwk_from_spki_pem(RSA_SPKI).expect("SPKI imports");
    let token =
        compact::sign_with_jwk(&private, b"pkcs1 interop", &JoseHeader::new("RS256")).unwrap();
    assert_eq!(
        compact::verify_with_jwk(&public, &token).unwrap(),
        b"pkcs1 interop"
    );
    // …and the same signature verifies against the PKCS#1 *public* file.
    let public_p1 = pem::jwk_from_pem(RSA_PUB_PKCS1).unwrap();
    assert!(compact::verify_with_jwk(&public_p1, &token).is_ok());
}

#[test]
fn crt_members_are_checked_not_trusted_and_not_repaired() {
    // Each variant differs from a valid key by one interior octet of one CRT member, so the
    // DER is well-formed and only the key's self-description is wrong. Accepting these
    // would mean either propagating a wrong exponent or silently substituting a computed
    // one — a corrupt key nobody notices.
    for (text, member) in [
        (RSA_PKCS1_BAD_DP, "exponent1 (dp)"),
        (RSA_PKCS1_BAD_DQ, "exponent2 (dq)"),
        (RSA_PKCS1_BAD_QI, "coefficient"),
    ] {
        let err = pem::jwk_from_pem(text).unwrap_err().to_string();
        assert!(err.contains(member), "{member}: {err}");
        assert!(err.contains("does not match"), "{member}: {err}");
    }
    // Re-emitting the identical bytes is accepted, so the refusals above are about the
    // claims the file makes and not about the fixture machinery.
    assert!(pem::jwk_from_pem(RSA_PKCS1_REPEMMED).is_ok());
}

#[test]
fn keys_that_do_not_describe_one_key_are_refused() {
    // `d` that is not the inverse of `e`, and `q` that does not divide `n`, are caught by
    // rebuilding the key from its parts rather than by trusting the file.
    let err = pem::jwk_from_pem(RSA_PKCS1_BAD_D).unwrap_err().to_string();
    assert!(err.contains("not internally consistent"), "{err}");
    assert!(err.to_lowercase().contains("exponent"), "{err}");
    for text in [RSA_PKCS1_BAD_Q, RSA_PKCS1_BAD_N] {
        let err = pem::jwk_from_pem(text).unwrap_err().to_string();
        assert!(err.contains("not internally consistent"), "{err}");
        assert!(err.to_lowercase().contains("modulus"), "{err}");
    }
}

#[test]
fn multi_prime_keys_are_refused_by_name() {
    // PKCS#1 allows more than two primes; an RSA JWK has `p`, `q`, and no member for a
    // third. Dropping a prime factor would produce a different key that verifies nothing,
    // so the refusal names the structure rather than failing as a parse error.
    let err = pem::jwk_from_pem(MULTI3_PKCS1).unwrap_err().to_string();
    assert!(err.contains("multi-prime"), "{err}");
    assert!(err.contains("7518"), "{err}");
}

#[test]
fn the_modulus_floor_applies_through_this_door_too() {
    // PKCS#1 must not be an easier way in than PKCS#8 for a weak key.
    let err = pem::jwk_from_pem(RSA1024_PKCS1).unwrap_err().to_string();
    assert!(err.contains("1024") && err.contains("minimum"), "{err}");
    assert!(pem::jwk_from_pem(RSA_PKCS1).is_ok(), "2048 is accepted");
}

#[test]
fn rsa_work_is_bounded_before_private_key_validation() {
    let oversized = vec![0u8; jose_rs::MAX_KEY_DER_BYTES + 1];
    let err = jwk::jwk_from_pkcs1_der(&oversized).unwrap_err().to_string();
    assert!(err.contains("MAX_KEY_DER_BYTES"), "{err}");

    let err = jwk::generate_rsa(jose_rs::MAX_RSA_BITS + 1)
        .unwrap_err()
        .to_string();
    assert!(err.contains("maximum"), "{err}");
}

#[test]
fn lines_wrapped_past_rfc_7468_are_refused_with_the_rule_named() {
    // RFC 7468 §3 caps a base64 line at 64 characters. Generic base64 writers emit 76, and
    // a decoder that only says "invalid base64" leaves the caller hunting for a corrupt
    // character rather than a wrapping width.
    let err = pem::jwk_from_pem(RSA_PKCS1_WRAPPED76)
        .unwrap_err()
        .to_string();
    assert!(err.contains("64 characters"), "{err}");
    assert!(err.contains("7468"), "{err}");
    assert!(
        pem::jwk_from_pem(RSA_PKCS1).is_ok(),
        "the same body at 64 imports"
    );
}

#[test]
fn the_two_doors_do_not_open_into_each_other() {
    // Format-explicit entry points refuse the other structure rather than sniffing it.
    assert!(jwk::jwk_from_pkcs1_der(&der(RSA_PKCS1)).is_ok());
    assert!(
        jwk::jwk_from_pkcs1_der(&der(RSA_PKCS8)).is_err(),
        "PKCS#8 is not PKCS#1"
    );
    assert!(
        jwk::jwk_from_pkcs8_der(&der(RSA_PKCS1)).is_err(),
        "PKCS#1 is not PKCS#8, and reading it as such would reinterpret the bytes"
    );
    assert!(jwk::jwk_from_pkcs1_public_der(&der(RSA_PUB_PKCS1)).is_ok());
    assert!(jwk::jwk_from_pkcs1_public_der(&der(RSA_PKCS1)).is_err());
    assert!(jwk::jwk_from_pkcs1_public_der(&der(EC_PKCS8)).is_err());
    // Trailing bytes after the DER are refused rather than ignored.
    let mut extended = der(RSA_PKCS1);
    extended.push(0x00);
    assert!(jwk::jwk_from_pkcs1_der(&extended).is_err());
}

/// Strip PEM armor to DER for the DER-level entry points.
fn der(text: &str) -> Vec<u8> {
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

const RSA_PKCS1: &str = r#"
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA1LJaNB27bcKlMjh0omip36nRGS39+6luu1Y7j9rRbNRTFrjJ
dPOEHTxtVMLib+pHFZzk57YZIeI1TkZlCWUK4urJx6VGmdT/ZWIS/Nba+xU5a9wd
1OrGfHADjgfYSvEnmbLSKHC9BkLkxP3HsO/EuIzr/FMbKDXxZxZ4nYFMWKXayYNl
/+4izk8OwwCKHbfS4Yzb9zveqwcp/MPQ7XOZKE4dPDGMWCcpl5IkA/Jar72r5+e3
vDk2H3UySayDAoOtwIAw4yQ9cdIaADgL6Q36fy+X92BzP5genb7u8x03iLbPf660
oWd0Yqbste/zwEuqOs7KoNVcfgeC7TRo1e4bKwIDAQABAoIBAERour9xYqOaS5Sb
+NN1k1F3JmQRWVOUeqNxSEXr7Jiyr6iqtUzSt8bJdSaiab7yHHvUkwD9nha6UUfE
N2HuqDI0rsJyI4N9sMkUYqQEnLjN6kKJMOUWv9EtG8+WMVhlOMXj8FkGbZ1ybW74
ar47V8u9s3bb6eukceiknxWVjQ8jblimlq7w5FBwUYfgz+h4ijfpE1aatqllO0M4
37A1qM4xRjFDW8tHnXznq/Io889kC4y9ftsTeh6oaRorf27TOZGHy01itxOmhk8Z
T1j72bImFRd4Y+wqU1Ww2+874v5l3o52+Y3rMqp8fMiScHq9TL8+PDi4ea+GLstS
TpyvWFECgYEA/dt7KLnKcgijlX00RcopF6s2jNBrviGpTG+OIz2jSeKK+TTj6gbo
4ffMe/fz251WwNsXd/G4ZqbW4wHIccRisCMqQEdMZa3E3MKroQQV2yqgaAYkH0ys
ad71AW/W8EwXeUzEDCCZU+WaGKIJuPfDwPwlU8Dm53Sdd8cQFc+JnzsCgYEA1n3v
FTT+5/MElq332JV/93bu6LfFGipIvkQ1xUic3nb6rnthE99E10gq76A7apv9QbhN
KP5s5vt+TeOk6vOP7++mj5kIBdb9oJFDWOwVdnP5qpOcBr+AZGMdif6x6Udu5Yl/
ngqcwASUy5yk5QGtGXjsD/OqMmis/UqZpYU/lNECgYEAiZ8YGI8IcmO+k0dKNF+R
gXRfYV2IW44SIw8DJpW+1UpMfyeuO2w9imt1XuugNzoIEwtzoKHZj0T5kB2iVhLa
UZTuzeQZRbI73FZpBySY2LU2Os7BfHprqgWmG35PLvyBaVA1pEFz/iimLp6B2NXx
OMk5TztvsqDk0U+Ip9pYSIsCgYATSJcqDO2t5MdQ1KsnqakrkmHAQmVSCOMpV/CN
oA2aYo//B9CefMAvqqlRidJNr2CBfBRTzyvzSED+t6yoAuW56I3M8zEpdT6wJN8t
K2xyjdKwZzzrzmO4osCRG3jbRDTQJiB3EPUuvjqyY47fl9r8I0b12C5BAfArhX1y
yBwDQQKBgGqRhiBn46cadwesKt2V0q5YZyjCDZB+cpXES1ORXbii0zGUXpUO8lSp
K97O78PjhUMtcClrxxfjIVq5U2+1qCRKxq0aRMqyKGtVW7V+43vVyHHbhoZEC+8K
sk1N86lYvP/PPCC/towOEnu7RdTR+OFgwlZZktva3aiWjNew188J
-----END RSA PRIVATE KEY-----
"#;

const RSA_PUB_PKCS1: &str = r#"
-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEA1LJaNB27bcKlMjh0omip36nRGS39+6luu1Y7j9rRbNRTFrjJdPOE
HTxtVMLib+pHFZzk57YZIeI1TkZlCWUK4urJx6VGmdT/ZWIS/Nba+xU5a9wd1OrG
fHADjgfYSvEnmbLSKHC9BkLkxP3HsO/EuIzr/FMbKDXxZxZ4nYFMWKXayYNl/+4i
zk8OwwCKHbfS4Yzb9zveqwcp/MPQ7XOZKE4dPDGMWCcpl5IkA/Jar72r5+e3vDk2
H3UySayDAoOtwIAw4yQ9cdIaADgL6Q36fy+X92BzP5genb7u8x03iLbPf660oWd0
Yqbste/zwEuqOs7KoNVcfgeC7TRo1e4bKwIDAQAB
-----END RSA PUBLIC KEY-----
"#;

const RSA_PKCS1_REPEMMED: &str = r#"
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA1LJaNB27bcKlMjh0omip36nRGS39+6luu1Y7j9rRbNRTFrjJ
dPOEHTxtVMLib+pHFZzk57YZIeI1TkZlCWUK4urJx6VGmdT/ZWIS/Nba+xU5a9wd
1OrGfHADjgfYSvEnmbLSKHC9BkLkxP3HsO/EuIzr/FMbKDXxZxZ4nYFMWKXayYNl
/+4izk8OwwCKHbfS4Yzb9zveqwcp/MPQ7XOZKE4dPDGMWCcpl5IkA/Jar72r5+e3
vDk2H3UySayDAoOtwIAw4yQ9cdIaADgL6Q36fy+X92BzP5genb7u8x03iLbPf660
oWd0Yqbste/zwEuqOs7KoNVcfgeC7TRo1e4bKwIDAQABAoIBAERour9xYqOaS5Sb
+NN1k1F3JmQRWVOUeqNxSEXr7Jiyr6iqtUzSt8bJdSaiab7yHHvUkwD9nha6UUfE
N2HuqDI0rsJyI4N9sMkUYqQEnLjN6kKJMOUWv9EtG8+WMVhlOMXj8FkGbZ1ybW74
ar47V8u9s3bb6eukceiknxWVjQ8jblimlq7w5FBwUYfgz+h4ijfpE1aatqllO0M4
37A1qM4xRjFDW8tHnXznq/Io889kC4y9ftsTeh6oaRorf27TOZGHy01itxOmhk8Z
T1j72bImFRd4Y+wqU1Ww2+874v5l3o52+Y3rMqp8fMiScHq9TL8+PDi4ea+GLstS
TpyvWFECgYEA/dt7KLnKcgijlX00RcopF6s2jNBrviGpTG+OIz2jSeKK+TTj6gbo
4ffMe/fz251WwNsXd/G4ZqbW4wHIccRisCMqQEdMZa3E3MKroQQV2yqgaAYkH0ys
ad71AW/W8EwXeUzEDCCZU+WaGKIJuPfDwPwlU8Dm53Sdd8cQFc+JnzsCgYEA1n3v
FTT+5/MElq332JV/93bu6LfFGipIvkQ1xUic3nb6rnthE99E10gq76A7apv9QbhN
KP5s5vt+TeOk6vOP7++mj5kIBdb9oJFDWOwVdnP5qpOcBr+AZGMdif6x6Udu5Yl/
ngqcwASUy5yk5QGtGXjsD/OqMmis/UqZpYU/lNECgYEAiZ8YGI8IcmO+k0dKNF+R
gXRfYV2IW44SIw8DJpW+1UpMfyeuO2w9imt1XuugNzoIEwtzoKHZj0T5kB2iVhLa
UZTuzeQZRbI73FZpBySY2LU2Os7BfHprqgWmG35PLvyBaVA1pEFz/iimLp6B2NXx
OMk5TztvsqDk0U+Ip9pYSIsCgYATSJcqDO2t5MdQ1KsnqakrkmHAQmVSCOMpV/CN
oA2aYo//B9CefMAvqqlRidJNr2CBfBRTzyvzSED+t6yoAuW56I3M8zEpdT6wJN8t
K2xyjdKwZzzrzmO4osCRG3jbRDTQJiB3EPUuvjqyY47fl9r8I0b12C5BAfArhX1y
yBwDQQKBgGqRhiBn46cadwesKt2V0q5YZyjCDZB+cpXES1ORXbii0zGUXpUO8lSp
K97O78PjhUMtcClrxxfjIVq5U2+1qCRKxq0aRMqyKGtVW7V+43vVyHHbhoZEC+8K
sk1N86lYvP/PPCC/towOEnu7RdTR+OFgwlZZktva3aiWjNew188J
-----END RSA PRIVATE KEY-----
"#;

const RSA_PKCS1_BAD_DP: &str = r#"
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA1LJaNB27bcKlMjh0omip36nRGS39+6luu1Y7j9rRbNRTFrjJ
dPOEHTxtVMLib+pHFZzk57YZIeI1TkZlCWUK4urJx6VGmdT/ZWIS/Nba+xU5a9wd
1OrGfHADjgfYSvEnmbLSKHC9BkLkxP3HsO/EuIzr/FMbKDXxZxZ4nYFMWKXayYNl
/+4izk8OwwCKHbfS4Yzb9zveqwcp/MPQ7XOZKE4dPDGMWCcpl5IkA/Jar72r5+e3
vDk2H3UySayDAoOtwIAw4yQ9cdIaADgL6Q36fy+X92BzP5genb7u8x03iLbPf660
oWd0Yqbste/zwEuqOs7KoNVcfgeC7TRo1e4bKwIDAQABAoIBAERour9xYqOaS5Sb
+NN1k1F3JmQRWVOUeqNxSEXr7Jiyr6iqtUzSt8bJdSaiab7yHHvUkwD9nha6UUfE
N2HuqDI0rsJyI4N9sMkUYqQEnLjN6kKJMOUWv9EtG8+WMVhlOMXj8FkGbZ1ybW74
ar47V8u9s3bb6eukceiknxWVjQ8jblimlq7w5FBwUYfgz+h4ijfpE1aatqllO0M4
37A1qM4xRjFDW8tHnXznq/Io889kC4y9ftsTeh6oaRorf27TOZGHy01itxOmhk8Z
T1j72bImFRd4Y+wqU1Ww2+874v5l3o52+Y3rMqp8fMiScHq9TL8+PDi4ea+GLstS
TpyvWFECgYEA/dt7KLnKcgijlX00RcopF6s2jNBrviGpTG+OIz2jSeKK+TTj6gbo
4ffMe/fz251WwNsXd/G4ZqbW4wHIccRisCMqQEdMZa3E3MKroQQV2yqgaAYkH0ys
ad71AW/W8EwXeUzEDCCZU+WaGKIJuPfDwPwlU8Dm53Sdd8cQFc+JnzsCgYEA1n3v
FTT+5/MElq332JV/93bu6LfFGipIvkQ1xUic3nb6rnthE99E10gq76A7apv9QbhN
KP5s5vt+TeOk6vOP7++mj5kIBdb9oJFDWOwVdnP5qpOcBr+AZGMdif6x6Udu5Yl/
ngqcwASUy5yk5QGtGXjsD/OqMmis/UqZpYU/lNECgYEAiZ8YGI8IcmO+k0dKNF+R
gXRfYV2IW44SIw8DJpW+1UpMfyeuO2w9imt1XuugNzoIEwtzoKHZj0T5kB2iVhLa
U5TuzeQZRbI73FZpBySY2LU2Os7BfHprqgWmG35PLvyBaVA1pEFz/iimLp6B2NXx
OMk5TztvsqDk0U+Ip9pYSIsCgYATSJcqDO2t5MdQ1KsnqakrkmHAQmVSCOMpV/CN
oA2aYo//B9CefMAvqqlRidJNr2CBfBRTzyvzSED+t6yoAuW56I3M8zEpdT6wJN8t
K2xyjdKwZzzrzmO4osCRG3jbRDTQJiB3EPUuvjqyY47fl9r8I0b12C5BAfArhX1y
yBwDQQKBgGqRhiBn46cadwesKt2V0q5YZyjCDZB+cpXES1ORXbii0zGUXpUO8lSp
K97O78PjhUMtcClrxxfjIVq5U2+1qCRKxq0aRMqyKGtVW7V+43vVyHHbhoZEC+8K
sk1N86lYvP/PPCC/towOEnu7RdTR+OFgwlZZktva3aiWjNew188J
-----END RSA PRIVATE KEY-----
"#;

const RSA_PKCS1_BAD_DQ: &str = r#"
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA1LJaNB27bcKlMjh0omip36nRGS39+6luu1Y7j9rRbNRTFrjJ
dPOEHTxtVMLib+pHFZzk57YZIeI1TkZlCWUK4urJx6VGmdT/ZWIS/Nba+xU5a9wd
1OrGfHADjgfYSvEnmbLSKHC9BkLkxP3HsO/EuIzr/FMbKDXxZxZ4nYFMWKXayYNl
/+4izk8OwwCKHbfS4Yzb9zveqwcp/MPQ7XOZKE4dPDGMWCcpl5IkA/Jar72r5+e3
vDk2H3UySayDAoOtwIAw4yQ9cdIaADgL6Q36fy+X92BzP5genb7u8x03iLbPf660
oWd0Yqbste/zwEuqOs7KoNVcfgeC7TRo1e4bKwIDAQABAoIBAERour9xYqOaS5Sb
+NN1k1F3JmQRWVOUeqNxSEXr7Jiyr6iqtUzSt8bJdSaiab7yHHvUkwD9nha6UUfE
N2HuqDI0rsJyI4N9sMkUYqQEnLjN6kKJMOUWv9EtG8+WMVhlOMXj8FkGbZ1ybW74
ar47V8u9s3bb6eukceiknxWVjQ8jblimlq7w5FBwUYfgz+h4ijfpE1aatqllO0M4
37A1qM4xRjFDW8tHnXznq/Io889kC4y9ftsTeh6oaRorf27TOZGHy01itxOmhk8Z
T1j72bImFRd4Y+wqU1Ww2+874v5l3o52+Y3rMqp8fMiScHq9TL8+PDi4ea+GLstS
TpyvWFECgYEA/dt7KLnKcgijlX00RcopF6s2jNBrviGpTG+OIz2jSeKK+TTj6gbo
4ffMe/fz251WwNsXd/G4ZqbW4wHIccRisCMqQEdMZa3E3MKroQQV2yqgaAYkH0ys
ad71AW/W8EwXeUzEDCCZU+WaGKIJuPfDwPwlU8Dm53Sdd8cQFc+JnzsCgYEA1n3v
FTT+5/MElq332JV/93bu6LfFGipIvkQ1xUic3nb6rnthE99E10gq76A7apv9QbhN
KP5s5vt+TeOk6vOP7++mj5kIBdb9oJFDWOwVdnP5qpOcBr+AZGMdif6x6Udu5Yl/
ngqcwASUy5yk5QGtGXjsD/OqMmis/UqZpYU/lNECgYEAiZ8YGI8IcmO+k0dKNF+R
gXRfYV2IW44SIw8DJpW+1UpMfyeuO2w9imt1XuugNzoIEwtzoKHZj0T5kB2iVhLa
UZTuzeQZRbI73FZpBySY2LU2Os7BfHprqgWmG35PLvyBaVA1pEFz/iimLp6B2NXx
OMk5TztvsqDk0U+Ip9pYSIsCgYATSJcqDO2t5MdQ1KsnqakrkmHAQmVSCOMpV/CN
oA2aYo//B9CefMAvqqlRidJNr2CBfBRTzyvzSED+t6yoAuW56o3M8zEpdT6wJN8t
K2xyjdKwZzzrzmO4osCRG3jbRDTQJiB3EPUuvjqyY47fl9r8I0b12C5BAfArhX1y
yBwDQQKBgGqRhiBn46cadwesKt2V0q5YZyjCDZB+cpXES1ORXbii0zGUXpUO8lSp
K97O78PjhUMtcClrxxfjIVq5U2+1qCRKxq0aRMqyKGtVW7V+43vVyHHbhoZEC+8K
sk1N86lYvP/PPCC/towOEnu7RdTR+OFgwlZZktva3aiWjNew188J
-----END RSA PRIVATE KEY-----
"#;

const RSA_PKCS1_BAD_QI: &str = r#"
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA1LJaNB27bcKlMjh0omip36nRGS39+6luu1Y7j9rRbNRTFrjJ
dPOEHTxtVMLib+pHFZzk57YZIeI1TkZlCWUK4urJx6VGmdT/ZWIS/Nba+xU5a9wd
1OrGfHADjgfYSvEnmbLSKHC9BkLkxP3HsO/EuIzr/FMbKDXxZxZ4nYFMWKXayYNl
/+4izk8OwwCKHbfS4Yzb9zveqwcp/MPQ7XOZKE4dPDGMWCcpl5IkA/Jar72r5+e3
vDk2H3UySayDAoOtwIAw4yQ9cdIaADgL6Q36fy+X92BzP5genb7u8x03iLbPf660
oWd0Yqbste/zwEuqOs7KoNVcfgeC7TRo1e4bKwIDAQABAoIBAERour9xYqOaS5Sb
+NN1k1F3JmQRWVOUeqNxSEXr7Jiyr6iqtUzSt8bJdSaiab7yHHvUkwD9nha6UUfE
N2HuqDI0rsJyI4N9sMkUYqQEnLjN6kKJMOUWv9EtG8+WMVhlOMXj8FkGbZ1ybW74
ar47V8u9s3bb6eukceiknxWVjQ8jblimlq7w5FBwUYfgz+h4ijfpE1aatqllO0M4
37A1qM4xRjFDW8tHnXznq/Io889kC4y9ftsTeh6oaRorf27TOZGHy01itxOmhk8Z
T1j72bImFRd4Y+wqU1Ww2+874v5l3o52+Y3rMqp8fMiScHq9TL8+PDi4ea+GLstS
TpyvWFECgYEA/dt7KLnKcgijlX00RcopF6s2jNBrviGpTG+OIz2jSeKK+TTj6gbo
4ffMe/fz251WwNsXd/G4ZqbW4wHIccRisCMqQEdMZa3E3MKroQQV2yqgaAYkH0ys
ad71AW/W8EwXeUzEDCCZU+WaGKIJuPfDwPwlU8Dm53Sdd8cQFc+JnzsCgYEA1n3v
FTT+5/MElq332JV/93bu6LfFGipIvkQ1xUic3nb6rnthE99E10gq76A7apv9QbhN
KP5s5vt+TeOk6vOP7++mj5kIBdb9oJFDWOwVdnP5qpOcBr+AZGMdif6x6Udu5Yl/
ngqcwASUy5yk5QGtGXjsD/OqMmis/UqZpYU/lNECgYEAiZ8YGI8IcmO+k0dKNF+R
gXRfYV2IW44SIw8DJpW+1UpMfyeuO2w9imt1XuugNzoIEwtzoKHZj0T5kB2iVhLa
UZTuzeQZRbI73FZpBySY2LU2Os7BfHprqgWmG35PLvyBaVA1pEFz/iimLp6B2NXx
OMk5TztvsqDk0U+Ip9pYSIsCgYATSJcqDO2t5MdQ1KsnqakrkmHAQmVSCOMpV/CN
oA2aYo//B9CefMAvqqlRidJNr2CBfBRTzyvzSED+t6yoAuW56I3M8zEpdT6wJN8t
K2xyjdKwZzzrzmO4osCRG3jbRDTQJiB3EPUuvjqyY47fl9r8I0b12C5BAfArhX1y
yBwDQQKBgGqRhiBn46cadwesKt2V0q5YZyjCDZB+cpXES1ORXbii0zGUXpUO8lSp
K97O78PjhUMtcClrxxfjIVq5U2+1qCRIxq0aRMqyKGtVW7V+43vVyHHbhoZEC+8K
sk1N86lYvP/PPCC/towOEnu7RdTR+OFgwlZZktva3aiWjNew188J
-----END RSA PRIVATE KEY-----
"#;

const RSA_PKCS1_BAD_D: &str = r#"
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA1LJaNB27bcKlMjh0omip36nRGS39+6luu1Y7j9rRbNRTFrjJ
dPOEHTxtVMLib+pHFZzk57YZIeI1TkZlCWUK4urJx6VGmdT/ZWIS/Nba+xU5a9wd
1OrGfHADjgfYSvEnmbLSKHC9BkLkxP3HsO/EuIzr/FMbKDXxZxZ4nYFMWKXayYNl
/+4izk8OwwCKHbfS4Yzb9zveqwcp/MPQ7XOZKE4dPDGMWCcpl5IkA/Jar72r5+e3
vDk2H3UySayDAoOtwIAw4yQ9cdIaADgL6Q36fy+X92BzP5genb7u8x03iLbPf660
oWd0Yqbste/zwEuqOs7KoNVcfgeC7TRo1e4bKwIDAQABAoIBAERour9xYqOaS5Sb
+NN1k1F3JmQRWVOUeqNxSEXr7Jiyr6iqtUzSt8bJdSaiab7yHHvUkwD9nha6UUfE
N2HuqDI0rsJyI4N9sMkUYqQEnLjN6kKJMOUWv9EtG8+WMVhlOMXj8FkGbZ1ybW74
ar47V8u9s3bb6eukceiknxWVjQ8jbFimlq7w5FBwUYfgz+h4ijfpE1aatqllO0M4
37A1qM4xRjFDW8tHnXznq/Io889kC4y9ftsTeh6oaRorf27TOZGHy01itxOmhk8Z
T1j72bImFRd4Y+wqU1Ww2+874v5l3o52+Y3rMqp8fMiScHq9TL8+PDi4ea+GLstS
TpyvWFECgYEA/dt7KLnKcgijlX00RcopF6s2jNBrviGpTG+OIz2jSeKK+TTj6gbo
4ffMe/fz251WwNsXd/G4ZqbW4wHIccRisCMqQEdMZa3E3MKroQQV2yqgaAYkH0ys
ad71AW/W8EwXeUzEDCCZU+WaGKIJuPfDwPwlU8Dm53Sdd8cQFc+JnzsCgYEA1n3v
FTT+5/MElq332JV/93bu6LfFGipIvkQ1xUic3nb6rnthE99E10gq76A7apv9QbhN
KP5s5vt+TeOk6vOP7++mj5kIBdb9oJFDWOwVdnP5qpOcBr+AZGMdif6x6Udu5Yl/
ngqcwASUy5yk5QGtGXjsD/OqMmis/UqZpYU/lNECgYEAiZ8YGI8IcmO+k0dKNF+R
gXRfYV2IW44SIw8DJpW+1UpMfyeuO2w9imt1XuugNzoIEwtzoKHZj0T5kB2iVhLa
UZTuzeQZRbI73FZpBySY2LU2Os7BfHprqgWmG35PLvyBaVA1pEFz/iimLp6B2NXx
OMk5TztvsqDk0U+Ip9pYSIsCgYATSJcqDO2t5MdQ1KsnqakrkmHAQmVSCOMpV/CN
oA2aYo//B9CefMAvqqlRidJNr2CBfBRTzyvzSED+t6yoAuW56I3M8zEpdT6wJN8t
K2xyjdKwZzzrzmO4osCRG3jbRDTQJiB3EPUuvjqyY47fl9r8I0b12C5BAfArhX1y
yBwDQQKBgGqRhiBn46cadwesKt2V0q5YZyjCDZB+cpXES1ORXbii0zGUXpUO8lSp
K97O78PjhUMtcClrxxfjIVq5U2+1qCRKxq0aRMqyKGtVW7V+43vVyHHbhoZEC+8K
sk1N86lYvP/PPCC/towOEnu7RdTR+OFgwlZZktva3aiWjNew188J
-----END RSA PRIVATE KEY-----
"#;

const RSA_PKCS1_BAD_Q: &str = r#"
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA1LJaNB27bcKlMjh0omip36nRGS39+6luu1Y7j9rRbNRTFrjJ
dPOEHTxtVMLib+pHFZzk57YZIeI1TkZlCWUK4urJx6VGmdT/ZWIS/Nba+xU5a9wd
1OrGfHADjgfYSvEnmbLSKHC9BkLkxP3HsO/EuIzr/FMbKDXxZxZ4nYFMWKXayYNl
/+4izk8OwwCKHbfS4Yzb9zveqwcp/MPQ7XOZKE4dPDGMWCcpl5IkA/Jar72r5+e3
vDk2H3UySayDAoOtwIAw4yQ9cdIaADgL6Q36fy+X92BzP5genb7u8x03iLbPf660
oWd0Yqbste/zwEuqOs7KoNVcfgeC7TRo1e4bKwIDAQABAoIBAERour9xYqOaS5Sb
+NN1k1F3JmQRWVOUeqNxSEXr7Jiyr6iqtUzSt8bJdSaiab7yHHvUkwD9nha6UUfE
N2HuqDI0rsJyI4N9sMkUYqQEnLjN6kKJMOUWv9EtG8+WMVhlOMXj8FkGbZ1ybW74
ar47V8u9s3bb6eukceiknxWVjQ8jblimlq7w5FBwUYfgz+h4ijfpE1aatqllO0M4
37A1qM4xRjFDW8tHnXznq/Io889kC4y9ftsTeh6oaRorf27TOZGHy01itxOmhk8Z
T1j72bImFRd4Y+wqU1Ww2+874v5l3o52+Y3rMqp8fMiScHq9TL8+PDi4ea+GLstS
TpyvWFECgYEA/dt7KLnKcgijlX00RcopF6s2jNBrviGpTG+OIz2jSeKK+TTj6gbo
4ffMe/fz251WwNsXd/G4ZqbW4wHIccRisiMqQEdMZa3E3MKroQQV2yqgaAYkH0ys
ad71AW/W8EwXeUzEDCCZU+WaGKIJuPfDwPwlU8Dm53Sdd8cQFc+JnzsCgYEA1n3v
FTT+5/MElq332JV/93bu6LfFGipIvkQ1xUic3nb6rnthE99E10gq76A7apv9QbhN
KP5s5vt+TeOk6vOP7++mj5kIBdb9oJFDWOwVdnP5qpOcBr+AZGMdif6x6Udu5Yl/
ngqcwASUy5yk5QGtGXjsD/OqMmis/UqZpYU/lNECgYEAiZ8YGI8IcmO+k0dKNF+R
gXRfYV2IW44SIw8DJpW+1UpMfyeuO2w9imt1XuugNzoIEwtzoKHZj0T5kB2iVhLa
UZTuzeQZRbI73FZpBySY2LU2Os7BfHprqgWmG35PLvyBaVA1pEFz/iimLp6B2NXx
OMk5TztvsqDk0U+Ip9pYSIsCgYATSJcqDO2t5MdQ1KsnqakrkmHAQmVSCOMpV/CN
oA2aYo//B9CefMAvqqlRidJNr2CBfBRTzyvzSED+t6yoAuW56I3M8zEpdT6wJN8t
K2xyjdKwZzzrzmO4osCRG3jbRDTQJiB3EPUuvjqyY47fl9r8I0b12C5BAfArhX1y
yBwDQQKBgGqRhiBn46cadwesKt2V0q5YZyjCDZB+cpXES1ORXbii0zGUXpUO8lSp
K97O78PjhUMtcClrxxfjIVq5U2+1qCRKxq0aRMqyKGtVW7V+43vVyHHbhoZEC+8K
sk1N86lYvP/PPCC/towOEnu7RdTR+OFgwlZZktva3aiWjNew188J
-----END RSA PRIVATE KEY-----
"#;

const RSA_PKCS1_WRAPPED76: &str = r#"
-----BEGIN RSA PRIVATE KEY-----
MIIEqAIBAAKCAQEA1LJaNB27bcKlMjh0omip36nRGS39+6luu1Y7j9rRbNRTFrjJdPOEHTxtVMLi
b+pHFZzk57YZIeI1TkZlCWUK4urJx6VGmdT/ZWIS/Nba+xU5a9wd1OrGfHADjgfYSvEnmbLSKHC9
BkLkxP3HsO/EuIzr/FMbKDXxZxZ4nYFMWKXayYNl/+4izk8OwwCKHbfS4Yzb9zveqwcp/MPQ7XOZ
KE4dPDGMWCcpl5IkA/Jar72r5+e3vDk2H3UySayDAoOtwIAw4yQ9cdIaADgL6Q36fy+X92BzP5ge
nb7u8x03iLbPf660oWd0Yqbste/zwEuqOs7KoNVcfgeC7TRo1e4bKwIDAQABAoIBAERour9xYqOa
S5Sb+NN1k1F3JmQRWVOUeqNxSEXr7Jiyr6iqtUzSt8bJdSaiab7yHHvUkwD9nha6UUfEN2HuqDI0
rsJyI4N9sMkUYqQEnLjN6kKJMOUWv9EtG8+WMVhlOMXj8FkGbZ1ybW74ar47V8u9s3bb6eukceik
nxWVjQ8jblimlq7w5FBwUYfgz+h4ijfpE1aatqllO0M437A1qM4xRjFDW8tHnXznq/Io889kC4y9
ftsTeh6oaRorf27TOZGHy01itxOmhk8ZT1j72bImFRd4Y+wqU1Ww2+874v5l3o52+Y3rMqp8fMiS
cHq9TL8+PDi4ea+GLstSTpyvWFECggCBAP3beyi5ynIIo5V9NEXKKRerNozQa74hqUxvjiM9o0ni
ivk04+oG6OH3zHv389udVsDbF3fxuGam1uMByHHEYrAjKkBHTGWtxNzCq6EEFdsqoGgGJB9MrGne
9QFv1vBMF3lMxAwgmVPlmhiiCbj3w8D8JVPA5ud0nXfHEBXPiZ87AoIAgQDWfe8VNP7n8wSWrffY
lX/3du7ot8UaKki+RDXFSJzedvque2ET30TXSCrvoDtqm/1BuE0o/mzm+35N46Tq84/v76aPmQgF
1v2gkUNY7BV2c/mqk5wGv4BkYx2J/rHpR27liX+eCpzABJTLnKTlAa0ZeOwP86oyaKz9SpmlhT+U
0QKCAIEAiZ8YGI8IcmO+k0dKNF+RgXRfYV2IW44SIw8DJpW+1UpMfyeuO2w9imt1XuugNzoIEwtz
oKHZj0T5kB2iVhLaUZTuzeQZRbI73FZpBySY2LU2Os7BfHprqgWmG35PLvyBaVA1pEFz/iimLp6B
2NXxOMk5TztvsqDk0U+Ip9pYSIsCggCAE0iXKgztreTHUNSrJ6mpK5JhwEJlUgjjKVfwjaANmmKP
/wfQnnzAL6qpUYnSTa9ggXwUU88r80hA/resqALlueiNzPMxKXU+sCTfLStsco3SsGc8685juKLA
kRt420Q00CYgdxD1Lr46smOO35fa/CNG9dguQQHwK4V9csgcA0ECggCAapGGIGfjpxp3B6wq3ZXS
rlhnKMINkH5ylcRLU5FduKLTMZRelQ7yVKkr3s7vw+OFQy1wKWvHF+MhWrlTb7WoJErGrRpEyrIo
a1VbtX7je9XIcduGhkQL7wqyTU3zqVi8/888IL+2jA4Se7tF1NH44WDCVlmS29rdqJaM17DXzwk=
-----END RSA PRIVATE KEY-----
"#;

const MULTI3_PKCS1: &str = r#"
-----BEGIN RSA PRIVATE KEY-----
MIIE2QIBAQKCAQEAsq9sswsa9BLvH+rusAH1tSB9DzYoSGMyOSEnI0SU//Zx/HEa
nmbtnb2c3Fa/m2rulyHglukMWmi70zjp2sC2GKziwlSqAzmtTX9W43hLll+edW7d
DoJI2ltijPjBVgBFZH5WhCkzfV4d1230RcxsNKid9p7H/w02hi1s5mWO7bB14OVU
YBkpnX1WFeDixSf3lBnPfQJ90OHs28pdeA5I+W7M2Ch7U10G4wl7LB8QuTPA3X6l
4z6ve57nqVc9uLH+S0jgeM82kPxHiU5tZ08bYoQJuMEuH9hqiVc3jjZ2fQyJCHG9
ueP42TKw/oKUk2tgWhO+NRCWF8tz47N/CSEGNQIDAQABAoIBADiO3lEtyrJG6/mm
WzbK6AMU7YDLG6UOAO+kVscLBj6euyW0h0BsQ/oR8nyr2KpRBoQ/7N7XlVlonUsW
UK81IG5fCseIFOhAcWJ+U/pcMVC/o2B4XvAAYYBaUg4A19PVL89GNxAt/dGSh4Xo
PEDHX6KVVtTdvQ45BNxIDfR3NCbWFfelJ//gp+ONzm4wQNRmZAcO0r5lUPH4Knc+
OnZwK1WJycJyFEFVd5D+KhC6CmQgWgk/+MJU24Ae6i0x9y+dBvLpgXXreLc/Dvzo
ug3BAoAZGHiezVuCaKVwaNyMnkzzezyYIxZpUDeRfFP15qqEM1RpnqDzhIVv8SZM
Zci3PgECVgdyW5snjOm+R+NhbVRDeaYTLiT23jC3vrxczj1RgGKB79m+TJTaGQ6Y
JnkyOyhpz3VElhqODBzdinCJXwNHL52RsAhcaHOocShTFOXs/0Fv95UuD03dAlYH
JjqBBnGxMXrGcVNl6+EYBfZ0qntckEq/hGw65dsvKEolKz/lffFWGC1AlL/1GKAb
Ui6lTgHHr2WWNiwZ2SlA+kLDVrBcJX0yycxN1vO4JfhTsfgAtQJWA0DxS7KVPFA6
otwf4/Bzh5/byqTe4lR2j2DRcDNbMC9r+CzQ0z0UM69BKDVNadQJpEhqeYHVQwt9
gLxU+l6xLFzKmGyf6uEPSDo86FWMFjBw8gqk/zUCVgPAD+xivvzeIbM6+y55v4fk
iNXGIBP8NNml00hKDuH71nkM6OWvXQt2fzZjURZ2pnXudD2OX+ypmzZikFu2yKcn
ICJrtPOBTt13cc5bNVmhwVPWBWwJAlYEv+Re4WfV9ppSBIQ3NqsOK8jKlCVac2fI
blEv5G6V0p9r3iEccTni/y1MPdHSJX08A2uEKG08Sy0QG7pKVwtsp9NTGsuHBWI2
CccqRcKXV6Lgm+5pGzCCAQwwggEIAlYDWzWGnM5SLBdzBdeGxXw4qEPjGpRyD1uN
5V67C5z84ZhCAmSUAmNzneCzg6vQq87sbJPtC8uPxQmI6R+BdnNuRLHl9PWKnmn4
+kzOWHdDRvKpMxGX9QJWANVN7oNTPVcw4x9aKF0yv6YWZHUe0Uo6wnllES6K5MTk
1c5eRdhp9DQHqslPiFh+4Hb8Kmc5PBIAkfq+FZfghEmNmLc9lhJJ4MPS+Y9A3HTq
nVLOVVkCVgKfWx5lTn0jsJc4daviLbSFj1tR4aQKdjB/ue0yt9i8b54vafOoDeLc
S3d5NKkPj5JbTm4dB+FUy0V7K8lKB8oz0M8vLxNgLzdrZhYrtsTx1nN07++B
-----END RSA PRIVATE KEY-----
"#;

const RSA1024_PKCS1: &str = r#"
-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQCsQ2kXI5K4HpdtfiI12TuyONtEtI7gxaf9MtJlGoM66pMikB4n
gEyyAJwIJyCGzWMFHgTWDBMmmbGiqWr+ltDOpDOHHlM809+ihEHMVUL6/wcEAQex
Sc63kvLB6cOsIhWs02zLCbH3ecv66qzFbbqItyzshoRyKNzFaRrAFrtA6wIDAQAB
AoGAW9pB8f2c4SImulJ0aWQgyaI5gMQKH14legQcXZ6qdMLZm6de/M8TliJvEIXU
eSyQ7QyZpYygtYdkSYiurXu7cGPVphXVwFe7q1ptjCAIOkpdaWT86sokv+OcS0Iu
cPVzOFNvPMY73D2rZOUgW1sLZ994csFXej6HaN8fjDf25/ECQQDZcjuUPdn4b00a
ilxO13N9JDNdixkFuPOFGZxJDZNVIwPrIDgcvOk1mwUD5ScLcAJBHSuaLjQ7wbSH
MWfFSEv5AkEAys5ZqPSlV7LqzMbW9oNdd7SPyai93mvFPP0HmmnP9CHcjovwx8CQ
GtydUGp5l0IlJ0yuPJMbj5KN2W63STqFAwJAG7pSWJvugJyIw3qjPLaClpGYLzR+
k1k7TFywriwZ/oBBjqkEHr4EKv7Ci/WbnfzBfNYgaj+8D2arA5ZMOj722QJAWjb6
uWbCmkVzn04gV55OGK7Qe5M9itCD98JS/IRvRhk+BIcJv8HQGLLko94JYpjA8D9z
Dm0eCHrX8M4IaGHIwwJBANhi2RjshKx2iFt3RZ1mOAKj9TqLKLFftU4K/OIqhx3V
6T1pC0oCATPbjZy1JEGDyE29k+aV8vDuLdFnFr+KnFQ=
-----END RSA PRIVATE KEY-----
"#;

const RSA_PKCS8: &str = r#"
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDUslo0HbttwqUy
OHSiaKnfqdEZLf37qW67VjuP2tFs1FMWuMl084QdPG1UwuJv6kcVnOTnthkh4jVO
RmUJZQri6snHpUaZ1P9lYhL81tr7FTlr3B3U6sZ8cAOOB9hK8SeZstIocL0GQuTE
/cew78S4jOv8UxsoNfFnFnidgUxYpdrJg2X/7iLOTw7DAIodt9LhjNv3O96rByn8
w9Dtc5koTh08MYxYJymXkiQD8lqvvavn57e8OTYfdTJJrIMCg63AgDDjJD1x0hoA
OAvpDfp/L5f3YHM/mB6dvu7zHTeIts9/rrShZ3Ripuy17/PAS6o6zsqg1Vx+B4Lt
NGjV7hsrAgMBAAECggEARGi6v3Fio5pLlJv403WTUXcmZBFZU5R6o3FIRevsmLKv
qKq1TNK3xsl1JqJpvvIce9STAP2eFrpRR8Q3Ye6oMjSuwnIjg32wyRRipAScuM3q
Qokw5Ra/0S0bz5YxWGU4xePwWQZtnXJtbvhqvjtXy72zdtvp66Rx6KSfFZWNDyNu
WKaWrvDkUHBRh+DP6HiKN+kTVpq2qWU7QzjfsDWozjFGMUNby0edfOer8ijzz2QL
jL1+2xN6HqhpGit/btM5kYfLTWK3E6aGTxlPWPvZsiYVF3hj7CpTVbDb7zvi/mXe
jnb5jesyqnx8yJJwer1Mvz48OLh5r4Yuy1JOnK9YUQKBgQD923soucpyCKOVfTRF
yikXqzaM0Gu+IalMb44jPaNJ4or5NOPqBujh98x79/PbnVbA2xd38bhmptbjAchx
xGKwIypAR0xlrcTcwquhBBXbKqBoBiQfTKxp3vUBb9bwTBd5TMQMIJlT5ZoYogm4
98PA/CVTwObndJ13xxAVz4mfOwKBgQDWfe8VNP7n8wSWrffYlX/3du7ot8UaKki+
RDXFSJzedvque2ET30TXSCrvoDtqm/1BuE0o/mzm+35N46Tq84/v76aPmQgF1v2g
kUNY7BV2c/mqk5wGv4BkYx2J/rHpR27liX+eCpzABJTLnKTlAa0ZeOwP86oyaKz9
SpmlhT+U0QKBgQCJnxgYjwhyY76TR0o0X5GBdF9hXYhbjhIjDwMmlb7VSkx/J647
bD2Ka3Ve66A3OggTC3OgodmPRPmQHaJWEtpRlO7N5BlFsjvcVmkHJJjYtTY6zsF8
emuqBaYbfk8u/IFpUDWkQXP+KKYunoHY1fE4yTlPO2+yoOTRT4in2lhIiwKBgBNI
lyoM7a3kx1DUqyepqSuSYcBCZVII4ylX8I2gDZpij/8H0J58wC+qqVGJ0k2vYIF8
FFPPK/NIQP63rKgC5bnojczzMSl1PrAk3y0rbHKN0rBnPOvOY7iiwJEbeNtENNAm
IHcQ9S6+OrJjjt+X2vwjRvXYLkEB8CuFfXLIHANBAoGAapGGIGfjpxp3B6wq3ZXS
rlhnKMINkH5ylcRLU5FduKLTMZRelQ7yVKkr3s7vw+OFQy1wKWvHF+MhWrlTb7Wo
JErGrRpEyrIoa1VbtX7je9XIcduGhkQL7wqyTU3zqVi8/888IL+2jA4Se7tF1NH4
4WDCVlmS29rdqJaM17DXzwk=
-----END PRIVATE KEY-----
"#;

const RSA_SPKI: &str = r#"
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1LJaNB27bcKlMjh0omip
36nRGS39+6luu1Y7j9rRbNRTFrjJdPOEHTxtVMLib+pHFZzk57YZIeI1TkZlCWUK
4urJx6VGmdT/ZWIS/Nba+xU5a9wd1OrGfHADjgfYSvEnmbLSKHC9BkLkxP3HsO/E
uIzr/FMbKDXxZxZ4nYFMWKXayYNl/+4izk8OwwCKHbfS4Yzb9zveqwcp/MPQ7XOZ
KE4dPDGMWCcpl5IkA/Jar72r5+e3vDk2H3UySayDAoOtwIAw4yQ9cdIaADgL6Q36
fy+X92BzP5genb7u8x03iLbPf660oWd0Yqbste/zwEuqOs7KoNVcfgeC7TRo1e4b
KwIDAQAB
-----END PUBLIC KEY-----
"#;

const EC_PKCS8: &str = r#"
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgEJtrrJW62mBrz2g/
hku0gVfzITFNti4tZT8f1u3ef0qhRANCAASGlJcykvrjZkfeyWLxUx2lOJ0U6FVr
cYRIACqVhVjke4LzkxPDt+JM/p5cAdSVa/U6qHPnr9SJ1VPedyDQ1zeI
-----END PRIVATE KEY-----
"#;

const RSA_PKCS1_BAD_N: &str = r#"
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA1LJaNB27bcKlMjh0omip36nRGS39+6luu1Y7j9rRbNRTFrjJ
dPOEHTxtVMLib+pHFZzk57YZIeI1TkZlCWUK4urJx6VGmdT/ZWIS/Nba+xU5a9wd
1OrGfHADjgfYSvEnmbLSKHC9BkLkxP3HsO/EuIzr/FMbKDXxZxZ4nYFMWKfayYNl
/+4izk8OwwCKHbfS4Yzb9zveqwcp/MPQ7XOZKE4dPDGMWCcpl5IkA/Jar72r5+e3
vDk2H3UySayDAoOtwIAw4yQ9cdIaADgL6Q36fy+X92BzP5genb7u8x03iLbPf660
oWd0Yqbste/zwEuqOs7KoNVcfgeC7TRo1e4bKwIDAQABAoIBAERour9xYqOaS5Sb
+NN1k1F3JmQRWVOUeqNxSEXr7Jiyr6iqtUzSt8bJdSaiab7yHHvUkwD9nha6UUfE
N2HuqDI0rsJyI4N9sMkUYqQEnLjN6kKJMOUWv9EtG8+WMVhlOMXj8FkGbZ1ybW74
ar47V8u9s3bb6eukceiknxWVjQ8jblimlq7w5FBwUYfgz+h4ijfpE1aatqllO0M4
37A1qM4xRjFDW8tHnXznq/Io889kC4y9ftsTeh6oaRorf27TOZGHy01itxOmhk8Z
T1j72bImFRd4Y+wqU1Ww2+874v5l3o52+Y3rMqp8fMiScHq9TL8+PDi4ea+GLstS
TpyvWFECgYEA/dt7KLnKcgijlX00RcopF6s2jNBrviGpTG+OIz2jSeKK+TTj6gbo
4ffMe/fz251WwNsXd/G4ZqbW4wHIccRisCMqQEdMZa3E3MKroQQV2yqgaAYkH0ys
ad71AW/W8EwXeUzEDCCZU+WaGKIJuPfDwPwlU8Dm53Sdd8cQFc+JnzsCgYEA1n3v
FTT+5/MElq332JV/93bu6LfFGipIvkQ1xUic3nb6rnthE99E10gq76A7apv9QbhN
KP5s5vt+TeOk6vOP7++mj5kIBdb9oJFDWOwVdnP5qpOcBr+AZGMdif6x6Udu5Yl/
ngqcwASUy5yk5QGtGXjsD/OqMmis/UqZpYU/lNECgYEAiZ8YGI8IcmO+k0dKNF+R
gXRfYV2IW44SIw8DJpW+1UpMfyeuO2w9imt1XuugNzoIEwtzoKHZj0T5kB2iVhLa
UZTuzeQZRbI73FZpBySY2LU2Os7BfHprqgWmG35PLvyBaVA1pEFz/iimLp6B2NXx
OMk5TztvsqDk0U+Ip9pYSIsCgYATSJcqDO2t5MdQ1KsnqakrkmHAQmVSCOMpV/CN
oA2aYo//B9CefMAvqqlRidJNr2CBfBRTzyvzSED+t6yoAuW56I3M8zEpdT6wJN8t
K2xyjdKwZzzrzmO4osCRG3jbRDTQJiB3EPUuvjqyY47fl9r8I0b12C5BAfArhX1y
yBwDQQKBgGqRhiBn46cadwesKt2V0q5YZyjCDZB+cpXES1ORXbii0zGUXpUO8lSp
K97O78PjhUMtcClrxxfjIVq5U2+1qCRKxq0aRMqyKGtVW7V+43vVyHHbhoZEC+8K
sk1N86lYvP/PPCC/towOEnu7RdTR+OFgwlZZktva3aiWjNew188J
-----END RSA PRIVATE KEY-----
"#;
