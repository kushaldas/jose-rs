//! Public-key extraction from X.509 certificates (RFC 5280 §4.1) — I4.
//!
//! This module answers exactly one question — *which public key does this certificate
//! present?* — and answers nothing else. It does not check the signature, the issuer, the
//! validity period, the key usage extensions, the name constraints or the chain. A certificate
//! is a *claim* about a key, and what comes back from these functions is that claim, not a
//! verified identity:
//!
//! > **Extracting a key from a certificate is not validating the certificate.** If the
//! > certificate's provenance matters, validate it with a path-building validator that has a
//! > trust anchor and a policy; then use the key. Nothing here can tell you that a certificate
//! > was issued to anybody in particular, and a test in this module pins the uncomfortable
//! > consequence: flipping bytes in the certificate's signature leaves the extracted key
//! > unchanged.
//!
//! That narrowness is also why this is separate from `x5c` handling in JWS: binding a
//! certificate to a signature is a different feature with its own rules (RFC 7515 §4.1.6), and
//! the two must not be conflated into one "verify certificate" call that silently does half of
//! each.
//!
//! # What is parsed, and what is refused
//!
//! The walk is positional and short: `Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm,
//! signatureValue }`, and inside `tbsCertificate` the `subjectPublicKeyInfo` is the element
//! after `version`(optional), `serialNumber`, `signature`, `issuer`, `validity` and `subject`.
//! `version` is `DEFAULT v1` and `EXPLICIT [0]`, so its absence shifts every later index by one;
//! the presence test is the tag of the first element, not a guess from the length.
//!
//! The located element is then handed to [`jwk_from_spki_der`](crate::jwk::jwk_from_spki_der),
//! so there is one SPKI parser in this crate, not two: whatever that importer refuses (unknown
//! curves, RSA-PSS parameters, a truncated BIT STRING) is refused here too, with the same
//! message.
//!
//! Structure rules are DER as RFC 5280 Appendix A.1 defines it, which is **stricter than
//! OpenSSL**: definite lengths only (measured, `cryptography` agrees and refuses the same
//! fixtures OpenSSL accepts), low-tag-number form only, minimal length encoding, and no
//! trailing bytes after the outer `SEQUENCE`. Inputs are bounded by
//! [`MAX_CERTIFICATE_DER_BYTES`].

use crate::error::{JoseError, Result};
use crate::jwk::Jwk;

/// The largest certificate this module will look at.
///
/// 128 KiB, generously above any real leaf certificate: the RSA-2048 fixtures here are under
/// 1 KiB, and even an ML-DSA certificate with a large key and many extensions stays well under
/// 16 KiB. The bound exists so a caller can hand this function a buffer from an untrusted
/// message without first inventing their own limit.
pub const MAX_CERTIFICATE_DER_BYTES: usize = 128 * 1024;

/// The RFC 7468 §8.1 label for an X.509 certificate.
const LABEL_CERTIFICATE: &str = "CERTIFICATE";

/// Tags used by the positional walk (RFC 5280 §4.1, ASN.1 universal tags).
mod tag {
    /// Universal, constructed, number 16.
    pub const SEQUENCE: u8 = 0x30;
    /// Context-specific, constructed, number 0: `version [0] EXPLICIT INTEGER`.
    pub const CONTEXT_0: u8 = 0xA0;
}

/// Extract the subject's public key from a DER-encoded X.509 certificate.
///
/// ```
/// // A real (test-only) certificate, so this example cannot drift into fiction.
/// const CERT: &[u8] = include_bytes!("../../tests/fixtures/cert/rsa_cert.der");
///
/// let key = jose_rs::jwk::public_jwk_from_certificate_der(CERT)?;
/// assert_eq!(key.kty, "RSA");
/// assert!(key.d.is_none(), "a certificate presents a public key");
/// // ...and that is all this tells you. Whether to trust the key is a separate decision,
/// // made by validating the certificate with something that has a trust anchor.
/// # Ok::<(), jose_rs::JoseError>(())
/// ```
///
/// The returned [`Jwk`] is **public-only**: it has no private part (there is none in a
/// certificate), and it carries no `kid`, `use` or `alg` — a certificate does not state how it
/// should be used, so nothing is invented on the caller's behalf.
///
/// See the [module documentation](self) for what this does *not* establish.
///
/// # Errors
///
/// [`JoseError::InvalidToken`] when the input is not a well-formed DER certificate: too large,
/// indefinite or non-minimal lengths, high-tag-number form, truncated element, wrong structure,
/// a `BIT STRING` that is not a usable key, or trailing bytes after the certificate.
/// [`JoseError::Key`] when the key itself is one this crate does not support (see
/// [`jwk_from_spki_der`](crate::jwk::jwk_from_spki_der)).
pub fn public_jwk_from_certificate_der(der: &[u8]) -> Result<Jwk> {
    if der.len() > MAX_CERTIFICATE_DER_BYTES {
        return Err(JoseError::InvalidToken(format!(
            "certificate is {} bytes, above this module's limit of {MAX_CERTIFICATE_DER_BYTES}",
            der.len()
        )));
    }

    // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
    let certificate = one_element(der, "Certificate")?;
    if certificate.tag != tag::SEQUENCE {
        return Err(not_a("Certificate", "SEQUENCE", certificate.tag));
    }
    let cert_elements = elements(certificate.body, "Certificate")?;
    if cert_elements.len() != 3 {
        return Err(JoseError::InvalidToken(format!(
            "Certificate must hold exactly three elements (tbsCertificate, signatureAlgorithm, \
             signatureValue) and holds {}; a certificate with extra or missing elements is not \
             one this crate can read positionally",
            cert_elements.len()
        )));
    }

    // TBSCertificate. `version` is optional and EXPLICIT [0], so the index of everything after
    // it depends on whether it is present — the one place in this walk where position is not
    // fixed and therefore the one place worth getting visibly right.
    let tbs = &cert_elements[0];
    if tbs.tag != tag::SEQUENCE {
        return Err(not_a("tbsCertificate", "SEQUENCE", tbs.tag));
    }
    let tbs_elements = elements(tbs.body, "tbsCertificate")?;
    let has_version = matches!(tbs_elements.first(), Some(first) if first.tag == tag::CONTEXT_0);
    let offset = usize::from(has_version);
    // serialNumber, signature, issuer, validity, subject, then subjectPublicKeyInfo.
    const SPKI_INDEX: usize = 5;
    let spki_index = offset + SPKI_INDEX;
    let Some(spki) = tbs_elements.get(spki_index) else {
        return Err(JoseError::InvalidToken(format!(
            "tbsCertificate has {} element(s){}; subjectPublicKeyInfo would be element {} and \
             is not present",
            tbs_elements.len(),
            if has_version {
                " including [0] version"
            } else {
                ""
            },
            spki_index + 1
        )));
    };
    if spki.tag != tag::SEQUENCE {
        return Err(not_a("subjectPublicKeyInfo", "SEQUENCE", spki.tag));
    }

    // Re-encode the located element and hand it to the one SPKI importer this crate has.
    let mut spki_der = Vec::with_capacity(spki.body.len() + 2);
    spki_der.push(spki.tag);
    der_encode_length(spki.body.len(), &mut spki_der);
    spki_der.extend_from_slice(spki.body);

    let jwk = crate::jwk::jwk_from_spki_der(&spki_der)?;
    // Defence in depth: an SPKI has no private part by definition, and the JWK this crate
    // returns from it should never have one. If that ever stops being true, the certificate API
    // is the place it would show up as a "trusted" private key, so it is checked here.
    if public_part_is_missing_or_private_present(&jwk) {
        return Err(JoseError::Key(
            "the certificate's subjectPublicKeyInfo produced a JWK with private material, which \
             an SPKI cannot legitimately contain"
                .into(),
        ));
    }
    Ok(jwk)
}

/// Extract the subject's public key from a PEM (`-----BEGIN CERTIFICATE-----`) certificate.
///
/// Exactly one PEM block, whose label must be `CERTIFICATE`. A file holding a chain — several
/// certificates in order — is refused with the block count rather than silently using the first
/// one: which certificate in a chain a caller means is a decision only the caller can make, and
/// a leaf-versus-root mix-up presents a different public key with no error at all.
///
/// # Errors
///
/// As [`public_jwk_from_certificate_der`], plus armor refusals, a wrong-label refusal and the
/// multi-block refusal.
pub fn public_jwk_from_certificate_pem(text: &str) -> Result<Jwk> {
    let (label, der) = super::pem::decompose(text)?;
    if label != LABEL_CERTIFICATE {
        return Err(JoseError::InvalidToken(format!(
            "expected a PEM \"{LABEL_CERTIFICATE}\" block and found \"{label}\""
        )));
    }
    public_jwk_from_certificate_der(&der)
}

/// One TLV, with nothing after it.
fn one_element<'a>(input: &'a [u8], what: &str) -> Result<Element<'a>> {
    let (element, rest) = read_element(input).map_err(|e| e.context(what))?;
    if !rest.is_empty() {
        return Err(JoseError::InvalidToken(format!(
            "{what} has {} trailing byte(s) after its outer element; DER has no place for them",
            rest.len()
        )));
    }
    Ok(element)
}

/// Walk a constructed body into its elements, refusing anything but canonical DER.
fn elements<'a>(body: &'a [u8], what: &str) -> Result<Vec<Element<'a>>> {
    let mut out = Vec::new();
    let mut rest = body;
    while !rest.is_empty() {
        let (element, remainder) = read_element(rest).map_err(|e| e.context(what))?;
        out.push(element);
        rest = remainder;
        if out.len() > 64 {
            // A certificate's real element counts are small; a runaway count means the lengths
            // are lying, and the walk should stop rather than allocate.
            return Err(JoseError::InvalidToken(format!(
                "{what} contains more than 64 elements, which no real certificate does"
            )));
        }
    }
    Ok(out)
}

/// A DER value: its tag and its body, borrowed from the input.
struct Element<'a> {
    tag: u8,
    body: &'a [u8],
}

/// A structural failure, with the enclosing element name attachable.
#[derive(Debug)]
struct ParseError(&'static str);

impl ParseError {
    /// Wrap this failure with the name of the element being read.
    fn context(self, what: &str) -> JoseError {
        JoseError::InvalidToken(format!("{what}: {}", self.0))
    }
}

/// Read one TLV, returning it and the unread remainder.
///
/// The rules are RFC 5280 Appendix A.1's DER profile, which is deliberately unforgiving:
///
/// * low-tag-number form only (a tag whose low five bits are all ones is high-tag-number form,
///   which PKIX forbids);
/// * definite lengths only — `0x80` (indefinite) is refused. OpenSSL tolerates this, and that
///   tolerance is one of the two places this module is stricter than a peer implementation; the
///   measured refusal in `interop/tests/cert_cryptography.py` pins it;
/// * minimal length encoding — a length below 0x80 must not use the long form;
/// * the declared length must fit the remaining bytes.
fn read_element(input: &[u8]) -> std::result::Result<(Element<'_>, &[u8]), ParseError> {
    let Some((&tag, rest)) = input.split_first() else {
        return Err(ParseError("ended where a tag was expected"));
    };
    if tag & 0x1f == 0x1f {
        return Err(ParseError(
            "uses high-tag-number form, which RFC 5280 Appendix A.1 forbids",
        ));
    }
    let Some((&first, rest)) = rest.split_first() else {
        return Err(ParseError("ended where a length was expected"));
    };
    let (length, rest) = if first & 0x80 == 0 {
        (usize::from(first), rest)
    } else {
        let count = usize::from(first & 0x7f);
        if count == 0 {
            return Err(ParseError(
                "uses an indefinite length; this module reads DER (RFC 5280 Appendix A.1), which \
                 requires definite lengths — note that OpenSSL accepts such a file and \
                 cryptography does not",
            ));
        }
        if count > 4 {
            return Err(ParseError("declares an absurdly long length"));
        }
        if rest.len() < count {
            return Err(ParseError("ended inside a length"));
        }
        let (raw, rest) = rest.split_at(count);
        let value = raw
            .iter()
            .fold(0usize, |acc, byte| (acc << 8) | usize::from(*byte));
        if value < 0x80 {
            return Err(ParseError(
                "uses a non-minimal length encoding, which is not DER",
            ));
        }
        (value, rest)
    };
    if rest.len() < length {
        return Err(ParseError(
            "declares more content than the input contains (truncated)",
        ));
    }
    let (body, remainder) = rest.split_at(length);
    Ok((Element { tag, body }, remainder))
}

/// Encode a DER length in minimal form (used to re-encode the located SPKI).
fn der_encode_length(length: usize, out: &mut Vec<u8>) {
    if length < 0x80 {
        out.push(length as u8);
        return;
    }
    let count = (usize::BITS - length.leading_zeros()).div_ceil(8) as usize;
    out.push(0x80 | count as u8);
    for index in (0..count).rev() {
        out.push(((length >> (index * 8)) & 0xff) as u8);
    }
}

/// A refusal that names what was expected and what was found.
fn not_a(what: &str, expected: &str, found: u8) -> JoseError {
    JoseError::InvalidToken(format!(
        "{what} should be a {expected} (tag 0x30) and has tag 0x{found:02X}; the certificate is \
         either not a certificate or uses a structure this positional reader cannot follow"
    ))
}

/// Whether a JWK from an SPKI unexpectedly carries a private part.
fn public_part_is_missing_or_private_present(jwk: &Jwk) -> bool {
    match jwk.kty.as_str() {
        "RSA" | "EC" | "OKP" => jwk.d.is_some(),
        "oct" => jwk.k.is_some(),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal, structurally valid certificate-shaped DER with a given SPKI body, built for
    /// the structural tests below so they do not depend on OpenSSL fixtures.
    fn shaped_certificate(spki_body: &[u8], with_version: bool) -> Vec<u8> {
        let mut tbs = Vec::new();
        if with_version {
            // [0] EXPLICIT INTEGER (2)
            tbs.extend_from_slice(&[0xA0, 0x03, 0x02, 0x01, 0x02]);
        }
        tbs.extend_from_slice(&[0x02, 0x01, 0x07]); // serialNumber
        tbs.extend_from_slice(&[0x30, 0x00]); // signature          (empty, never read)
        tbs.extend_from_slice(&[0x30, 0x00]); // issuer
        tbs.extend_from_slice(&[0x30, 0x00]); // validity
        tbs.extend_from_slice(&[0x30, 0x00]); // subject
        tbs.push(0x30); // subjectPublicKeyInfo
        der_encode_length(spki_body.len(), &mut tbs);
        tbs.extend_from_slice(spki_body);

        let mut cert = vec![0x30];
        der_encode_length(tbs.len(), &mut cert);
        cert.extend_from_slice(&tbs);
        cert.extend_from_slice(&[0x30, 0x00]); // signatureAlgorithm
        cert.extend_from_slice(&[0x03, 0x02, 0x00, 0x00]); // signatureValue
        let mut outer = vec![0x30];
        der_encode_length(cert.len(), &mut outer);
        outer.extend_from_slice(&cert);
        outer
    }

    #[test]
    fn length_encoder_is_minimal_and_round_trips() {
        for length in [0usize, 1, 0x7f, 0x80, 300, 70_000] {
            let mut out = Vec::new();
            der_encode_length(length, &mut out);
            // The encoder's own output must be accepted by the reader.
            let mut buffer = vec![0x30];
            buffer.extend_from_slice(&out);
            buffer.resize(buffer.len() + length, 0xAB);
            let (element, rest) = read_element(&buffer).expect("reads back");
            assert_eq!(element.body.len(), length, "{length}");
            assert!(rest.is_empty());
            // And never non-minimal.
            if length < 0x80 {
                assert_eq!(out.len(), 1, "{length} should be short form");
            }
        }
    }

    #[test]
    fn structural_refusals_name_the_element_being_read() {
        let empty_spki = [];
        let with_version = shaped_certificate(&empty_spki, true);
        // Structurally the walk reaches an empty SPKI and hands it to the SPKI importer, which
        // is the right place for *that* complaint. The point here is that the certificate walk
        // itself got that far, rather than refusing on shape.
        let err = public_jwk_from_certificate_der(&with_version).expect_err("empty spki");
        let message = err.to_string();
        assert!(
            !message.contains("subjectPublicKeyInfo should be a SEQUENCE"),
            "{message}"
        );

        // Indefinite length on the outer element.
        let indefinite = {
            let mut out = vec![0x30, 0x80];
            out.extend_from_slice(&with_version[2..]);
            out.extend_from_slice(&[0x00, 0x00]);
            out
        };
        let err = public_jwk_from_certificate_der(&indefinite).expect_err("indefinite");
        assert!(err.to_string().contains("indefinite length"), "{err}");

        // Truncation.
        let err = public_jwk_from_certificate_der(&with_version[..with_version.len() / 2])
            .expect_err("truncated");
        assert!(
            err.to_string().contains("truncated") || err.to_string().contains("ended"),
            "{err}"
        );

        // High-tag-number form.
        let err =
            public_jwk_from_certificate_der(&[0x3F, 0x01, 0x02, 0x01, 0x00]).expect_err("high tag");
        assert!(err.to_string().contains("high-tag-number"), "{err}");

        // Non-minimal length: 0x81 0x03 for three bytes could have been 0x03.
        let err = public_jwk_from_certificate_der(&[0x30, 0x81, 0x03, 0x02, 0x01, 0x00])
            .expect_err("non-minimal");
        assert!(err.to_string().contains("non-minimal"), "{err}");

        // Trailing bytes after the certificate.
        let mut trailing = with_version.clone();
        trailing.push(0x00);
        let err = public_jwk_from_certificate_der(&trailing).expect_err("trailing");
        assert!(err.to_string().contains("trailing byte"), "{err}");

        // Wrong outer tag.
        let err = public_jwk_from_certificate_der(&[0x31, 0x00]).expect_err("not a sequence");
        let message = err.to_string();
        assert!(message.contains("Certificate"), "{message}");
        assert!(message.contains("0x31"), "{message}");
    }

    #[test]
    fn an_oversized_input_is_refused_before_parsing() {
        let der = shaped_certificate(&[], true);
        let mut huge = der.clone();
        // Pad by repeating a valid element so the buffer is DER-shaped but enormous.
        while huge.len() <= MAX_CERTIFICATE_DER_BYTES {
            huge.extend_from_slice(&der);
        }
        let err = public_jwk_from_certificate_der(&huge).expect_err("too large");
        assert!(err.to_string().contains("131072"), "{err}");
    }
}
