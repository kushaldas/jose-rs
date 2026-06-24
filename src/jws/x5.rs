//! X.509 certificate-binding helpers for JWS headers (RFC 7515 §4.1.6–4.1.8).
//!
//! These tie a JWS protected header's `x5c` / `x5t#S256` members to the
//! actual signing certificate, so a verifier can confirm the header names
//! the certificate it expects rather than trusting it blindly. They do **not**
//! perform path validation — that is the X.509 layer's job (see the
//! `underskrift` crate); they only compute and compare thumbprints and decode
//! the leaf from `x5c`.

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use sha2::{Digest, Sha256};

use crate::base64url;
use crate::error::{JoseError, Result};
use crate::header::JoseHeader;

/// Compute the RFC 7515 §4.1.8 `x5t#S256` thumbprint of a DER-encoded
/// certificate: the base64url-encoded SHA-256 digest of the DER bytes.
pub fn x5t_s256_of_der(cert_der: &[u8]) -> String {
    let digest = Sha256::digest(cert_der);
    base64url::encode(&digest)
}

/// Decode the leaf (first) certificate from a header's `x5c` member.
///
/// Per RFC 7515 §4.1.6 each `x5c` entry is the **standard** base64 (not
/// base64url) DER encoding of a certificate, leaf-first. Returns the DER
/// bytes of the leaf.
pub fn leaf_cert_der_from_x5c(header: &JoseHeader) -> Result<Vec<u8>> {
    let chain = header
        .x5c
        .as_ref()
        .ok_or_else(|| JoseError::InvalidHeader("header has no x5c member".into()))?;
    let leaf = chain
        .first()
        .ok_or_else(|| JoseError::InvalidHeader("x5c is empty".into()))?;
    BASE64_STANDARD
        .decode(leaf.as_bytes())
        .map_err(|e| JoseError::InvalidHeader(format!("x5c[0] is not valid base64 DER: {e}")))
}

/// Verify that a header's `x5t#S256` (and, if present, the `x5c` leaf) binds
/// to the supplied signing certificate.
///
/// Checks performed:
/// - If the header carries `x5t#S256`, it must equal the SHA-256 thumbprint
///   of `cert_der`.
/// - If the header carries `x5c`, the decoded leaf DER must equal `cert_der`.
/// - At least one of the two members must be present (otherwise there is no
///   binding to check and the call is rejected, so a caller cannot mistake a
///   header with no cert binding for a verified one).
///
/// Returns `Ok(())` when every present binding matches. This does not chase
/// `x5u` (a URL) — dereferencing remote material is out of scope for the same
/// SSRF/key-substitution reasons the crate never auto-fetches `jku`/`x5u`.
pub fn verify_cert_binding(header: &JoseHeader, cert_der: &[u8]) -> Result<()> {
    let mut checked_any = false;

    if let Some(want) = header.x5t_s256.as_deref() {
        let got = x5t_s256_of_der(cert_der);
        if got != want {
            return Err(JoseError::InvalidHeader(
                "x5t#S256 does not match the signing certificate".into(),
            ));
        }
        checked_any = true;
    }

    if header.x5c.is_some() {
        let leaf = leaf_cert_der_from_x5c(header)?;
        if leaf != cert_der {
            return Err(JoseError::InvalidHeader(
                "x5c leaf certificate does not match the signing certificate".into(),
            ));
        }
        checked_any = true;
    }

    if !checked_any {
        return Err(JoseError::InvalidHeader(
            "header carries no x5c or x5t#S256 binding to verify".into(),
        ));
    }
    Ok(())
}

/// Set the `x5t#S256` and `x5c` (leaf-only) members on a header from a
/// DER-encoded signing certificate. Convenience for the sign side.
pub fn bind_cert_to_header(header: &mut JoseHeader, cert_der: &[u8]) {
    header.x5t_s256 = Some(x5t_s256_of_der(cert_der));
    header.x5c = Some(vec![BASE64_STANDARD.encode(cert_der)]);
}

#[cfg(test)]
mod tests {
    use super::*;

    // A small, arbitrary byte string standing in for a DER certificate. The
    // helpers operate on opaque DER bytes (thumbprint + equality), so a real
    // X.509 structure is not required to exercise the binding logic.
    const FAKE_CERT_A: &[u8] = b"\x30\x82-fake-der-certificate-A";
    const FAKE_CERT_B: &[u8] = b"\x30\x82-fake-der-certificate-B";

    #[test]
    fn thumbprint_is_stable_and_distinct() {
        let a = x5t_s256_of_der(FAKE_CERT_A);
        let a2 = x5t_s256_of_der(FAKE_CERT_A);
        let b = x5t_s256_of_der(FAKE_CERT_B);
        assert_eq!(a, a2);
        assert_ne!(a, b);
    }

    #[test]
    fn bind_then_verify_roundtrip() {
        let mut header = JoseHeader::new("ES256");
        bind_cert_to_header(&mut header, FAKE_CERT_A);
        assert!(header.x5t_s256.is_some());
        assert!(header.x5c.is_some());
        verify_cert_binding(&header, FAKE_CERT_A).unwrap();
    }

    #[test]
    fn verify_rejects_wrong_cert() {
        let mut header = JoseHeader::new("ES256");
        bind_cert_to_header(&mut header, FAKE_CERT_A);
        let err = verify_cert_binding(&header, FAKE_CERT_B)
            .unwrap_err()
            .to_string();
        assert!(err.contains("x5t#S256 does not match"), "unexpected: {err}");
    }

    #[test]
    fn verify_rejects_x5c_leaf_mismatch() {
        // x5t#S256 absent, only x5c present, and it names a different cert.
        let mut header = JoseHeader::new("ES256");
        header.x5c = Some(vec![BASE64_STANDARD.encode(FAKE_CERT_B)]);
        let err = verify_cert_binding(&header, FAKE_CERT_A)
            .unwrap_err()
            .to_string();
        assert!(err.contains("x5c leaf"), "unexpected: {err}");
    }

    #[test]
    fn verify_requires_some_binding() {
        let header = JoseHeader::new("ES256");
        let err = verify_cert_binding(&header, FAKE_CERT_A)
            .unwrap_err()
            .to_string();
        assert!(err.contains("no x5c or x5t#S256"), "unexpected: {err}");
    }

    #[test]
    fn leaf_from_x5c_decodes_first_entry() {
        let mut header = JoseHeader::new("ES256");
        header.x5c = Some(vec![
            BASE64_STANDARD.encode(FAKE_CERT_A),
            BASE64_STANDARD.encode(FAKE_CERT_B),
        ]);
        let leaf = leaf_cert_der_from_x5c(&header).unwrap();
        assert_eq!(leaf, FAKE_CERT_A);
    }
}
