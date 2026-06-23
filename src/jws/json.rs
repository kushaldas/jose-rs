//! JWS JSON Serialization (RFC 7515 Section 7.2).
//!
//! Supports both Flattened (Section 7.2.2) and General (Section 7.2.1)
//! forms, plus the JAdES-enabling extensions:
//!
//! - **Detached payload** (RFC 7515 Appendix F): the `payload` member is
//!   omitted from the JSON and supplied out-of-band at verify time.
//! - **Per-signature unprotected headers** (`header` member): populated on
//!   the sign side and consulted (returned) on the verify side — JAdES
//!   carries `etsiU` here.
//! - **Per-signature verification results**: [`verify_general_all`] returns
//!   one outcome per signature so a caller can see every signer's status,
//!   not just the first that verified.
//! - **RFC 7797 `b64`** and the understood-`crit` allow-list, via the
//!   [`crate::jws::SignOptions`] / [`crate::jws::VerifyOptions`] carried
//!   from `jws::compact`.

use serde::{Deserialize, Serialize};

use crate::base64url;
use crate::error::{JoseError, Result};
use crate::header::JoseHeader;
use crate::jws::compact::{signing_input, validate_header_opts, validate_sign_header_opts};
use crate::jws::{SignOptions, VerifyOptions};

// ---------------------------------------------------------------------------
// Data structures
// ---------------------------------------------------------------------------

/// Flattened JWS JSON Serialization (RFC 7515 Section 7.2.2).
///
/// Contains a single signature over the payload. The `payload` member is
/// `None` for a detached signature (RFC 7515 Appendix F).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlattenedJws {
    /// Base64url-encoded payload. Omitted (detached) when `None`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<String>,
    /// Base64url-encoded protected header.
    pub protected: String,
    /// Optional per-signature unprotected header parameters.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub header: Option<serde_json::Value>,
    /// Base64url-encoded signature.
    pub signature: String,
}

/// A single signature entry in General JWS JSON Serialization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwsSignature {
    /// Base64url-encoded protected header.
    pub protected: String,
    /// Optional unprotected header parameters (JAdES `etsiU` lives here).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub header: Option<serde_json::Value>,
    /// Base64url-encoded signature.
    pub signature: String,
}

/// General JWS JSON Serialization (RFC 7515 Section 7.2.1).
///
/// Contains one or more signatures over a shared payload. The `payload`
/// member is `None` for a detached signature (RFC 7515 Appendix F).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneralJws {
    /// Base64url-encoded payload (shared across all signatures). Omitted
    /// (detached) when `None`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<String>,
    /// Array of signature objects.
    pub signatures: Vec<JwsSignature>,
}

/// Outcome of verifying one signature entry in a General JWS.
#[derive(Debug, Clone)]
pub struct SignatureResult {
    /// Index of the signature within the `signatures` array.
    pub index: usize,
    /// Parsed protected header for this signature (`None` if it could not be
    /// decoded — in which case `error` explains why).
    pub protected_header: Option<JoseHeader>,
    /// The unprotected `header` member as carried in the JWS, if any.
    pub unprotected_header: Option<serde_json::Value>,
    /// Whether this signature verified successfully.
    pub verified: bool,
    /// Why verification failed (or the entry was skipped), if applicable.
    pub error: Option<String>,
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Resolve the effective payload bytes for a verify operation: the embedded
/// member if present, otherwise the caller-supplied detached payload. It is
/// an error for both or neither to be present.
fn resolve_payload<'a>(
    embedded: Option<&'a str>,
    detached: Option<&'a [u8]>,
    b64: bool,
) -> Result<Vec<u8>> {
    match (embedded, detached) {
        (Some(_), Some(_)) => Err(JoseError::InvalidToken(
            "both an embedded and a detached payload were supplied".into(),
        )),
        (None, None) => Err(JoseError::InvalidToken(
            "JWS has no payload member and no detached payload was supplied".into(),
        )),
        (Some(p), None) => {
            if b64 {
                base64url::decode(p)
            } else {
                Ok(p.as_bytes().to_vec())
            }
        }
        (None, Some(d)) => Ok(d.to_vec()),
    }
}

// ---------------------------------------------------------------------------
// Flattened JWS operations
// ---------------------------------------------------------------------------

/// Create a Flattened JWS JSON from a signer, payload, and header.
///
/// The supplied `header.alg` is cross-checked against `signer.algorithm()`
/// before signing; mismatches (including `alg: "none"` or an unsupported
/// `crit`) are rejected.
pub fn sign_flattened(
    signer: &dyn kryptering::Signer,
    payload: &[u8],
    header: &JoseHeader,
) -> Result<FlattenedJws> {
    sign_flattened_opts(signer, payload, header, None, &SignOptions::new())
}

/// Create a Flattened JWS JSON with full control over the unprotected
/// header, detached payload, and RFC 7797 / `crit` options.
///
/// - `unprotected`: the per-signature `header` member (JAdES `etsiU`, etc.).
/// - `opts.b64 == false`: RFC 7797 unencoded payload; the embedded `payload`
///   member, when present, carries the raw bytes.
pub fn sign_flattened_opts(
    signer: &dyn kryptering::Signer,
    payload: &[u8],
    header: &JoseHeader,
    unprotected: Option<serde_json::Value>,
    opts: &SignOptions,
) -> Result<FlattenedJws> {
    let detached = sign_flattened_detached_opts(signer, payload, header, unprotected, opts)?;
    // Attached form: embed the payload member.
    let payload_member = if opts.b64 {
        base64url::encode(payload)
    } else {
        String::from_utf8(payload.to_vec()).map_err(|_| {
            JoseError::InvalidToken("unencoded (b64=false) payload must be valid UTF-8".into())
        })?
    };
    Ok(FlattenedJws {
        payload: Some(payload_member),
        ..detached
    })
}

/// Create a **detached** Flattened JWS JSON (the `payload` member is
/// omitted). The payload is signed but not carried; the verifier supplies it
/// out-of-band.
pub fn sign_flattened_detached(
    signer: &dyn kryptering::Signer,
    payload: &[u8],
    header: &JoseHeader,
) -> Result<FlattenedJws> {
    sign_flattened_detached_opts(signer, payload, header, None, &SignOptions::new())
}

/// Detached Flattened sign with full options.
pub fn sign_flattened_detached_opts(
    signer: &dyn kryptering::Signer,
    payload: &[u8],
    header: &JoseHeader,
    unprotected: Option<serde_json::Value>,
    opts: &SignOptions,
) -> Result<FlattenedJws> {
    let b64 = validate_sign_header_opts(header, signer, opts)?;
    let header_json = serde_json::to_vec(header)?;
    let protected_b64 = base64url::encode(&header_json);
    let input = signing_input(&protected_b64, payload, b64);
    let sig = signer.sign(&input).map_err(JoseError::Crypto)?;
    Ok(FlattenedJws {
        payload: None,
        protected: protected_b64,
        header: unprotected,
        signature: base64url::encode(&sig),
    })
}

/// Verify a Flattened JWS JSON and return the decoded payload.
///
/// The protected header's `alg` is cross-checked against
/// `verifier.algorithm()`; `alg: "none"` and any unsupported `crit` are
/// rejected before any cryptographic operation. The JWS must carry an
/// embedded payload — use [`verify_flattened_detached`] for the detached
/// case.
pub fn verify_flattened(
    verifier: &dyn kryptering::Verifier,
    jws: &FlattenedJws,
) -> Result<Vec<u8>> {
    verify_flattened_opts(verifier, jws, None, &VerifyOptions::new())
}

/// Verify a **detached** Flattened JWS JSON against an externally supplied
/// payload.
pub fn verify_flattened_detached(
    verifier: &dyn kryptering::Verifier,
    jws: &FlattenedJws,
    detached_payload: &[u8],
) -> Result<Vec<u8>> {
    verify_flattened_opts(verifier, jws, Some(detached_payload), &VerifyOptions::new())
}

/// Verify a Flattened JWS JSON with full control over the detached payload
/// and `crit` options.
pub fn verify_flattened_opts(
    verifier: &dyn kryptering::Verifier,
    jws: &FlattenedJws,
    detached_payload: Option<&[u8]>,
    opts: &VerifyOptions,
) -> Result<Vec<u8>> {
    crate::jws::compact::ensure_token_size(&jws.protected)?;
    if let Some(p) = &jws.payload {
        crate::jws::compact::ensure_token_size(p)?;
    }
    let b64 = validate_header_opts(&jws.protected, verifier, opts)?;
    let payload = resolve_payload(jws.payload.as_deref(), detached_payload, b64)?;
    let input = signing_input(&jws.protected, &payload, b64);
    let sig = base64url::decode(&jws.signature)?;
    let valid = verifier.verify(&input, &sig).map_err(JoseError::Crypto)?;
    if !valid {
        return Err(JoseError::InvalidToken(
            "signature verification failed".into(),
        ));
    }
    Ok(payload)
}

// ---------------------------------------------------------------------------
// General JWS operations
// ---------------------------------------------------------------------------

/// One signer entry for a General JWS: a signer, its protected header, and
/// an optional per-signature unprotected `header` member.
pub struct GeneralSigner<'a> {
    pub signer: &'a dyn kryptering::Signer,
    pub protected: &'a JoseHeader,
    pub unprotected: Option<serde_json::Value>,
    pub options: SignOptions,
}

impl<'a> GeneralSigner<'a> {
    /// Convenience constructor with default options and no unprotected
    /// header.
    pub fn new(signer: &'a dyn kryptering::Signer, protected: &'a JoseHeader) -> Self {
        Self {
            signer,
            protected,
            unprotected: None,
            options: SignOptions::new(),
        }
    }
}

/// Create a General JWS JSON with multiple signers.
///
/// Each element of `signers` is a `(signer, header)` pair. All signers sign
/// the same payload; their protected headers are serialized independently.
/// No per-signature unprotected header is emitted — use
/// [`sign_general_full`] for that.
pub fn sign_general(
    signers: &[(&dyn kryptering::Signer, &JoseHeader)],
    payload: &[u8],
) -> Result<GeneralJws> {
    let entries: Vec<GeneralSigner> = signers
        .iter()
        .map(|(s, h)| GeneralSigner::new(*s, h))
        .collect();
    sign_general_full(&entries, payload, true)
}

/// Create a General JWS JSON with per-signature unprotected headers and
/// RFC 7797 / `crit` options, optionally detached.
///
/// `embed_payload == false` produces a detached JWS (the `payload` member is
/// omitted). All entries must agree on the effective `b64` value (they sign
/// over a shared payload, so a mixed encoding would be ambiguous).
pub fn sign_general_full(
    signers: &[GeneralSigner],
    payload: &[u8],
    embed_payload: bool,
) -> Result<GeneralJws> {
    if signers.is_empty() {
        return Err(JoseError::InvalidToken(
            "at least one signer is required".into(),
        ));
    }

    // Determine the shared b64 from the first entry and require agreement.
    let shared_b64 = signers[0].options.b64;
    if signers.iter().any(|e| e.options.b64 != shared_b64) {
        return Err(JoseError::InvalidToken(
            "all signers in a General JWS must agree on the b64 setting".into(),
        ));
    }

    let mut signatures = Vec::with_capacity(signers.len());
    for entry in signers {
        let b64 = validate_sign_header_opts(entry.protected, entry.signer, &entry.options)?;
        let header_json = serde_json::to_vec(entry.protected)?;
        let protected_b64 = base64url::encode(&header_json);
        let input = signing_input(&protected_b64, payload, b64);
        let sig = entry.signer.sign(&input).map_err(JoseError::Crypto)?;
        signatures.push(JwsSignature {
            protected: protected_b64,
            header: entry.unprotected.clone(),
            signature: base64url::encode(&sig),
        });
    }

    let payload_member = if embed_payload {
        let member = if shared_b64 {
            base64url::encode(payload)
        } else {
            String::from_utf8(payload.to_vec()).map_err(|_| {
                JoseError::InvalidToken("unencoded (b64=false) payload must be valid UTF-8".into())
            })?
        };
        Some(member)
    } else {
        None
    };

    Ok(GeneralJws {
        payload: payload_member,
        signatures,
    })
}

/// Verify at least one signature in a General JWS JSON.
///
/// Iterates through signatures whose protected header's `alg` matches
/// `verifier.algorithm()` (per-entry algorithm binding — J-01/J-02).
/// Returns the decoded payload on the first successful cryptographic
/// verification. For per-signature outcomes, use [`verify_general_all`].
pub fn verify_general(verifier: &dyn kryptering::Verifier, jws: &GeneralJws) -> Result<Vec<u8>> {
    verify_general_opts(verifier, jws, None, &VerifyOptions::new())
}

/// Verify a General JWS, returning the payload on the first valid signature,
/// with control over the detached payload and `crit` options.
pub fn verify_general_opts(
    verifier: &dyn kryptering::Verifier,
    jws: &GeneralJws,
    detached_payload: Option<&[u8]>,
    opts: &VerifyOptions,
) -> Result<Vec<u8>> {
    if jws.signatures.is_empty() {
        return Err(JoseError::InvalidToken("no signatures present".into()));
    }
    // Short-circuit on the first signature that verifies: `verify_general`
    // only needs one valid signature, so there is no reason to run the verifier
    // over the remaining (caller-supplied) entries. Exhaustive per-signature
    // reporting is available via `verify_general_all`.
    let (_results, payload) = verify_general_inner(verifier, jws, detached_payload, opts, true)?;
    payload.ok_or_else(|| JoseError::InvalidToken("no signature verified successfully".into()))
}

/// Verify **every** signature in a General JWS against the given verifier and
/// return a per-signature outcome.
///
/// This is the multi-signer reporting API: a caller (e.g. a JAdES validator)
/// can see, for each signature, whether it verified, the parsed protected
/// header, and the unprotected `header` member. Entries whose algorithm does
/// not match the verifier are reported as `verified: false` with an
/// explanatory `error` rather than silently skipped.
///
/// The returned tuple's second element is `Some(payload)` when **at least one**
/// signature verified (so the caller does not have to base64url-decode it
/// again), and `None` when no signature verified — the API never hands back
/// payload bytes that nothing authenticated. An error is returned only for
/// whole-JWS problems (no signatures, payload resolution failure); individual
/// signature failures are reported in the results vector.
pub fn verify_general_all(
    verifier: &dyn kryptering::Verifier,
    jws: &GeneralJws,
    detached_payload: Option<&[u8]>,
    opts: &VerifyOptions,
) -> Result<(Vec<SignatureResult>, Option<Vec<u8>>)> {
    if jws.signatures.is_empty() {
        return Err(JoseError::InvalidToken("no signatures present".into()));
    }
    verify_general_inner(verifier, jws, detached_payload, opts, false)
}

/// Shared core for the General-JWS verify paths. Attempts each signature,
/// collecting per-entry results, and returns the payload only if at least one
/// signature verified (`None` otherwise).
///
/// When `stop_on_first_valid` is true the loop returns as soon as a signature
/// verifies (used by `verify_general`, which needs only one valid signature);
/// when false every signature is attempted (used by `verify_general_all`).
fn verify_general_inner(
    verifier: &dyn kryptering::Verifier,
    jws: &GeneralJws,
    detached_payload: Option<&[u8]>,
    opts: &VerifyOptions,
    stop_on_first_valid: bool,
) -> Result<(Vec<SignatureResult>, Option<Vec<u8>>)> {
    if let Some(p) = &jws.payload {
        crate::jws::compact::ensure_token_size(p)?;
    }

    // The b64 setting is per-protected-header, but the payload member is
    // shared, so resolve the payload using the first decodable header's b64.
    // For the common (all-b64-true) case this is exactly the classic
    // behaviour. We compute it lazily below per entry to keep raw bytes.
    let mut results = Vec::with_capacity(jws.signatures.len());
    let mut resolved_payload: Option<Vec<u8>> = None;

    for (index, entry) in jws.signatures.iter().enumerate() {
        let mut result = SignatureResult {
            index,
            protected_header: None,
            unprotected_header: entry.header.clone(),
            verified: false,
            error: None,
        };

        // Decode the protected header for reporting (best-effort).
        if let Ok(bytes) = base64url::decode(&entry.protected) {
            if let Ok(h) = serde_json::from_slice::<JoseHeader>(&bytes) {
                result.protected_header = Some(h);
            }
        }

        let b64 = match validate_header_opts(&entry.protected, verifier, opts) {
            Ok(b) => b,
            Err(e) => {
                result.error = Some(e.to_string());
                results.push(result);
                continue;
            }
        };

        let payload = match resolve_payload(jws.payload.as_deref(), detached_payload, b64) {
            Ok(p) => p,
            Err(e) => {
                // A payload-resolution problem is fatal for the whole JWS.
                return Err(e);
            }
        };

        let input = signing_input(&entry.protected, &payload, b64);
        let sig = match base64url::decode(&entry.signature) {
            Ok(s) => s,
            Err(e) => {
                result.error = Some(format!("signature is not valid base64url: {e}"));
                results.push(result);
                continue;
            }
        };
        match verifier.verify(&input, &sig) {
            Ok(true) => {
                result.verified = true;
                resolved_payload = Some(payload);
            }
            Ok(false) => {
                result.error = Some("signature verification failed".into());
            }
            Err(e) => {
                result.error = Some(format!("verifier error: {e}"));
            }
        }
        let verified = result.verified;
        results.push(result);
        if stop_on_first_valid && verified {
            break;
        }
    }

    // Return the payload only when a signature actually verified. A verification
    // API must never hand back payload bytes that nothing authenticated, so a
    // caller cannot accidentally consume unsigned data.
    Ok((results, resolved_payload))
}

#[cfg(test)]
mod tests {
    use super::*;
    use kryptering::{
        HashAlgorithm, SignatureAlgorithm, SoftwareKey, SoftwareSigner, SoftwareVerifier,
    };

    fn hmac_key(secret: &[u8]) -> SoftwareKey {
        SoftwareKey::Hmac(secret.to_vec())
    }

    fn hmac_signer(secret: &[u8]) -> SoftwareSigner {
        SoftwareSigner::new(
            SignatureAlgorithm::Hmac(HashAlgorithm::Sha256),
            hmac_key(secret),
        )
        .unwrap()
    }

    fn hmac_verifier(secret: &[u8]) -> SoftwareVerifier {
        SoftwareVerifier::new(
            SignatureAlgorithm::Hmac(HashAlgorithm::Sha256),
            hmac_key(secret),
        )
        .unwrap()
    }

    const KEY_A: &[u8] = b"my-secret-key-at-least-32-bytes!";
    const KEY_B: &[u8] = b"another-key-that-is-32-bytes-xx!";
    const WRONG_KEY: &[u8] = b"wrong-key-that-is-also-32-bytes!";

    // -----------------------------------------------------------------------
    // Flattened JWS tests
    // -----------------------------------------------------------------------

    #[test]
    fn flattened_sign_verify_roundtrip() {
        let header = JoseHeader::new("HS256");
        let payload = b"flattened test payload";

        let jws = sign_flattened(&hmac_signer(KEY_A), payload, &header).unwrap();
        let recovered = verify_flattened(&hmac_verifier(KEY_A), &jws).unwrap();
        assert_eq!(recovered, payload);
    }

    #[test]
    fn flattened_serializes_to_valid_json() {
        let header = JoseHeader::new("HS256");
        let payload = b"json check";

        let jws = sign_flattened(&hmac_signer(KEY_A), payload, &header).unwrap();
        let json_str = serde_json::to_string(&jws).unwrap();

        let v: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert!(v.get("payload").is_some());
        assert!(v.get("protected").is_some());
        assert!(v.get("signature").is_some());
        assert!(v.get("signatures").is_none());
    }

    #[test]
    fn flattened_verify_wrong_key_fails() {
        let header = JoseHeader::new("HS256");
        let payload = b"secret data";

        let jws = sign_flattened(&hmac_signer(KEY_A), payload, &header).unwrap();
        let result = verify_flattened(&hmac_verifier(WRONG_KEY), &jws);
        assert!(result.is_err());
    }

    /// Detached flattened: payload member omitted, supplied at verify time.
    #[test]
    fn flattened_detached_roundtrip() {
        let header = JoseHeader::new("HS256");
        let payload = b"detached payload bytes";

        let jws = sign_flattened_detached(&hmac_signer(KEY_A), payload, &header).unwrap();
        assert!(jws.payload.is_none(), "detached JWS must omit payload");

        // Serialized JSON must not contain a payload member.
        let json_str = serde_json::to_string(&jws).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert!(v.get("payload").is_none(), "payload leaked: {json_str}");

        let recovered = verify_flattened_detached(&hmac_verifier(KEY_A), &jws, payload).unwrap();
        assert_eq!(recovered, payload);

        // Wrong detached payload must fail.
        assert!(verify_flattened_detached(&hmac_verifier(KEY_A), &jws, b"wrong").is_err());
    }

    /// A detached JWS verified without supplying the payload is an error.
    #[test]
    fn flattened_detached_requires_payload() {
        let header = JoseHeader::new("HS256");
        let jws = sign_flattened_detached(&hmac_signer(KEY_A), b"p", &header).unwrap();
        let err = verify_flattened(&hmac_verifier(KEY_A), &jws)
            .unwrap_err()
            .to_string();
        assert!(err.contains("no detached payload"), "unexpected: {err}");
    }

    /// Flattened sign with an unprotected header member round-trips and the
    /// member is carried in the JSON but not part of the signing input.
    #[test]
    fn flattened_unprotected_header_is_carried() {
        let header = JoseHeader::new("HS256");
        let unprotected = serde_json::json!({"kid": "unprotected-kid"});
        let jws = sign_flattened_opts(
            &hmac_signer(KEY_A),
            b"p",
            &header,
            Some(unprotected.clone()),
            &SignOptions::new(),
        )
        .unwrap();
        assert_eq!(jws.header.as_ref(), Some(&unprotected));
        // Still verifies (unprotected header is not signed).
        assert!(verify_flattened(&hmac_verifier(KEY_A), &jws).is_ok());
    }

    // -----------------------------------------------------------------------
    // General JWS tests
    // -----------------------------------------------------------------------

    #[test]
    fn general_two_signatures_verify_with_either_key() {
        let header_a = JoseHeader::new("HS256");
        let header_b = JoseHeader::new("HS256");
        let payload = b"multi-sig payload";

        let signer_a = hmac_signer(KEY_A);
        let signer_b = hmac_signer(KEY_B);

        let signers: Vec<(&dyn kryptering::Signer, &JoseHeader)> =
            vec![(&signer_a, &header_a), (&signer_b, &header_b)];

        let jws = sign_general(&signers, payload).unwrap();
        assert_eq!(jws.signatures.len(), 2);

        let recovered_a = verify_general(&hmac_verifier(KEY_A), &jws).unwrap();
        assert_eq!(recovered_a, payload);

        let recovered_b = verify_general(&hmac_verifier(KEY_B), &jws).unwrap();
        assert_eq!(recovered_b, payload);
    }

    #[test]
    fn general_verify_wrong_key_fails() {
        let header = JoseHeader::new("HS256");
        let payload = b"general payload";

        let signer_a = hmac_signer(KEY_A);
        let signers: Vec<(&dyn kryptering::Signer, &JoseHeader)> = vec![(&signer_a, &header)];

        let jws = sign_general(&signers, payload).unwrap();
        let result = verify_general(&hmac_verifier(WRONG_KEY), &jws);
        assert!(result.is_err());
    }

    #[test]
    fn general_serializes_to_valid_json() {
        let header = JoseHeader::new("HS256");
        let payload = b"json check general";

        let signer = hmac_signer(KEY_A);
        let signers: Vec<(&dyn kryptering::Signer, &JoseHeader)> = vec![(&signer, &header)];

        let jws = sign_general(&signers, payload).unwrap();
        let json_str = serde_json::to_string(&jws).unwrap();

        let v: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert!(v.get("payload").is_some());
        assert!(v.get("signatures").is_some());
        let sigs = v["signatures"].as_array().unwrap();
        assert_eq!(sigs.len(), 1);
        assert!(sigs[0].get("protected").is_some());
        assert!(sigs[0].get("signature").is_some());
    }

    /// Per-signature results: two signers, verifier holds only KEY_A. The
    /// first (KEY_A) entry reports verified, the second (KEY_B) does not.
    #[test]
    fn general_per_signature_results() {
        let header_a = JoseHeader::new("HS256");
        let header_b = JoseHeader::new("HS256");
        let payload = b"multi-sig results";
        let signer_a = hmac_signer(KEY_A);
        let signer_b = hmac_signer(KEY_B);
        let signers: Vec<(&dyn kryptering::Signer, &JoseHeader)> =
            vec![(&signer_a, &header_a), (&signer_b, &header_b)];
        let jws = sign_general(&signers, payload).unwrap();

        let (results, recovered) =
            verify_general_all(&hmac_verifier(KEY_A), &jws, None, &VerifyOptions::new()).unwrap();
        assert_eq!(results.len(), 2);
        assert!(results[0].verified, "entry 0 (KEY_A) should verify");
        assert!(!results[1].verified, "entry 1 (KEY_B) should not verify");
        assert!(results[1].error.is_some());
        assert_eq!(recovered.as_deref(), Some(&payload[..]));
    }

    /// `verify_general_all` must NOT return payload bytes when no signature
    /// verifies, so a caller cannot accidentally consume unauthenticated data.
    #[test]
    fn general_all_yields_no_payload_when_nothing_verifies() {
        let header = JoseHeader::new("HS256");
        let signer = hmac_signer(KEY_A);
        let signers: Vec<(&dyn kryptering::Signer, &JoseHeader)> = vec![(&signer, &header)];
        let jws = sign_general(&signers, b"top secret").unwrap();

        // Verify with the wrong key: the single signature fails.
        let (results, payload) =
            verify_general_all(&hmac_verifier(KEY_B), &jws, None, &VerifyOptions::new()).unwrap();
        assert!(!results[0].verified);
        assert!(
            payload.is_none(),
            "no payload may be returned when nothing verified"
        );
    }

    /// Per-signature unprotected header is reported back in the results.
    #[test]
    fn general_unprotected_header_reported() {
        let header = JoseHeader::new("HS256");
        let signer = hmac_signer(KEY_A);
        let etsi = serde_json::json!({"etsiU": ["sig-timestamp"]});
        let entry = GeneralSigner {
            signer: &signer,
            protected: &header,
            unprotected: Some(etsi.clone()),
            options: SignOptions::new(),
        };
        let jws = sign_general_full(std::slice::from_ref(&entry), b"p", true).unwrap();
        assert_eq!(jws.signatures[0].header.as_ref(), Some(&etsi));

        let (results, _) =
            verify_general_all(&hmac_verifier(KEY_A), &jws, None, &VerifyOptions::new()).unwrap();
        assert_eq!(results[0].unprotected_header.as_ref(), Some(&etsi));
        assert!(results[0].verified);
    }

    /// Detached General JWS: payload omitted, supplied at verify time.
    #[test]
    fn general_detached_roundtrip() {
        let header = JoseHeader::new("HS256");
        let payload = b"detached general payload";
        let signer = hmac_signer(KEY_A);
        let entry = GeneralSigner::new(&signer, &header);
        let jws = sign_general_full(std::slice::from_ref(&entry), payload, false).unwrap();
        assert!(jws.payload.is_none());

        let recovered = verify_general_opts(
            &hmac_verifier(KEY_A),
            &jws,
            Some(payload),
            &VerifyOptions::new(),
        )
        .unwrap();
        assert_eq!(recovered, payload);
    }

    /// J-01 regression: Flattened verify rejects alg-header mismatch.
    #[test]
    fn flattened_alg_header_mismatch_rejected() {
        use kryptering::Signer;
        let mut header = JoseHeader::new("RS256");
        header.kid = Some("attacker".into());
        let protected = base64url::encode(&serde_json::to_vec(&header).unwrap());
        let payload = base64url::encode(b"p");
        let signing_input = format!("{protected}.{payload}");
        let sig = hmac_signer(KEY_A).sign(signing_input.as_bytes()).unwrap();
        let jws = FlattenedJws {
            payload: Some(payload),
            protected,
            header: None,
            signature: base64url::encode(&sig),
        };
        let result = verify_flattened(&hmac_verifier(KEY_A), &jws);
        assert!(result.is_err());
    }

    /// J-03 regression: Flattened verify rejects alg=none.
    #[test]
    fn flattened_alg_none_rejected() {
        let header = JoseHeader::new("none");
        let protected = base64url::encode(&serde_json::to_vec(&header).unwrap());
        let payload = base64url::encode(b"p");
        let jws = FlattenedJws {
            payload: Some(payload),
            protected,
            header: None,
            signature: String::new(),
        };
        let result = verify_flattened(&hmac_verifier(KEY_A), &jws);
        assert!(result.is_err());
    }

    /// J-02 regression: General verify with only mismatched-alg entries fails.
    #[test]
    fn general_all_mismatched_alg_fails() {
        let payload_b64 = base64url::encode(b"p");
        let mut rs256_header = JoseHeader::new("RS256");
        rs256_header.kid = Some("attacker".into());
        let protected = base64url::encode(&serde_json::to_vec(&rs256_header).unwrap());
        let signing_input = format!("{protected}.{payload_b64}");
        use kryptering::Signer;
        let sig = hmac_signer(KEY_A).sign(signing_input.as_bytes()).unwrap();
        let jws = GeneralJws {
            payload: Some(payload_b64),
            signatures: vec![JwsSignature {
                protected,
                header: None,
                signature: base64url::encode(&sig),
            }],
        };
        let result = verify_general(&hmac_verifier(KEY_A), &jws);
        assert!(result.is_err());
    }

    #[test]
    fn general_roundtrip_through_json() {
        let header = JoseHeader::new("HS256");
        let payload = b"roundtrip via json";

        let signer = hmac_signer(KEY_A);
        let signers: Vec<(&dyn kryptering::Signer, &JoseHeader)> = vec![(&signer, &header)];

        let jws = sign_general(&signers, payload).unwrap();
        let json_str = serde_json::to_string(&jws).unwrap();
        let deserialized: GeneralJws = serde_json::from_str(&json_str).unwrap();

        let recovered = verify_general(&hmac_verifier(KEY_A), &deserialized).unwrap();
        assert_eq!(recovered, payload);
    }

    /// MAX_TOKEN_BYTES guard on the JSON verify path: an oversized protected
    /// header (or payload member) is refused before any crypto.
    #[test]
    fn flattened_oversize_payload_rejected() {
        let header = JoseHeader::new("HS256");
        let jws = FlattenedJws {
            payload: Some("a".repeat(crate::MAX_TOKEN_BYTES + 1)),
            protected: base64url::encode(&serde_json::to_vec(&header).unwrap()),
            header: None,
            signature: base64url::encode(b"x"),
        };
        let err = verify_flattened(&hmac_verifier(KEY_A), &jws)
            .unwrap_err()
            .to_string();
        assert!(err.contains("MAX_TOKEN_BYTES"), "unexpected: {err}");
    }
}
