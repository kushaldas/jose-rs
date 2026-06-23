//! JWS Compact Serialization (RFC 7515 Section 3.1).
//!
//! Format: `BASE64URL(header).BASE64URL(payload).BASE64URL(signature)`

use crate::algorithm::JwsAlgorithm;
use crate::base64url;
use crate::error::{JoseError, Result};
use crate::header::JoseHeader;

/// `crit` header parameters this library understands natively (RFC 7515
/// §4.1.11). A caller may extend the understood set for JAdES (`etsiU`,
/// `sigT`, …) via [`SignOptions::understood_crit`] /
/// [`VerifyOptions::understood_crit`]; anything outside the union of this
/// list and the caller's list is rejected. RFC 7797 `b64` lives here
/// because the library implements its semantics.
pub const LIB_UNDERSTOOD_CRIT: &[&str] = &["b64"];

/// Options controlling the JWS signing input (RFC 7797 unencoded payload
/// and the understood-`crit` allow-list).
///
/// The default — `SignOptions::default()` — reproduces the classic RFC 7515
/// behaviour: base64url-encoded payload, attached, and only the library's
/// built-in understood `crit` params permitted.
#[derive(Debug, Clone)]
pub struct SignOptions {
    /// RFC 7797: when `false`, the payload is carried unencoded and the
    /// signing input is `ASCII(protected) || '.' || payload` over the raw
    /// payload bytes. When `false` the protected header MUST contain
    /// `"b64": false` and list `"b64"` in `crit` — this is enforced.
    ///
    /// Defaults to `true` (classic base64url) — see the manual [`Default`]
    /// impl. A derived `Default` would make this `false`, silently selecting
    /// RFC 7797 unencoded mode, so it is set explicitly here.
    pub b64: bool,
    /// Additional `crit` header parameters the caller understands and has
    /// processed out-of-band (e.g. JAdES `etsiU`, `sigT`). These are
    /// permitted in `crit` on top of [`LIB_UNDERSTOOD_CRIT`].
    pub understood_crit: Vec<String>,
}

impl SignOptions {
    /// Classic RFC 7515 behaviour: base64url-encoded, attached payload,
    /// no extra understood `crit`.
    pub fn new() -> Self {
        Self {
            b64: true,
            understood_crit: Vec::new(),
        }
    }
}

impl Default for SignOptions {
    /// Classic RFC 7515 behaviour (`b64 = true`). Defined manually so the
    /// default is not the surprising `b64 = false` a derive would produce.
    fn default() -> Self {
        Self::new()
    }
}

/// Options controlling JWS verification (RFC 7797 unencoded payload and the
/// understood-`crit` allow-list).
#[derive(Debug, Clone, Default)]
pub struct VerifyOptions {
    /// Additional `crit` header parameters the caller understands. A `crit`
    /// entry outside the union of [`LIB_UNDERSTOOD_CRIT`] and this list is
    /// rejected (RFC 7515 §4.1.11).
    pub understood_crit: Vec<String>,
}

impl VerifyOptions {
    /// Classic behaviour: only the library's built-in understood `crit`.
    pub fn new() -> Self {
        Self::default()
    }
}

/// Validate a `crit` list against the union of the library's understood
/// params and the caller-supplied understood set (RFC 7515 §4.1.11).
///
/// An empty `crit` array is itself a protocol violation (RFC 7515 says
/// `crit` MUST NOT be empty when present). Any entry not understood is
/// rejected. Returns whether `b64` appeared in `crit`.
fn validate_crit(crit: Option<&Vec<String>>, understood_extra: &[String]) -> Result<bool> {
    let Some(crit) = crit else {
        return Ok(false);
    };
    if crit.is_empty() {
        return Err(JoseError::InvalidHeader(
            "crit must not be empty when present".into(),
        ));
    }
    let mut saw_b64 = false;
    for param in crit {
        if param == "b64" {
            saw_b64 = true;
        }
        let understood = LIB_UNDERSTOOD_CRIT.contains(&param.as_str())
            || understood_extra.iter().any(|u| u == param);
        if !understood {
            return Err(JoseError::InvalidHeader(format!(
                "unsupported crit extension: {param}"
            )));
        }
    }
    Ok(saw_b64)
}

/// Read the RFC 7797 `b64` header param (default `true`) from the protected
/// header's `extra` map, enforcing the §6 rule that `b64`, when present,
/// must be listed in `crit`. Returns the effective `b64` value.
fn resolve_b64(header: &JoseHeader, crit_listed_b64: bool) -> Result<bool> {
    match header.extra.get("b64") {
        None => Ok(true),
        Some(value) => {
            let b = value.as_bool().ok_or_else(|| {
                JoseError::InvalidHeader("b64 header param must be a boolean".into())
            })?;
            // RFC 7797 §6: if b64 is present it MUST be integrity-protected
            // by being listed in crit.
            if !crit_listed_b64 {
                return Err(JoseError::InvalidHeader(
                    "b64 header param must be listed in crit (RFC 7797 §6)".into(),
                ));
            }
            Ok(b)
        }
    }
}

/// Build the JWS signing input for a (possibly unencoded) payload.
///
/// RFC 7515: `ASCII(BASE64URL(protected)) || '.' || BASE64URL(payload)`.
/// RFC 7797 with `b64:false`: `ASCII(BASE64URL(protected)) || '.' ||
/// payload` where the payload bytes are appended verbatim.
pub(crate) fn signing_input(protected_b64: &str, payload: &[u8], b64: bool) -> Vec<u8> {
    let mut input = Vec::with_capacity(protected_b64.len() + 1 + payload.len());
    input.extend_from_slice(protected_b64.as_bytes());
    input.push(b'.');
    if b64 {
        input.extend_from_slice(base64url::encode(payload).as_bytes());
    } else {
        input.extend_from_slice(payload);
    }
    input
}

pub(crate) fn ensure_token_size(token: &str) -> Result<()> {
    if token.len() > crate::MAX_TOKEN_BYTES {
        return Err(JoseError::InvalidToken(format!(
            "token size {} exceeds MAX_TOKEN_BYTES ({})",
            token.len(),
            crate::MAX_TOKEN_BYTES
        )));
    }
    Ok(())
}

/// Cross-check the protected header against the signer and the RFC 7797 /
/// understood-`crit` policy carried in `opts`. Returns the effective `b64`
/// flag (so the caller knows whether to encode the payload).
pub(crate) fn validate_sign_header_opts(
    header: &JoseHeader,
    signer: &dyn kryptering::Signer,
    opts: &SignOptions,
) -> Result<bool> {
    let crit_listed_b64 = validate_crit(header.crit.as_ref(), &opts.understood_crit)?;
    if header.alg == "none" {
        return Err(JoseError::InvalidHeader(
            "alg=\"none\" is not permitted".into(),
        ));
    }
    let header_alg = JwsAlgorithm::from_str(&header.alg)?;
    let header_sig_alg = header_alg.to_crypto()?;
    if signer.algorithm() != header_sig_alg {
        return Err(JoseError::InvalidHeader(format!(
            "header alg {} does not match signer algorithm",
            header.alg
        )));
    }
    // Effective b64 from the header, cross-checked against the caller's
    // intent: the header is authoritative (it is what gets signed), but it
    // must agree with opts.b64 so a caller cannot think it signed unencoded
    // while emitting an encoded payload.
    let header_b64 = resolve_b64(header, crit_listed_b64)?;
    if header_b64 != opts.b64 {
        return Err(JoseError::InvalidHeader(format!(
            "header b64={header_b64} disagrees with requested b64={}",
            opts.b64
        )));
    }
    Ok(header_b64)
}

/// Sign a payload and produce a JWS Compact Serialization string.
///
/// The `signer` provides the cryptographic operation -- it can be a software
/// key or an HSM-backed key. The supplied `header.alg` is cross-checked
/// against `signer.algorithm()` before any cryptographic operation;
/// mismatches (including `alg: "none"` or a non-empty `crit`) are rejected.
pub fn sign(
    signer: &dyn kryptering::Signer,
    payload: &[u8],
    header: &JoseHeader,
) -> Result<String> {
    sign_with_options(signer, payload, header, &SignOptions::new())
}

/// Sign a payload and produce a JWS Compact Serialization, honouring the
/// RFC 7797 `b64` and understood-`crit` policy in `opts`.
///
/// With `opts.b64 == false` (RFC 7797 unencoded payload) the payload is
/// embedded verbatim in the second compact segment. RFC 7797 §5.2 forbids a
/// `.` in an unencoded compact payload (it would be confused with the
/// segment separator); such a payload is rejected here.
pub fn sign_with_options(
    signer: &dyn kryptering::Signer,
    payload: &[u8],
    header: &JoseHeader,
    opts: &SignOptions,
) -> Result<String> {
    let b64 = validate_sign_header_opts(header, signer, opts)?;
    let header_json = serde_json::to_vec(header)?;
    let header_b64 = base64url::encode(&header_json);
    let input = signing_input(&header_b64, payload, b64);
    let signature = signer.sign(&input).map_err(JoseError::Crypto)?;
    let sig_b64 = base64url::encode(&signature);
    if b64 {
        let payload_b64 = base64url::encode(payload);
        Ok(format!("{header_b64}.{payload_b64}.{sig_b64}"))
    } else {
        // RFC 7797 §5.2: an unencoded compact payload must not contain a dot.
        if payload.contains(&b'.') {
            return Err(JoseError::InvalidToken(
                "unencoded (b64=false) compact payload must not contain '.'".into(),
            ));
        }
        let payload_str = std::str::from_utf8(payload).map_err(|_| {
            JoseError::InvalidToken(
                "unencoded (b64=false) compact payload must be valid UTF-8".into(),
            )
        })?;
        Ok(format!("{header_b64}.{payload_str}.{sig_b64}"))
    }
}

/// Validate a protected header against the verifier and the
/// understood-`crit` / RFC 7797 policy in `opts`. Returns the effective
/// `b64` flag so the caller can decide how to reconstruct the signing input.
pub(crate) fn validate_header_opts(
    header_b64: &str,
    verifier: &dyn kryptering::Verifier,
    opts: &VerifyOptions,
) -> Result<bool> {
    let header_json = base64url::decode(header_b64)?;
    let header: JoseHeader = serde_json::from_slice(&header_json)?;

    // RFC 7515 §4.1.11: reject crit params we do not understand.
    let crit_listed_b64 = validate_crit(header.crit.as_ref(), &opts.understood_crit)?;

    // Reject alg="none" at the parse layer — never reach the verifier.
    if header.alg == "none" {
        return Err(JoseError::InvalidToken(
            "alg=\"none\" is not permitted".into(),
        ));
    }

    let header_alg = JwsAlgorithm::from_str(&header.alg)?;
    let header_sig_alg = header_alg.to_crypto()?;
    if verifier.algorithm() != header_sig_alg {
        return Err(JoseError::InvalidToken(format!(
            "header alg {} does not match verifier algorithm",
            header.alg
        )));
    }

    resolve_b64(&header, crit_listed_b64)
}

/// Verify a JWS Compact Serialization string.
///
/// Returns the decoded payload on success. The token's `alg` header is
/// cross-checked against `verifier.algorithm()` — mismatches are rejected
/// before any cryptographic operation. `alg: "none"` is always rejected.
pub fn verify(verifier: &dyn kryptering::Verifier, token: &str) -> Result<Vec<u8>> {
    verify_with_options(verifier, token, &VerifyOptions::new())
}

/// Verify a JWS Compact Serialization, honouring the RFC 7797 `b64` and
/// understood-`crit` policy in `opts`.
///
/// With an unencoded payload (`b64:false`) the second compact segment is the
/// raw payload bytes (not base64url) and is returned verbatim; the signing
/// input is reconstructed per RFC 7797.
pub fn verify_with_options(
    verifier: &dyn kryptering::Verifier,
    token: &str,
    opts: &VerifyOptions,
) -> Result<Vec<u8>> {
    ensure_token_size(token)?;
    let parts: Vec<&str> = token.splitn(3, '.').collect();
    if parts.len() != 3 {
        return Err(JoseError::InvalidToken(
            "expected 3 dot-separated parts".into(),
        ));
    }
    let b64 = validate_header_opts(parts[0], verifier, opts)?;
    let payload = if b64 {
        base64url::decode(parts[1])?
    } else {
        parts[1].as_bytes().to_vec()
    };
    let input = signing_input(parts[0], &payload, b64);
    let signature = base64url::decode(parts[2])?;
    let valid = verifier
        .verify(&input, &signature)
        .map_err(JoseError::Crypto)?;
    if !valid {
        return Err(JoseError::InvalidToken(
            "signature verification failed".into(),
        ));
    }
    Ok(payload)
}

/// Sign a payload using a JWK directly — the one-shot signer-side API.
///
/// The signing algorithm is derived from `jwk.alg` (which must be set to
/// one of the JWS algorithm identifiers). The supplied `header.alg` is
/// cross-checked against it, `Jwk::check_op(Sign)` is enforced, the
/// signer is built internally, and `sign` runs. All the phase-4 sign-side
/// bindings (header/signer alg agreement, `alg: "none"` rejection,
/// non-empty `crit` rejection) apply transitively.
pub fn sign_with_jwk(jwk: &crate::jwk::Jwk, payload: &[u8], header: &JoseHeader) -> Result<String> {
    // 1. Derive the algorithm from the JWK.
    let jwk_alg_str = jwk
        .alg
        .as_deref()
        .ok_or_else(|| JoseError::Key("JWK alg must be set for sign_with_jwk".into()))?;
    let jwk_alg = JwsAlgorithm::from_str(jwk_alg_str)?;
    let sig_alg = jwk_alg.to_crypto()?;

    // 2. Header must agree with the JWK's pinned alg.
    if header.alg != jwk_alg_str {
        return Err(JoseError::InvalidHeader(format!(
            "header alg {} does not match JWK alg {jwk_alg_str}",
            header.alg
        )));
    }

    // 3. Enforce use / key_ops.
    jwk.check_op(crate::jwk::JwkOp::Sign)?;

    // 4. Convert to SoftwareKey and build the signer.
    let sw_key = crate::jwk::jwk_to_software_key(jwk)?;
    let signer = kryptering::SoftwareSigner::new(sig_alg, sw_key).map_err(JoseError::Crypto)?;

    // 5. Standard sign — applies the full phase-4 sign-side binding.
    sign(&signer, payload, header)
}

/// Verify a JWS Compact Serialization string using a JWK directly.
///
/// This is the safer one-shot API: it decodes the token's protected
/// header, derives the JWS algorithm from it, enforces `Jwk::check_op`
/// for `Verify`, requires any pinned `jwk.alg` to match, constructs the
/// appropriate `kryptering::SoftwareVerifier` internally, and runs
/// verification. The caller does not need to pick an algorithm, build
/// a verifier, or remember to check `use`/`key_ops`.
///
/// Returns the decoded payload on success. All the usual JWS-layer
/// hardening (alg-header binding, `alg: "none"` rejection, non-empty
/// `crit` rejection, `MAX_TOKEN_BYTES` cap) applies transitively.
pub fn verify_with_jwk(jwk: &crate::jwk::Jwk, token: &str) -> Result<Vec<u8>> {
    // 1. Read the token's header to determine the algorithm.
    let header = decode_header(token)?;
    let header_alg = JwsAlgorithm::from_str(&header.alg)?;
    let sig_alg = header_alg.to_crypto()?;

    // 2. If the JWK pins an alg, require exact agreement with the header.
    if let Some(jwk_alg) = jwk.alg.as_deref() {
        if jwk_alg != header.alg {
            return Err(JoseError::InvalidToken(format!(
                "JWK alg {jwk_alg} does not match token header alg {}",
                header.alg
            )));
        }
    }

    // 3. Enforce use / key_ops.
    jwk.check_op(crate::jwk::JwkOp::Verify)?;

    // 4. Convert to a SoftwareKey and build the verifier.
    let sw_key = crate::jwk::jwk_to_software_key(jwk)?;
    let verifier = kryptering::SoftwareVerifier::new(sig_alg, sw_key).map_err(JoseError::Crypto)?;

    // 5. Standard verify — applies the full JWS-layer binding.
    verify(&verifier, token)
}

/// Decode the header from a JWS Compact Serialization without verifying.
pub fn decode_header(token: &str) -> Result<JoseHeader> {
    ensure_token_size(token)?;
    let header_b64 = token
        .split('.')
        .next()
        .ok_or_else(|| JoseError::InvalidToken("empty token".into()))?;
    let header_json = base64url::decode(header_b64)?;
    serde_json::from_slice(&header_json).map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kryptering::{
        HashAlgorithm, SignatureAlgorithm, SoftwareKey, SoftwareSigner, SoftwareVerifier,
    };

    fn hmac_key() -> SoftwareKey {
        SoftwareKey::Hmac(b"my-secret-key-at-least-32-bytes!".to_vec())
    }

    fn hmac_signer() -> SoftwareSigner {
        SoftwareSigner::new(SignatureAlgorithm::Hmac(HashAlgorithm::Sha256), hmac_key()).unwrap()
    }

    fn hmac_verifier() -> SoftwareVerifier {
        SoftwareVerifier::new(SignatureAlgorithm::Hmac(HashAlgorithm::Sha256), hmac_key()).unwrap()
    }

    #[test]
    fn sign_verify_hmac_roundtrip() {
        let header = JoseHeader::new("HS256");
        let payload = b"hello, world!";

        let token = sign(&hmac_signer(), payload, &header).unwrap();

        // Token should have 3 dot-separated parts.
        assert_eq!(token.split('.').count(), 3);

        // Verify and recover payload.
        let recovered = verify(&hmac_verifier(), &token).unwrap();
        assert_eq!(recovered, payload);
    }

    #[test]
    fn sign_verify_ed25519_roundtrip() {
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;

        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        let signer_key = SoftwareKey::Ed25519 {
            private: Some(signing_key),
            public: verifying_key,
        };
        let verifier_key = SoftwareKey::Ed25519 {
            private: None,
            public: verifying_key,
        };

        let signer = SoftwareSigner::new(SignatureAlgorithm::Ed25519, signer_key).unwrap();
        let verifier = SoftwareVerifier::new(SignatureAlgorithm::Ed25519, verifier_key).unwrap();

        let header = JoseHeader::new("EdDSA");
        let payload = b"EdDSA test payload";

        let token = sign(&signer, payload, &header).unwrap();
        let recovered = verify(&verifier, &token).unwrap();
        assert_eq!(recovered, payload);

        // Decode header without verification.
        let decoded = decode_header(&token).unwrap();
        assert_eq!(decoded.alg, "EdDSA");
    }

    #[test]
    fn verify_wrong_key_fails() {
        let header = JoseHeader::new("HS256");
        let payload = b"secret data";

        let token = sign(&hmac_signer(), payload, &header).unwrap();

        // Verify with a different key.
        let wrong_key = SoftwareKey::Hmac(b"wrong-key-that-is-also-32-bytes!".to_vec());
        let wrong_verifier =
            SoftwareVerifier::new(SignatureAlgorithm::Hmac(HashAlgorithm::Sha256), wrong_key)
                .unwrap();

        let result = verify(&wrong_verifier, &token);
        assert!(result.is_err());
    }

    #[test]
    fn malformed_token_wrong_parts() {
        let result = verify(&hmac_verifier(), "only.two");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("3 dot-separated parts"),
            "unexpected error: {err}"
        );

        let result2 = verify(&hmac_verifier(), "noparts");
        assert!(result2.is_err());
    }

    #[test]
    fn tampered_payload_fails_verification() {
        let header = JoseHeader::new("HS256");
        let payload = b"original payload";

        let token = sign(&hmac_signer(), payload, &header).unwrap();

        // Tamper with the payload part (second segment).
        let parts: Vec<&str> = token.splitn(3, '.').collect();
        let tampered_payload = base64url::encode(b"tampered payload");
        let tampered_token = format!("{}.{}.{}", parts[0], tampered_payload, parts[2]);

        let result = verify(&hmac_verifier(), &tampered_token);
        assert!(result.is_err());
    }

    /// Algorithm confusion regression (J-01): a token with header alg="RS256"
    /// MUST be rejected by an HMAC verifier, even if the attacker crafted a
    /// matching HMAC signature using the RSA public key as the HMAC secret.
    ///
    /// The attacker-forged token is constructed manually because the
    /// phase-4 sign-side binding refuses to emit such a token through
    /// the library's own API.
    #[test]
    fn alg_header_mismatch_is_rejected() {
        use kryptering::Signer;
        let payload = b"payload";

        // Attacker-forged token: header says RS256, but the signature is
        // HMAC-SHA256 over the signing input using the verifier's key.
        let mut header = JoseHeader::new("RS256");
        header.kid = Some("attacker".into());
        let header_b64 = base64url::encode(&serde_json::to_vec(&header).unwrap());
        let payload_b64 = base64url::encode(payload);
        let signing_input = format!("{header_b64}.{payload_b64}");
        let sig = hmac_signer().sign(signing_input.as_bytes()).unwrap();
        let token = format!("{signing_input}.{}", base64url::encode(&sig));

        // HMAC verifier must refuse because header alg disagrees with verifier algorithm.
        let result = verify(&hmac_verifier(), &token);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("does not match verifier algorithm"),
            "unexpected error: {err}"
        );
    }

    /// none-downgrade regression (J-03): a token with alg="none" must be
    /// rejected unconditionally, even if the caller hands in a real verifier.
    #[test]
    fn alg_none_is_rejected() {
        let payload = b"payload";
        let header = JoseHeader::new("none");
        // Build a token with alg="none" manually — no signer will accept "none",
        // so we craft the parts directly.
        let header_b64 = base64url::encode(&serde_json::to_vec(&header).unwrap());
        let payload_b64 = base64url::encode(payload);
        let token = format!("{header_b64}.{payload_b64}.");

        let result = verify(&hmac_verifier(), &token);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("none"), "unexpected error: {err}");
    }

    /// Phase 9: sign_with_jwk + verify_with_jwk round-trip.
    #[test]
    fn sign_with_jwk_roundtrip() {
        let mut jwk = crate::jwk::generate_symmetric(32).unwrap();
        jwk.alg = Some("HS256".into());

        let header = JoseHeader::new("HS256");
        let token = sign_with_jwk(&jwk, b"hello", &header).unwrap();

        let recovered = verify_with_jwk(&jwk, &token).unwrap();
        assert_eq!(recovered, b"hello");
    }

    /// Phase 9: sign_with_jwk rejects a JWK with no alg pinned.
    #[test]
    fn sign_with_jwk_rejects_missing_alg() {
        let jwk = crate::jwk::generate_symmetric(32).unwrap(); // no alg set
        let header = JoseHeader::new("HS256");
        let err = sign_with_jwk(&jwk, b"p", &header).unwrap_err().to_string();
        assert!(err.contains("alg must be set"), "unexpected: {err}");
    }

    /// Phase 9: sign_with_jwk rejects use="enc" even on the sign side.
    #[test]
    fn sign_with_jwk_rejects_use_enc() {
        let mut jwk = crate::jwk::generate_symmetric(32).unwrap();
        jwk.alg = Some("HS256".into());
        jwk.use_ = Some("enc".into());

        let header = JoseHeader::new("HS256");
        let err = sign_with_jwk(&jwk, b"p", &header).unwrap_err().to_string();
        assert!(err.contains("`use` is enc"), "unexpected: {err}");
    }

    /// Phase 9: header alg must agree with jwk.alg.
    #[test]
    fn sign_with_jwk_header_alg_must_match() {
        let mut jwk = crate::jwk::generate_symmetric(32).unwrap();
        jwk.alg = Some("HS256".into());
        // Header claims HS384 but JWK is HS256.
        let header = JoseHeader::new("HS384");
        let err = sign_with_jwk(&jwk, b"p", &header).unwrap_err().to_string();
        assert!(err.contains("does not match JWK alg"), "unexpected: {err}");
    }

    /// Phase 8: verify_with_jwk happy path (HMAC).
    #[test]
    fn verify_with_jwk_hmac_roundtrip() {
        // Generate a symmetric JWK for HS256.
        let mut jwk = crate::jwk::generate_symmetric(32).unwrap();
        jwk.alg = Some("HS256".into());

        // Sign via SoftwareKey path for setup.
        let sw = crate::jwk::jwk_to_software_key(&jwk).unwrap();
        let signer =
            kryptering::SoftwareSigner::new(JwsAlgorithm::HS256.to_crypto().unwrap(), sw).unwrap();
        let header = JoseHeader::new("HS256");
        let token = sign(&signer, b"payload", &header).unwrap();

        // Verify via the one-shot JWK API.
        let recovered = verify_with_jwk(&jwk, &token).unwrap();
        assert_eq!(recovered, b"payload");
    }

    /// Phase 8: verify_with_jwk enforces use="enc" blocks Verify.
    #[test]
    fn verify_with_jwk_use_enc_is_rejected() {
        let mut jwk = crate::jwk::generate_symmetric(32).unwrap();
        jwk.alg = Some("HS256".into());
        jwk.use_ = Some("enc".into());

        let sw = crate::jwk::jwk_to_software_key(&jwk).unwrap();
        let signer =
            kryptering::SoftwareSigner::new(JwsAlgorithm::HS256.to_crypto().unwrap(), sw).unwrap();
        let header = JoseHeader::new("HS256");
        let token = sign(&signer, b"payload", &header).unwrap();

        let err = verify_with_jwk(&jwk, &token).unwrap_err().to_string();
        assert!(err.contains("`use` is enc"), "unexpected: {err}");
    }

    /// Phase 8: verify_with_jwk enforces JWK alg must match token header alg.
    #[test]
    fn verify_with_jwk_pinned_alg_mismatch() {
        let mut jwk = crate::jwk::generate_symmetric(32).unwrap();
        jwk.alg = Some("HS384".into()); // JWK claims HS384...

        // ...but we build an HS256-keyed signer and sign with HS256.
        let k_bytes = crate::base64url::decode(jwk.k.as_ref().unwrap()).unwrap();
        let signer = kryptering::SoftwareSigner::new(
            JwsAlgorithm::HS256.to_crypto().unwrap(),
            kryptering::SoftwareKey::Hmac(k_bytes),
        )
        .unwrap();
        let header = JoseHeader::new("HS256");
        let token = sign(&signer, b"payload", &header).unwrap();

        let err = verify_with_jwk(&jwk, &token).unwrap_err().to_string();
        assert!(
            err.contains("does not match token header alg"),
            "unexpected: {err}"
        );
    }

    /// Phase 4: sign-side mismatch between header.alg and signer.algorithm()
    /// is rejected. Mirror of the verify-side alg-confusion fix.
    #[test]
    fn sign_rejects_header_alg_mismatch() {
        // HMAC signer, but header advertises RS256.
        let header = JoseHeader::new("RS256");
        let err = sign(&hmac_signer(), b"payload", &header)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("does not match signer algorithm"),
            "unexpected error: {err}"
        );
    }

    /// Phase 4: sign refuses alg="none" unconditionally.
    #[test]
    fn sign_rejects_alg_none() {
        let header = JoseHeader::new("none");
        let err = sign(&hmac_signer(), b"payload", &header)
            .unwrap_err()
            .to_string();
        assert!(err.contains("none"), "unexpected error: {err}");
    }

    /// Phase 4: sign refuses a non-empty crit header.
    #[test]
    fn sign_rejects_crit() {
        let mut header = JoseHeader::new("HS256");
        header.crit = Some(vec!["ext".into()]);
        let err = sign(&hmac_signer(), b"payload", &header)
            .unwrap_err()
            .to_string();
        assert!(err.contains("crit"), "unexpected error: {err}");
    }

    /// Phase 3: oversized tokens are rejected before any decoding.
    #[test]
    fn oversize_token_is_rejected() {
        let big = "a".repeat(crate::MAX_TOKEN_BYTES + 1);
        let err = verify(&hmac_verifier(), &big).unwrap_err().to_string();
        assert!(err.contains("MAX_TOKEN_BYTES"), "unexpected error: {err}");
    }

    #[test]
    fn oversize_decode_header_is_rejected() {
        let big = "a".repeat(crate::MAX_TOKEN_BYTES + 1);
        let err = decode_header(&big).unwrap_err().to_string();
        assert!(err.contains("MAX_TOKEN_BYTES"), "unexpected error: {err}");
    }

    /// crit enforcement regression (J-04): a crit array naming an extension
    /// the library does not understand must be rejected on the verify path.
    /// Token constructed manually because the sign-side binding refuses to
    /// emit such a token.
    #[test]
    fn unknown_crit_is_rejected() {
        use kryptering::Signer;
        let payload = b"payload";
        let mut header = JoseHeader::new("HS256");
        header.crit = Some(vec!["x-unknown-ext".to_string()]);
        let header_b64 = base64url::encode(&serde_json::to_vec(&header).unwrap());
        let payload_b64 = base64url::encode(payload);
        let signing_input = format!("{header_b64}.{payload_b64}");
        let sig = hmac_signer().sign(signing_input.as_bytes()).unwrap();
        let token = format!("{signing_input}.{}", base64url::encode(&sig));

        let result = verify(&hmac_verifier(), &token);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("crit"), "unexpected error: {err}");
    }

    /// An empty `crit` array is itself a protocol violation (RFC 7515
    /// §4.1.11) and must be rejected.
    #[test]
    fn empty_crit_is_rejected() {
        use kryptering::Signer;
        let mut header = JoseHeader::new("HS256");
        header.crit = Some(vec![]);
        let header_b64 = base64url::encode(&serde_json::to_vec(&header).unwrap());
        let payload_b64 = base64url::encode(b"p");
        let signing_input = format!("{header_b64}.{payload_b64}");
        let sig = hmac_signer().sign(signing_input.as_bytes()).unwrap();
        let token = format!("{signing_input}.{}", base64url::encode(&sig));
        let err = verify(&hmac_verifier(), &token).unwrap_err().to_string();
        assert!(err.contains("crit must not be empty"), "unexpected: {err}");
    }

    /// RFC 7797 round-trip: sign and verify with an unencoded payload.
    #[test]
    fn b64_false_roundtrip() {
        let mut header = JoseHeader::new("HS256");
        header.crit = Some(vec!["b64".to_string()]);
        header
            .extra
            .insert("b64".to_string(), serde_json::Value::Bool(false));

        let payload = b"unencoded RFC 7797 payload";
        let opts = SignOptions {
            b64: false,
            understood_crit: vec![],
        };
        let token = sign_with_options(&hmac_signer(), payload, &header, &opts).unwrap();

        // The middle segment is the raw payload, not base64url.
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts[1].as_bytes(), payload);

        let recovered =
            verify_with_options(&hmac_verifier(), &token, &VerifyOptions::new()).unwrap();
        assert_eq!(recovered, payload);
    }

    /// RFC 7797 §6: a `b64` param that is not listed in `crit` must be
    /// rejected (it would otherwise be unprotected).
    #[test]
    fn b64_false_without_crit_is_rejected() {
        let mut header = JoseHeader::new("HS256");
        // b64=false but crit does NOT list it.
        header
            .extra
            .insert("b64".to_string(), serde_json::Value::Bool(false));
        let opts = SignOptions {
            b64: false,
            understood_crit: vec![],
        };
        let err = sign_with_options(&hmac_signer(), b"p", &header, &opts)
            .unwrap_err()
            .to_string();
        assert!(err.contains("must be listed in crit"), "unexpected: {err}");
    }

    /// An unencoded compact payload containing a dot is rejected (RFC 7797
    /// §5.2 — it would collide with the segment separator).
    #[test]
    fn b64_false_dotted_payload_is_rejected() {
        let mut header = JoseHeader::new("HS256");
        header.crit = Some(vec!["b64".to_string()]);
        header
            .extra
            .insert("b64".to_string(), serde_json::Value::Bool(false));
        let opts = SignOptions {
            b64: false,
            understood_crit: vec![],
        };
        let err = sign_with_options(&hmac_signer(), b"a.b", &header, &opts)
            .unwrap_err()
            .to_string();
        assert!(err.contains("must not contain"), "unexpected: {err}");
    }

    /// A caller-supplied understood crit param (JAdES-style) is accepted.
    #[test]
    fn caller_understood_crit_is_accepted() {
        let mut header = JoseHeader::new("HS256");
        header.crit = Some(vec!["etsiU".to_string()]);
        header
            .extra
            .insert("etsiU".to_string(), serde_json::Value::Array(vec![]));
        let opts = SignOptions {
            b64: true,
            understood_crit: vec!["etsiU".to_string()],
        };
        let token = sign_with_options(&hmac_signer(), b"p", &header, &opts).unwrap();
        let vopts = VerifyOptions {
            understood_crit: vec!["etsiU".to_string()],
        };
        let recovered = verify_with_options(&hmac_verifier(), &token, &vopts).unwrap();
        assert_eq!(recovered, b"p");
        // Without declaring etsiU understood, verification rejects it.
        let err = verify_with_options(&hmac_verifier(), &token, &VerifyOptions::new())
            .unwrap_err()
            .to_string();
        assert!(err.contains("crit"), "unexpected: {err}");
    }

    /// ML-DSA sign/verify round-trip via the JWK API.
    ///
    /// One test per variant — ML-DSA keypairs are large (the expanded
    /// signing key for ML-DSA-87 is ~5 KiB), so looping all three in one
    /// test function blows the default debug-build stack.
    #[cfg(feature = "post-quantum")]
    fn mldsa_roundtrip(variant: kryptering::MlDsaVariant) {
        let jwk = crate::jwk::generate::generate_mldsa(variant).unwrap();
        let header = JoseHeader::new(variant.name());
        let payload = b"post-quantum JWS payload";

        let token = sign_with_jwk(&jwk, payload, &header)
            .unwrap_or_else(|e| panic!("{} sign failed: {e}", variant.name()));
        assert_eq!(token.split('.').count(), 3);

        let recovered = verify_with_jwk(&jwk, &token)
            .unwrap_or_else(|e| panic!("{} verify failed: {e}", variant.name()));
        assert_eq!(recovered, payload);
    }

    #[cfg(feature = "post-quantum")]
    #[test]
    fn sign_verify_mldsa_44_roundtrip() {
        mldsa_roundtrip(kryptering::MlDsaVariant::MlDsa44);
    }

    #[cfg(feature = "post-quantum")]
    #[test]
    fn sign_verify_mldsa_65_roundtrip() {
        mldsa_roundtrip(kryptering::MlDsaVariant::MlDsa65);
    }

    /// ML-DSA-87's expanded signing key is large enough that seed expansion
    /// plus ML-DSA signing blow the default debug-build test-thread
    /// stack (2 MiB). Run this variant on a fresh 8 MiB thread so the
    /// test actually completes. Release builds fit in the default stack,
    /// so this is purely a test-harness concern.
    #[cfg(feature = "post-quantum")]
    #[test]
    fn sign_verify_mldsa_87_roundtrip() {
        std::thread::Builder::new()
            .stack_size(8 * 1024 * 1024)
            .spawn(|| mldsa_roundtrip(kryptering::MlDsaVariant::MlDsa87))
            .expect("spawn mldsa-87 test thread")
            .join()
            .expect("mldsa-87 test thread panicked");
    }

    /// ML-DSA alg-confusion regression: a token signed with ML-DSA-44 must
    /// be rejected by a JWK pinned to ML-DSA-65. The phase-4 alg-binding
    /// catches the mismatch before any crypto runs.
    #[cfg(feature = "post-quantum")]
    #[test]
    fn mldsa_variant_mismatch_is_rejected() {
        use kryptering::MlDsaVariant;
        let jwk_44 = crate::jwk::generate::generate_mldsa(MlDsaVariant::MlDsa44).unwrap();
        let jwk_65 = crate::jwk::generate::generate_mldsa(MlDsaVariant::MlDsa65).unwrap();

        let header = JoseHeader::new("ML-DSA-44");
        let token = sign_with_jwk(&jwk_44, b"payload", &header).unwrap();

        // Verifier pinned to ML-DSA-65 must refuse a ML-DSA-44 token.
        let err = verify_with_jwk(&jwk_65, &token).unwrap_err().to_string();
        assert!(err.contains("does not match"), "unexpected error: {err}");
    }
}
