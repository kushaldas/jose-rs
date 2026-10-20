//! Error and result types for JOSE operations.

/// Errors produced by JOSE operations.
#[derive(Debug, thiserror::Error)]
pub enum JoseError {
    /// A cryptographic backend operation failed.
    #[error("cryptographic error: {0}")]
    Crypto(#[from] kryptering::Error),

    /// A serialized JOSE token is malformed or fails structural validation.
    #[error("invalid token format: {0}")]
    InvalidToken(String),

    /// A JOSE protected header is malformed or violates configured policy.
    #[error("invalid header: {0}")]
    InvalidHeader(String),

    /// JWT claims are malformed or violate configured validation policy.
    #[error("invalid claims: {0}")]
    InvalidClaims(String),

    /// The requested or encoded JOSE algorithm is unsupported.
    #[error("unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),

    /// Key material is malformed, incomplete, or incompatible with an operation.
    #[error("key error: {0}")]
    Key(String),

    /// JWT validation found that the token has expired.
    #[error("token expired")]
    Expired,

    /// JWT validation found that the token is not valid yet.
    #[error("token not yet valid")]
    NotYetValid,

    /// The JWT issuer does not match the configured issuer.
    #[error("invalid issuer")]
    InvalidIssuer,

    /// The JWT audience does not contain the configured audience.
    #[error("invalid audience")]
    InvalidAudience,

    /// JSON serialization or deserialization failed.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Base64url decoding failed.
    #[error("base64 decode error: {0}")]
    Base64(String),
}

/// The coarse kind of an error, for callers who need to branch without matching on
/// every variant.
///
/// Why this exists rather than more variants: [`JoseError`] is an exhaustive enum,
/// so adding a variant is a breaking change for every downstream `match`, while a
/// category is additive and can be extended without one. Match on this when the
/// question is "what sort of thing went wrong"; match on [`JoseError`] when the
/// answer must distinguish, say, expiry from audience.
///
/// # What this deliberately does not separate
///
/// [`ErrorCategory::Cryptographic`] covers *both* "the MAC/tag did not match" and
/// "the backend refused the key", and no accessor splits them. That is not laziness:
/// a caller-visible distinction between an integrity failure and a key failure is an
/// oracle — it tells a prober whether a structure was well-formed enough to reach the
/// tag check, which is precisely how padding and oracle attacks get their signal. The
/// distinction exists internally; it is not exported.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ErrorCategory {
    /// This build cannot perform the requested capability: an algorithm, curve, key
    /// type, or serialization it does not implement. Retrying with different input
    /// will not help; enabling a feature or changing the request will.
    UnsupportedCapability,

    /// The document could not be parsed, or it parsed and violated its own
    /// structure rules: malformed base64url, a duplicated member, a `crit` naming
    /// an absent parameter, claims that are not an object.
    InvalidStructure,

    /// The document was well-formed and cryptographically fine, but the caller's
    /// policy refused it: expiry, not-yet-valid, issuer, audience.
    PolicyRejection,

    /// A signature or MAC was checked and returned "does not verify".
    ///
    /// Only produced where this crate can say so precisely: its own verdict from a
    /// completed check. A backend that *refuses* a signature as malformed (an ECDSA
    /// scalar outside the curve order, for instance) arrives as
    /// [`ErrorCategory::Cryptographic`] instead, and the two are deliberately not
    /// reconciled into one bucket by inspecting messages. Both mean "this did not
    /// authenticate"; a caller that branches differently on which of the two it was
    /// has built the oracle this design refuses to expose. Use
    /// [`JoseError::is_authentication_failure`] for the merged question.
    AuthenticationFailure,

    /// A key is malformed, incomplete, or not permitted for the operation
    /// (`use`/`key_ops`, a pinned `alg` mismatch, a size below the algorithm's
    /// minimum).
    KeyMaterial,

    /// A cryptographic backend reported a failure. Covers integrity failures of
    /// encrypted content, which are intentionally not labelled as such.
    Cryptographic,

    /// Encoding or serialization failure at the JSON/base64url boundary.
    Encoding,
}

impl JoseError {
    /// Classify this error.
    ///
    /// Coarse by design. Note that [`JoseError::InvalidHeader`] and
    /// [`JoseError::InvalidClaims`] land in
    /// [`ErrorCategory::InvalidStructure`] even when the message describes a policy
    /// refusal (e.g. a required `kid`): the variants carry structure *and* policy
    /// cases, and claiming a finer split than the variants express would make the
    /// category a second, contradicting source of truth. Use the specific variants
    /// when the distinction matters.
    pub fn category(&self) -> ErrorCategory {
        match self {
            JoseError::UnsupportedAlgorithm(_) => ErrorCategory::UnsupportedCapability,
            JoseError::InvalidToken(_)
            | JoseError::InvalidHeader(_)
            | JoseError::InvalidClaims(_) => {
                // A signature that simply did not verify is reported as
                // `InvalidToken` with this crate's own fixed message. Comparing
                // against the constant this crate emits — rather than substring
                // sniffing arbitrary text — keeps the classification exact.
                if self.is_own_authentication_failure() {
                    ErrorCategory::AuthenticationFailure
                } else {
                    ErrorCategory::InvalidStructure
                }
            }
            JoseError::Expired
            | JoseError::NotYetValid
            | JoseError::InvalidIssuer
            | JoseError::InvalidAudience => ErrorCategory::PolicyRejection,
            JoseError::Key(_) => ErrorCategory::KeyMaterial,
            JoseError::Crypto(_) => ErrorCategory::Cryptographic,
            JoseError::Json(_) | JoseError::Base64(_) => ErrorCategory::Encoding,
        }
    }

    /// The merged question: "did a verification fail?".
    ///
    /// True for this crate's own "signature did not verify" verdict *and* for backend
    /// cryptographic failures. On a path that was verifying or decrypting, that union is
    /// exactly "the credential did not authenticate", and it is exposed as one answer
    /// because splitting it (was the tag wrong, or was the structure refused on the way to
    /// the tag?) is a signal an attacker can request.
    ///
    /// Call it only on errors from a verify/decrypt path: on a key-import or encryption
    /// path a [`JoseError::Crypto`] means something else entirely, and this function
    /// cannot tell which path produced the error.
    pub fn is_authentication_failure(&self) -> bool {
        match self {
            JoseError::Crypto(_) => true,
            JoseError::InvalidToken(message) => message == crate::SIGNATURE_VERIFICATION_FAILED,
            _ => false,
        }
    }

    /// `true` when this is this crate's own "the signature did not verify" verdict.
    ///
    /// Implemented against the constants this crate raises, not by searching
    /// messages: a heuristic over error text would classify a *description* of a
    /// failure as the failure itself.
    fn is_own_authentication_failure(&self) -> bool {
        match self {
            JoseError::InvalidToken(message) => message == crate::SIGNATURE_VERIFICATION_FAILED,
            _ => false,
        }
    }
}

/// Result type returned by `jose-rs` operations.
pub type Result<T> = std::result::Result<T, JoseError>;
