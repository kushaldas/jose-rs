//! Values that arrived under authentication, and the header that came with them.
//!
//! The trust boundary in JOSE is not "trusted versus untrusted data" — after a
//! signature check or an AEAD opening, everything is trusted *as far as the check
//! reached*. The boundary is between:
//!
//! * **what was integrity-protected** — the JWS protected header, the JWE
//!   protected header, and the payload/plaintext they authenticated; and
//! * **what was not** — JWE `unprotected`, the per-signature/per-recipient
//!   `header` member, and the JSON serialization's shared `unprotected` object.
//!   Those bytes travel in the clear and are attacker-chosen even when the
//!   document verifies perfectly.
//!
//! The concrete hazard is order of operations: an implementation that reads
//! `unprotected.kid` to *choose* a key has made its own authentication decision
//! depend on unauthenticated input, which is how "encrypt-then-sign" confusion and
//! kid-confusion attacks work. This module cannot prevent a caller from ignoring
//! that, but it removes the most common way to fall into it by accident —
//! re-parsing the header after the fact, from whichever copy is nearest, and
//! getting the unprotected one.
//!
//! [`Authenticated<T>`] carries the verified value, the authenticated header, and
//! the unprotected metadata **as separate, differently-named fields**, and it is
//! only constructible by the verification paths in this crate. There is no public
//! constructor, so an `Authenticated` value always means what its name claims.
//!
//! ```
//! use jose_rs::jwk;
//! use jose_rs::jws::compact;
//! use jose_rs::JoseHeader;
//!
//! let mut jwk = jwk::generate_ed25519()?;
//! jwk.alg = Some("EdDSA".into());
//! let mut header = JoseHeader::new("EdDSA");
//! header.typ = Some("application+jwt".into());
//! let token = compact::sign_with_jwk(&jwk, b"payload", &header)?;
//!
//! // One parse, and the authenticated header comes back with the payload.
//! let outcome = compact::verify_with_jwk_authenticated(&jwk, &token)?;
//! assert_eq!(outcome.value, b"payload");
//! assert_eq!(outcome.protected.typ.as_deref(), Some("application+jwt"));
//! // Nothing unauthenticated was carried in a compact JWS at all.
//! assert!(outcome.unprotected.is_empty());
//! # Ok::<(), jose_rs::JoseError>(())
//! ```

use crate::header::JoseHeader;
use serde_json::Value;

/// A value that arrived under signature or AEAD authentication.
///
/// Fields are public because they are the answer, not because they are
/// interchangeable: [`protected`](Self::protected) was integrity-protected by the
/// operation that produced this value, and [`unprotected`](Self::unprotected)
/// explicitly was not. Use the protected header for any decision — algorithm, key
/// identity, content type, `crit` — and treat the unprotected entries as
/// display-only metadata.
#[derive(Debug, Clone)]
pub struct Authenticated<T> {
    /// The verified payload, plaintext, or parsed claims.
    pub value: T,
    /// The protected header that was authenticated with this value.
    ///
    /// This is the header *the signature covered* (or the JWE protected header the
    /// AEAD tag authenticated), parsed once by the verification path. It is not a
    /// re-parse of whatever bytes the caller still has.
    pub protected: JoseHeader,
    /// Unauthenticated metadata carried by the document, verbatim.
    ///
    /// A compact JWS carries none, so this is usually empty. A flattened or general
    /// JWS/JWE can carry several objects (the shared `unprotected` member plus a
    /// `header` member per signature/recipient); each is one entry here, in the
    /// order they appeared.
    ///
    /// **Never select a key, an algorithm, or a trust decision from these.** They
    /// are not integrity-protected: a document that verifies perfectly can carry a
    /// hostile `kid` here.
    pub unprotected: Vec<Value>,
}

impl<T> Authenticated<T> {
    /// Construct an outcome.
    ///
    /// `pub(crate)`: the type's meaning is "a verification path produced this", and
    /// a public constructor would let anyone mint that claim. Verification paths in
    /// this crate call it; callers only ever receive the result.
    pub(crate) fn new(value: T, protected: JoseHeader, unprotected: Vec<Value>) -> Self {
        Self {
            value,
            protected,
            unprotected,
        }
    }

    /// Discard the header and keep the value.
    pub fn into_value(self) -> T {
        self.value
    }

    /// Transform the value, keeping the header context.
    ///
    /// Useful for parsing a verified payload into a domain type without losing the
    /// authenticated header next to it.
    pub fn map<U, F: FnOnce(T) -> U>(self, f: F) -> Authenticated<U> {
        Authenticated {
            value: f(self.value),
            protected: self.protected,
            unprotected: self.unprotected,
        }
    }

    /// The authenticated `alg` value.
    ///
    /// A convenience for the single most common header read after verification —
    /// and the reason it exists as a method is so that read does not have to reach
    /// for a header from somewhere else.
    pub fn algorithm(&self) -> &str {
        &self.protected.alg
    }

    /// The `kid` from the **authenticated** header only.
    ///
    /// Deliberately does not consult [`unprotected`](Self::unprotected), unlike a
    /// `PlainHeader`-style getter that would search every object it can find.
    pub fn kid(&self) -> Option<&str> {
        self.protected.kid.as_deref()
    }

    /// `true` when the document carried any unauthenticated metadata.
    ///
    /// A caller that logs "this document tried to tell me something outside the
    /// signature" can gate on this.
    pub fn has_unprotected(&self) -> bool {
        !self.unprotected.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn outcome() -> Authenticated<Vec<u8>> {
        let mut protected = JoseHeader::new("ES256");
        protected.kid = Some("signed-kid".into());
        Authenticated::new(
            b"payload".to_vec(),
            protected,
            vec![serde_json::json!({"kid": "unsigned-kid"})],
        )
    }

    #[test]
    fn the_kid_accessor_reads_the_authenticated_header_only() {
        // The whole point of the type in one assertion: the document carries a
        // second, unauthenticated `kid`, and the accessor must not see it.
        let outcome = outcome();
        assert_eq!(outcome.kid(), Some("signed-kid"));
        assert_eq!(
            outcome.unprotected[0].get("kid").and_then(Value::as_str),
            Some("unsigned-kid"),
            "the unauthenticated value is still *reported*, it is simply not authoritative"
        );
        assert!(outcome.has_unprotected());
    }

    #[test]
    fn mapping_keeps_the_header_context() {
        let parsed = outcome().map(|bytes| String::from_utf8(bytes).unwrap());
        assert_eq!(parsed.value, "payload");
        assert_eq!(parsed.algorithm(), "ES256");
        assert_eq!(parsed.kid(), Some("signed-kid"));
        assert_eq!(parsed.unprotected.len(), 1);
    }

    #[test]
    fn a_compact_style_document_has_no_unprotected_metadata() {
        let outcome = Authenticated::new(b"x".to_vec(), JoseHeader::new("EdDSA"), Vec::new());
        assert!(!outcome.has_unprotected());
        assert_eq!(outcome.clone().into_value(), b"x".to_vec());
    }
}
