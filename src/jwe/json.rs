//! JWE JSON Serialization (RFC 7516 §7.2), single recipient, protected header.
//!
//! This module implements the *flattened* syntax (RFC 7516 §7.2.2) for the
//! key-management and content algorithms this crate already supports, with
//! all JOSE header parameters carried in the integrity-protected `protected`
//! member:
//!
//! ```text
//! {
//!   "protected":    "eyJhbGciOiJBMjU2S1ciLCJlbmMiOiJBMjU2R0NNIn0",
//!   "encrypted_key":"…",
//!   "iv":           "…",
//!   "ciphertext":   "…",
//!   "tag":          "…"
//! }
//! ```
//!
//! The unprotected header locations — `unprotected` (shared) and `header`
//! (per-recipient) — are **read**, under one rule (ADR 0013): a value the
//! message cannot authenticate may only answer a question something else has
//! already answered. So `alg` is accepted there only for a key that pins it (the
//! JWK APIs), while `enc` — which decides how the ciphertext and tag octets are
//! split — must always be integrity protected, and the parameter names across
//! the three locations must be disjoint (RFC 7516 §7.2.1). This crate never
//! *emits* unprotected parameters.
//!
//! A message carrying `recipients` is the *general* syntax and is refused here
//! by name: parse it with [`crate::jwe::general::GeneralJwe`], which flattens to
//! this module's type internally and so shares every rule below (ADR 0014).
//!
//! External additional authenticated data *is* supported: pass it with
//! [`crate::jwe::JweEncryptOptions::with_external_aad`] when encrypting and
//! [`crate::jwe::JweDecryptOptions::with_external_aad`] when decrypting. It
//! lands in the `aad` member and is authenticated (not encrypted), which is
//! exactly why the compact serialization cannot carry it.
//!
//! Unknown *private* members are ignored during processing as RFC 7516
//! §7.2.1 requires, but they are retained in [`FlattenedJwe::other`] so that
//! re-serializing does not silently drop data and
//! [`FlattenedJwe::to_compact`] can refuse a lossy conversion.
//!
//! # Reading order
//!
//! [`FlattenedJwe`] is parsed, not authenticated. Decryption runs the shared
//! policy from the crate-internal `jwe::internal` module — the same code path as
//! the compact
//! serialization — and returns plaintext only after the content tag verifies
//! over the *verbatim* `protected` bytes (plus external AAD, when present).

use crate::algorithm::{JweAlgorithm, JweEncryption};
use crate::base64url;
use crate::error::{JoseError, Result};
use crate::header::JoseHeader;
use crate::jwe::internal::{
    self, ensure_token_size, jwe_alg_decrypt_op, jwe_alg_encrypt_op, minimum_plaintext_len,
    recipient_key, JweDecryptOptions, JweEncryptOptions, KeyMaterial,
};
use crate::member_map::MemberMap;

/// Top-level members of the JWE JSON Serialization that this module rejects by
/// name, with the reason surfaced to the caller.
///
/// These are *registered* members (RFC 7516 §7.2.1), not unknown private
/// members, so ignoring them would silently discard header parameters that
/// change how the ciphertext must be interpreted.
const REJECTED_MEMBERS: &[(&str, &str)] = &[(
    "recipients",
    "this is a general JWE JSON serialization (RFC 7516 §7.2.1); parse it with \
         jose_rs::jwe::general::GeneralJwe::from_json and decrypt a named recipient",
)];

/// Members that identify the object as a JWS rather than a JWE
/// (RFC 7516 §9: a JWS has `payload`/`signature`, a JWE has `ciphertext`).
///
/// Checked before `ciphertext` is reported missing so a mis-routed token
/// produces "this is a JWS" instead of a confusing structural error.
pub(crate) const JWS_MEMBERS: &[&str] = &["payload", "signatures", "signature"];

/// A flattened JWE JSON Serialization (RFC 7516 §7.2.2), parsed but not yet
/// authenticated.
///
/// Every member keeps its **encoded string form** rather than decoded bytes:
/// `protected` is the exact data the content tag covers, and re-encoding a
/// re-serialized header would authenticate something different.
///
/// ```
/// use jose_rs::jwe::json;
/// # use jose_rs::{JweAlgorithm, JweEncryption};
/// let key = [7u8; 32]; // Example only; generate a secret key in production.
/// let jwe = json::encrypt_flattened(&key, b"hi", JweAlgorithm::Dir, JweEncryption::A256GCM)?;
/// let text = jwe.to_json()?;
/// let back = json::FlattenedJwe::from_json(&text)?;
/// assert_eq!(json::decrypt_flattened(&key, &back)?, b"hi");
/// # Ok::<(), jose_rs::JoseError>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlattenedJwe {
    /// `BASE64URL(UTF8(JWE Protected Header))`.
    ///
    /// Required by this crate version: `enc` (and, for the raw-key APIs,
    /// `alg`) must be integrity protected, so a message with no protected
    /// header cannot be authenticated here at all (ADR 0011).
    pub protected: Option<String>,
    /// JWE Shared Unprotected Header, the `unprotected` member
    /// (RFC 7516 §7.2.1).
    ///
    /// **Not integrity protected.** Nothing in a decrypt decision may depend on
    /// these values unless the caller independently pinned the answer to the key
    /// it holds — which is what the JWK APIs do for `alg` and the only exception
    /// this crate grants (ADR 0013). Retained verbatim so that re-serializing
    /// does not drop them.
    pub unprotected: Option<serde_json::Map<String, serde_json::Value>>,
    /// JWE Per-Recipient Unprotected Header, the flattened `header` member
    /// (RFC 7516 §7.2.2). Same trust rules as [`Self::unprotected`].
    pub header: Option<serde_json::Map<String, serde_json::Value>>,
    /// `BASE64URL(JWE AAD)`: external additional authenticated data supplied
    /// out of band (RFC 7516 §2, §7.2.1).
    ///
    /// Authenticated but not encrypted, and covered by the content tag only
    /// through the AAD input `ASCII(protected || '.' || this member)`, so a
    /// recipient must know these bytes before it can authenticate the message.
    /// See [`crate::jwe::JweDecryptOptions::with_external_aad`].
    pub aad: Option<String>,
    /// `BASE64URL(JWE Encrypted Key)`; `None` when the member is absent,
    /// which is required for `dir` (RFC 7516 §5.1 step 5).
    pub encrypted_key: Option<String>,
    /// `BASE64URL(JWE Initialization Vector)`.
    pub iv: Option<String>,
    /// `BASE64URL(JWE Ciphertext)`. The only mandatory member.
    pub ciphertext: String,
    /// `BASE64URL(JWE Authentication Tag)`.
    pub tag: Option<String>,
    /// Unrecognized top-level members, retained in document order.
    ///
    /// Ignored while processing (RFC 7516 §7.2.1) but kept so that
    /// [`Self::to_json`] round-trips and [`Self::to_compact`] can refuse to
    /// discard information. Never a source of key material or trust.
    pub other: Vec<(String, serde_json::Value)>,
}

impl FlattenedJwe {
    /// Parse a flattened JWE JSON Serialization.
    ///
    /// # Errors
    ///
    /// [`JoseError::InvalidToken`] when the text is longer than
    /// [`crate::MAX_TOKEN_BYTES`], is not a JSON object, repeats a member
    /// name, gives a member the wrong JSON type, omits `ciphertext` (or
    /// `protected`), carries a member this crate version refuses
    /// (see the module documentation), holds a JWS member, or contains a
    /// non-canonical base64url value. [`JoseError::Json`] for JSON syntax
    /// errors. Header *content* policy (`alg`/`enc`/`crit`/`zip`) is checked
    /// later, by the decrypt path.
    pub fn from_json(text: &str) -> Result<Self> {
        ensure_token_size(text)?;
        let mut map = MemberMap::from_json(text)?;

        for name in JWS_MEMBERS {
            if map.contains(name) {
                return Err(JoseError::InvalidToken(format!(
                    "member {name} belongs to a JWS; this is not a JWE JSON object"
                )));
            }
        }
        for (name, reason) in REJECTED_MEMBERS {
            if map.contains(name) {
                return Err(JoseError::InvalidToken(format!(
                    "unsupported JWE JSON member {name}: {reason}"
                )));
            }
        }

        let protected = require_protected(&mut map)?;
        let unprotected = object_member(&mut map, "unprotected")?;
        // `header` is the *per-recipient* unprotected header in the flattened
        // syntax (RFC 7516 §7.2.2), not a JWS signature.
        let per_recipient = object_member(&mut map, "header")?;
        let aad = optional_member(&mut map, "aad")?;
        let ciphertext = require_member(&mut map, "ciphertext")?;
        let iv = optional_member(&mut map, "iv")?;
        let tag = optional_member(&mut map, "tag")?;
        let encrypted_key = optional_member(&mut map, "encrypted_key")?;

        // Every base64url member is decoded now, so a malformed value is a
        // structural error at parse time rather than a puzzling failure
        // inside the crypto layer later.
        for value in [
            Some(protected.as_str()),
            aad.as_deref(),
            iv.as_deref(),
            tag.as_deref(),
            encrypted_key.as_deref(),
            Some(ciphertext.as_str()),
        ]
        .into_iter()
        .flatten()
        {
            base64url::decode(value)?;
        }

        // RFC 7516 §7.2.1: one header parameter may not live in two places.
        ensure_header_locations_disjoint(&protected, unprotected.as_ref(), per_recipient.as_ref())?;

        let other = map.drain_leftovers().into_iter().collect::<Vec<_>>();

        Ok(Self {
            protected: Some(protected),
            unprotected,
            header: per_recipient,
            aad,
            encrypted_key,
            iv,
            ciphertext,
            tag,
            other,
        })
    }

    /// Serialize back to the flattened JSON syntax.
    ///
    /// Members are written into a JSON map, so a name cannot appear twice
    /// (RFC 7515 §4 / RFC 7516 §5.2 step 4). Retained private members are
    /// re-emitted unchanged.
    pub fn to_json(&self) -> Result<String> {
        let mut map = serde_json::Map::new();
        if let Some(protected) = &self.protected {
            map.insert("protected".into(), serde_json::json!(protected));
        }
        if let Some(unprotected) = &self.unprotected {
            if !unprotected.is_empty() {
                map.insert(
                    "unprotected".into(),
                    serde_json::Value::Object(unprotected.clone()),
                );
            }
        }
        if let Some(header) = &self.header {
            if !header.is_empty() {
                map.insert("header".into(), serde_json::Value::Object(header.clone()));
            }
        }
        if let Some(aad) = &self.aad {
            // RFC 7516 §7.2.1: absent rather than empty.
            if !aad.is_empty() {
                map.insert("aad".into(), serde_json::json!(aad));
            }
        }
        if let Some(encrypted_key) = &self.encrypted_key {
            // RFC 7516 §7.2.1: absent when the JWE Encrypted Key is empty.
            if !encrypted_key.is_empty() {
                map.insert("encrypted_key".into(), serde_json::json!(encrypted_key));
            }
        }
        if let Some(iv) = &self.iv {
            if !iv.is_empty() {
                map.insert("iv".into(), serde_json::json!(iv));
            }
        }
        if let Some(tag) = &self.tag {
            if !tag.is_empty() {
                map.insert("tag".into(), serde_json::json!(tag));
            }
        }
        map.insert("ciphertext".into(), serde_json::json!(&self.ciphertext));

        // Retained private members are written last and `write_into` refuses
        // any name already present, so a token that smuggled a private member
        // named `ciphertext` cannot be re-emitted with two meanings.
        let retained: Vec<(String, serde_json::Value)> = self
            .other
            .iter()
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect();
        MemberMap::new(retained)?.write_into(&mut map)?;

        let text = serde_json::to_string(&map)?;
        ensure_token_size(&text)?;
        Ok(text)
    }

    /// Convert to the compact serialization (RFC 7516 §7.1).
    ///
    /// Refuses any message that the compact syntax cannot represent, instead
    /// of dropping information: a missing `protected`, `iv` or `tag` member,
    /// and (from ADR 0012/0013 onward) external AAD, unprotected headers or
    /// retained private members.
    pub fn to_compact(&self) -> Result<String> {
        if !self.other.is_empty() {
            let names: Vec<&str> = self.other.iter().map(|(n, _)| n.as_str()).collect();
            return Err(JoseError::InvalidToken(format!(
                "cannot convert to compact serialization: private members {names:?} \
                 have no compact representation"
            )));
        }
        for (name, present) in [
            ("unprotected", self.unprotected.is_some()),
            ("header", self.header.is_some()),
        ] {
            if present {
                return Err(JoseError::InvalidToken(format!(
                    "cannot convert to compact serialization: {name} header parameters are \
                     not integrity protected and the compact form has nowhere to put them \
                     (RFC 7516 \u{a7}7.1)"
                )));
            }
        }
        if self.aad.is_some() {
            return Err(JoseError::InvalidToken(
                "cannot convert to compact serialization: the compact form has no \"aad\" \
                 member, so external additional authenticated data would be lost"
                    .into(),
            ));
        }
        let protected = self.protected.as_deref().ok_or_else(|| {
            JoseError::InvalidToken(
                "cannot convert to compact serialization: no protected header".into(),
            )
        })?;
        // Every content algorithm this crate supports produces a non-empty IV
        // and tag, so an absent member means the message is not one this
        // conversion can round-trip.
        let iv = self.iv.as_deref().ok_or_else(|| {
            JoseError::InvalidToken("cannot convert to compact serialization: no iv member".into())
        })?;
        let tag = self.tag.as_deref().ok_or_else(|| {
            JoseError::InvalidToken("cannot convert to compact serialization: no tag member".into())
        })?;
        let encrypted_key = self.encrypted_key.as_deref().unwrap_or_default();
        let token = format!(
            "{protected}.{encrypted_key}.{iv}.{}.{}",
            self.ciphertext, tag
        );
        ensure_token_size(&token)?;
        Ok(token)
    }

    /// Build a flattened JWE from a compact serialization string.
    ///
    /// The conversion is lossless in this direction: the compact form carries
    /// exactly the five members this syntax supports.
    pub fn from_compact(token: &str) -> Result<Self> {
        ensure_token_size(token)?;
        let parts: Vec<&str> = token.splitn(6, '.').collect();
        if parts.len() != 5 {
            return Err(JoseError::InvalidToken(
                "JWE compact serialization must have 5 dot-separated parts".into(),
            ));
        }
        let jwe = Self {
            protected: Some(parts[0].to_string()),
            unprotected: None,
            header: None,
            aad: None,
            encrypted_key: (!parts[1].is_empty()).then(|| parts[1].to_string()),
            iv: Some(parts[2].to_string()),
            ciphertext: parts[3].to_string(),
            tag: Some(parts[4].to_string()),
            other: Vec::new(),
        };
        // Re-parse through the JSON path so both entry points enforce the
        // same rules (canonical base64url, non-empty protected header).
        jwe.to_json().and_then(|text| Self::from_json(&text))
    }

    /// The protected header **as parsed from the unauthenticated token**.
    ///
    /// Inspection only: the content tag has not been checked, so nothing here
    /// is trustworthy. Never select a key or make an authorization decision
    /// from it; use it for logging or key *candidate* selection at most, and
    /// only the successful return of a decrypt function attests to these
    /// bytes.
    pub fn peek_protected_header(&self) -> Result<Option<JoseHeader>> {
        let Some(protected) = self.protected.as_deref() else {
            return Ok(None);
        };
        let json = base64url::decode(protected)?;
        let header: JoseHeader = serde_json::from_slice(&json)?;
        Ok(Some(header))
    }

    /// `alg` as conveyed **outside** the protected header, if the message puts
    /// it there (RFC 7516 §7.2.1 allows `unprotected` or `header`).
    ///
    /// Untrusted by construction — the point of exposing it separately is that
    /// a caller must never treat it as the answer.
    pub fn unprotected_alg(&self) -> Option<&str> {
        [self.unprotected.as_ref(), self.header.as_ref()]
            .into_iter()
            .flatten()
            .filter_map(|location| location.get("alg").and_then(|v| v.as_str()))
            .next()
    }

    /// The JOSE Header as the recipient sees it: the union of the protected,
    /// shared unprotected and per-recipient unprotected members
    /// (RFC 7516 §7.2.1).
    ///
    /// Inspection only, and *unauthenticated* by definition wherever an
    /// unprotected member contributes a value — see
    /// [`Self::peek_protected_header`] for the authenticated subset.
    pub fn peek_jose_header(&self) -> Result<serde_json::Map<String, serde_json::Value>> {
        let mut union = serde_json::Map::new();
        // Take the protected members from the *raw* encoded JSON rather than
        // from a re-serialized `JoseHeader`: re-serializing would synthesize
        // fields the sender never sent (an empty `alg`, for instance) and would
        // lose the sender's own member set.
        if let Some(protected) = self.protected.as_deref() {
            let json = base64url::decode(protected)?;
            let object: serde_json::Map<String, serde_json::Value> = serde_json::from_slice(&json)?;
            union.extend(object);
        }
        for location in [self.unprotected.as_ref(), self.header.as_ref()]
            .into_iter()
            .flatten()
        {
            for (key, value) in location {
                if union.contains_key(key) {
                    return Err(JoseError::InvalidToken(format!(
                        "header parameter {key} appears in more than one header location"
                    )));
                }
                union.insert(key.clone(), value.clone());
            }
        }
        Ok(union)
    }

    /// The declared key-management algorithm, if the header parses.
    ///
    /// Untrusted: see [`Self::peek_protected_header`].
    pub fn peek_alg(&self) -> Result<Option<JweAlgorithm>> {
        match self.peek_protected_header()? {
            Some(header) => match JweAlgorithm::from_str(&header.alg) {
                Ok(alg) => Ok(Some(alg)),
                // An unrecognized `alg` string is not an error here: the
                // caller is inspecting, and the decrypt path reports it with
                // the allow-list context attached.
                Err(_) => Ok(None),
            },
            None => Ok(None),
        }
    }
}

/// Read the mandatory `protected` member (shared by both JSON syntaxes).
///
/// RFC 7516 §7.2.1 permits an absent protected header, but this crate always
/// requires one: `enc` must be integrity protected (it decides how the
/// ciphertext and tag octets are split), and a message with no protected header
/// has nowhere to put it. ADR 0011 and ADR 0013.
pub(crate) fn require_protected(map: &mut MemberMap) -> Result<String> {
    match map.take_string("protected")? {
        None => Err(JoseError::InvalidToken(
            "JWE JSON member \"protected\" is required by this crate: the content encryption \
             algorithm (\"enc\") must be integrity protected"
                .into(),
        )),
        Some(value) if value.is_empty() => Err(JoseError::InvalidToken(
            "JWE JSON member \"protected\" must be absent rather than empty (RFC 7516 §7.2.1)"
                .into(),
        )),
        Some(value) => Ok(value),
    }
}

/// Require a string member, with the RFC 7516 presence rules applied.
///
/// An empty string is rejected: RFC 7516 §7.2.1 says a member whose value is
/// empty MUST be absent, so accepting `""` would accept a message the sender
/// could not have produced.
pub(crate) fn require_member(map: &mut MemberMap, name: &str) -> Result<String> {
    match map.take_string(name)? {
        None => Err(JoseError::InvalidToken(format!(
            "JWE JSON member {name} is required"
        ))),
        Some(value) if value.is_empty() => Err(JoseError::InvalidToken(format!(
            "JWE JSON member {name} must be absent rather than empty (RFC 7516 §7.2.1)"
        ))),
        Some(value) => Ok(value),
    }
}

/// Header parameters that must never appear in an unprotected location.
///
/// - `enc`: the content encryption algorithm decides how the ciphertext and tag
///   octets are split. If it were attacker-chosen, swapping bytes between the
///   `ciphertext` and `tag` members under a *different* `enc` could produce a
///   message that authenticates under one reading of the envelope and means
///   something else under another;
/// - `zip`: RFC 7516 §4.1.3 — "MUST occur only within the JWE Protected
///   Header";
/// - `crit`: declaring an extension critical in data nobody authenticates lets
///   an attacker either force rejection or, symmetrically, strip the marker;
/// - `b64`: an RFC 7797 member that does not exist for JWE at all;
/// - `epk`/`apu`/`apv`/`p2s`/`p2c`/`iv`/`tag`: parameters of key-management
///   algorithms this crate does not implement (see
///   [`crate::jwe::internal::UNIMPLEMENTED_JWE_MEMBERS`]). Accepting them in an
///   unauthenticated position would mean reading key-agreement inputs an
///   attacker chose.
const UNPROTECTED_FORBIDDEN: &[&str] = &[
    "enc", "zip", "crit", "b64", "epk", "apu", "apv", "p2s", "p2c", "iv", "tag",
];

/// Read an optional unprotected-header member (`unprotected`, `header`).
///
/// These members carry a JSON *object*, not a base64url string. An empty object
/// is refused: RFC 7516 §7.2.1 says the member MUST be absent when the
/// corresponding header value is empty, and an empty object would otherwise be
/// an ambiguous "present but says nothing" header location.
pub(crate) fn object_member(
    map: &mut MemberMap,
    name: &str,
) -> Result<Option<serde_json::Map<String, serde_json::Value>>> {
    let Some(value) = map.take(name) else {
        return Ok(None);
    };
    let serde_json::Value::Object(object) = value else {
        return Err(JoseError::InvalidToken(format!(
            "JWE JSON member {name} must be a JSON object of header parameters"
        )));
    };
    if object.is_empty() {
        return Err(JoseError::InvalidToken(format!(
            "JWE JSON member {name} must be absent rather than empty (RFC 7516 §7.2.1)"
        )));
    }
    // RFC 7516 §4.1.1: `alg` is a case-sensitive ASCII string. A number or
    // object here is a header parameter nobody could honour, and ignoring it
    // silently would leave the message with no algorithm and a puzzling
    // downstream error.
    if let Some(alg) = object.get("alg") {
        if !alg.is_string() {
            return Err(JoseError::InvalidToken(format!(
                "JWE JSON member {name} carries a non-string \"alg\" value"
            )));
        }
    }
    for forbidden in UNPROTECTED_FORBIDDEN {
        if object.contains_key(*forbidden) {
            // (`alg` is deliberately absent from this list: RFC 7516 §7.2.1
            // allows it in an unprotected location, and the decrypt path only
            // accepts it when the caller's key pins the same value.)
            return Err(JoseError::InvalidToken(format!(
                "header parameter {forbidden} must be integrity protected and cannot appear in \
                 the {name} member"
            )));
        }
    }
    Ok(Some(object))
}

/// RFC 7516 §7.2.1: "The Header Parameter names in the three locations MUST be
/// disjoint."
///
/// A name in two locations has no defined meaning — implementations disagree on
/// which wins, which is exactly the ambiguity that header-injection attacks
/// exploit. Enforced at parse time, so no code downstream has to decide.
pub(crate) fn ensure_header_locations_disjoint(
    protected_b64: &str,
    unprotected: Option<&serde_json::Map<String, serde_json::Value>>,
    per_recipient: Option<&serde_json::Map<String, serde_json::Value>>,
) -> Result<()> {
    let protected_json = base64url::decode(protected_b64)?;
    let protected: serde_json::Map<String, serde_json::Value> =
        serde_json::from_slice(&protected_json)?;

    let mut seen: Vec<(&str, &'static str)> = protected
        .keys()
        .map(|key| (key.as_str(), "protected"))
        .collect();
    for (location, object) in [("unprotected", unprotected), ("header", per_recipient)] {
        let Some(object) = object else {
            continue;
        };
        for key in object.keys() {
            if let Some((first, first_location)) =
                seen.iter().find(|(name, _)| *name == key.as_str())
            {
                return Err(JoseError::InvalidToken(format!(
                    "header parameter {first} appears in both the {first_location} and {location} members; the three header locations must be disjoint (RFC 7516 §7.2.1)"
                )));
            }
            seen.push((key.as_str(), location));
        }
    }
    Ok(())
}

/// Read an optional string member; `None` when absent or empty.
///
/// An explicit empty value is accepted here (and treated as absent) because
/// several producers emit `"encrypted_key":""` for `dir`; it is never
/// re-emitted by [`FlattenedJwe::to_json`].
pub(crate) fn optional_member(map: &mut MemberMap, name: &str) -> Result<Option<String>> {
    Ok(match map.take_string(name)? {
        None => None,
        Some(value) if value.is_empty() => None,
        Some(value) => Some(value),
    })
}

// ---------------------------------------------------------------------------
// Encryption
// ---------------------------------------------------------------------------

/// Encrypt `plaintext` into a flattened JWE JSON Serialization.
///
/// Key formats match [`crate::jwe::encrypt`]: the CEK for `dir`, the KEK for
/// `A128KW`/`A192KW`/`A256KW`, and SPKI DER for `RSA-OAEP*`. The protected
/// header is `{"alg":…,"enc":…}`; use
/// [`encrypt_flattened_with_header`] to add authenticated members.
///
/// # Errors
///
/// As for [`crate::jwe::encrypt`] — unsupported algorithms, wrong-size keys
/// and encryption failures.
pub fn encrypt_flattened(
    key: &[u8],
    plaintext: &[u8],
    alg: JweAlgorithm,
    enc: JweEncryption,
) -> Result<FlattenedJwe> {
    encrypt_flattened_with_header(JoseHeader::for_jwe(alg, enc), key, plaintext, alg, enc)
}

/// [`encrypt_flattened`] with an explicit protected header, strict policy.
///
/// # Errors
///
/// As for [`crate::jwe::encrypt_with_header`]: header/algorithm disagreement,
/// duplicate members, unimplemented members, `crit`, key-reference members,
/// or an oversized header.
pub fn encrypt_flattened_with_header(
    header: JoseHeader,
    key: &[u8],
    plaintext: &[u8],
    alg: JweAlgorithm,
    enc: JweEncryption,
) -> Result<FlattenedJwe> {
    encrypt_flattened_with_header_options(
        header,
        key,
        plaintext,
        alg,
        enc,
        &JweEncryptOptions::new(),
    )
}

/// [`encrypt_flattened_with_header`] with explicit [`JweEncryptOptions`].
///
/// The JWK operation permissions are not checked by this raw-key API; use
/// [`encrypt_flattened_with_jwk_header`] for that.
pub fn encrypt_flattened_with_header_options(
    header: JoseHeader,
    key: &[u8],
    plaintext: &[u8],
    alg: JweAlgorithm,
    enc: JweEncryption,
    opts: &JweEncryptOptions,
) -> Result<FlattenedJwe> {
    encrypt_flattened_material(
        header,
        KeyMaterial::Bytes(zeroize::Zeroizing::new(key.to_vec())),
        plaintext,
        alg,
        enc,
        opts,
    )
}

/// Shared flattened-JSON emit core for both key shapes.
fn encrypt_flattened_material(
    header: JoseHeader,
    key: KeyMaterial,
    plaintext: &[u8],
    alg: JweAlgorithm,
    enc: JweEncryption,
    opts: &JweEncryptOptions,
) -> Result<FlattenedJwe> {
    // External AAD, if configured, is encoded once and used for both the AAD
    // input and the `aad` member, so the two can never disagree.
    let aad_b64 = match opts.external_aad() {
        None => None,
        Some(bytes) => {
            internal::ensure_external_aad_present(bytes)?;
            Some(base64url::encode(bytes))
        }
    };
    let core = internal::encrypt_core(&header, key, plaintext, alg, enc, opts, aad_b64.as_deref())?;
    let mut jwe = FlattenedJwe::from_core(&core);
    jwe.aad = aad_b64;
    Ok(jwe)
}

/// Encrypt with a JWK, mirroring [`crate::jwe::encrypt_with_jwk`].
///
/// `jwk.alg` supplies the key-management algorithm and
/// [`crate::jwk::Jwk::check_op`] is enforced (`Encrypt` for `dir`, `WrapKey`
/// otherwise), so a signing-pinned key cannot be used to encrypt.
pub fn encrypt_flattened_with_jwk(
    jwk: &crate::jwk::Jwk,
    plaintext: &[u8],
    enc: JweEncryption,
) -> Result<FlattenedJwe> {
    let alg = pinned_alg(jwk)?;
    jwk.check_op(jwe_alg_encrypt_op(alg))?;
    encrypt_flattened_material(
        JoseHeader::for_jwe(alg, enc),
        recipient_key(jwk, alg, false)?,
        plaintext,
        alg,
        enc,
        &JweEncryptOptions::new(),
    )
}

/// [`encrypt_flattened_with_jwk`] with an explicit protected header.
///
/// # Errors
///
/// JWK operation/algorithm rejection, or the header rules of
/// [`encrypt_flattened_with_header`].
pub fn encrypt_flattened_with_jwk_header(
    jwk: &crate::jwk::Jwk,
    header: JoseHeader,
    plaintext: &[u8],
    enc: JweEncryption,
) -> Result<FlattenedJwe> {
    encrypt_flattened_with_jwk_header_options(
        jwk,
        header,
        plaintext,
        enc,
        &JweEncryptOptions::new(),
    )
}

/// [`encrypt_flattened_with_jwk_header`] with explicit [`JweEncryptOptions`].
pub fn encrypt_flattened_with_jwk_header_options(
    jwk: &crate::jwk::Jwk,
    header: JoseHeader,
    plaintext: &[u8],
    enc: JweEncryption,
    opts: &JweEncryptOptions,
) -> Result<FlattenedJwe> {
    let alg = pinned_alg(jwk)?;
    jwk.check_op(jwe_alg_encrypt_op(alg))?;
    encrypt_flattened_material(
        header,
        recipient_key(jwk, alg, false)?,
        plaintext,
        alg,
        enc,
        opts,
    )
}

/// Read the key-management algorithm pinned in `jwk.alg`.
///
/// The JWK APIs take the algorithm from the *key*, never from token header
/// data, which is what makes the `alg` binding check on the decrypt side
/// meaningful. The error text is specific to these APIs so a caller can tell
/// which entry point rejected the key.
pub(crate) fn pinned_alg(jwk: &crate::jwk::Jwk) -> Result<JweAlgorithm> {
    let alg = jwk
        .alg
        .as_deref()
        .ok_or_else(|| JoseError::Key("JWK alg must be set for the JWE JSON JWK APIs".into()))?;
    JweAlgorithm::from_str(alg)
}

impl FlattenedJwe {
    /// Assemble the members of an already-encrypted message.
    ///
    /// `encrypted_key` follows the RFC 7516 §7.2.1 presence rule: absent for
    /// `dir`, where the wrapped key is the empty octet sequence.
    fn from_core(core: &internal::EncryptedCore) -> Self {
        Self {
            protected: Some(core.header_b64.clone()),
            // This crate never emits unprotected header members (ADR 0013): a
            // parameter that is not integrity protected is a target, and every
            // message we produce can carry its parameters in the protected
            // header.
            unprotected: None,
            header: None,
            // External AAD is set by the caller-side entry point, which is the
            // only place that knows the octets.
            aad: None,
            encrypted_key: (!core.encrypted_key.is_empty())
                .then(|| base64url::encode(&core.encrypted_key)),
            iv: (!core.iv.is_empty()).then(|| base64url::encode(&core.iv)),
            ciphertext: base64url::encode(&core.ciphertext),
            tag: (!core.tag.is_empty()).then(|| base64url::encode(&core.tag)),
            other: Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Decryption
// ---------------------------------------------------------------------------

/// Decrypt with a raw key, accepting every algorithm the library supports.
///
/// Prefer [`decrypt_flattened_with_options`] in new code, and
/// [`decrypt_flattened_with_jwk`] when the key pins its algorithm.
pub fn decrypt_flattened(key: &[u8], jwe: &FlattenedJwe) -> Result<Vec<u8>> {
    decrypt_flattened_with_options(key, jwe, &JweDecryptOptions::permissive())
}

/// Decrypt a flattened JWE, enforcing the caller's algorithm allow-list and
/// plaintext-size limit.
///
/// The policy and key-management steps are the shared ones used by the
/// compact serialization ([`crate::jwe::decrypt_with_options`]), and the
/// content tag is verified over the verbatim `protected` bytes. No plaintext
/// is returned until authentication and the exact size check succeed.
///
/// # Errors
///
/// [`JoseError::UnsupportedAlgorithm`] for an allow-list miss,
/// [`JoseError::InvalidHeader`] / [`JoseError::InvalidToken`] for header
/// policy or structural problems, [`JoseError::Key`] for unusable key
/// material, [`JoseError::Crypto`] when authentication fails, and
/// [`JoseError::InvalidToken`] when the plaintext exceeds
/// [`JweDecryptOptions::with_max_plaintext`].
pub fn decrypt_flattened_with_options(
    key: &[u8],
    jwe: &FlattenedJwe,
    options: &JweDecryptOptions,
) -> Result<Vec<u8>> {
    // Raw key material pins nothing, so this entry point has to be able to
    // authenticate `alg` itself: an algorithm read from an unprotected member
    // would simply be the attacker's choice. The JWK APIs, which do pin an
    // algorithm on the key, may accept the unprotected placement.
    decrypt_impl(
        &KeyMaterial::Bytes(zeroize::Zeroizing::new(key.to_vec())),
        jwe,
        options,
        None,
    )
}

/// Shared decryption core behind the raw-key and JWK entry points.
///
/// `pinned_alg` is the algorithm the caller's key already pins, when it pins
/// one. With a pin, an `alg` conveyed outside the protected header
/// (RFC 7516 §7.2.1) is *checked against the key* instead of believed, which is
/// the only safe way to use it; the token cannot steer the key-management
/// algorithm anywhere the key disagrees. Without a pin, `alg` must come from
/// the integrity-protected header.
///
/// `enc` always comes from the protected header: it decides how the ciphertext
/// and tag octets are split, so an attacker-chosen `enc` could make a byte
/// stream authenticate under one reading and mean something else under another.
fn decrypt_impl(
    key: &KeyMaterial,
    jwe: &FlattenedJwe,
    options: &JweDecryptOptions,
    pinned_alg: Option<&str>,
) -> Result<Vec<u8>> {
    let protected = jwe.protected.as_deref().ok_or_else(|| {
        JoseError::InvalidHeader("JWE JSON requires a protected header carrying enc".into())
    })?;
    ensure_token_size(protected)?;
    ensure_token_size(&jwe.ciphertext)?;

    let protected_header = jwe
        .peek_protected_header()?
        .ok_or_else(|| JoseError::InvalidHeader("unreadable protected header".into()))?;

    // Resolve where `alg` is conveyed, and refuse the unprotected placement
    // unless something other than the token pins it.
    let unprotected_alg = if protected_header.alg.is_empty() {
        let outer = jwe.unprotected_alg().ok_or_else(|| {
            JoseError::InvalidHeader(
                "neither the protected header nor an unprotected header member conveys alg \
                 (RFC 7516 §7.2.1)"
                    .into(),
            )
        })?;
        match pinned_alg {
            Some(pinned) if pinned != outer => {
                return Err(JoseError::InvalidToken(format!(
                    "JWK alg {pinned} does not match token header alg {outer}"
                )));
            }
            Some(_) => Some(outer),
            None => {
                return Err(JoseError::InvalidHeader(format!(
                    "alg {outer} is conveyed in an unprotected header member, which the raw-key API cannot trust; use the JWK API with a key whose `alg` pins it, or send a message that carries alg in the protected header"
                )))
            }
        }
    } else {
        if let Some(pinned) = pinned_alg {
            if pinned != protected_header.alg {
                return Err(JoseError::InvalidToken(format!(
                    "JWK alg {pinned} does not match token header alg {}",
                    protected_header.alg
                )));
            }
        }
        None
    };

    let encrypted_key_b64 = jwe.encrypted_key.as_deref().unwrap_or_default();
    let iv_b64 = jwe.iv.as_deref().unwrap_or_default();
    let tag_b64 = jwe.tag.as_deref().unwrap_or_default();

    let (envelope, _protected_header) = internal::parse_envelope(
        protected,
        unprotected_alg,
        encrypted_key_b64,
        iv_b64,
        &jwe.ciphertext,
        tag_b64,
        options.understood_crit(),
    )?;

    // Defence in depth: `pinned_alg` is the policy that permits an
    // unauthenticated `alg`, so the envelope must never report one without it.
    debug_assert!(envelope.alg_authenticated || pinned_alg.is_some());

    options.check(envelope.alg, envelope.enc)?;
    options.check_plaintext_size(minimum_plaintext_len(jwe.ciphertext.len(), envelope.enc))?;

    // `protected_header` is the decoded *protected* header: the only place a
    // peer key (`epk`) is believed (ADR 0013 refuses it anywhere else).
    let cek = internal::recover_cek(
        key,
        envelope.alg,
        envelope.enc,
        &envelope.encrypted_key,
        &protected_header,
    )?;
    let external_aad = options.resolve_external_aad(jwe.aad.as_deref())?;
    let aad = internal::aad_input(protected, external_aad.as_deref());
    internal::finish_decrypt(&envelope, &cek, &aad, options)
}

/// Decrypt with a JWK, mirroring [`crate::jwe::decrypt_with_jwk`].
///
/// `jwk.alg` must be set and must equal the token's `alg`, whether the token
/// conveys it in the protected header or in an unprotected member
/// (RFC 7516 §7.2.1): the key pins the key-management algorithm, so the header
/// value is checked rather than believed. `Jwk::check_op` (`Decrypt` /
/// `UnwrapKey`) is enforced as well.
///
/// This is the only JWE entry point that accepts an unprotected `alg`, and it
/// is safe precisely because the key answers the question first.
///
/// Refuses a message that carries an `aad` member, because the out-of-band
/// bytes cannot be guessed: use [`decrypt_flattened_with_jwk_and_aad`] for
/// those.
pub fn decrypt_flattened_with_jwk(jwk: &crate::jwk::Jwk, jwe: &FlattenedJwe) -> Result<Vec<u8>> {
    decrypt_flattened_with_jwk_impl(jwk, jwe, None)
}

/// [`decrypt_flattened_with_jwk`] for a message that carries an `aad` member.
///
/// The key checks are identical; the only difference is that `external_aad`
/// supplies the out-of-band bytes the content tag is computed over.
///
/// # Errors
///
/// As for [`decrypt_flattened_with_jwk`], plus
/// [`crate::jwe::JweDecryptOptions::with_external_aad`]'s mismatch errors when
/// the message's `aad` member and `external_aad` disagree.
pub fn decrypt_flattened_with_jwk_and_aad(
    jwk: &crate::jwk::Jwk,
    jwe: &FlattenedJwe,
    external_aad: &[u8],
) -> Result<Vec<u8>> {
    decrypt_flattened_with_jwk_impl(jwk, jwe, Some(external_aad))
}

pub(crate) fn decrypt_flattened_with_jwk_impl(
    jwk: &crate::jwk::Jwk,
    jwe: &FlattenedJwe,
    external_aad: Option<&[u8]>,
) -> Result<Vec<u8>> {
    let mut options = JweDecryptOptions::pinned_to_jwk(jwk)?;
    if let Some(aad) = external_aad {
        internal::ensure_external_aad_present(aad)?;
        options = options.with_external_aad(aad);
    }
    decrypt_flattened_with_jwk_options(jwk, jwe, &options)
}

/// [`decrypt_flattened_with_jwk`] with the caller's full
/// [`JweDecryptOptions`] — plaintext size limit, external AAD, and
/// caller-understood `crit` extensions (ADR 0015).
///
/// The key's pin is not relaxable: `jwk.alg` supplies the key-management
/// algorithm, and if the options' allow-list excludes it the decryption is
/// refused. Everything else in the options is honoured as given, including the
/// content-algorithm allow-list (an empty one means "as pinned by the key").
///
/// # Errors
///
/// As [`decrypt_flattened_with_jwk`], plus [`JoseError::UnsupportedAlgorithm`]
/// when the options' allow-list excludes the key's algorithm.
pub fn decrypt_flattened_with_jwk_options(
    jwk: &crate::jwk::Jwk,
    jwe: &FlattenedJwe,
    options: &JweDecryptOptions,
) -> Result<Vec<u8>> {
    let jwk_alg = jwk
        .alg
        .as_deref()
        .ok_or_else(|| JoseError::Key("JWK alg must be set for the JWE JWK APIs".into()))?;
    // The algorithm is taken from the key. The token's own claim (wherever it
    // is placed) is compared against it inside `decrypt_impl`.
    let alg = JweAlgorithm::from_str(jwk_alg)?;

    jwk.check_op(jwe_alg_decrypt_op(alg))?;
    let key = recipient_key(jwk, alg, true)?;
    let options = options.clone().allow_any_enc_when_unset();
    decrypt_impl(&key, jwe, &options, Some(jwk_alg))
}

/// Decode the protected header of a flattened JWE **without** authenticating
/// anything.
///
/// Inspection only — see [`FlattenedJwe::peek_protected_header`].
pub fn decode_header(jwe: &FlattenedJwe) -> Result<Option<JoseHeader>> {
    jwe.peek_protected_header()
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jwe::{compact, json};

    fn key() -> Vec<u8> {
        vec![0x42u8; 32]
    }

    /// RFC 7516 Appendix A.3: A128KW + A128CBC-HS256, alg and enc in the
    /// protected header. Re-expressed as the flattened JSON syntax of
    /// RFC 7516 §7.2.2 — the member values are unchanged from the RFC's
    /// compact serialization, which is exactly the equivalence §7.2.1
    /// requires ("each JWE Encrypted Key value ... is identical to the value
    /// that would have been computed for ... the JWE Compact Serialization").
    const RFC7516_A3: (&str, &str, &str, &str, &str, &str) = (
        // oct key (A128KW KEK), base64url
        "GawgguFyGrWKav7AX4VKUg",
        "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
        "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
        "AxY8DCtDaGlsbGljb3RoZQ",
        "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY",
        "U0m_YmjN04DJvceFICbCVQ",
    );

    fn rfc7516_a3_json() -> String {
        let (_kek, protected, encrypted_key, iv, ciphertext, tag) = RFC7516_A3;
        serde_json::json!({
            "protected": protected,
            "encrypted_key": encrypted_key,
            "iv": iv,
            "ciphertext": ciphertext,
            "tag": tag,
        })
        .to_string()
    }

    #[test]
    fn rfc7516_a3_vector_decrypts_as_flattened_json() {
        let (kek, ..) = RFC7516_A3;
        let jwe = json::FlattenedJwe::from_json(&rfc7516_a3_json()).unwrap();
        let plaintext = json::decrypt_flattened(&base64url::decode(kek).unwrap(), &jwe).unwrap();
        assert_eq!(plaintext, b"Live long and prosper.");
    }

    #[test]
    fn rfc7516_a3_vector_tampered_tag_fails() {
        let (kek, ..) = RFC7516_A3;
        let mut value: serde_json::Value = serde_json::from_str(&rfc7516_a3_json()).unwrap();
        let mut tag = base64url::decode(value["tag"].as_str().unwrap()).unwrap();
        tag[0] ^= 1;
        value["tag"] = base64url::encode(&tag).into();
        let jwe = json::FlattenedJwe::from_json(&value.to_string()).unwrap();
        assert!(json::decrypt_flattened(&base64url::decode(kek).unwrap(), &jwe).is_err());
    }

    /// Flattened JSON and compact carry the same five values, so a message
    /// produced by one path must decrypt with the other, in both directions.
    #[test]
    fn json_and_compact_interoperate() {
        for alg in [
            JweAlgorithm::Dir,
            JweAlgorithm::A128KW,
            JweAlgorithm::A192KW,
            JweAlgorithm::A256KW,
        ] {
            for enc in [
                JweEncryption::A128GCM,
                JweEncryption::A192GCM,
                JweEncryption::A256GCM,
                JweEncryption::A128CbcHs256,
                JweEncryption::A192CbcHs384,
                JweEncryption::A256CbcHs512,
            ] {
                let key = vec![0x11u8; enc_key_len(alg, enc)];
                let plaintext = b"serialization equivalence";

                let flattened = json::encrypt_flattened(&key, plaintext, alg, enc).unwrap();
                let compact_token = flattened.to_compact().unwrap();
                assert_eq!(
                    compact::decrypt(&key, &compact_token).unwrap(),
                    plaintext,
                    "{alg:?}/{enc:?}: JSON message unreadable as compact"
                );

                let from_compact = json::FlattenedJwe::from_compact(&compact_token).unwrap();
                assert_eq!(
                    json::decrypt_flattened(&key, &from_compact).unwrap(),
                    plaintext,
                    "{alg:?}/{enc:?}: compact message unreadable as JSON"
                );
                // Compact -> flattened -> compact must reproduce the token.
                assert_eq!(from_compact.to_compact().unwrap(), compact_token);
            }
        }
    }

    fn enc_key_len(alg: JweAlgorithm, enc: JweEncryption) -> usize {
        match alg {
            JweAlgorithm::Dir => enc.cek_size(),
            JweAlgorithm::A128KW => 16,
            JweAlgorithm::A192KW => 24,
            JweAlgorithm::A256KW => 32,
            _ => 32,
        }
    }

    #[test]
    fn dir_omits_the_encrypted_key_member() {
        let jwe = json::encrypt_flattened(&key(), b"p", JweAlgorithm::Dir, JweEncryption::A256GCM)
            .unwrap();
        assert!(jwe.encrypted_key.is_none(), "dir: no wrapped key");
        let text = jwe.to_json().unwrap();
        let value: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert!(
            !value.as_object().unwrap().contains_key("encrypted_key"),
            "RFC 7516 §7.2.1: the member MUST be absent when empty: {text}"
        );
        assert!(value.as_object().unwrap().contains_key("ciphertext"));
        assert!(value.as_object().unwrap().contains_key("iv"));
        assert!(value.as_object().unwrap().contains_key("tag"));
    }

    #[test]
    fn aes_kw_includes_the_encrypted_key_member() {
        let jwe = json::encrypt_flattened(
            &[9u8; 32],
            b"p",
            JweAlgorithm::A256KW,
            JweEncryption::A256GCM,
        )
        .unwrap();
        assert!(jwe.encrypted_key.as_deref().is_some_and(|k| !k.is_empty()));
    }

    #[test]
    fn json_roundtrip_is_byte_stable() {
        let jwe =
            json::encrypt_flattened(&key(), b"hello", JweAlgorithm::Dir, JweEncryption::A256GCM)
                .unwrap();
        let text = jwe.to_json().unwrap();
        let parsed = json::FlattenedJwe::from_json(&text).unwrap();
        assert_eq!(parsed, jwe);
        assert_eq!(parsed.to_json().unwrap(), text);
    }

    #[test]
    fn retained_private_members_survive_and_block_compact_conversion() {
        let jwe =
            json::encrypt_flattened(&key(), b"hello", JweAlgorithm::Dir, JweEncryption::A256GCM)
                .unwrap();
        let mut value: serde_json::Value = serde_json::from_str(&jwe.to_json().unwrap()).unwrap();
        value["tenant"] = serde_json::json!("acme");
        let parsed = json::FlattenedJwe::from_json(&value.to_string()).unwrap();
        assert_eq!(
            parsed
                .other
                .iter()
                .map(|(n, _)| n.as_str())
                .collect::<Vec<_>>(),
            vec!["tenant"],
            "unknown private members must be retained, not dropped"
        );
        // Still decryptable: RFC 7516 §7.2.1 says such members are ignored.
        assert_eq!(json::decrypt_flattened(&key(), &parsed).unwrap(), b"hello");
        // But the compact form cannot carry them.
        let err = parsed.to_compact().unwrap_err().to_string();
        assert!(err.contains("tenant"), "{err}");
    }

    #[test]
    fn re_emitted_private_member_may_not_shadow_a_jwe_member() {
        let mut jwe =
            json::encrypt_flattened(&key(), b"hi", JweAlgorithm::Dir, JweEncryption::A256GCM)
                .unwrap();
        jwe.other
            .push(("ciphertext".into(), serde_json::json!("bogus")));
        let err = jwe.to_json().unwrap_err().to_string();
        assert!(err.contains("duplicate JSON member ciphertext"), "{err}");
    }

    // -- strict parser --

    #[test]
    fn rejects_duplicate_members() {
        let text = r#"{"protected":"AA","ciphertext":"AA","ciphertext":"BB","iv":"AA","tag":"AA"}"#;
        let err = json::FlattenedJwe::from_json(text).unwrap_err().to_string();
        assert!(err.contains("duplicate JSON member ciphertext"), "{err}");
    }

    #[test]
    fn rejects_missing_members_by_name() {
        let base = serde_json::json!({
            "protected": "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0",
            "ciphertext": "AA",
            "iv": "AAAAAAAAAAAAAAAA",
            "tag": "AAAAAAAAAAAAAAAA",
        })
        .to_string();
        assert!(json::FlattenedJwe::from_json(&base).is_ok());

        for missing in ["protected", "ciphertext"] {
            let mut value: serde_json::Value = serde_json::from_str(&base).unwrap();
            value.as_object_mut().unwrap().remove(missing);
            let err = json::FlattenedJwe::from_json(&value.to_string())
                .unwrap_err()
                .to_string();
            assert!(err.contains("is required"), "{missing}: {err}");
        }

        // The `protected` message says *why*, because that member is the
        // difference between an authenticated and an unauthenticated `enc`.
        let mut value: serde_json::Value = serde_json::from_str(&base).unwrap();
        value.as_object_mut().unwrap().remove("protected");
        let err = json::FlattenedJwe::from_json(&value.to_string())
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("integrity protected") && err.contains("encryption algorithm"),
            "{err}"
        );
    }

    /// RFC 7516 §7.2.1: a member whose value is empty MUST be absent, so an
    /// empty `protected` is a structural error rather than an empty header.
    #[test]
    fn rejects_empty_required_members() {
        let text = r#"{"protected":"","ciphertext":"AA","iv":"AA","tag":"AA"}"#;
        let err = json::FlattenedJwe::from_json(text).unwrap_err().to_string();
        assert!(err.contains("must be absent rather than empty"), "{err}");
    }

    /// `"encrypted_key":""` is tolerated as absent (several producers emit it
    /// for `dir`) but is never re-emitted.
    #[test]
    fn tolerates_empty_encrypted_key_but_does_not_reemit_it() {
        let jwe = json::encrypt_flattened(&key(), b"p", JweAlgorithm::Dir, JweEncryption::A256GCM)
            .unwrap();
        let mut value: serde_json::Value = serde_json::from_str(&jwe.to_json().unwrap()).unwrap();
        value["encrypted_key"] = serde_json::json!("");
        let parsed = json::FlattenedJwe::from_json(&value.to_string()).unwrap();
        assert_eq!(parsed.encrypted_key, None);
        assert!(!parsed.to_json().unwrap().contains("encrypted_key"));
    }

    #[test]
    fn rejects_wrong_member_types() {
        for (member, value) in [
            ("protected", serde_json::json!(5)),
            ("ciphertext", serde_json::json!(["a"])),
            ("iv", serde_json::json!({"n": 1})),
            ("tag", serde_json::json!(null)),
            ("encrypted_key", serde_json::json!(true)),
        ] {
            let mut obj = serde_json::Map::new();
            obj.insert("protected".into(), serde_json::json!("AA"));
            obj.insert("ciphertext".into(), serde_json::json!("AA"));
            obj.insert("iv".into(), serde_json::json!("AA"));
            obj.insert("tag".into(), serde_json::json!("AA"));
            obj.remove(member);
            obj.insert(member.into(), value);
            let err = json::FlattenedJwe::from_json(&serde_json::to_string(&obj).unwrap())
                .unwrap_err()
                .to_string();
            assert!(err.contains("must be a string"), "{member}: {err}");
        }
    }

    #[test]
    fn rejects_non_canonical_base64url() {
        let text = r#"{"protected":"eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0","ciphertext":"AA==","iv":"AAAAAAAAAAAAAAAA","tag":"AAAAAAAAAAAAAAAA"}"#;
        let err = json::FlattenedJwe::from_json(text).unwrap_err().to_string();
        assert!(err.contains("base64"), "{err}");
    }

    #[test]
    fn rejects_the_general_syntax_member_with_a_reason() {
        let mut obj = serde_json::Map::new();
        obj.insert("protected".into(), serde_json::json!("AA"));
        obj.insert("ciphertext".into(), serde_json::json!("AA"));
        obj.insert("recipients".into(), serde_json::json!([]));
        let err = FlattenedJwe::from_json(&serde_json::to_string(&obj).unwrap())
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("unsupported JWE JSON member recipients"),
            "{err}"
        );
    }

    // -- unprotected header members (RFC 7516 §7.2.1) --

    /// A message shape as compact as the syntax it replaces: `kid` where an
    /// attacker can see it, but not where they can change it.
    #[test]
    fn unprotected_members_are_parsed_and_retained() {
        let jwe = FlattenedJwe::from_json(
            r#"{
                "protected": "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0",
                "unprotected": {"jku": "https://example.invalid/jwks"},
                "header": {"kid": "recipient-1"},
                "iv": "AAAAAAAAAAAAAAAA",
                "ciphertext": "AA",
                "tag": "AAAAAAAAAAAAAAAA"
            }"#,
        )
        .unwrap();
        assert_eq!(
            jwe.unprotected
                .as_ref()
                .and_then(|m| m.get("jku"))
                .and_then(|v| v.as_str()),
            Some("https://example.invalid/jwks")
        );
        assert_eq!(
            jwe.header
                .as_ref()
                .and_then(|m| m.get("kid"))
                .and_then(|v| v.as_str()),
            Some("recipient-1")
        );
        // Round-trips, so re-serializing a peer's message loses nothing.
        let text = jwe.to_json().unwrap();
        assert_eq!(FlattenedJwe::from_json(&text).unwrap(), jwe);
        // But the compact form has nowhere to put them.
        let err = jwe.to_compact().unwrap_err().to_string();
        assert!(err.contains("not integrity protected"), "{err}");
    }

    #[test]
    fn header_parameter_names_must_be_disjoint_across_locations() {
        // RFC 7516 §7.2.1: the three locations MUST be disjoint.
        let text = r#"{
            "protected": "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwia2lkIjoiaW4ifQ",
            "unprotected": {"kid": "out"},
            "ciphertext": "AA",
            "iv": "AAAAAAAAAAAAAAAA",
            "tag": "AAAAAAAAAAAAAAAA"
        }"#;
        let err = FlattenedJwe::from_json(text).unwrap_err().to_string();
        assert!(
            err.contains("kid appears in both the protected and unprotected members"),
            "{err}"
        );

        let text = r#"{
            "protected": "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0",
            "unprotected": {"kid": "shared"},
            "header": {"kid": "per-recipient"},
            "ciphertext": "AA",
            "iv": "AAAAAAAAAAAAAAAA",
            "tag": "AAAAAAAAAAAAAAAA"
        }"#;
        let err = FlattenedJwe::from_json(text).unwrap_err().to_string();
        assert!(
            err.contains("kid appears in both the unprotected and header members"),
            "{err}"
        );
    }

    #[test]
    fn parameters_that_must_be_authenticated_cannot_sit_unprotected() {
        for (member, parameter) in [
            ("unprotected", "enc"),
            ("unprotected", "crit"),
            ("unprotected", "zip"),
            ("unprotected", "epk"),
            ("header", "enc"),
            ("header", "b64"),
            ("header", "p2s"),
        ] {
            let mut obj = serde_json::Map::new();
            obj.insert(
                "protected".into(),
                serde_json::json!("eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0"),
            );
            obj.insert("ciphertext".into(), serde_json::json!("AA"));
            obj.insert("iv".into(), serde_json::json!("AAAAAAAAAAAAAAAA"));
            obj.insert("tag".into(), serde_json::json!("AAAAAAAAAAAAAAAA"));
            obj.insert(member.into(), serde_json::json!({ parameter: "whatever" }));
            let err = FlattenedJwe::from_json(&serde_json::to_string(&obj).unwrap())
                .unwrap_err()
                .to_string();
            assert!(
                err.contains(&format!(
                    "header parameter {parameter} must be integrity protected"
                )) && err.contains(&format!("the {member} member")),
                "{member}/{parameter}: {err}"
            );
        }
    }

    #[test]
    fn unprotected_header_member_shape_is_strict() {
        let base = r#"{"protected":"eyJlbmMiOiJBMjU2R0NNIn0","ciphertext":"AA","iv":"AAAAAAAAAAAAAAAA","tag":"AAAAAAAAAAAAAAAA"}"#;
        for (member, value) in [
            // RFC 7516 §7.2.1: absent rather than empty.
            ("unprotected", serde_json::json!({})),
            ("header", serde_json::json!({})),
            // Not an object at all.
            ("unprotected", serde_json::json!("kid")),
            ("header", serde_json::json!(["kid"])),
            // An algorithm that is not a string.
            ("header", serde_json::json!({"alg": 128})),
        ] {
            let mut obj: serde_json::Value = serde_json::from_str(base).unwrap();
            obj[member] = value.clone();
            let err = FlattenedJwe::from_json(&obj.to_string())
                .unwrap_err()
                .to_string();
            assert!(
                err.contains(&format!("JWE JSON member {member}"))
                    || err.contains("non-string \"alg\""),
                "{member}={value}: {err}"
            );
        }
    }

    #[test]
    fn unprotected_alg_requires_a_key_that_pins_it() {
        // The message conveys alg only in the per-recipient unprotected header,
        // exactly as RFC 7516 §A.5 does.
        let jwe = FlattenedJwe::from_json(
            r#"{
                "protected": "eyJlbmMiOiJBMjU2R0NNIn0",
                "header": {"alg": "dir"},
                "ciphertext": "AA",
                "iv": "AAAAAAAAAAAAAAAA",
                "tag": "AAAAAAAAAAAAAAAA"
            }"#,
        )
        .unwrap();
        assert_eq!(jwe.unprotected_alg(), Some("dir"));
        assert_eq!(jwe.peek_alg().unwrap(), None, "protected header has no alg");

        // The raw-key API has nothing to check it against, so it refuses.
        let err = decrypt_flattened(&key(), &jwe).unwrap_err().to_string();
        assert!(
            err.contains("raw-key API cannot trust") && err.contains("alg dir"),
            "{err}"
        );

        // A key pinned to the same algorithm accepts it...
        let mut pinned = crate::jwk::generate_symmetric(32).unwrap();
        pinned.alg = Some("dir".into());
        assert!(decrypt_flattened_with_jwk(&pinned, &jwe).is_err()); // wrong key bytes, but the
                                                                     // policy accepted the algorithm
                                                                     // ...and a key pinned elsewhere refuses it before any crypto.
        let mut mismatched = crate::jwk::generate_symmetric(32).unwrap();
        mismatched.alg = Some("A256KW".into());
        let err = decrypt_flattened_with_jwk(&mismatched, &jwe)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("JWK alg A256KW does not match token header alg dir"),
            "{err}"
        );
    }

    #[test]
    fn jose_header_union_is_reported_without_being_trusted() {
        let jwe = FlattenedJwe::from_json(
            r#"{
                "protected": "eyJlbmMiOiJBMjU2R0NNIn0",
                "unprotected": {"jku": "https://example.invalid/jwks"},
                "header": {"alg": "dir", "kid": "7"},
                "ciphertext": "AA",
                "iv": "AAAAAAAAAAAAAAAA",
                "tag": "AAAAAAAAAAAAAAAA"
            }"#,
        )
        .unwrap();
        let union = jwe.peek_jose_header().unwrap();
        assert_eq!(union["enc"], serde_json::json!("A256GCM"));
        assert_eq!(union["alg"], serde_json::json!("dir"));
        assert_eq!(union["kid"], serde_json::json!("7"));
        assert_eq!(
            union["jku"],
            serde_json::json!("https://example.invalid/jwks"),
            "reported as data; nothing in this crate fetches or trusts it"
        );
    }

    #[test]
    fn rejects_a_jws_object_as_not_a_jwe() {
        let text = r#"{"protected":"AA","payload":"AA","signature":"AA"}"#;
        let err = json::FlattenedJwe::from_json(text).unwrap_err().to_string();
        assert!(err.contains("belongs to a JWS"), "{err}");
    }

    #[test]
    fn rejects_oversized_input() {
        let big = format!(
            r#"{{"protected":"AA","ciphertext":"{}","iv":"AA","tag":"AA"}}"#,
            "A".repeat(crate::MAX_TOKEN_BYTES)
        );
        let err = json::FlattenedJwe::from_json(&big).unwrap_err().to_string();
        assert!(err.contains("MAX_TOKEN_BYTES"), "{err}");
    }

    #[test]
    fn rejects_malformed_compact_input() {
        for token in ["", "a.b", "a.b.c.d", "a.b.c.d.e.f"] {
            assert!(
                json::FlattenedJwe::from_compact(token).is_err(),
                "{token} must not parse as a JWE compact token"
            );
        }
    }

    // -- policy parity with the compact path --

    #[test]
    fn allow_list_applies_to_json_messages() {
        let token =
            json::encrypt_flattened(&key(), b"p", JweAlgorithm::Dir, JweEncryption::A256GCM)
                .unwrap();
        let options =
            JweDecryptOptions::new(vec![JweAlgorithm::A256KW], vec![JweEncryption::A256GCM]);
        let err = json::decrypt_flattened_with_options(&key(), &token, &options)
            .unwrap_err()
            .to_string();
        assert!(err.contains("allow-list"), "{err}");
    }

    #[test]
    fn plaintext_limit_applies_to_json_messages() {
        let token = json::encrypt_flattened(
            &key(),
            &vec![0x41u8; 4096],
            JweAlgorithm::Dir,
            JweEncryption::A256GCM,
        )
        .unwrap();
        let options = JweDecryptOptions::new(vec![JweAlgorithm::Dir], vec![JweEncryption::A256GCM])
            .with_max_plaintext(16);
        let err = json::decrypt_flattened_with_options(&key(), &token, &options)
            .unwrap_err()
            .to_string();
        assert!(err.contains("maximum size"), "{err}");
    }

    #[test]
    fn zip_and_crit_are_rejected_on_json_messages() {
        let jwe = json::encrypt_flattened(&key(), b"p", JweAlgorithm::Dir, JweEncryption::A256GCM)
            .unwrap();
        let protected = jwe.protected.clone().unwrap();
        let mut header: JoseHeader =
            serde_json::from_slice(&base64url::decode(&protected).unwrap()).unwrap();

        header.extra.insert("zip".into(), serde_json::json!("DEF"));
        let mut tampered = jwe.clone();
        tampered.protected = Some(base64url::encode(&serde_json::to_vec(&header).unwrap()));
        let err = json::decrypt_flattened(&key(), &tampered)
            .unwrap_err()
            .to_string();
        assert!(err.contains("zip"), "{err}");

        header.extra.clear();
        header.crit = Some(vec!["ext".into()]);
        tampered.protected = Some(base64url::encode(&serde_json::to_vec(&header).unwrap()));
        let err = json::decrypt_flattened(&key(), &tampered)
            .unwrap_err()
            .to_string();
        assert!(err.contains("crit"), "{err}");
    }

    #[test]
    fn changed_protected_header_breaks_authentication() {
        let jwe = json::encrypt_flattened(
            &key(),
            b"payload",
            JweAlgorithm::Dir,
            JweEncryption::A256GCM,
        )
        .unwrap();
        let protected = jwe.protected.clone().unwrap();
        let mut header: JoseHeader =
            serde_json::from_slice(&base64url::decode(&protected).unwrap()).unwrap();
        header.kid = Some("attacker".into());
        let mut tampered = jwe;
        tampered.protected = Some(base64url::encode(&serde_json::to_vec(&header).unwrap()));
        assert!(json::decrypt_flattened(&key(), &tampered).is_err());
    }

    #[test]
    fn wrong_key_fails() {
        let jwe = json::encrypt_flattened(&key(), b"p", JweAlgorithm::Dir, JweEncryption::A256GCM)
            .unwrap();
        assert!(json::decrypt_flattened(&[0x99u8; 32], &jwe).is_err());
    }

    #[test]
    fn missing_iv_is_a_structural_failure_not_a_panic() {
        let mut jwe =
            json::encrypt_flattened(&key(), b"p", JweAlgorithm::Dir, JweEncryption::A256GCM)
                .unwrap();
        jwe.iv = None;
        assert!(json::decrypt_flattened(&key(), &jwe).is_err());
    }

    #[test]
    fn missing_protected_header_is_rejected_before_any_crypto() {
        let mut jwe =
            json::encrypt_flattened(&key(), b"p", JweAlgorithm::Dir, JweEncryption::A256GCM)
                .unwrap();
        jwe.protected = None;
        let err = json::decrypt_flattened(&key(), &jwe)
            .unwrap_err()
            .to_string();
        assert!(err.contains("protected header"), "{err}");
        assert!(jwe.peek_protected_header().unwrap().is_none());
        assert_eq!(jwe.peek_alg().unwrap(), None);
    }

    // -- JWK paths --

    #[test]
    fn jwk_roundtrip_and_operation_pins() {
        let mut jwk = crate::jwk::generate_symmetric(32).unwrap();
        jwk.alg = Some("A256KW".into());
        let token = json::encrypt_flattened_with_jwk(&jwk, b"jwk", JweEncryption::A128GCM).unwrap();
        assert_eq!(
            json::decrypt_flattened_with_jwk(&jwk, &token).unwrap(),
            b"jwk"
        );

        // A signing-pinned key may not encrypt.
        let mut signer = crate::jwk::generate_symmetric(32).unwrap();
        signer.alg = Some("HS256".into());
        assert!(json::encrypt_flattened_with_jwk(&signer, b"p", JweEncryption::A128GCM).is_err());

        // `use: sig` may neither encrypt nor decrypt a JWE.
        let mut restricted = crate::jwk::generate_symmetric(32).unwrap();
        restricted.alg = Some("A256KW".into());
        restricted.use_ = Some("sig".into());
        assert!(
            json::encrypt_flattened_with_jwk(&restricted, b"p", JweEncryption::A128GCM).is_err()
        );

        // A JWK whose pinned alg differs from the token's is refused.
        let mut other = jwk.clone();
        other.alg = Some("A128KW".into());
        let err = json::decrypt_flattened_with_jwk(&other, &token)
            .unwrap_err()
            .to_string();
        assert!(err.contains("does not match token header alg"), "{err}");
    }

    #[test]
    fn jwk_header_path_authenticates_extra_members() {
        let mut jwk = crate::jwk::generate_symmetric(32).unwrap();
        jwk.alg = Some("dir".into());
        let mut header = JoseHeader::for_jwe(JweAlgorithm::Dir, JweEncryption::A256GCM);
        header.kid = Some("recipient-1".into());
        header.typ = Some("audit-record".into());
        let token = json::encrypt_flattened_with_jwk_header(
            &jwk,
            header.clone(),
            b"ctx",
            JweEncryption::A256GCM,
        )
        .unwrap();
        assert_eq!(
            json::decrypt_flattened_with_jwk(&jwk, &token).unwrap(),
            b"ctx"
        );
        let peeked = decode_header(&token).unwrap().unwrap();
        assert_eq!(peeked.kid.as_deref(), Some("recipient-1"));
        assert_eq!(peeked.typ.as_deref(), Some("audit-record"));

        // Key-reference members stay opt-in on this path too.
        let mut with_jku = header.clone();
        with_jku.jku = Some("https://attacker.invalid/jwks".into());
        let err = json::encrypt_flattened_with_jwk_header(
            &jwk,
            with_jku.clone(),
            b"p",
            JweEncryption::A256GCM,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("allow_key_reference_headers"), "{err}");
        json::encrypt_flattened_with_jwk_header_options(
            &jwk,
            with_jku,
            b"p",
            JweEncryption::A256GCM,
            &JweEncryptOptions::new().with_key_reference_headers(true),
        )
        .unwrap();
    }

    #[test]
    fn emit_side_header_rules_match_compact() {
        let mut header = JoseHeader::for_jwe(JweAlgorithm::Dir, JweEncryption::A256GCM);
        header.extra.insert("zip".into(), serde_json::json!("DEF"));
        let err = json::encrypt_flattened_with_header(
            header,
            &key(),
            b"p",
            JweAlgorithm::Dir,
            JweEncryption::A256GCM,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("zip"), "{err}");

        // alg/enc disagreement is refused on this path as well.
        let mismatched = JoseHeader::for_jwe(JweAlgorithm::A256KW, JweEncryption::A256GCM);
        let err = json::encrypt_flattened_with_header(
            mismatched,
            &key(),
            b"p",
            JweAlgorithm::Dir,
            JweEncryption::A256GCM,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("does not match"), "{err}");
    }

    #[test]
    fn rsa_oaep_json_roundtrip() {
        let mut jwk = crate::jwk::generate_rsa(2048).unwrap();
        jwk.alg = Some("RSA-OAEP-256".into());
        let token = json::encrypt_flattened_with_jwk(&jwk, b"rsa", JweEncryption::A256GCM).unwrap();
        assert_eq!(
            json::decrypt_flattened_with_jwk(&jwk, &token).unwrap(),
            b"rsa"
        );
        // The same message decrypts from its compact form.
        let text = token.to_compact().unwrap();
        let back = json::FlattenedJwe::from_compact(&text).unwrap();
        assert_eq!(
            json::decrypt_flattened_with_jwk(&jwk, &back).unwrap(),
            b"rsa"
        );
    }

    // -- external additional authenticated data --

    fn aad_opts(bytes: &[u8]) -> JweEncryptOptions {
        JweEncryptOptions::new().with_external_aad(bytes)
    }

    fn aad_dec_opts(bytes: &[u8]) -> JweDecryptOptions {
        JweDecryptOptions::new(vec![JweAlgorithm::Dir], vec![JweEncryption::A256GCM])
            .with_external_aad(bytes)
    }

    #[test]
    fn external_aad_roundtrips_and_is_authenticated() {
        let aad = b"invoice-42";
        let jwe = encrypt_flattened_with_header_options(
            JoseHeader::for_jwe(JweAlgorithm::Dir, JweEncryption::A256GCM),
            &key(),
            b"payload",
            JweAlgorithm::Dir,
            JweEncryption::A256GCM,
            &aad_opts(aad),
        )
        .unwrap();

        // The member is present, base64url, and carries the octets.
        assert_eq!(jwe.aad.as_deref(), Some(base64url::encode(aad).as_str()));
        assert!(jwe.to_json().unwrap().contains("\"aad\""));

        // Same bytes: decrypts.
        assert_eq!(
            decrypt_flattened_with_options(&key(), &jwe, &aad_dec_opts(aad)).unwrap(),
            b"payload"
        );

        // Different bytes: named error, not a bare authentication failure.
        let wrong = decrypt_flattened_with_options(&key(), &jwe, &aad_dec_opts(b"invoice-43"))
            .unwrap_err()
            .to_string();
        assert!(
            wrong.contains("does not match the message's \"aad\" member"),
            "{wrong}"
        );

        // No bytes at all: told what is missing.
        let missing = decrypt_flattened(&key(), &jwe).unwrap_err().to_string();
        assert!(missing.contains("with_external_aad"), "{missing}");

        // Tampering with the member changes the AAD input, so the tag fails.
        // This is the point: `aad` is unencrypted but authenticated.
        let mut tampered = jwe.clone();
        tampered.aad = Some(base64url::encode(b"invoice-99"));
        let err = decrypt_flattened_with_options(&key(), &tampered, &aad_dec_opts(b"invoice-42"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("does not match"), "{err}");
        // The interesting substitution: an attacker replaces the member *and*
        // the recipient is talked into using the substituted bytes. Caller
        // expectation and member now agree, so the only thing left standing is
        // the content tag, which was computed over the original AAD input.
        // That is the proof that `aad` is authenticated, not merely sent.
        let substituted = b"invoice-99";
        let mut flipped = jwe.clone();
        flipped.aad = Some(base64url::encode(substituted));
        assert!(matches!(
            decrypt_flattened_with_options(&key(), &flipped, &aad_dec_opts(substituted)),
            Err(JoseError::Crypto(_))
        ));
    }

    #[test]
    fn options_and_message_must_agree_about_the_aad_member() {
        // Message without external AAD, caller supplies some.
        let plain =
            encrypt_flattened(&key(), b"p", JweAlgorithm::Dir, JweEncryption::A256GCM).unwrap();
        assert!(plain.aad.is_none());
        let err = decrypt_flattened_with_options(&key(), &plain, &aad_dec_opts(b"extra"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("has no \"aad\" member"), "{err}");
    }

    #[test]
    fn empty_external_aad_is_refused_on_both_sides() {
        let err = encrypt_flattened_with_header_options(
            JoseHeader::for_jwe(JweAlgorithm::Dir, JweEncryption::A256GCM),
            &key(),
            b"p",
            JweAlgorithm::Dir,
            JweEncryption::A256GCM,
            &aad_opts(b""),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("must not be empty"), "{err}");

        let jwe = encrypt_flattened_with_header_options(
            JoseHeader::for_jwe(JweAlgorithm::Dir, JweEncryption::A256GCM),
            &key(),
            b"p",
            JweAlgorithm::Dir,
            JweEncryption::A256GCM,
            &aad_opts(b"x"),
        )
        .unwrap();
        let err = decrypt_flattened_with_jwk_and_aad(
            &{
                let mut jwk = crate::jwk::generate_symmetric(32).unwrap();
                jwk.alg = Some("dir".into());
                jwk
            },
            &jwe,
            b"",
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("must not be empty"), "{err}");
    }

    #[test]
    fn external_aad_blocks_the_compact_serialization() {
        // Encrypting compact with the option set is refused rather than
        // silently producing a token whose AAD the recipient cannot rebuild.
        let err = compact::encrypt_with_header_options(
            JoseHeader::for_jwe(JweAlgorithm::Dir, JweEncryption::A256GCM),
            &key(),
            b"p",
            JweAlgorithm::Dir,
            JweEncryption::A256GCM,
            &aad_opts(b"secret-context"),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("requires the JWE JSON serialization"), "{err}");

        // And decrypting compact with it is refused too.
        let token =
            compact::encrypt(&key(), b"p", JweAlgorithm::Dir, JweEncryption::A256GCM).unwrap();
        let err = compact::decrypt_with_options(&key(), &token, &aad_dec_opts(b"ctx"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("requires the JWE JSON serialization"), "{err}");

        // A JSON message with external AAD cannot be pushed into compact.
        let jwe = encrypt_flattened_with_header_options(
            JoseHeader::for_jwe(JweAlgorithm::Dir, JweEncryption::A256GCM),
            &key(),
            b"p",
            JweAlgorithm::Dir,
            JweEncryption::A256GCM,
            &aad_opts(b"ctx"),
        )
        .unwrap();
        let err = jwe.to_compact().unwrap_err().to_string();
        assert!(
            err.contains("external additional authenticated data"),
            "{err}"
        );
    }

    #[test]
    fn jwk_path_carries_external_aad() {
        let mut jwk = crate::jwk::generate_symmetric(32).unwrap();
        jwk.alg = Some("dir".into());
        let jwe = encrypt_flattened_with_jwk_header_options(
            &jwk,
            JoseHeader::for_jwe(JweAlgorithm::Dir, JweEncryption::A256GCM),
            b"ctx",
            JweEncryption::A256GCM,
            &aad_opts(b"tenant-7"),
        )
        .unwrap();
        assert_eq!(
            decrypt_flattened_with_jwk_and_aad(&jwk, &jwe, b"tenant-7").unwrap(),
            b"ctx"
        );
        // Without the AAD the same key refuses the message.
        assert!(decrypt_flattened_with_jwk(&jwk, &jwe).is_err());
    }

    #[test]
    fn aad_member_must_be_a_string_and_canonical() {
        let jwe =
            encrypt_flattened(&key(), b"p", JweAlgorithm::Dir, JweEncryption::A256GCM).unwrap();
        for value in [serde_json::json!(5), serde_json::json!("AA==")] {
            let mut obj: serde_json::Value = serde_json::from_str(&jwe.to_json().unwrap()).unwrap();
            obj["aad"] = value.clone();
            let err = FlattenedJwe::from_json(&obj.to_string())
                .unwrap_err()
                .to_string();
            assert!(
                err.contains("must be a string") || err.contains("base64"),
                "{value}: {err}"
            );
        }
    }

    #[test]
    fn empty_plaintext_roundtrip() {
        let token = json::encrypt_flattened(&key(), b"", JweAlgorithm::Dir, JweEncryption::A256GCM)
            .unwrap();
        assert_eq!(json::decrypt_flattened(&key(), &token).unwrap(), b"");
    }
}
