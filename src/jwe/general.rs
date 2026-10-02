//! General JWE JSON Serialization (RFC 7516 §7.2.1) — multiple recipients.
//!
//! The general syntax encrypts one message to several recipients. There is a
//! single ciphertext, one IV, one authentication tag and one protected header,
//! and then one array element per recipient carrying that recipient's encrypted
//! CEK and its own unprotected header:
//!
//! ```text
//! {
//!   "protected":   "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
//!   "unprotected": {"jku": "https://server.example.com/keys.jwks"},
//!   "recipients": [
//!     { "header": {"kid":"1"}, "encrypted_key": "…" },
//!     { "header": {"kid":"7"}, "encrypted_key": "…" }
//!   ],
//!   "iv": "…", "ciphertext": "…", "tag": "…"
//! }
//! ```
//!
//! Decryption is *always scoped to one recipient*. That is not a convenience
//! restriction: RFC 7516 §7.2.1 defines the header the content tag is validated
//! under as the union of the shared members and **that recipient's** unprotected
//! members, so a "decrypt it for whoever" entry point would have to pick a
//! recipient on unauthenticated data and then authenticate against a header the
//! caller never agreed to. The caller names the recipient — by position with
//! [`decrypt_general_with_jwk`], or by the key's own `kid` with
//! [`decrypt_general_with_jwk_by_kid`] — and everything else follows from that.
//!
//! The security rules of the flattened syntax carry over unchanged, because a
//! general message is *flattened* internally before it is decrypted (which is
//! exactly the equivalence RFC 7516 §7.2.1 states between the two syntaxes):
//!
//! - `enc` must be integrity protected;
//! - an unprotected `alg` is accepted only against a key that pins it
//!   (ADR 0013);
//! - header parameter names must be disjoint across the locations that
//!   contribute to *that* recipient's header;
//! - unknown members are ignored for processing but retained, so re-serializing
//!   does not silently drop what a peer sent.

use serde_json::{Map, Value};

use crate::algorithm::{JweAlgorithm, JweEncryption};
use crate::base64url;
use crate::error::{JoseError, Result};
use crate::header::JoseHeader;
use crate::jwe::internal::{self, ensure_token_size, JweDecryptOptions, JweEncryptOptions};
use crate::jwe::json::{self as json_mod, FlattenedJwe};
use crate::member_map::MemberMap;

/// Maximum number of recipients a general message may name.
///
/// Key management costs grow linearly with the recipient count, and a
/// recipient array is attacker-sized data: a 10 000-element array is a cheap
/// denial of service against any implementation that parses it eagerly. The
/// limit bounds parsing and every later selection step; RFC 8725 §1 imposes no
/// number, so this is a deliberate operational bound (ADR 0014).
pub const MAX_RECIPIENTS: usize = 32;

/// One element of the `recipients` array (RFC 7516 §7.2.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recipient {
    /// JWE Per-Recipient Unprotected Header, the element's `header` member.
    ///
    /// Not integrity protected; it contributes to *this* recipient's JOSE
    /// Header, so its contents change what the content tag is validated
    /// against. See [`crate::jwe::json::FlattenedJwe::unprotected`] for the
    /// trust rules (ADR 0013).
    pub header: Option<Map<String, Value>>,
    /// `BASE64URL(JWE Encrypted Key)` for this recipient; absent for `dir`.
    pub encrypted_key: Option<String>,
    /// Unrecognized members of the element, retained in document order and
    /// ignored while processing (RFC 7516 §7.2.1).
    pub other: Vec<(String, Value)>,
}

impl Recipient {
    /// Parse one `recipients` array element.
    ///
    /// # Errors
    ///
    /// [`JoseError::InvalidToken`] when the element is not a JSON object, its
    /// `header` is not a non-empty object of authenticable-position
    /// parameters, or its `encrypted_key` is not canonical base64url.
    fn from_value(value: Value) -> Result<Self> {
        let Value::Object(object) = value else {
            return Err(JoseError::InvalidToken(
                "each JWE \"recipients\" element must be a JSON object".into(),
            ));
        };
        let mut map = MemberMap::new(object.into_iter().collect::<Vec<_>>())?;
        let header = json_mod::object_member(&mut map, "header")?;
        let encrypted_key = match map.take("encrypted_key") {
            None => None,
            Some(Value::String(value)) if value.is_empty() => None,
            Some(Value::String(value)) => {
                base64url::decode(&value)?;
                Some(value)
            }
            Some(_) => {
                return Err(JoseError::InvalidToken(
                    "JWE \"recipients\" element member \"encrypted_key\" must be a string".into(),
                ))
            }
        };
        Ok(Self {
            header,
            encrypted_key,
            other: map.drain_leftovers(),
        })
    }

    /// Re-serialize this element.
    fn to_value(&self) -> Result<Value> {
        let mut object = Map::new();
        if let Some(header) = &self.header {
            if !header.is_empty() {
                object.insert("header".into(), Value::Object(header.clone()));
            }
        }
        if let Some(encrypted_key) = &self.encrypted_key {
            if !encrypted_key.is_empty() {
                object.insert("encrypted_key".into(), Value::String(encrypted_key.clone()));
            }
        }
        MemberMap::new(self.other.clone())?.write_into(&mut object)?;
        Ok(Value::Object(object))
    }
}

/// A general JWE JSON Serialization (RFC 7516 §7.2.1): parsed, not
/// authenticated.
///
/// The shared members are the same as in the flattened syntax
/// ([`FlattenedJwe`]); what changes is that `encrypted_key` and the
/// per-recipient unprotected header move into one array element per recipient.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneralJwe {
    /// `BASE64URL(UTF8(JWE Protected Header))`, kept verbatim.
    pub protected: Option<String>,
    /// JWE Shared Unprotected Header, shared by every recipient.
    pub unprotected: Option<Map<String, Value>>,
    /// `BASE64URL(JWE AAD)` (ADR 0012).
    pub aad: Option<String>,
    /// `BASE64URL(JWE Initialization Vector)`.
    pub iv: Option<String>,
    /// `BASE64URL(JWE Ciphertext)`. The only mandatory member.
    pub ciphertext: String,
    /// `BASE64URL(JWE Authentication Tag)`.
    pub tag: Option<String>,
    /// One element per recipient; never empty, never more than
    /// [`MAX_RECIPIENTS`].
    pub recipients: Vec<Recipient>,
    /// Unrecognized top-level members, retained and ignored.
    pub other: Vec<(String, Value)>,
}

impl GeneralJwe {
    /// Parse a general JWE JSON Serialization.
    ///
    /// # Errors
    ///
    /// [`JoseError::InvalidToken`] when the text exceeds
    /// [`crate::MAX_TOKEN_BYTES`], is not a JSON object, repeats a member name,
    /// omits `ciphertext` or `protected`, carries a top-level `header` or
    /// `encrypted_key` (those live in the recipient elements), has a
    /// `recipients` member that is not a non-empty array of at most
    /// [`MAX_RECIPIENTS`] objects, breaks the disjointness rule for any
    /// recipient, or places a parameter that must be integrity protected in an
    /// unprotected position.
    pub fn from_json(text: &str) -> Result<Self> {
        ensure_token_size(text)?;
        let mut map = MemberMap::from_json(text)?;

        for name in json_mod::JWS_MEMBERS {
            if map.contains(name) {
                return Err(JoseError::InvalidToken(format!(
                    "member {name} belongs to a JWS; this is not a JWE JSON object"
                )));
            }
        }
        // In the general syntax these two live inside each recipient element,
        // and accepting them at the top level would silently apply one
        // recipient's key to the others.
        for name in ["header", "encrypted_key"] {
            if map.contains(name) {
                return Err(JoseError::InvalidToken(format!(
                    "JWE general serialization has no top-level \"{name}\" member; it belongs \
                     to a \"recipients\" element (RFC 7516 §7.2.1)"
                )));
            }
        }

        let protected = json_mod::require_protected(&mut map)?;
        let unprotected = json_mod::object_member(&mut map, "unprotected")?;
        let aad = json_mod::optional_member(&mut map, "aad")?;
        let ciphertext = json_mod::require_member(&mut map, "ciphertext")?;
        let iv = json_mod::optional_member(&mut map, "iv")?;
        let tag = json_mod::optional_member(&mut map, "tag")?;

        let raw_recipients = map.take("recipients").ok_or_else(|| {
            JoseError::InvalidToken(
                "JWE JSON member \"recipients\" is required for the general serialization; \
                     if the message has one recipient it is the flattened syntax — use \
                     jose_rs::jwe::json::FlattenedJwe::from_json"
                    .into(),
            )
        })?;
        let Value::Array(elements) = raw_recipients else {
            return Err(JoseError::InvalidToken(
                "JWE JSON member \"recipients\" must be an array of JSON objects".into(),
            ));
        };
        if elements.is_empty() {
            return Err(JoseError::InvalidToken(
                "JWE \"recipients\" must hold at least one recipient (RFC 7516 §7.2.1)".into(),
            ));
        }
        if elements.len() > MAX_RECIPIENTS {
            return Err(JoseError::InvalidToken(format!(
                "JWE \"recipients\" names {} recipients, more than this crate's bound of \
                 {MAX_RECIPIENTS}",
                elements.len()
            )));
        }
        let mut recipients = Vec::with_capacity(elements.len());
        for element in elements {
            recipients.push(Recipient::from_value(element)?);
        }

        for value in [
            Some(protected.as_str()),
            aad.as_deref(),
            iv.as_deref(),
            tag.as_deref(),
            Some(ciphertext.as_str()),
        ]
        .into_iter()
        .flatten()
        {
            base64url::decode(value)?;
        }

        // Disjointness is per recipient: the header that recipient's tag is
        // validated under is the union of the shared members and that element's
        // own unprotected header (RFC 7516 §7.2.1).
        // Disjointness is per recipient: the header that recipient's tag is
        // validated under is the union of the protected header, the shared
        // unprotected header and *that* element's header (RFC 7516 §7.2.1).
        for (index, recipient) in recipients.iter().enumerate() {
            json_mod::ensure_header_locations_disjoint(
                &protected,
                unprotected.as_ref(),
                recipient.header.as_ref(),
            )
            .map_err(|err| match err {
                JoseError::InvalidToken(message) => {
                    JoseError::InvalidToken(format!("{message} (checked for recipient {index})"))
                }
                other => other,
            })?;
        }

        Ok(Self {
            protected: Some(protected),
            unprotected,
            aad,
            iv,
            ciphertext,
            tag,
            recipients,
            other: map.drain_leftovers(),
        })
    }

    /// Serialize back to the general JSON syntax.
    pub fn to_json(&self) -> Result<String> {
        let mut map = Map::new();
        if let Some(protected) = &self.protected {
            map.insert("protected".into(), Value::String(protected.clone()));
        }
        if let Some(unprotected) = &self.unprotected {
            if !unprotected.is_empty() {
                map.insert("unprotected".into(), Value::Object(unprotected.clone()));
            }
        }
        if let Some(aad) = &self.aad {
            if !aad.is_empty() {
                map.insert("aad".into(), Value::String(aad.clone()));
            }
        }
        if let Some(iv) = &self.iv {
            if !iv.is_empty() {
                map.insert("iv".into(), Value::String(iv.clone()));
            }
        }
        if let Some(tag) = &self.tag {
            if !tag.is_empty() {
                map.insert("tag".into(), Value::String(tag.clone()));
            }
        }
        map.insert("ciphertext".into(), Value::String(self.ciphertext.clone()));

        let mut elements = Vec::with_capacity(self.recipients.len());
        for recipient in &self.recipients {
            elements.push(recipient.to_value()?);
        }
        map.insert("recipients".into(), Value::Array(elements));

        MemberMap::new(self.other.clone())?.write_into(&mut map)?;
        let text = serde_json::to_string(&map)?;
        ensure_token_size(&text)?;
        Ok(text)
    }

    /// Number of recipients named by the message.
    #[must_use]
    pub fn recipient_count(&self) -> usize {
        self.recipients.len()
    }

    /// Flatten the message for one recipient (RFC 7516 §7.2.2 equivalence).
    ///
    /// This is the internal shape every decrypt path uses: a general message and
    /// its flattened form carry identical ciphertext, tag and per-recipient key,
    /// so decrypting through the flattened code path means one policy
    /// implementation, not two.
    ///
    /// # Errors
    ///
    /// [`JoseError::InvalidToken`] when `recipient` is out of range.
    pub fn flatten_for(&self, recipient: usize) -> Result<FlattenedJwe> {
        let entry = self.recipients.get(recipient).ok_or_else(|| {
            JoseError::InvalidToken(format!(
                "recipient {recipient} is out of range: this message names {} recipient(s)",
                self.recipients.len()
            ))
        })?;
        Ok(FlattenedJwe {
            protected: self.protected.clone(),
            unprotected: self.unprotected.clone(),
            // The recipient element's `header` *is* the flattened `header`.
            header: entry.header.clone(),
            aad: self.aad.clone(),
            encrypted_key: entry.encrypted_key.clone(),
            iv: self.iv.clone(),
            ciphertext: self.ciphertext.clone(),
            tag: self.tag.clone(),
            other: Vec::new(),
        })
    }

    /// The JOSE Header a given recipient computes over: shared members plus that
    /// element's unprotected header (RFC 7516 §7.2.1).
    ///
    /// Inspection only. Values contributed by `unprotected` / `header` are not
    /// authenticated — see [`FlattenedJwe::peek_jose_header`].
    pub fn peek_jose_header_for(&self, recipient: usize) -> Result<Map<String, Value>> {
        self.flatten_for(recipient)?.peek_jose_header()
    }

    /// The `kid` each recipient element conveys, unauthenticated.
    ///
    /// Key *candidate* selection only: a `kid` in an unprotected position is a
    /// hint the sender (or an attacker) chose, never an authorization
    /// (ADR 0013).
    pub fn recipient_kids(&self) -> Vec<Option<&str>> {
        self.recipients
            .iter()
            .map(|entry| {
                entry
                    .header
                    .as_ref()
                    .and_then(|header| header.get("kid"))
                    .and_then(Value::as_str)
                    .or_else(|| {
                        self.unprotected
                            .as_ref()
                            .and_then(|header| header.get("kid"))
                            .and_then(Value::as_str)
                    })
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Emitting a general JWE
// ---------------------------------------------------------------------------

/// One recipient of a general JWE being created.
///
/// `header` is the element's unprotected header. This crate only lets you put
/// parameters there that are safe to leave unauthenticated: `alg`, `enc`, `zip`
/// and `crit` are refused, because a value that decides how the message is
/// decrypted or validated must be integrity protected (ADR 0013). `kid` is the
/// intended use.
#[derive(Debug, Clone)]
pub struct RecipientSpec<'a> {
    /// Key-management key for this recipient (public key for key transport,
    /// KEK for key wrapping).
    pub key: &'a [u8],
    /// `kid` to place in this recipient's unprotected header, if any.
    pub kid: Option<&'a str>,
}

impl<'a> RecipientSpec<'a> {
    /// A recipient with no per-recipient header parameters.
    #[must_use]
    pub fn new(key: &'a [u8]) -> Self {
        Self { key, kid: None }
    }

    /// A recipient identified by `kid` in its unprotected header.
    #[must_use]
    pub fn with_kid(key: &'a [u8], kid: &'a str) -> Self {
        Self {
            key,
            kid: Some(kid),
        }
    }

    fn header(&self) -> Option<Map<String, Value>> {
        self.kid.map(|kid| {
            let mut object = Map::new();
            object.insert("kid".into(), Value::String(kid.to_owned()));
            object
        })
    }
}

/// Encrypt to several recipients, General JWE JSON Serialization.
///
/// All recipients share one key-management algorithm and one content encryption
/// algorithm; the CEK is generated once, the plaintext is encrypted once, and
/// only the CEK wrapping repeats — that is the shape RFC 7516 §7.2.1 defines.
///
/// # Errors
///
/// [`JoseError::InvalidHeader`] when `recipients` is empty, when `header.alg`
/// does not match `alg` or `header.enc` does not match `enc`, or when the header
/// fails the JWE emit policy (unimplemented members, `crit`, duplicate members,
/// key-reference members, header size);
/// [`JoseError::UnsupportedAlgorithm`] when `alg` is `dir` (direct agreement
/// conveys no encrypted key, so it cannot address more than one recipient) or is
/// not implemented; [`JoseError::Key`] for a wrong-size KEK.
pub fn encrypt_general(
    header: &JoseHeader,
    recipients: &[RecipientSpec<'_>],
    plaintext: &[u8],
    alg: JweAlgorithm,
    enc: JweEncryption,
) -> Result<GeneralJwe> {
    encrypt_general_options(
        header,
        recipients,
        plaintext,
        alg,
        enc,
        &JweEncryptOptions::new(),
    )
}

/// [`encrypt_general`] with explicit [`JweEncryptOptions`].
///
/// External additional authenticated data, when configured on the options with
/// [`JweEncryptOptions::with_external_aad`], becomes the `aad` member and is
/// authenticated for *every* recipient at once: it is part of the shared AAD
/// input of a single ciphertext (ADR 0012).
pub fn encrypt_general_options(
    header: &JoseHeader,
    recipients: &[RecipientSpec<'_>],
    plaintext: &[u8],
    alg: JweAlgorithm,
    enc: JweEncryption,
    opts: &JweEncryptOptions,
) -> Result<GeneralJwe> {
    if recipients.is_empty() {
        return Err(JoseError::InvalidHeader(
            "a general JWE needs at least one recipient".into(),
        ));
    }
    if recipients.len() > MAX_RECIPIENTS {
        return Err(JoseError::InvalidHeader(format!(
            "a general JWE cannot name {} recipients; this crate's bound is {MAX_RECIPIENTS}",
            recipients.len()
        )));
    }
    // Encoded once and used for both the AAD input and the `aad` member, so the
    // two can never disagree.
    let aad_b64 = match opts.external_aad() {
        None => None,
        Some(bytes) => {
            internal::ensure_external_aad_present(bytes)?;
            Some(base64url::encode(bytes))
        }
    };

    // Direct key agreement agrees the CEK with exactly one recipient, so it can
    // never address a general JWE. Refused here, before any key work, with the
    // reason and the alternative named.
    if internal::alg_is_agreement(alg) {
        return Err(internal::direct_agreement_not_multi(alg));
    }
    let keys: Vec<internal::KeyMaterial> = recipients
        .iter()
        .map(|recipient| {
            internal::KeyMaterial::Bytes(zeroize::Zeroizing::new(recipient.key.to_vec()))
        })
        .collect();
    let (core, wrapped) =
        internal::encrypt_core_multi(header, &keys, plaintext, alg, enc, opts, aad_b64.as_deref())?;

    let entries = recipients
        .iter()
        .zip(wrapped)
        .map(|(spec, key)| Recipient {
            header: spec.header(),
            encrypted_key: (!key.is_empty()).then(|| base64url::encode(&key)),
            other: Vec::new(),
        })
        .collect();

    Ok(GeneralJwe {
        protected: Some(core.header_b64),
        // Never emitted (ADR 0013): an unprotected shared header is a target,
        // not a feature. The per-recipient `kid` is the one exception the RFC
        // itself needs, and it is caller-chosen, never invented.
        unprotected: None,
        aad: aad_b64,
        iv: (!core.iv.is_empty()).then(|| base64url::encode(&core.iv)),
        ciphertext: base64url::encode(&core.ciphertext),
        tag: (!core.tag.is_empty()).then(|| base64url::encode(&core.tag)),
        recipients: entries,
        other: Vec::new(),
    })
}

/// [`encrypt_general`] addressed by JWK, taking the algorithm from each key.
///
/// Every key must pin the same `alg` in [`Jwk::alg`](crate::jwk::Jwk::alg) — the
/// algorithm is a property of the key, and a general message whose recipients
/// disagree about it would have to carry it unprotected.
///
/// # Errors
///
/// [`JoseError::Key`] when a key omits `alg`, pins a different algorithm than
/// the others, or fails its operation check; otherwise the errors of
/// [`encrypt_general`].
pub fn encrypt_general_with_jwks(
    header: &JoseHeader,
    jwks: &[&crate::jwk::Jwk],
    plaintext: &[u8],
    enc: JweEncryption,
) -> Result<GeneralJwe> {
    encrypt_general_with_jwks_options(header, jwks, plaintext, enc, &JweEncryptOptions::new())
}

/// [`encrypt_general_with_jwks`] with explicit [`JweEncryptOptions`] (external
/// AAD, key-reference header opt-in).
pub fn encrypt_general_with_jwks_options(
    header: &JoseHeader,
    jwks: &[&crate::jwk::Jwk],
    plaintext: &[u8],
    enc: JweEncryption,
    opts: &JweEncryptOptions,
) -> Result<GeneralJwe> {
    if jwks.is_empty() {
        return Err(JoseError::InvalidHeader(
            "a general JWE needs at least one recipient".into(),
        ));
    }
    // Key material is materialized first: `jwk_to_jwe_key_bytes` returns owned
    // (zeroizing) bytes that must outlive the recipient specs.
    let mut materials = Vec::with_capacity(jwks.len());
    let mut pinned: Option<JweAlgorithm> = None;
    for jwk in jwks {
        let alg = json_mod::pinned_alg(jwk)?;
        // Refused per key, before any material is built, and with the reason each
        // mode actually has: direct agreement cannot address a general JWE at all,
        // while the wrapping modes could but have nowhere authenticated to put
        // one `epk` per recipient (ADR 0017, ADR 0018).
        if internal::agreement_kek_len(alg).is_some() {
            return Err(internal::per_recipient_epk_unsupported(alg));
        }
        if internal::alg_is_agreement(alg) {
            return Err(internal::direct_agreement_not_multi(alg));
        }
        jwk.check_op(internal::jwe_alg_encrypt_op(alg))?;
        match pinned {
            None => pinned = Some(alg),
            Some(previous) if previous != alg => {
                return Err(JoseError::Key(format!(
                    "general JWE recipients must pin the same alg; one pins {} and another {}",
                    previous.as_str(),
                    alg.as_str()
                )));
            }
            Some(_) => {}
        }
        materials.push(internal::jwk_to_jwe_key_bytes(jwk, alg, false)?);
    }
    let alg = pinned.unwrap_or(JweAlgorithm::Dir);
    let specs: Vec<RecipientSpec<'_>> = jwks
        .iter()
        .zip(&materials)
        .map(|(jwk, material)| RecipientSpec {
            key: material.as_slice(),
            kid: jwk.kid.as_deref(),
        })
        .collect();
    encrypt_general_options(header, &specs, plaintext, alg, enc, opts)
}

/// Decrypt the given recipient of a general JWE with a JWK.
///
/// The recipient is named by the caller, not inferred: `recipient` selects the
/// array element whose encrypted key and unprotected header are used, and the
/// content tag is then validated under *that* recipient's header.
///
/// `jwk.alg` must pin the key-management algorithm the recipient's header
/// declares, whether that header is the protected one or the element's
/// unprotected `header` (ADR 0013), and `Jwk::check_op` is enforced.
///
/// # Errors
///
/// [`JoseError::InvalidToken`] for an out-of-range `recipient`, an
/// algorithm the key does not pin, or a failed external-AAD match;
/// [`JoseError::UnsupportedAlgorithm`] for an allow-list miss;
/// [`JoseError::Crypto`] when authentication fails.
pub fn decrypt_general_with_jwk(
    jwk: &crate::jwk::Jwk,
    jwe: &GeneralJwe,
    recipient: usize,
) -> Result<Vec<u8>> {
    json_mod::decrypt_flattened_with_jwk_impl(jwk, &jwe.flatten_for(recipient)?, None)
}

/// [`decrypt_general_with_jwk`] with the caller's [`JweDecryptOptions`] —
/// plaintext size limit, external AAD, and caller-understood `crit` extensions
/// (ADR 0015) — for a recipient of a general message.
///
/// # Errors
///
/// As [`decrypt_general_with_jwk`].
pub fn decrypt_general_with_jwk_options(
    jwk: &crate::jwk::Jwk,
    jwe: &GeneralJwe,
    recipient: usize,
    options: &JweDecryptOptions,
) -> Result<Vec<u8>> {
    json_mod::decrypt_flattened_with_jwk_options(jwk, &jwe.flatten_for(recipient)?, options)
}

/// [`decrypt_general_with_jwk`] for a message carrying an `aad` member.
pub fn decrypt_general_with_jwk_and_aad(
    jwk: &crate::jwk::Jwk,
    jwe: &GeneralJwe,
    recipient: usize,
    external_aad: &[u8],
) -> Result<Vec<u8>> {
    json_mod::decrypt_flattened_with_jwk_impl(jwk, &jwe.flatten_for(recipient)?, Some(external_aad))
}

/// Decrypt with the recipient whose unprotected `kid` matches `jwk.kid`.
///
/// The `kid` is an unauthenticated hint, so it is used only to *narrow* the
/// candidates; the key's pinned `alg` and the content tag still have to agree.
/// Zero matches and more than one match are both errors, because picking
/// arbitrarily would decide between recipients on attacker-chosen data.
///
/// # Errors
///
/// [`JoseError::InvalidToken`] when `jwk.kid` is unset, names no recipient, or
/// names more than one; otherwise the errors of [`decrypt_general_with_jwk`].
pub fn decrypt_general_with_jwk_by_kid(jwk: &crate::jwk::Jwk, jwe: &GeneralJwe) -> Result<Vec<u8>> {
    let (index, _) = select_recipient_by_kid(jwk, jwe)?;
    decrypt_general_with_jwk(jwk, jwe, index)
}

/// Resolve which recipient a key is for, and what the message looked like to
/// that selection.
///
/// Returns the chosen index together with the number of candidates that *did*
/// match the key's `kid`, so a caller building diagnostics can tell "one hit"
/// from "I picked from several" — the latter is refused outright, but the count
/// is what a log line needs.
pub(crate) fn select_recipient_by_kid(
    jwk: &crate::jwk::Jwk,
    jwe: &GeneralJwe,
) -> Result<(usize, usize)> {
    let kid = jwk
        .kid
        .as_deref()
        .ok_or_else(|| JoseError::Key("JWK kid must be set to select a recipient by kid".into()))?;
    let matches: Vec<usize> = jwe
        .recipient_kids()
        .iter()
        .enumerate()
        .filter_map(|(index, candidate)| (*candidate == Some(kid)).then_some(index))
        .collect();
    match matches.len() {
        0 => Err(JoseError::InvalidToken(format!(
            "no recipient of this JWE carries kid {kid}"
        ))),
        1 => Ok((matches[0], 1)),
        count => Err(JoseError::InvalidToken(format!(
            "{count} recipients of this JWE carry kid {kid}; the choice cannot be made from an \
             unauthenticated header parameter"
        ))),
    }
}

/// Decode the protected header of a general JWE **without** authenticating.
///
/// Inspection only — see [`FlattenedJwe::peek_protected_header`].
pub fn decode_header(jwe: &GeneralJwe) -> Result<Option<JoseHeader>> {
    jwe.flatten_for(0)?.peek_protected_header()
}
