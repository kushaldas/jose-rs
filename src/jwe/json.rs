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
//! Deliberately not implemented yet, and refused with an explicit error
//! rather than ignored, because each changes what a recipient must believe
//! about the message:
//!
//! - `unprotected` / `header` — unprotected header parameters, whose
//!   disjointness across the three header locations RFC 7516 §7.2.1 requires
//!   (ADR 0013);
//! - `recipients` — the general syntax and multiple recipients (ADR 0014).
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
    self, all_enc_algorithms, ensure_token_size, jwe_alg_decrypt_op, jwe_alg_encrypt_op,
    jwk_to_jwe_key_bytes, minimum_plaintext_len, JweDecryptOptions, JweEncryptOptions,
};
use crate::member_map::MemberMap;

/// Top-level members of the JWE JSON Serialization that this module rejects
/// by name, with the reason surfaced to the caller.
///
/// These are *registered* members (RFC 7516 §7.2.1), not unknown private
/// members, so ignoring them would silently discard header parameters that
/// change how the ciphertext must be interpreted.
const REJECTED_MEMBERS: &[(&str, &str)] = &[
    (
        "recipients",
        "general JWE JSON serialization (multiple recipients) is not implemented \
         by this crate version; use the flattened syntax or the compact serialization",
    ),
    (
        "unprotected",
        "the JWE shared unprotected header is not implemented by this crate version; \
         carry header parameters in the protected header",
    ),
    (
        "header",
        "the JWE per-recipient unprotected header is not implemented by this crate \
         version; carry header parameters in the protected header",
    ),
];

/// Members that identify the object as a JWS rather than a JWE
/// (RFC 7516 §9: a JWS has `payload`/`signature`, a JWE has `ciphertext`).
///
/// Checked before `ciphertext` is reported missing so a mis-routed token
/// produces "this is a JWS" instead of a confusing structural error.
const JWS_MEMBERS: &[&str] = &["payload", "signatures", "signature"];

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
    /// Required by this crate version: the `alg` and `enc` parameters must be
    /// integrity protected, and unprotected header members are not
    /// implemented (ADR 0011).
    pub protected: Option<String>,
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

        let protected = require_member(&mut map, "protected")?;
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

        let other = map.drain_leftovers().into_iter().collect::<Vec<_>>();

        Ok(Self {
            protected: Some(protected),
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

/// Require a string member, with the RFC 7516 presence rules applied.
///
/// An empty string is rejected: RFC 7516 §7.2.1 says a member whose value is
/// empty MUST be absent, so accepting `""` would accept a message the sender
/// could not have produced.
fn require_member(map: &mut MemberMap, name: &str) -> Result<String> {
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

/// Read an optional string member; `None` when absent or empty.
///
/// An explicit empty value is accepted here (and treated as absent) because
/// several producers emit `"encrypted_key":""` for `dir`; it is never
/// re-emitted by [`FlattenedJwe::to_json`].
fn optional_member(map: &mut MemberMap, name: &str) -> Result<Option<String>> {
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
    let key_bytes = jwk_to_jwe_key_bytes(jwk, alg, false)?;
    encrypt_flattened(&key_bytes, plaintext, alg, enc)
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
    let key_bytes = jwk_to_jwe_key_bytes(jwk, alg, false)?;
    encrypt_flattened_with_header_options(header, &key_bytes, plaintext, alg, enc, opts)
}

/// Read the key-management algorithm pinned in `jwk.alg`.
///
/// The JWK APIs take the algorithm from the *key*, never from token header
/// data, which is what makes the `alg` binding check on the decrypt side
/// meaningful. The error text is specific to these APIs so a caller can tell
/// which entry point rejected the key.
fn pinned_alg(jwk: &crate::jwk::Jwk) -> Result<JweAlgorithm> {
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
    // This crate version requires alg/enc to be integrity protected; with no
    // unprotected-header support there is nowhere else to carry them.
    let protected = jwe.protected.as_deref().ok_or_else(|| {
        JoseError::InvalidHeader("JWE JSON requires a protected header carrying alg and enc".into())
    })?;
    ensure_token_size(protected)?;
    ensure_token_size(&jwe.ciphertext)?;

    let encrypted_key_b64 = jwe.encrypted_key.as_deref().unwrap_or_default();
    let iv_b64 = jwe.iv.as_deref().unwrap_or_default();
    let tag_b64 = jwe.tag.as_deref().unwrap_or_default();

    let (envelope, _protected_header) = internal::parse_envelope(
        protected,
        encrypted_key_b64,
        iv_b64,
        &jwe.ciphertext,
        tag_b64,
    )?;

    options.check(envelope.alg, envelope.enc)?;
    options.check_plaintext_size(minimum_plaintext_len(jwe.ciphertext.len(), envelope.enc))?;

    let cek = internal::recover_cek(key, envelope.alg, envelope.enc, &envelope.encrypted_key)?;
    let external_aad = options.resolve_external_aad(jwe.aad.as_deref())?;
    let aad = internal::aad_input(protected, external_aad.as_deref());
    internal::finish_decrypt(&envelope, &cek, &aad, options)
}

/// Decrypt with a JWK, mirroring [`crate::jwe::decrypt_with_jwk`].
///
/// `jwk.alg` must be set and must equal the token's protected `alg`, so the
/// key-management algorithm is bound to the key rather than to attacker-
/// controlled header data; `Jwk::check_op` (`Decrypt` / `UnwrapKey`) is
/// enforced as well.
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

fn decrypt_flattened_with_jwk_impl(
    jwk: &crate::jwk::Jwk,
    jwe: &FlattenedJwe,
    external_aad: Option<&[u8]>,
) -> Result<Vec<u8>> {
    let header = jwe
        .peek_protected_header()?
        .ok_or_else(|| JoseError::InvalidHeader("missing protected header".into()))?;
    let alg = JweAlgorithm::from_str(&header.alg)?;

    let jwk_alg = jwk
        .alg
        .as_deref()
        .ok_or_else(|| JoseError::Key("JWK alg must be set for the JWE JWK APIs".into()))?;
    if jwk_alg != header.alg {
        return Err(JoseError::InvalidToken(format!(
            "JWK alg {jwk_alg} does not match token header alg {}",
            header.alg
        )));
    }

    jwk.check_op(jwe_alg_decrypt_op(alg))?;
    let key_bytes = jwk_to_jwe_key_bytes(jwk, alg, true)?;
    let mut options = JweDecryptOptions::new(vec![alg], all_enc_algorithms());
    if let Some(aad) = external_aad {
        internal::ensure_external_aad_present(aad)?;
        options = options.with_external_aad(aad);
    }
    decrypt_flattened_with_options(&key_bytes, jwe, &options)
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
            assert!(
                err.contains(&format!("member {missing} is required")),
                "{err}"
            );
        }
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
    fn rejects_unimplemented_members_with_a_reason() {
        for member in ["unprotected", "header", "recipients"] {
            let mut obj = serde_json::Map::new();
            obj.insert("protected".into(), serde_json::json!("AA"));
            obj.insert("ciphertext".into(), serde_json::json!("AA"));
            obj.insert(member.into(), serde_json::json!({}));
            let err = json::FlattenedJwe::from_json(&serde_json::to_string(&obj).unwrap())
                .unwrap_err()
                .to_string();
            assert!(
                err.contains(&format!("unsupported JWE JSON member {member}")),
                "{err}"
            );
        }
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
