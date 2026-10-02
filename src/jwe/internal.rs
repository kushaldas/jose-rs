//! Shared, crate-private JWE processing.
//!
//! Every JWE serialization (compact, flattened JSON, general JSON) must apply
//! the *same* header policy, key-management rules, content-encryption limits
//! and algorithm allow-list semantics. Duplicating that logic per serializer
//! is how an algorithm-substitution or header-confusion gap reappears in one
//! path while another path stays correct, so the shared pieces live here and
//! the serialization modules only translate between a wire shape and this
//! model.
//!
//! Two invariants hold throughout:
//!
//! 1. **Parsed is not authenticated.** [`ParsedEnvelope`] is the result of
//!    structure and policy checks only. No plaintext and no CEK leaves this
//!    module until `content_decrypt` has verified the tag over the *original*
//!    serialized bytes.
//! 2. **Key material stays inside zeroizing owners.** CEKs move as
//!    `Zeroizing<Vec<u8>>` and a raw CEK is never part of a public API.
//!
//! This module is the ADR 0011 extraction of the code that previously lived in
//! `jwe/compact.rs`; behaviour, error variants and messages are unchanged.

use zeroize::Zeroizing;

use crate::algorithm::{JweAlgorithm, JweEncryption};
use crate::base64url;
use crate::error::{JoseError, Result};
use crate::header::JoseHeader;
use crate::jwe::content;

// ---------------------------------------------------------------------------
// Size limits
// ---------------------------------------------------------------------------

/// Reject a serialized token larger than [`crate::MAX_TOKEN_BYTES`].
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

/// Lower bound on the plaintext length implied by an encoded ciphertext,
/// computed *before* base64url decoding so oversized content is refused
/// before any key operation runs.
///
/// - AES-GCM: plaintext length equals ciphertext length.
/// - AES-CBC-HS: PKCS#7 padding occupies 1..=16 bytes, so the plaintext is at
///   least `ciphertext_len - 16`.
///
/// For a valid unpadded base64url input, `encoded_len * 3 / 4` is the exact
/// decoded length; invalid encodings fail in the decode step afterwards.
pub(crate) fn minimum_plaintext_len(encoded_ciphertext_len: usize, enc: JweEncryption) -> usize {
    let ciphertext_len = encoded_ciphertext_len * 3 / 4;
    match enc {
        JweEncryption::A128GCM | JweEncryption::A192GCM | JweEncryption::A256GCM => ciphertext_len,
        JweEncryption::A128CbcHs256 | JweEncryption::A192CbcHs384 | JweEncryption::A256CbcHs512 => {
            ciphertext_len.saturating_sub(16)
        }
    }
}

// ---------------------------------------------------------------------------
// Emit-side header policy
// ---------------------------------------------------------------------------

/// Options controlling JWE encryption with a caller-supplied protected
/// header.
///
/// [`Default`] / [`JweEncryptOptions::new`] is the strict policy used by the
/// plain `encrypt_with_header*` entry points.
///
/// The struct is `#[non_exhaustive]` so new policy switches can be added
/// without breaking callers: start from [`JweEncryptOptions::new`] and use
/// the `with_*` builders.
///
/// ```
/// use jose_rs::jwe::JweEncryptOptions;
///
/// let opts = JweEncryptOptions::new().with_key_reference_headers(true);
/// assert!(opts.allow_key_reference_headers);
/// ```
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct JweEncryptOptions {
    /// Permit the key-reference members `jku`, `jwk`, `x5u` and `x5c`
    /// ([`crate::header::KEY_REFERENCE_MEMBERS`]) in the protected header.
    /// Defaults to `false`.
    ///
    /// RFC 7516 §4.1.4-4.1.7 uses these to identify the recipient's key.
    /// This crate never reads them, but a peer may dereference or trust
    /// them, so they are refused unless the caller opts in.
    pub allow_key_reference_headers: bool,
    /// External additional authenticated data, carried by the JSON `aad`
    /// member (RFC 7516 §2 / §7.2.1). Never `pub`: the value must reach
    /// [`aad_input`](self::aad_input) unaltered, so only this crate's
    /// serializers may position it.
    external_aad: Option<Vec<u8>>,
    /// Private header parameters the caller has implemented, which may
    /// therefore be listed in `crit`. See
    /// [`JweEncryptOptions::with_understood_crit`].
    understood_crit: Vec<String>,
}

impl JweEncryptOptions {
    /// Strict defaults: no key-reference header members, no external AAD.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set [`allow_key_reference_headers`](Self::allow_key_reference_headers).
    #[must_use]
    pub fn with_key_reference_headers(mut self, allow: bool) -> Self {
        self.allow_key_reference_headers = allow;
        self
    }

    /// Encrypt with external additional authenticated data.
    ///
    /// The bytes are placed in the message's `aad` member and are covered by
    /// the content authentication tag through the RFC's AAD input construction
    /// (`ASCII(protected || '.' || BASE64URL(aad))`, RFC 7516 §5.1 step 14);
    /// they are *not* encrypted, so they must
    /// not be confidential, and the recipient has to know them out of band.
    /// Only the JSON serializations can carry them — the compact form has no
    /// `aad` member, so the compact APIs refuse this option rather than
    /// dropping it. An empty value is refused at use time, because RFC 7516
    /// §7.2.1 requires the member to be absent when the value is empty and an
    /// empty AAD is therefore indistinguishable from no AAD at all.
    ///
    /// ```
    /// use jose_rs::jwe::JweEncryptOptions;
    /// let opts = JweEncryptOptions::new().with_external_aad(b"invoice-42");
    /// assert!(opts.external_aad().is_some());
    /// ```
    #[must_use]
    pub fn with_external_aad(mut self, aad: impl AsRef<[u8]>) -> Self {
        self.external_aad = Some(aad.as_ref().to_vec());
        self
    }

    /// The configured external additional authenticated data, if any.
    #[must_use]
    pub fn external_aad(&self) -> Option<&[u8]> {
        self.external_aad.as_deref()
    }

    /// Declare that the caller implements the private header parameters in
    /// `names`, so they may be listed in the protected header's `crit` member.
    ///
    /// This crate implements **no** JWE critical extensions of its own. The
    /// list is the caller's: a `crit` entry outside it is refused, on both the
    /// emit and the receive side, which is what keeps an unread extension from
    /// being silently ignored (RFC 7516 §4.1.13 / RFC 7515 §4.1.11).
    ///
    /// ```
    /// use jose_rs::jwe::JweEncryptOptions;
    /// let opts = JweEncryptOptions::new().with_understood_crit(["etsiU"]);
    /// assert_eq!(opts.understood_crit(), ["etsiU"]);
    /// ```
    #[must_use]
    pub fn with_understood_crit<I, S>(mut self, names: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.understood_crit = names.into_iter().map(Into::into).collect();
        self
    }

    /// The header parameters the caller declared it understands.
    #[must_use]
    pub fn understood_crit(&self) -> &[String] {
        &self.understood_crit
    }
}

/// Registered header members this crate does not implement for JWE compact
/// encryption, and so must not emit (RFC 7516 / RFC 7518 registry):
///
/// - `zip`: content compression (RFC 7516 §4.1.3); not implemented, and
///   RFC 8725 §3.6 advises against compressing before encryption;
/// - `b64`: RFC 7797 unencoded payload, a JWS-only member;
/// - `epk`, `apu`, `apv`: ECDH-ES key agreement (RFC 7518 §4.6.1), parsed
///   but not wired for encryption;
/// - `p2s`, `p2c`: PBES2 (RFC 7518 §4.8.1), not wired;
/// - `iv`, `tag`: AES-GCM key wrapping (RFC 7518 §4.7.1), not implemented.
///
/// Emitting any of these would describe processing that did not happen, so a
/// peer that implements them would read the token differently. Which members
/// those are depends on the key-management algorithm: `apu`/`apv` feed the
/// Concat KDF, so they are emittable exactly when the algorithm runs it.
///
/// `epk` stays on the list for every algorithm, including the agreement ones:
/// the library generates the ephemeral key itself (RFC 7518 §4.6 — "A new
/// ephemeral public key value MUST be generated for each key agreement
/// operation"), so a caller-supplied one is refused rather than reused.
pub(crate) const UNIMPLEMENTED_JWE_MEMBERS: &[&str] =
    &["zip", "b64", "epk", "apu", "apv", "p2s", "p2c", "iv", "tag"];

/// The members `alg` cannot legitimately accompany in a header this crate emits.
pub(crate) fn unimplemented_jwe_members(alg: JweAlgorithm) -> &'static [&'static str] {
    if alg_is_agreement(alg) {
        // `apu`/`apv` are Concat KDF inputs and are honoured by the derivation.
        &["zip", "b64", "epk", "p2s", "p2c", "iv", "tag"]
    } else {
        UNIMPLEMENTED_JWE_MEMBERS
    }
}

/// The refusal shared by every path that would put a direct-agreement algorithm
/// in front of a general JWE.
///
/// The reason is structural, not a missing feature: in direct mode the agreed
/// key **is** the CEK, so a second recipient would need a second CEK, and one
/// ciphertext cannot be encrypted under two keys. RFC 7518 §4.6 offers key
/// agreement *with key wrapping* as the multi-recipient form.
pub(crate) fn direct_agreement_not_multi(alg: JweAlgorithm) -> JoseError {
    JoseError::UnsupportedAlgorithm(format!(
        "{} agrees the content encryption key with one recipient, so it cannot address a general \
         JWE; use the flattened or compact serialization for one recipient, or ECDH-ES+A128KW/\
         +A192KW/+A256KW to wrap a shared CEK for several",
        alg.as_str()
    ))
}

/// Whether `alg` derives its key by agreement rather than transporting or
/// wrapping one.
///
/// Agreement modes differ structurally, not just cryptographically: their key
/// material is a JWK rather than bytes, the peer key arrives inside the message
/// (`epk`), and the CEK is *agreed* rather than carried — so `encrypted_key` is
/// empty in direct mode and one recipient is all direct mode can address.
pub(crate) fn alg_is_agreement(alg: JweAlgorithm) -> bool {
    matches!(
        alg,
        JweAlgorithm::EcdhEs
            | JweAlgorithm::EcdhEsA128kw
            | JweAlgorithm::EcdhEsA192kw
            | JweAlgorithm::EcdhEsA256kw
    )
}

/// Header parameters defined by RFC 7516 or RFC 7518 for use with JWE.
///
/// RFC 7515 §4.1.11 forbids a producer from listing these in `crit`: they are
/// not extensions, so declaring them critical says nothing a recipient does not
/// already have to do, and an implementation that "checked" the marker would be
/// agreeing to a constraint it had to satisfy anyway.
pub(crate) const REGISTERED_JWE_MEMBERS: &[&str] = &[
    "alg", "enc", "zip", "crit", "b64", "kid", "cty", "typ", "jku", "jwk", "x5u", "x5c", "x5t",
    "x5t#S256", "epk", "apu", "apv", "p2s", "p2c", "iv", "tag",
];

/// Whether `param` is a header parameter this message actually carries.
///
/// RFC 7515 §4.1.11: a producer "MUST NOT ... [list] names that do not occur as
/// Header Parameter names within the JOSE Header". Registered names live in
/// typed fields; everything a caller may legitimately list is a private member
/// in [`JoseHeader::extra`].
fn header_has_param(header: &JoseHeader, param: &str) -> bool {
    match param {
        "alg" => !header.alg.is_empty(),
        "enc" => header.enc.is_some(),
        "kid" => header.kid.is_some(),
        "typ" => header.typ.is_some(),
        "cty" => header.cty.is_some(),
        "jku" => header.jku.is_some(),
        "jwk" => header.jwk.is_some(),
        "x5u" => header.x5u.is_some(),
        "x5c" => header.x5c.is_some(),
        "x5t" => header.x5t.is_some(),
        "x5t#S256" => header.x5t_s256.is_some(),
        "crit" => header.crit.is_some(),
        _ => header.extra.contains_key(param),
    }
}

/// Apply the `crit` rules of RFC 7516 §4.1.13 (which adopts RFC 7515 §4.1.11)
/// to a **protected** header.
///
/// Identical on the emit and the receive side on purpose: a message this crate
/// is willing to write is always one it is willing to read, and the two checks
/// drifting apart is how implementations end up producing tokens they cannot
/// themselves decrypt. `understood` is the caller's list — this crate
/// implements no critical extensions of its own.
///
/// Rules:
/// 1. `crit` must not be empty;
/// 2. no duplicate names;
/// 3. no registered JWE/JWA name (those are not extensions);
/// 4. every name must be in `understood` — this is the rule that makes an
///    unread extension fail loudly instead of being ignored;
/// 5. every name must actually occur in the header.
///
/// The check runs against the protected header only, which is also where RFC
/// 7515 §4.1.11 requires `crit` to be: on the JSON serializations an extension
/// could in principle be carried unprotected, and this crate refuses that — a
/// parameter whose criticality is asserted by bytes nobody authenticates is not
/// critical (ADR 0015).
pub(crate) fn validate_crit(header: &JoseHeader, understood: &[String]) -> Result<()> {
    let Some(crit) = header.crit.as_ref() else {
        return Ok(());
    };
    if crit.is_empty() {
        return Err(JoseError::InvalidHeader(
            "crit header must not be empty (RFC 7515 §4.1.11)".into(),
        ));
    }
    for (index, param) in crit.iter().enumerate() {
        if crit[..index].contains(param) {
            return Err(JoseError::InvalidHeader(format!(
                "crit lists {param} more than once (RFC 7515 §4.1.11)"
            )));
        }
        if REGISTERED_JWE_MEMBERS.contains(&param.as_str()) {
            return Err(JoseError::InvalidHeader(format!(
                "crit must not name the registered header parameter {param}; it is not an \
                 extension (RFC 7515 §4.1.11)"
            )));
        }
        if !understood.iter().any(|known| known == param) {
            return Err(JoseError::InvalidHeader(format!(
                "unsupported crit extension: {param}"
            )));
        }
        if !header_has_param(header, param) {
            return Err(JoseError::InvalidHeader(format!(
                "crit names {param} but it is absent from the protected header \
                 (RFC 7515 §4.1.11)"
            )));
        }
    }
    Ok(())
}

/// Validate the JWE-specific content of a caller-supplied protected header
/// before it is serialized and used as additional authenticated data.
///
/// Callers must already have checked that `header.alg` / `header.enc` match
/// the algorithms actually used. The shared rules (duplicate members,
/// key-reference members, size) are applied afterwards by
/// [`JoseHeader::to_protected_b64`]. Rules enforced here:
///
/// 1. `extra` must not contain an [`UNIMPLEMENTED_JWE_MEMBERS`] entry; for
///    `zip` the check and message match the decrypt path, so a token this
///    crate emits is always one it can decrypt.
/// 2. `crit` passes [`validate_crit`] against the caller's understood-extension
///    list. This crate implements no critical extensions itself, so with an
///    empty list — the default — `crit` must be absent.
///
/// # Errors
///
/// Returns [`JoseError::InvalidHeader`] naming the first rule violated.
pub(crate) fn validate_encrypt_header(
    header: &JoseHeader,
    alg: JweAlgorithm,
    understood: &[String],
) -> Result<()> {
    // Rule 1. `extra["crit"]` is not handled here: it duplicates a typed
    // field, which `to_protected_b64` rejects before anything is emitted.
    if header.extra.contains_key("zip") {
        return Err(JoseError::InvalidHeader(
            "unsupported zip header: content compression is not supported".into(),
        ));
    }
    if let Some(name) = unimplemented_jwe_members(alg)
        .iter()
        .find(|name| header.extra.contains_key(**name))
    {
        // `epk` is refused even for the agreement algorithms, for a different
        // reason than the rest: the member is implemented, but the key in it is
        // not ours to choose. Accepting one would make ephemeral-key reuse —
        // which leaks the agreed key — expressible as a function argument.
        if *name == "epk" && alg_is_agreement(alg) {
            return Err(JoseError::InvalidHeader(
                "epk is generated by this crate for each encryption (RFC 7518 §4.6 requires a new ephemeral key per key agreement operation); do not supply one"
                    .into(),
            ));
        }
        return Err(JoseError::InvalidHeader(format!(
            "unsupported JWE header member {name}: not implemented for JWE encryption"
        )));
    }

    // Rule 2: the caller's list is the only thing that can license a `crit`
    // entry, and it licenses nothing that this crate does not itself process.
    validate_crit(header, understood)
}

// ---------------------------------------------------------------------------
// Algorithm policy (decrypt side)
// ---------------------------------------------------------------------------

/// Algorithm policy and plaintext-size limit for JWE decryption.
///
/// Use [`JweDecryptOptions::new`] to pin an explicit allow-list of key
/// management algorithms and content encryption algorithms. Tokens whose
/// header advertises anything outside the allow-list are rejected before
/// any cryptographic operation — the canonical defence against
/// algorithm-substitution attacks when one key is reused across configs.
#[derive(Debug, Clone, Default)]
pub struct JweDecryptOptions {
    allowed_alg: Vec<JweAlgorithm>,
    allowed_enc: Vec<JweEncryption>,
    allow_all: bool,
    max_plaintext: Option<usize>,
    /// External additional authenticated data expected from the message's
    /// `aad` member (RFC 7516 §2). See
    /// [`JweDecryptOptions::with_external_aad`].
    external_aad: Option<Vec<u8>>,
    /// Private header parameters the caller has implemented, and so may accept
    /// when a message lists them in `crit`. See
    /// [`JweDecryptOptions::with_understood_crit`].
    understood_crit: Vec<String>,
}

impl JweDecryptOptions {
    /// Construct options pinning an explicit allow-list.
    pub fn new(allowed_alg: Vec<JweAlgorithm>, allowed_enc: Vec<JweEncryption>) -> Self {
        Self {
            allowed_alg,
            allowed_enc,
            allow_all: false,
            max_plaintext: None,
            external_aad: None,
            understood_crit: Vec::new(),
        }
    }

    /// Options pinned to a JWK's own `alg`, accepting every content algorithm
    /// the library supports.
    ///
    /// This is what the JWK decryption APIs use: the algorithm comes from the
    /// *key*, never from token header data, which is what makes comparing the
    /// token's claim against it meaningful (ADR 0013). Callers who also need
    /// external AAD or caller-understood `crit` extensions build on the result.
    ///
    /// # Errors
    ///
    /// [`JoseError::Key`] when `jwk.alg` is unset, and
    /// [`JoseError::UnsupportedAlgorithm`] when it names something this crate
    /// does not implement for JWE.
    pub fn pinned_to_jwk(jwk: &crate::jwk::Jwk) -> Result<Self> {
        let alg = jwk
            .alg
            .as_deref()
            .ok_or_else(|| JoseError::Key("JWK alg must be set for the JWE JWK APIs".into()))?;
        let alg = JweAlgorithm::from_str(alg)?;
        Ok(Self::new(
            vec![alg],
            crate::jwe::internal::all_enc_algorithms(),
        ))
    }

    /// Permit every algorithm the library supports. Used internally by
    /// [`crate::jwe::decrypt`] for backwards compatibility — new code should
    /// prefer [`JweDecryptOptions::new`].
    pub fn permissive() -> Self {
        Self {
            allowed_alg: Vec::new(),
            allowed_enc: Vec::new(),
            allow_all: true,
            max_plaintext: None,
            external_aad: None,
            understood_crit: Vec::new(),
        }
    }

    /// Limit returned plaintext to at most `bytes` bytes (inclusive).
    ///
    /// Zero permits only empty plaintext. By default there is no additional
    /// plaintext limit; [`crate::MAX_TOKEN_BYTES`] still bounds the token.
    /// This does not enable compression or change the algorithm policy.
    /// Oversized ciphertext is rejected before decoding or key operations
    /// when its length proves the plaintext cannot fit. CBC padding requires
    /// up to one extra 16-byte block and an exact post-authentication check.
    /// This bounds plaintext, not total process memory or key-operation cost.
    ///
    /// ```
    /// use jose_rs::{jwe::{self, JweDecryptOptions}, JweAlgorithm, JweEncryption};
    /// let options = JweDecryptOptions::new(
    ///     vec![JweAlgorithm::Dir], vec![JweEncryption::A256GCM],
    /// ).with_max_plaintext(1024);
    /// let key = [7_u8; 32]; // Example only; generate a secret key in production.
    /// let token = jwe::encrypt(&key, b"message", JweAlgorithm::Dir, JweEncryption::A256GCM)?;
    /// assert_eq!(jwe::decrypt_with_options(&key, &token, &options)?, b"message");
    /// # Ok::<(), jose_rs::JoseError>(())
    /// ```
    #[must_use]
    pub fn with_max_plaintext(mut self, bytes: usize) -> Self {
        self.max_plaintext = Some(bytes);
        self
    }

    /// Supply the external additional authenticated data for a message that
    /// carries an `aad` member.
    ///
    /// RFC 7516 keeps this data out of the ciphertext but *inside* the content
    /// authentication tag's reach: it is authenticated, not confidential, and
    /// a recipient must already know it. If the message has no `aad` member,
    /// or the bytes differ from it, decryption is refused with an explanatory
    /// error instead of a bare authentication failure — the member's presence
    /// and encoding are not secret, and a caller who forgot to pass the AAD
    /// deserves better than `Crypto("decryption failed")`.
    ///
    /// ```
    /// use jose_rs::{jwe::JweDecryptOptions, JweAlgorithm, JweEncryption};
    /// let options = JweDecryptOptions::new(
    ///     vec![JweAlgorithm::Dir], vec![JweEncryption::A256GCM],
    /// ).with_external_aad(b"invoice-42");
    /// assert_eq!(options.external_aad(), Some(&b"invoice-42"[..]));
    /// ```
    #[must_use]
    pub fn with_external_aad(mut self, aad: impl AsRef<[u8]>) -> Self {
        self.external_aad = Some(aad.as_ref().to_vec());
        self
    }

    /// The configured external additional authenticated data, if any.
    #[must_use]
    pub fn external_aad(&self) -> Option<&[u8]> {
        self.external_aad.as_deref()
    }

    /// Accept a `crit` member listing the private header parameters in `names`.
    ///
    /// A message listing anything outside this list is refused, and with the
    /// default (empty) list a message carrying `crit` at all is refused — the
    /// behaviour this crate has always had, now expressible as an explicit
    /// opt-in rather than a hard denial (RFC 7516 §4.1.13, RFC 7515 §4.1.11,
    /// ADR 0015). Declaring an extension "understood" is a claim about *code the
    /// caller wrote*: jose-rs reads the member, checks that it is present and
    /// integrity protected, and hands it over in
    /// [`JoseHeader::extra`](crate::JoseHeader::extra). It does not act on it.
    ///
    /// ```
    /// use jose_rs::jwe::JweDecryptOptions;
    /// use jose_rs::JweAlgorithm;
    /// use jose_rs::JweEncryption;
    /// let opts = JweDecryptOptions::new(vec![JweAlgorithm::A128KW], vec![JweEncryption::A128GCM])
    ///     .with_understood_crit(["etsiU"]);
    /// assert_eq!(opts.understood_crit(), ["etsiU"]);
    /// ```
    #[must_use]
    pub fn with_understood_crit<I, S>(mut self, names: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.understood_crit = names.into_iter().map(Into::into).collect();
        self
    }

    /// The header parameters the caller declared it understands.
    #[must_use]
    pub fn understood_crit(&self) -> &[String] {
        &self.understood_crit
    }

    /// Fill in "every supported content algorithm" when the caller did not
    /// constrain one (crate-internal: the JWK APIs take the key-management
    /// algorithm from the key and must not force the caller to enumerate `enc`).
    pub(crate) fn allow_any_enc_when_unset(self) -> Self {
        if self.allowed_enc.is_empty() {
            Self {
                allowed_enc: all_enc_algorithms(),
                ..self
            }
        } else {
            self
        }
    }

    /// Resolve a message's `aad` member against the caller's expectation.
    ///
    /// Returns the **encoded** form to feed [`aad_input`][self::aad_input], or
    /// `None` when neither side has external AAD. Every disagreement between
    /// "the message says there is external AAD" and "the caller supplied some"
    /// is refused here, before key derivation, because all four combinations
    /// are distinguishable without any secret and each is a plausible
    /// integration mistake.
    pub(crate) fn resolve_external_aad(&self, aad_b64: Option<&str>) -> Result<Option<String>> {
        let supplied = self.external_aad.as_deref();
        match (aad_b64, supplied) {
            (None, None) => Ok(None),
            (Some(member), None) => Err(JoseError::InvalidToken(format!(
                "message carries external additional authenticated data ({member}); supply \
                 the same bytes with JweDecryptOptions::with_external_aad"
            ))),
            (None, Some(_)) => Err(JoseError::InvalidToken(
                "decrypt options carry external additional authenticated data but the message \
                 has no \"aad\" member"
                    .into(),
            )),
            (Some(member), Some(bytes)) => {
                // The tag covers the base64url *text*, so the caller's bytes
                // must re-encode to the member exactly. Checking it here turns
                // "wrong external AAD" into a named error rather than a
                // generic authentication failure.
                if base64url::encode(bytes) != member {
                    return Err(JoseError::InvalidToken(
                        "external additional authenticated data does not match the message's \
                         \"aad\" member"
                            .into(),
                    ));
                }
                Ok(Some(member.to_string()))
            }
        }
    }

    pub(crate) fn check_plaintext_size(&self, bytes: usize) -> Result<()> {
        if self.max_plaintext.is_some_and(|limit| bytes > limit) {
            return Err(JoseError::InvalidToken(
                "plaintext exceeds configured maximum size".into(),
            ));
        }
        Ok(())
    }

    pub(crate) fn check(&self, alg: JweAlgorithm, enc: JweEncryption) -> Result<()> {
        if self.allow_all {
            return Ok(());
        }
        if !self.allowed_alg.contains(&alg) {
            return Err(JoseError::UnsupportedAlgorithm(format!(
                "JWE alg {} is not in the caller's allow-list",
                alg.as_str()
            )));
        }
        if !self.allowed_enc.contains(&enc) {
            return Err(JoseError::UnsupportedAlgorithm(format!(
                "JWE enc {} is not in the caller's allow-list",
                enc.as_str()
            )));
        }
        Ok(())
    }
}

/// Every content-encryption algorithm the library supports. Used by the
/// JWK-first decrypt path, which pins `alg` to the JWK but leaves `enc`
/// flexible (the CEK length is bound to `enc` and re-validated downstream).
pub(crate) fn all_enc_algorithms() -> Vec<JweEncryption> {
    vec![
        JweEncryption::A128CbcHs256,
        JweEncryption::A192CbcHs384,
        JweEncryption::A256CbcHs512,
        JweEncryption::A128GCM,
        JweEncryption::A192GCM,
        JweEncryption::A256GCM,
    ]
}

// ---------------------------------------------------------------------------
// Parsed (unauthenticated) envelope
// ---------------------------------------------------------------------------

/// A JWE envelope after structural and policy checks, before authentication.
///
/// `header_b64` keeps the *original* encoded protected-header bytes verbatim:
/// they are the first component of the AEAD/MAC input, and re-serializing the
/// parsed header would produce different bytes (member order, escaping), which
/// would both break authentication and let a re-encode hide a header change.
/// The parsed [`JoseHeader`] is returned separately by [`parse_envelope`]: it
/// is caller-facing data (which headers were authenticated), while this struct
/// is the encrypted content the crypto layer consumes.
#[derive(Debug)]
pub(crate) struct ParsedEnvelope<'a> {
    /// Verbatim base64url protected header (AAD input, never re-encoded).
    pub header_b64: &'a str,
    /// Key-management algorithm, already allow-listed by the caller.
    pub alg: JweAlgorithm,
    /// Whether `alg` came from the integrity-protected header.
    ///
    /// RFC 7516 §7.2.1 allows `alg` to sit in an unprotected member of the JSON
    /// serialization. Nothing in this crate *trusts* an unauthenticated
    /// algorithm: when this is `false` the caller must have independently
    /// pinned the algorithm to the key it holds (see the JWK decrypt paths),
    /// so the header value is being *checked*, not believed.
    pub alg_authenticated: bool,
    /// Content-encryption algorithm, already allow-listed by the caller.
    pub enc: JweEncryption,
    /// Wrapped key (empty for `dir`).
    pub encrypted_key: Vec<u8>,
    /// Content IV.
    pub iv: Vec<u8>,
    /// Content ciphertext.
    pub ciphertext: Vec<u8>,
    /// Content authentication tag.
    pub tag: Vec<u8>,
}

/// Decode and policy-check one envelope's fields.
///
/// `unprotected_alg` is the `alg` value conveyed outside the protected header,
/// if any (JSON serialization only; the compact path passes `None`).
///
/// Rejects `zip` (compression is not implemented, so returning the still
/// compressed bytes as "plaintext" would be a silent integrity failure) and
/// any `crit` member (no JWE critical extension is implemented), then resolves
/// the typed algorithms. The caller enforces its own algorithm allow-list with
/// [`JweDecryptOptions::check`] once `alg` / `enc` are known.
///
/// # Errors
///
/// [`JoseError::InvalidHeader`] for a policy violation or a missing/unknown
/// `enc`; [`JoseError::UnsupportedAlgorithm`] for an unknown `alg`;
/// [`JoseError::Base64`] / [`JoseError::Json`] for malformed field data.
///
/// Returns the envelope content together with the parsed protected header.
pub(crate) fn parse_envelope<'a>(
    header_b64: &'a str,
    unprotected_alg: Option<&str>,
    encrypted_key_b64: &str,
    iv_b64: &str,
    ciphertext_b64: &str,
    tag_b64: &str,
    understood_crit: &[String],
) -> Result<(ParsedEnvelope<'a>, JoseHeader)> {
    let header_json = base64url::decode(header_b64)?;
    let header: JoseHeader = serde_json::from_slice(&header_json)?;

    // RFC 7516 §4.1.3: the library does not implement content compression.
    // Reject tokens declaring a `zip` member instead of silently returning
    // the still-compressed bytes as plaintext.
    if header.extra.contains_key("zip") {
        return Err(JoseError::InvalidHeader(
            "unsupported zip header: content compression is not supported".into(),
        ));
    }

    // RFC 7516 §4.1.13 / RFC 7515 §4.1.11: `crit` may name only extensions the
    // *caller* has declared it implements. With the default (empty) list, any
    // `crit` is refused — which is the pre-existing behaviour, kept as the
    // default rather than re-litigated (ADR 0015).
    validate_crit(&header, understood_crit)?;

    // `alg` normally lives in the protected header. The JSON serialization may
    // instead convey it in an unprotected member (`unprotected_alg`), which is
    // legal (RFC 7516 §7.2.1) but unauthenticated: the flag records where it
    // came from so callers can demand a key-pinned algorithm before accepting
    // it. The compact serialization always passes `None`, so an absent `alg`
    // there keeps its original "unknown algorithm" error.
    let (alg, alg_authenticated) = match (header.alg.as_str(), unprotected_alg) {
        ("", Some(outer)) => (JweAlgorithm::from_str(outer)?, false),
        (protected, _) => (JweAlgorithm::from_str(protected)?, !protected.is_empty()),
    };
    let enc_str = header
        .enc
        .as_deref()
        .ok_or_else(|| JoseError::InvalidHeader("missing enc field".into()))?;
    let enc = JweEncryption::from_str(enc_str)?;

    let envelope = ParsedEnvelope {
        header_b64,
        alg,
        alg_authenticated,
        enc,
        encrypted_key: base64url::decode(encrypted_key_b64)?,
        iv: base64url::decode(iv_b64)?,
        ciphertext: base64url::decode(ciphertext_b64)?,
        tag: base64url::decode(tag_b64)?,
    };
    Ok((envelope, header))
}

/// Content-decrypt an envelope and enforce the plaintext-size limit. The
/// caller has already run the algorithm allow-list check and recovered the CEK.
///
/// The exact AES-CBC plaintext length is known only after authenticated
/// padding removal; on a size rejection the authenticated plaintext is wiped
/// instead of returned.
pub(crate) fn finish_decrypt(
    envelope: &ParsedEnvelope<'_>,
    cek: &[u8],
    aad: &[u8],
    options: &JweDecryptOptions,
) -> Result<Vec<u8>> {
    let mut plaintext = Zeroizing::new(content::content_decrypt(
        envelope.enc,
        cek,
        &envelope.iv,
        &envelope.ciphertext,
        &envelope.tag,
        aad,
    )?);
    options.check_plaintext_size(plaintext.len())?;
    Ok(std::mem::take(&mut *plaintext))
}

// ---------------------------------------------------------------------------
// Key management: produce CEK (encrypt side)
// ---------------------------------------------------------------------------

/// Returns `(cek, encrypted_key)`. For `dir`, `encrypted_key` is empty.
///
/// The CEK is returned wrapped in `Zeroizing` so its heap buffer is
/// wiped when it goes out of scope — key material never lingers in
/// the allocator after the encryption completes.
pub(crate) fn produce_cek(
    key: &[u8],
    alg: JweAlgorithm,
    enc: JweEncryption,
) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>)> {
    // Direct key agreement: the key *is* the CEK, so there is nothing to wrap
    // and no `encrypted_key` member to emit.
    if alg == JweAlgorithm::Dir {
        check_dir_key(key, enc)?;
        return Ok((Zeroizing::new(key.to_vec()), Vec::new()));
    }
    let cek = Zeroizing::new(content::random_bytes(enc.cek_size()));
    let wrapped = wrap_cek(&cek, key, alg, enc)?;
    Ok((cek, wrapped))
}

/// Wrap an existing CEK for one recipient.
///
/// Split out of [`produce_cek`] because the General JWE Serialization
/// (RFC 7516 §7.2.1) encrypts the *same* CEK once per recipient: content
/// encryption happens a single time and only the key-management step repeats.
///
/// # Errors
///
/// [`JoseError::UnsupportedAlgorithm`] for `dir` (which conveys no key) or
/// unimplemented key management, [`JoseError::Key`] for a wrong-length KEK,
/// [`JoseError::Crypto`] for a wrap failure.
pub(crate) fn wrap_cek(
    cek: &[u8],
    key: &[u8],
    alg: JweAlgorithm,
    _enc: JweEncryption,
) -> Result<Vec<u8>> {
    match alg {
        // `dir` has no per-recipient key: the shared key is the CEK itself.
        // Asking to "wrap it for another recipient" is asking for a second copy
        // of the CEK, which is not what direct key agreement means.
        JweAlgorithm::Dir => Err(JoseError::UnsupportedAlgorithm(
            "dir conveys no encrypted key, so a general JWE cannot address a second recipient; \
             use a key-wrapping or key-transport algorithm to reach several recipients"
                .into(),
        )),

        // AES Key Wrap.
        JweAlgorithm::A128KW | JweAlgorithm::A192KW | JweAlgorithm::A256KW => {
            check_kek_size(alg, key)?;
            let kw_alg = jwe_alg_to_keywrap(alg)?;
            kryptering::keywrap::wrap(kw_alg, key, cek).map_err(JoseError::Crypto)
        }

        // RSA-OAEP.
        JweAlgorithm::RsaOaep256 => {
            let pub_key = parse_rsa_public_key(key)?;
            let kt_alg = jwe_alg_to_keytransport(alg)?;
            kryptering::keytransport::kt_encrypt(kt_alg, &pub_key, cek, None)
                .map_err(JoseError::Crypto)
        }

        #[cfg(feature = "deprecated")]
        JweAlgorithm::RsaOaep => {
            let pub_key = parse_rsa_public_key(key)?;
            let kt_alg = jwe_alg_to_keytransport(alg)?;
            kryptering::keytransport::kt_encrypt(kt_alg, &pub_key, cek, None)
                .map_err(JoseError::Crypto)
        }

        _ => Err(JoseError::UnsupportedAlgorithm(format!(
            "key management algorithm {} not yet implemented",
            alg.as_str()
        ))),
    }
}

/// RFC 7518 §4.6.2's `OtherInfo`, split the way the backend's parameters want
/// it: AlgorithmID, PartyUInfo, and PartyVInfo with **SuppPubInfo on its tail**.
///
/// The backend defines OtherInfo as `AlgID || PartyUInfo || PartyVInfo`; JOSE
/// appends SuppPubInfo (the key length in bits, big-endian). Appending it to the
/// last field makes the concatenation byte-identical to the RFC's, which the
/// unit test below pins against the byte array printed in Appendix C.
struct OtherInfo {
    algorithm_id: Vec<u8>,
    party_u: Vec<u8>,
    party_v: Vec<u8>,
}

impl OtherInfo {
    /// The whole structure as one buffer.
    ///
    /// The backend takes the three fields separately, so production code never
    /// needs this; it exists so the tests can assert the *concatenation* — which
    /// is what the backend hashes — against the octet array RFC 7518 Appendix C
    /// prints.
    #[cfg(test)]
    fn as_bytes(&self) -> Vec<u8> {
        let mut out =
            Vec::with_capacity(self.algorithm_id.len() + self.party_u.len() + self.party_v.len());
        out.extend_from_slice(&self.algorithm_id);
        out.extend_from_slice(&self.party_u);
        out.extend_from_slice(&self.party_v);
        out
    }
}

/// Build [`OtherInfo`] from already-decoded party values.
///
/// Each field is `Datalen || Data` with a big-endian 32-bit length. An absent
/// `apu`/`apv` contributes the empty octet sequence — **four zero octets**, not
/// nothing, which is the single easiest way to derive a key nobody else
/// derives.
fn other_info(alg_id: &str, apu: Option<&[u8]>, apv: Option<&[u8]>, key_len: usize) -> OtherInfo {
    fn length_prefixed(data: Option<&[u8]>) -> Vec<u8> {
        let data = data.unwrap_or(&[]);
        let mut out = Vec::with_capacity(4 + data.len());
        out.extend_from_slice(&(data.len() as u32).to_be_bytes());
        out.extend_from_slice(data);
        out
    }

    let mut party_v = length_prefixed(apv);
    party_v.extend_from_slice(&((key_len as u32) * 8).to_be_bytes());
    OtherInfo {
        algorithm_id: length_prefixed(Some(alg_id.as_bytes())),
        party_u: length_prefixed(apu),
        party_v,
    }
}

/// JOSE's Concat KDF, RFC 7518 §4.6.2 (NIST SP 800-56A §5.8.1 single step).
///
/// Derives the agreed key from the ECDH shared secret `Z`. Three properties are
/// worth stating because they are the ones an implementation gets wrong:
///
/// * **the digest is always SHA-256** — RFC 7518 §4.6.2 fixes it ("where the
///   Digest Method is SHA-256") rather than tying it to the key size, so a
///   derivation that picked SHA-512 for a 256-bit CEK would agree with nobody,
///   including the RFC's own Appendix C vector (which this crate's tests assert);
/// * **`OtherInfo` is length-prefixed**: each of AlgorithmID, PartyUInfo and
///   PartyVInfo is `Datalen || Data` with a big-endian 32-bit `Datalen`, and
///   SuppPubInfo is the key length *in bits* as a 32-bit big-endian value.
///   Skipping a prefix, or using a zero length for an absent `apu` instead of
///   the four zero octets, changes the derived key with no error anywhere;
/// * **`apu` and `apv` must differ** when both are used (RFC 7518 §4.6.2), so
///   that the two party values actually identify two parties.
///
/// `alg_id` is the ASCII `enc` value for direct key agreement and the ASCII
/// `alg` value for key agreement with key wrapping (RFC 7518 §4.6.2). `apu` and
/// `apv` are the base64url *encoded* header values, decoded here.
///
/// # Errors
///
/// [`JoseError::InvalidHeader`] for a non-canonical `apu`/`apv`, or for equal
/// ones; [`JoseError::Crypto`] if the backend rejects the derivation.
pub(crate) fn concat_kdf(
    z: &[u8],
    key_len: usize,
    alg_id: &str,
    apu: Option<&str>,
    apv: Option<&str>,
) -> Result<Zeroizing<Vec<u8>>> {
    let apu = apu.map(crate::base64url::decode).transpose()?;
    let apv = apv.map(crate::base64url::decode).transpose()?;
    if let (Some(apu), Some(apv)) = (&apu, &apv) {
        if apu == apv {
            return Err(JoseError::InvalidHeader(
                "apu and apv must be distinct when both are present (RFC 7518 §4.6.2)".into(),
            ));
        }
    }

    let info = other_info(alg_id, apu.as_deref(), apv.as_deref(), key_len);
    // kryptering's OtherInfo is the concatenation of these three fields in
    // order, so the bytes it hashes are RFC 7518 §4.6.2's OtherInfo exactly.
    let params = kryptering::kdf::ConcatKdfParams {
        hash: kryptering::HashAlgorithm::Sha256,
        algorithm_id: Some(info.algorithm_id),
        party_u_info: Some(info.party_u),
        party_v_info: Some(info.party_v),
    };
    let derived = kryptering::kdf::concat_kdf(z, key_len, &params).map_err(JoseError::Crypto)?;
    if derived.len() != key_len {
        return Err(JoseError::Key(format!(
            "Concat KDF derived {} bytes, expected {key_len}",
            derived.len()
        )));
    }
    Ok(Zeroizing::new(derived))
}

/// Read an `apu`/`apv` header member as the base64url string it must be.
///
/// These members are not typed fields, so they arrive through the untyped
/// member map and can hold any JSON value. A non-string is refused rather than
/// stringified: `"apu": 5` and `"apu": "5"` would otherwise derive the same key
/// while looking nothing alike.
fn agreement_member(header: &JoseHeader, name: &str) -> Result<Option<String>> {
    match header.extra.get(name) {
        None => Ok(None),
        Some(value) => match value.as_str() {
            Some(text) => Ok(Some(text.to_string())),
            None => Err(JoseError::InvalidHeader(format!(
                "{name} must be a base64url string (RFC 7518 §4.6.1)"
            ))),
        },
    }
}

/// The key-encryption key length an agreement-with-wrapping algorithm names.
///
/// `None` for every other algorithm, including `ECDH-ES` itself: in direct mode
/// there is no KEK, the KDF output *is* the CEK. This is also the predicate this
/// crate uses to ask "is this an agreement algorithm that wraps?".
///
/// The length comes from the **algorithm**, never from `enc`: `keydatalen` is the
/// KEK's bit length in this mode (RFC 7518 §4.6.2), while the CEK it wraps is
/// sized by `enc` — an `ECDH-ES+A128KW` + `A256GCM` message derives a 128-bit KEK
/// for a 256-bit CEK.
pub(crate) fn agreement_kek_len(alg: JweAlgorithm) -> Option<usize> {
    match alg {
        JweAlgorithm::EcdhEsA128kw => Some(16),
        JweAlgorithm::EcdhEsA192kw => Some(24),
        JweAlgorithm::EcdhEsA256kw => Some(32),
        _ => None,
    }
}

/// The refusal when a key-agreement algorithm is asked to address a general JWE.
///
/// In wrapping modes the cryptography scales to several recipients on its own —
/// one CEK, one agreement per recipient — but each recipient needs its *own*
/// ephemeral value, and RFC 7516 gives a recipient element no protected header of
/// its own to carry it in. Publishing it in the element's unprotected `header` is
/// what RFC 7520 §5.13 and other implementations do, and this crate does not read
/// or write an unauthenticated key contribution until that trade-off is decided
/// (ADR 0018, which records the argument and the alternatives).
pub(crate) fn per_recipient_epk_unsupported(alg: JweAlgorithm) -> JoseError {
    JoseError::UnsupportedAlgorithm(format!(
        "{} addresses several recipients by agreeing a separate key-encryption key with each, \
         which needs one epk per recipient; RFC 7516 gives a recipient element no protected \
         header of its own to carry it in, so only the single-recipient (flattened and compact) \
         forms are supported for this algorithm",
        alg.as_str()
    ))
}

/// Publish `ephemeral`'s public half as the message's `epk` member.
///
/// Public half only: the ephemeral private scalar must never travel in the
/// message (RFC 7518 §4.6.1.1).
fn with_epk(header: &JoseHeader, ephemeral: &crate::jwk::Jwk) -> Result<JoseHeader> {
    let mut with_epk = header.clone();
    with_epk.extra.insert(
        "epk".into(),
        serde_json::to_value(own_public_jwk(ephemeral))?,
    );
    Ok(with_epk)
}

/// Read the sender's ephemeral public key from a received agreement message.
///
/// The **authenticated protected header only**: the JSON serializations already
/// refuse `epk` in an unprotected position (ADR 0013), so a recipient never
/// derives a key from a value the sender did not integrity protect.
fn epk_from_header(header: &JoseHeader) -> Result<crate::jwk::Jwk> {
    let epk_value = header
        .extra
        .get("epk")
        .ok_or_else(|| JoseError::InvalidHeader(
            "key agreement requires an epk (ephemeral public key) member in the protected header (RFC 7518 §4.6.1.1)"
                .into(),
        ))?;
    serde_json::from_value(epk_value.clone())
        .map_err(|e| JoseError::InvalidHeader(format!("epk is not a well-formed JWK: {e}")))
}

/// The sender's half of a key agreement, with the ephemeral key already published.
///
/// Holds the agreement handles rather than a derived key, and is consumed by
/// either mode: direct agreement derives the CEK, wrapping modes derive a KEK and
/// wrap. Nothing here hands out `Z` (ADR 0016).
struct AgreementSender {
    own: crate::jwk::agreement::AgreementKey,
    peer: crate::jwk::agreement::PeerKey,
    /// The caller's header plus the `epk` member naming [`Self::own`].
    header: JoseHeader,
}

/// Generate this operation's ephemeral key and pair it with `recipient`.
///
/// The curve is the **recipient's** (`peer_key` refuses an off-curve or
/// private-bearing peer): agreement is only defined within one curve, and this
/// way a P-521 recipient cannot be talked into a P-521→P-256 downgrade through a
/// caller-chosen ephemeral key. `epk` is not an input anywhere in this crate,
/// which is how RFC 7518 §4.6's "MUST generate a new ephemeral key ... for each
/// key agreement operation" stays true.
fn agreement_sender(header: &JoseHeader, recipient: &crate::jwk::Jwk) -> Result<AgreementSender> {
    use crate::jwk::agreement::{agreement_key, peer_key};
    // Senders legitimately hold the recipient's *private* JWK (the RFC's own
    // examples do), so `d` is dropped rather than refused — but only the public
    // half is ever used, and only the public half is ever published.
    let peer = peer_key(&recipient.to_public_jwk())?;
    let ephemeral = crate::jwk::generate_ec(peer.curve().as_crv_str())?;
    let own = agreement_key(&ephemeral)?;
    Ok(AgreementSender {
        own,
        peer,
        header: with_epk(header, &ephemeral)?,
    })
}

impl AgreementSender {
    /// Concat KDF over this agreement, with the header's `apu`/`apv` as inputs.
    ///
    /// `alg_id` and `key_len` are decided by the caller because the two
    /// agreement modes disagree about both — see [`Self::derive_cek`] and
    /// [`Self::wrap`].
    fn derive(
        &self,
        alg_id: &str,
        apu: Option<&str>,
        apv: Option<&str>,
        key_len: usize,
    ) -> Result<Zeroizing<Vec<u8>>> {
        self.own.derive_key(&self.peer, alg_id, apu, apv, key_len)
    }

    /// Direct agreement: the KDF output **is** the CEK, so AlgorithmID is the
    /// ASCII `enc` value and keydatalen the CEK length (`enc.cek_size()`).
    fn derive_cek(&self, enc: JweEncryption) -> Result<Zeroizing<Vec<u8>>> {
        let apu = agreement_member(&self.header, "apu")?;
        let apv = agreement_member(&self.header, "apv")?;
        self.derive(enc.as_str(), apu.as_deref(), apv.as_deref(), enc.cek_size())
    }

    /// Agreement with key wrapping: AlgorithmID is the ASCII **`alg`** value and
    /// keydatalen the KEK length the algorithm names (§4.6.2) — so the same two
    /// keys derive a different KEK here than the CEK they derive under `ECDH-ES`,
    /// which is what stops a message from being read under the wrong mode.
    fn wrap(&self, alg: JweAlgorithm, cek: &[u8]) -> Result<Vec<u8>> {
        let kek_len = agreement_kek_len(alg).ok_or_else(|| {
            JoseError::UnsupportedAlgorithm(format!(
                "{} does not wrap a key with an agreed key-encryption key",
                alg.as_str()
            ))
        })?;
        let apu = agreement_member(&self.header, "apu")?;
        let apv = agreement_member(&self.header, "apv")?;
        let kek = self.derive(alg.as_str(), apu.as_deref(), apv.as_deref(), kek_len)?;
        kryptering::keywrap::wrap(jwe_alg_to_keywrap(alg)?, &kek, cek).map_err(JoseError::Crypto)
    }
}

/// Direct key agreement (`ECDH-ES`): agree the CEK and return the header that
/// carries the ephemeral public key.
///
/// The sender's half is generated here and nowhere else. RFC 7518 §4.6 requires
/// a new ephemeral key per operation, so the value is not an input: accepting
/// one would let a caller reuse an ephemeral key across two messages to two
/// recipients, which reveals the agreed keys to anyone who sees both. The public
/// half is published as `epk` in the protected header, which is also the AAD
/// input — so an attacker who swaps `epk` for a key they control breaks the tag
/// rather than receiving the plaintext (though they can make a recipient derive
/// a key the attacker chose; see the module docs and ADR 0016/0017).
///
/// Returns the header with `epk` inserted, plus the agreed CEK.
fn agree_direct(
    header: &JoseHeader,
    recipient: &crate::jwk::Jwk,
    enc: JweEncryption,
) -> Result<(JoseHeader, Zeroizing<Vec<u8>>)> {
    // The sender's half, the recipient's half and the header carrying `epk` are
    // built by one function shared with the wrapping modes, so "where does the
    // ephemeral key come from" has exactly one answer in this crate.
    let sender = agreement_sender(header, recipient)?;
    let cek = sender.derive_cek(enc)?;
    Ok((sender.header, cek))
}

/// The public-only JWK to publish as `epk`: the freshly generated key with its
/// private component removed.
fn own_public_jwk(ephemeral: &crate::jwk::Jwk) -> crate::jwk::Jwk {
    ephemeral.to_public_jwk()
}

/// Recover the CEK by direct key agreement, from the recipient's private JWK and
/// the `epk` the message carries.
///
/// `epk` is read from the **authenticated protected header only** (the JSON
/// serializations already refuse it in an unprotected position, ADR 0013), and
/// `peer_key` refuses private material in it and validates the point. A curve
/// mismatch against the recipient's own key is refused before any derivation.
fn agree_direct_recover(
    header: &JoseHeader,
    recipient: &crate::jwk::Jwk,
    enc: JweEncryption,
    encrypted_key: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    use crate::jwk::agreement::{agreement_key, peer_key};

    // RFC 7518 §4.6: in Direct Key Agreement mode "the empty octet sequence is
    // used as the JWE Encrypted Key value". A message that conveys one as well
    // is describing two key-management schemes at once, and the CEK it decrypts
    // under would depend on which one a recipient happened to look at first.
    if !encrypted_key.is_empty() {
        return Err(JoseError::InvalidToken(
            "ECDH-ES: encrypted key must be empty (direct key agreement conveys no key)".into(),
        ));
    }

    let epk = epk_from_header(header)?;
    let peer = peer_key(&epk)?;
    let own = agreement_key(recipient)?;

    let apu = agreement_member(header, "apu")?;
    let apv = agreement_member(header, "apv")?;
    own.derive_key(
        &peer,
        enc.as_str(),
        apu.as_deref(),
        apv.as_deref(),
        enc.cek_size(),
    )
}

/// Recover the CEK from a message that agreed a key-encryption key and wrapped it.
///
/// Mirror of [`AgreementSender::wrap`]: AlgorithmID `alg`, keydatalen the KEK
/// length, then AES-KW. Unlike direct mode this mode **must** convey an encrypted
/// key — a message that omits it has no CEK to recover, and reading it as though
/// the agreement supplied the CEK directly would mix two key-management schemes
/// (that is the substitution this check exists to block).
fn agree_wrap_recover(
    header: &JoseHeader,
    recipient: &crate::jwk::Jwk,
    alg: JweAlgorithm,
    enc: JweEncryption,
    encrypted_key: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    use crate::jwk::agreement::{agreement_key, peer_key};

    let kek_len = agreement_kek_len(alg).ok_or_else(|| {
        JoseError::UnsupportedAlgorithm(format!(
            "{} does not wrap a key with an agreed key-encryption key",
            alg.as_str()
        ))
    })?;
    if encrypted_key.is_empty() {
        return Err(JoseError::InvalidToken(format!(
            "{}: an encrypted key is required (the CEK is wrapped under the agreed key)",
            alg.as_str()
        )));
    }

    let epk = epk_from_header(header)?;
    let peer = peer_key(&epk)?;
    let own = agreement_key(recipient)?;
    let apu = agreement_member(header, "apu")?;
    let apv = agreement_member(header, "apv")?;
    let kek = own.derive_key(&peer, alg.as_str(), apu.as_deref(), apv.as_deref(), kek_len)?;

    let cek = kryptering::keywrap::unwrap(jwe_alg_to_keywrap(alg)?, &kek, encrypted_key)
        .map_err(JoseError::Crypto)?;
    if cek.len() != enc.cek_size() {
        return Err(JoseError::Key(format!(
            "{}: unwrapped CEK length {} does not match the {} bytes {} requires",
            alg.as_str(),
            cek.len(),
            enc.cek_size(),
            enc.as_str()
        )));
    }
    Ok(Zeroizing::new(cek))
}

/// Check a `dir` key against the CEK size the content algorithm requires.
fn check_dir_key(key: &[u8], enc: JweEncryption) -> Result<()> {
    let cek_len = enc.cek_size();
    if key.len() != cek_len {
        return Err(JoseError::Key(format!(
            "dir: key length {} does not match required CEK size {}",
            key.len(),
            cek_len
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Key management: recover CEK (decrypt side)
// ---------------------------------------------------------------------------

pub(crate) fn recover_cek(
    key: &KeyMaterial,
    alg: JweAlgorithm,
    enc: JweEncryption,
    encrypted_key: &[u8],
    header: &JoseHeader,
) -> Result<Zeroizing<Vec<u8>>> {
    let cek_len = enc.cek_size();

    // Key agreement first, and separately: it needs the JWK and the message's
    // `epk`, so it never reaches the byte-oriented match below. Handling it
    // before that match is also what makes the raw-key refusal reach a caller
    // who passed bytes with an agreement algorithm — `(Bytes, _)` would
    // otherwise swallow it into "not yet implemented".
    if alg_is_agreement(alg) {
        return match (key, alg) {
            (KeyMaterial::Jwk(recipient), JweAlgorithm::EcdhEs) => {
                agree_direct_recover(header, recipient, enc, encrypted_key)
            }
            (KeyMaterial::Jwk(recipient), other) if agreement_kek_len(other).is_some() => {
                agree_wrap_recover(header, recipient, other, enc, encrypted_key)
            }
            (KeyMaterial::Jwk(_), other) => Err(JoseError::UnsupportedAlgorithm(format!(
                "{} is not implemented by this crate",
                other.as_str()
            ))),
            (KeyMaterial::Bytes(_), other) => Err(JoseError::Key(format!(
                "{} requires a JWK: key agreement needs the curve and coordinates of a key, and the peer key is read from the message's epk header member, so the raw-key API cannot express it",
                other.as_str()
            ))),
        };
    }
    let key = match key {
        KeyMaterial::Bytes(bytes) => bytes.as_slice(),
        // Unreachable: every agreement algorithm returned above.
        KeyMaterial::Jwk(_) => {
            return Err(JoseError::Key(
                "internal error: JWK key material reached a byte-oriented recovery path".into(),
            ))
        }
    };

    match alg {
        JweAlgorithm::Dir => {
            if !encrypted_key.is_empty() {
                return Err(JoseError::InvalidToken(
                    "dir: encrypted key must be empty".into(),
                ));
            }
            if key.len() != cek_len {
                return Err(JoseError::Key(format!(
                    "dir: key length {} does not match required CEK size {}",
                    key.len(),
                    cek_len
                )));
            }
            Ok(Zeroizing::new(key.to_vec()))
        }

        JweAlgorithm::A128KW | JweAlgorithm::A192KW | JweAlgorithm::A256KW => {
            check_kek_size(alg, key)?;
            let kw_alg = jwe_alg_to_keywrap(alg)?;
            let cek = Zeroizing::new(
                kryptering::keywrap::unwrap(kw_alg, key, encrypted_key)
                    .map_err(JoseError::Crypto)?,
            );
            if cek.len() != cek_len {
                return Err(JoseError::Key(format!(
                    "unwrapped CEK length {} does not match expected {}",
                    cek.len(),
                    cek_len
                )));
            }
            Ok(cek)
        }

        JweAlgorithm::RsaOaep256 => rsa_oaep_recover_cek(key, alg, encrypted_key, cek_len),

        #[cfg(feature = "deprecated")]
        JweAlgorithm::RsaOaep => rsa_oaep_recover_cek(key, alg, encrypted_key, cek_len),

        _ => Err(JoseError::UnsupportedAlgorithm(format!(
            "key management algorithm {} not yet implemented",
            alg.as_str()
        ))),
    }
}

/// Shared RSA-OAEP CEK recovery (used by both RSA-OAEP-256 and the deprecated
/// SHA-1 RSA-OAEP variant).
///
/// A random fallback CEK is generated before attempting the unwrap. Invalid
/// OAEP ciphertexts and incorrectly sized results use that fallback so they
/// continue through content authentication instead of returning early. This
/// implicit-rejection pattern prevents callers from distinguishing an OAEP
/// failure from a valid unwrap followed by failed content authentication.
/// Trusted-key parsing and algorithm-configuration errors remain explicit.
fn rsa_oaep_recover_cek(
    key: &[u8],
    alg: JweAlgorithm,
    encrypted_key: &[u8],
    cek_len: usize,
) -> Result<Zeroizing<Vec<u8>>> {
    let priv_key = parse_rsa_private_key(key)?;
    let kt_alg = jwe_alg_to_keytransport(alg)?;

    // Generate this unconditionally so successful and failed unwraps perform
    // the same random-number generation work. It is zeroized if unused.
    let fallback_cek = Zeroizing::new(content::random_bytes(cek_len));
    let recovered = kryptering::keytransport::kt_decrypt(kt_alg, &priv_key, encrypted_key, None)
        .map(Zeroizing::new);

    match recovered {
        Ok(cek) if cek.len() == cek_len => Ok(cek),
        // `cek`, when present with the wrong length, and the fallback are both
        // `Zeroizing`, so neither recovered nor dummy key material lingers.
        Ok(_) | Err(_) => Ok(fallback_cek),
    }
}

// ---------------------------------------------------------------------------
// Algorithm mapping helpers
// ---------------------------------------------------------------------------

/// Verify that the supplied Key Encryption Key is exactly the size
/// demanded by the declared AES Key Wrap algorithm.
///
/// Prevents silent acceptance of a 32-byte key for `A128KW` (or similar
/// mis-sized KEKs) if the underlying crypto backend does not validate
/// strictly.
pub(crate) fn check_kek_size(alg: JweAlgorithm, key: &[u8]) -> Result<()> {
    let expected = match alg {
        JweAlgorithm::A128KW => 16,
        JweAlgorithm::A192KW => 24,
        JweAlgorithm::A256KW => 32,
        _ => return Ok(()),
    };
    if key.len() != expected {
        return Err(JoseError::Key(format!(
            "{}: KEK must be {} bytes, got {}",
            alg.as_str(),
            expected,
            key.len()
        )));
    }
    Ok(())
}

/// The AES key wrapping a key-management algorithm performs.
///
/// The `A*KW` algorithms and the ECDH-agreement-with-wrapping algorithms share
/// this mapping on purpose: they run *the same* RFC 3394 wrap, and differ only in
/// where the key-encryption key came from — held by both parties already, or
/// derived from the agreement. Accepting both here keeps a third spelling of
/// "128-bit AES-KW" out of the codebase; it does **not** make the raw-byte path
/// reachable for agreement, which is dispatched away long before this is called
/// ([`recover_cek`], [`encrypt_core_multi`]).
pub(crate) fn jwe_alg_to_keywrap(alg: JweAlgorithm) -> Result<kryptering::KeyWrapAlgorithm> {
    use kryptering::{AesKeySize, KeyWrapAlgorithm};
    match alg {
        JweAlgorithm::A128KW | JweAlgorithm::EcdhEsA128kw => {
            Ok(KeyWrapAlgorithm::AesKw(AesKeySize::Aes128))
        }
        JweAlgorithm::A192KW | JweAlgorithm::EcdhEsA192kw => {
            Ok(KeyWrapAlgorithm::AesKw(AesKeySize::Aes192))
        }
        JweAlgorithm::A256KW | JweAlgorithm::EcdhEsA256kw => {
            Ok(KeyWrapAlgorithm::AesKw(AesKeySize::Aes256))
        }
        _ => Err(JoseError::UnsupportedAlgorithm(format!(
            "{} is not a key wrap algorithm",
            alg.as_str()
        ))),
    }
}

pub(crate) fn jwe_alg_to_keytransport(
    alg: JweAlgorithm,
) -> Result<kryptering::KeyTransportAlgorithm> {
    use kryptering::{HashAlgorithm, KeyTransportAlgorithm, OaepConfig};
    match alg {
        #[cfg(feature = "deprecated")]
        JweAlgorithm::RsaOaep => Ok(KeyTransportAlgorithm::RsaOaep(OaepConfig {
            digest: HashAlgorithm::Sha1,
            mgf_digest: HashAlgorithm::Sha1,
        })),
        JweAlgorithm::RsaOaep256 => Ok(KeyTransportAlgorithm::RsaOaep(OaepConfig {
            digest: HashAlgorithm::Sha256,
            mgf_digest: HashAlgorithm::Sha256,
        })),
        _ => Err(JoseError::UnsupportedAlgorithm(format!(
            "{} is not a key transport algorithm",
            alg.as_str()
        ))),
    }
}

// ---------------------------------------------------------------------------
// RSA key parsing
// ---------------------------------------------------------------------------

pub(crate) fn parse_rsa_public_key(der: &[u8]) -> Result<kryptering::SoftwareKey> {
    use rsa::pkcs8::DecodePublicKey;
    use rsa::traits::PublicKeyParts;
    let key = rsa::RsaPublicKey::from_public_key_der(der)
        .map_err(|e| JoseError::Key(format!("failed to parse RSA public key DER: {e}")))?;
    if key.n().bits() < crate::MIN_RSA_BITS {
        return Err(JoseError::Key(format!(
            "RSA key size {} bits is below the required minimum of {}",
            key.n().bits(),
            crate::MIN_RSA_BITS
        )));
    }
    kryptering::SoftwareKey::from_spki_der(kryptering::KeyAlgorithm::Rsa, der).map_err(Into::into)
}

pub(crate) fn parse_rsa_private_key(der: &[u8]) -> Result<kryptering::SoftwareKey> {
    use rsa::pkcs8::DecodePrivateKey;
    use rsa::traits::PublicKeyParts;
    let key = rsa::RsaPrivateKey::from_pkcs8_der(der)
        .map_err(|e| JoseError::Key(format!("failed to parse RSA private key PKCS#8 DER: {e}")))?;
    if key.n().bits() < crate::MIN_RSA_BITS {
        return Err(JoseError::Key(format!(
            "RSA key size {} bits is below the required minimum of {}",
            key.n().bits(),
            crate::MIN_RSA_BITS
        )));
    }
    kryptering::SoftwareKey::from_pkcs8_der(kryptering::KeyAlgorithm::Rsa, der).map_err(Into::into)
}

// ---------------------------------------------------------------------------
// JWK-aware key material (shared by the raw-key one-shot APIs and the
// JSON serialization APIs)
// ---------------------------------------------------------------------------

/// Determine which `JwkOp` governs a JWE alg on the encrypt side.
///
/// `Dir` uses the key directly for content encryption (`Encrypt`);
/// key-transport (`A*KW`, `RSA-OAEP*`) wraps a CEK (`WrapKey`).
pub(crate) fn jwe_alg_encrypt_op(alg: JweAlgorithm) -> crate::jwk::JwkOp {
    match alg {
        JweAlgorithm::Dir => crate::jwk::JwkOp::Encrypt,
        // Agreement is neither encryption nor wrapping: the recipient's key is
        // used to *derive*, and RFC 7517 §4.3 spells that `deriveKey`. A key
        // pinned to `wrapKey` therefore cannot be an ECDH-ES recipient key.
        a if alg_is_agreement(a) => crate::jwk::JwkOp::DeriveKey,
        _ => crate::jwk::JwkOp::WrapKey,
    }
}

/// Determine which `JwkOp` governs a JWE alg on the decrypt side.
pub(crate) fn jwe_alg_decrypt_op(alg: JweAlgorithm) -> crate::jwk::JwkOp {
    match alg {
        JweAlgorithm::Dir => crate::jwk::JwkOp::Decrypt,
        a if alg_is_agreement(a) => crate::jwk::JwkOp::DeriveKey,
        _ => crate::jwk::JwkOp::UnwrapKey,
    }
}

/// The key material one key-management step operates on.
///
/// Two shapes, because the algorithms consume two different things:
///
/// * [`KeyMaterial::Bytes`] — a shared CEK (`dir`), an AES key-wrap KEK, or RSA
///   DER. The algorithm consumes the bytes and nothing else.
/// * [`KeyMaterial::Jwk`] — the ECDH key-agreement family. Agreement cannot work
///   from bytes: it needs the curve and coordinates, whether private material is
///   present, and the key's own `use`/`key_ops`/`alg` statements (ADR 0016). On
///   the producing side it also has to publish a freshly generated public key,
///   which raw bytes could not express.
///
/// Raw-key public APIs therefore hand out [`KeyMaterial::Bytes`] and cannot
/// reach an agreement algorithm at all: there is no way to name a curve, and no
/// `epk` to agree with, in a `&[u8]`.
pub(crate) enum KeyMaterial {
    Bytes(Zeroizing<Vec<u8>>),
    /// Boxed so the byte variant stays small: a `Jwk` is well over half a
    /// kilobyte, and this enum is passed around by value on every encrypt.
    Jwk(Box<crate::jwk::Jwk>),
}

impl KeyMaterial {
    /// Key bytes, for the transport and wrapping algorithms.
    fn bytes(&self) -> Result<&[u8]> {
        match self {
            Self::Bytes(bytes) => Ok(bytes),
            Self::Jwk(_) => Err(JoseError::Key(
                "internal error: JWK key material reached a byte-oriented key-management path"
                    .into(),
            )),
        }
    }
}

/// Route a JWK into the form `alg` consumes.
pub(crate) fn recipient_key(
    jwk: &crate::jwk::Jwk,
    alg: JweAlgorithm,
    for_decrypt: bool,
) -> Result<KeyMaterial> {
    if alg_is_agreement(alg) {
        Ok(KeyMaterial::Jwk(Box::new(jwk.clone())))
    } else {
        Ok(KeyMaterial::Bytes(jwk_to_jwe_key_bytes(
            jwk,
            alg,
            for_decrypt,
        )?))
    }
}

/// Convert a JWK to the raw key-material form that the raw-key encrypt and
/// decrypt paths expect for the given JWE algorithm.
///
/// - For `dir`, `A*KW`: returns the `k` bytes of an `oct` JWK.
/// - For `RSA-OAEP*` on the encrypt side: returns SPKI DER of the public key.
/// - For `RSA-OAEP*` on the decrypt side: returns PKCS#8 DER of the private key.
pub(crate) fn jwk_to_jwe_key_bytes(
    jwk: &crate::jwk::Jwk,
    alg: JweAlgorithm,
    for_decrypt: bool,
) -> Result<Zeroizing<Vec<u8>>> {
    match alg {
        JweAlgorithm::Dir | JweAlgorithm::A128KW | JweAlgorithm::A192KW | JweAlgorithm::A256KW => {
            if jwk.kty.as_str() != "oct" {
                return Err(JoseError::Key(format!(
                    "JWE alg {} requires kty oct, got {}",
                    alg.as_str(),
                    jwk.kty.as_str()
                )));
            }
            let k = jwk
                .k
                .as_deref()
                .ok_or_else(|| JoseError::Key("JWK is missing `k`".into()))?;
            Ok(Zeroizing::new(base64url::decode(k)?))
        }
        JweAlgorithm::RsaOaep256 => rsa_jwk_to_der(jwk, for_decrypt),
        #[cfg(feature = "deprecated")]
        JweAlgorithm::RsaOaep => rsa_jwk_to_der(jwk, for_decrypt),
        _ => Err(JoseError::UnsupportedAlgorithm(format!(
            "JWE alg {} not supported via JWK one-shot API",
            alg.as_str()
        ))),
    }
}

fn rsa_jwk_to_der(jwk: &crate::jwk::Jwk, for_decrypt: bool) -> Result<Zeroizing<Vec<u8>>> {
    let sw = crate::jwk::jwk_to_software_key(jwk)?;
    if sw.algorithm() != kryptering::KeyAlgorithm::Rsa {
        return Err(JoseError::Key("RSA JWK expected".into()));
    }
    if for_decrypt {
        if !sw.has_private_key() {
            return Err(JoseError::Key("JWK lacks RSA private components".into()));
        }
        sw.export_private().map_err(Into::into)
    } else {
        Ok(Zeroizing::new(sw.export_spki_der()?))
    }
}

// ---------------------------------------------------------------------------
// Shared encryption core (compact and JSON serializations)
// ---------------------------------------------------------------------------

/// Key management plus content encryption, before any serialization.
///
/// `header_b64` is the exact string that was used as the additional
/// authenticated data, so a serializer that emits it verbatim produces a
/// message the recipient can authenticate.
pub(crate) struct EncryptedCore {
    /// `BASE64URL(UTF8(JWE Protected Header))`, also the AAD input.
    pub header_b64: String,
    /// Wrapped key (empty for `dir`).
    pub encrypted_key: Vec<u8>,
    /// Content IV.
    pub iv: Vec<u8>,
    /// Content ciphertext.
    pub ciphertext: Vec<u8>,
    /// Content authentication tag.
    pub tag: Vec<u8>,
}

/// Build the content-authentication input (RFC 7516 §5.1 step 14).
///
/// `ASCII(Encoded Protected Header)`, or — when a JWE AAD value is present,
/// which only the JSON serialization can carry —
/// `ASCII(Encoded Protected Header || '.' || BASE64URL(JWE AAD))`.
///
/// `external_aad_b64` must be the *encoded* form: the RFC authenticates the
/// base64url text, not the raw additional-authenticated-data octets, so the
/// same bytes under two different encodings are different messages.
/// Refuse an external AAD that encodes to nothing.
///
/// RFC 7516 §7.2.1 requires the `aad` member to be absent when the value is
/// empty, and the AAD *input* differs between "no member" and `""` (the
/// separator), so accepting an empty value would let a sender and a recipient
/// disagree about which message they hold.
pub(crate) fn ensure_external_aad_present(bytes: &[u8]) -> Result<()> {
    if bytes.is_empty() {
        return Err(JoseError::InvalidHeader(
            "external additional authenticated data must not be empty; an empty JWE AAD is indistinguishable from no AAD (RFC 7516 §7.2.1)"
                .into(),
        ));
    }
    Ok(())
}

pub(crate) fn aad_input(header_b64: &str, external_aad_b64: Option<&str>) -> Vec<u8> {
    match external_aad_b64 {
        None => header_b64.as_bytes().to_vec(),
        Some(aad_b64) => format!("{header_b64}.{aad_b64}").into_bytes(),
    }
}

/// Encrypt once, for any serialization.
///
/// Applies the whole emit-side policy in one place, so a new serializer
/// cannot skip a rule:
///
/// 1. `header.alg` / `header.enc` must agree with the algorithms actually
///    used (RFC 8725 §3.1);
/// 2. [`validate_encrypt_header`] (unimplemented members, `crit`);
/// 3. [`JoseHeader::to_protected_b64`] (duplicate members, key-reference
///    members, header size);
/// 4. a size pre-flight so a token this crate could not decode is never
///    produced;
/// 5. key management and content encryption over
///    [`aad_input`](self::aad_input).
///
/// `aad_b64` is the encoded external AAD (`None` for compact and for JSON
/// without an `aad` member).
pub(crate) fn encrypt_core(
    header: &JoseHeader,
    key: KeyMaterial,
    plaintext: &[u8],
    alg: JweAlgorithm,
    enc: JweEncryption,
    opts: &JweEncryptOptions,
    aad_b64: Option<&str>,
) -> Result<EncryptedCore> {
    if header.alg != alg.as_str() {
        return Err(JoseError::InvalidHeader(format!(
            "protected header alg {} does not match JWE algorithm {}",
            header.alg,
            alg.as_str()
        )));
    }
    if header.enc.as_deref() != Some(enc.as_str()) {
        return Err(JoseError::InvalidHeader(format!(
            "protected header enc {:?} does not match JWE encryption {}",
            header.enc,
            enc.as_str()
        )));
    }
    // alg/enc agree; now the JWE-specific member rules, then the shared
    // duplicate / key-reference / size rules while serializing.
    validate_encrypt_header(header, alg, opts.understood_crit())?;
    let header_b64 = header.to_protected_b64(opts.allow_key_reference_headers)?;

    // The ciphertext is at least as long as the plaintext, so refuse before
    // any key wrapping or encryption when the token cannot possibly fit. The
    // external AAD (plus its `.` separator) is part of the serialized
    // message, so it counts against the limit too.
    let aad_len = aad_b64.map_or(0, |aad| aad.len() + 1);
    crate::ensure_emit_size(
        header_b64.len() + aad_len + content::base64url_len(plaintext.len()) + 4,
    )?;

    let (core, wrapped) = encrypt_core_multi(header, &[key], plaintext, alg, enc, opts, aad_b64)?;
    Ok(EncryptedCore {
        encrypted_key: wrapped.into_iter().next().unwrap_or_default(),
        ..core
    })
}

/// Shared body of a general-serialization encryption.
///
/// The whole emit-side policy runs **once** — the protected header, the AAD
/// input and the content encryption are shared by every recipient — and only
/// key management repeats, which is what RFC 7516 §7.2.1 requires: one
/// ciphertext, one encrypted CEK per recipient.
///
/// All recipients share the key-management algorithm. Per-recipient algorithms
/// would put `alg` in the element's unprotected header, where it is not
/// integrity protected, and this crate will not *emit* an algorithm a recipient
/// cannot authenticate (ADR 0013).
///
/// Returns the shared envelope plus `keys[i]`'s wrapped CEK, positionally.
pub(crate) fn encrypt_core_multi(
    header: &JoseHeader,
    keys: &[KeyMaterial],
    plaintext: &[u8],
    alg: JweAlgorithm,
    enc: JweEncryption,
    opts: &JweEncryptOptions,
    aad_b64: Option<&str>,
) -> Result<(EncryptedCore, Vec<Vec<u8>>)> {
    let Some((first, rest)) = keys.split_first() else {
        return Err(JoseError::InvalidHeader(
            "a JWE must name at least one recipient key".into(),
        ));
    };

    if header.alg != alg.as_str() {
        return Err(JoseError::InvalidHeader(format!(
            "protected header alg {} does not match JWE algorithm {}",
            header.alg,
            alg.as_str()
        )));
    }
    if header.enc.as_deref() != Some(enc.as_str()) {
        return Err(JoseError::InvalidHeader(format!(
            "protected header enc {:?} does not match JWE encryption {}",
            header.enc,
            enc.as_str()
        )));
    }
    validate_encrypt_header(header, alg, opts.understood_crit())?;

    // Direct key agreement has to happen before the header is serialized,
    // because publishing the ephemeral public key *changes* the protected header
    // that is then used as the AAD input. `Cow` so that every other algorithm
    // keeps borrowing the caller's header.
    let (header, agreed, sender): (
        std::borrow::Cow<'_, JoseHeader>,
        Option<Zeroizing<Vec<u8>>>,
        Option<AgreementSender>,
    ) = match (first, alg) {
        (KeyMaterial::Jwk(recipient), JweAlgorithm::EcdhEs) => {
            if !rest.is_empty() {
                // The agreed key *is* the CEK, and it is agreed with exactly
                // one recipient. Two recipients would need two different
                // CEKs, and one ciphertext cannot be encrypted under two.
                return Err(direct_agreement_not_multi(alg));
            }
            let (header, cek) = agree_direct(header, recipient, enc)?;
            (std::borrow::Cow::Owned(header), Some(cek), None)
        }
        // Agreement with key wrapping: the CEK is generated normally and wrapped
        // per recipient, so all this mode needs up front is the ephemeral key to
        // publish (which changes the protected header, hence "before serialize").
        (KeyMaterial::Jwk(recipient), other) if agreement_kek_len(other).is_some() => {
            if !rest.is_empty() {
                return Err(per_recipient_epk_unsupported(other));
            }
            let sender = agreement_sender(header, recipient)?;
            (
                std::borrow::Cow::Owned(sender.header.clone()),
                None,
                Some(sender),
            )
        }
        (KeyMaterial::Jwk(_), other) => {
            return Err(JoseError::UnsupportedAlgorithm(format!(
                "{} is not implemented by this crate",
                other.as_str()
            )))
        }
        (KeyMaterial::Bytes(_), other) if alg_is_agreement(other) => {
            return Err(JoseError::Key(format!(
                "{} requires a JWK; the raw-key API cannot name a curve or carry the peer key",
                other.as_str()
            )))
        }
        _ => (std::borrow::Cow::Borrowed(header), None, None),
    };
    let header_b64 = header.to_protected_b64(opts.allow_key_reference_headers)?;

    // The ciphertext is at least as long as the plaintext, so refuse before any
    // key wrapping or encryption when the token cannot possibly fit. The
    // external AAD (plus its `.` separator) is part of the serialized message,
    // so it counts against the limit too, as does each additional recipient's
    // encrypted key.
    let aad_len = aad_b64.map_or(0, |aad| aad.len() + 1);
    let extra_keys_len = content::base64url_len(plaintext.len()).saturating_mul(rest.len());
    crate::ensure_emit_size(
        header_b64.len() + aad_len + content::base64url_len(plaintext.len()) + 4 + extra_keys_len,
    )?;

    // 1. Generate or use the CEK, wrap it for the first recipient. Direct key
    // agreement has already agreed it, and conveys nothing; agreement with
    // wrapping generates it normally and wraps it with the agreed KEK.
    let (cek, first_wrapped) = match (agreed, sender) {
        (Some(cek), _) => (cek, Vec::new()),
        (None, Some(sender)) => {
            let cek = Zeroizing::new(content::random_bytes(enc.cek_size()));
            let wrapped = sender.wrap(alg, &cek)?;
            (cek, wrapped)
        }
        (None, None) => produce_cek(first.bytes()?, alg, enc)?,
    };

    // 2. Content encryption — once, over the shared AAD input.
    let aad = aad_input(&header_b64, aad_b64);
    let (iv, ciphertext, tag) = content::content_encrypt(enc, &cek, plaintext, &aad)?;

    // 3. Same CEK, wrapped for each remaining recipient.
    let mut wrapped = Vec::with_capacity(keys.len());
    wrapped.push(first_wrapped);
    for key in rest {
        wrapped.push(wrap_cek(&cek, key.bytes()?, alg, enc)?);
    }

    Ok((
        EncryptedCore {
            header_b64,
            encrypted_key: Vec::new(),
            iv,
            ciphertext,
            tag,
        },
        wrapped,
    ))
}

#[cfg(test)]
mod tests {
    use super::other_info;

    #[test]
    fn other_info_matches_the_rfc_7518_appendix_c_bytes() {
        // RFC 7518 §C prints OtherInfo as an explicit octet array for
        // AlgorithmID = "A128GCM", PartyUInfo = "Alice", PartyVInfo = "Bob" and
        // a 128-bit key. Transcribed here, so the layout is pinned by the RFC
        // rather than by this implementation's own output.
        #[rustfmt::skip]
        let expected: Vec<u8> = vec![
            0, 0, 0, 7, 65, 49, 50, 56, 71, 67, 77, // 7 | "A128GCM"
            0, 0, 0, 5, 65, 108, 105, 99, 101,      // 5 | "Alice"
            0, 0, 0, 3, 66, 111, 98,                // 3 | "Bob"
            0, 0, 0, 128,                            // SuppPubInfo: 128 bits
        ];
        let info = other_info("A128GCM", Some(b"Alice"), Some(b"Bob"), 16);
        assert_eq!(info.as_bytes(), expected);
    }

    #[test]
    fn an_absent_party_info_is_four_zero_octets() {
        // Not "absent": the length prefix stays, and dropping it changes the
        // derived key with no error anywhere.
        #[rustfmt::skip]
        let absent_u: Vec<u8> = vec![
            0, 0, 0, 7, 65, 49, 50, 56, 71, 67, 77, // 7 | "A128GCM"
            0, 0, 0, 0,                              // PartyUInfo: empty
            0, 0, 0, 3, 66, 111, 98,                 // 3 | "Bob"
            0, 0, 0, 128,
        ];
        let info = other_info("A128GCM", None, Some(b"Bob"), 16);
        assert_eq!(info.as_bytes(), absent_u);

        // And the empty octet sequence is what an empty header value encodes to
        // as well, so `""` and an absent parameter coincide — which is the
        // server-behaviour divergence documented in the interop notes, not a
        // bug in either reading.
        assert_eq!(
            other_info("A128GCM", Some(b""), Some(b"Bob"), 16).as_bytes(),
            absent_u
        );
    }

    #[test]
    fn supp_pub_info_carries_the_bit_length_big_endian() {
        for (key_len, expected) in [
            (16usize, vec![0u8, 0, 0, 128]),
            (24, vec![0, 0, 0, 192]),
            (32, vec![0, 0, 1, 0]),
        ] {
            let info = other_info("A128GCM", None, None, key_len);
            let bytes = info.as_bytes();
            let tail = &bytes[bytes.len() - 4..];
            assert_eq!(tail, expected, "{key_len} octets = {} bits", key_len * 8);
        }
    }
}
