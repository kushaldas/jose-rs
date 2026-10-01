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
//! This module is the ADR-0012 extraction of the code that previously lived in
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
}

impl JweEncryptOptions {
    /// Strict defaults: no key-reference header members.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set [`allow_key_reference_headers`](Self::allow_key_reference_headers).
    #[must_use]
    pub fn with_key_reference_headers(mut self, allow: bool) -> Self {
        self.allow_key_reference_headers = allow;
        self
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
/// Emitting any of these would describe processing that did not happen, so
/// a peer that implements them would read the token differently.
pub(crate) const UNIMPLEMENTED_JWE_MEMBERS: &[&str] =
    &["zip", "b64", "epk", "apu", "apv", "p2s", "p2c", "iv", "tag"];

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
/// 2. `crit` must be absent. No JWE critical extensions are implemented, and
///    an empty `crit` array is invalid (RFC 7515 §4.1.11).
///
/// # Errors
///
/// Returns [`JoseError::InvalidHeader`] naming the first rule violated.
pub(crate) fn validate_encrypt_header(header: &JoseHeader) -> Result<()> {
    // Rule 1. `extra["crit"]` is not handled here: it duplicates a typed
    // field, which `to_protected_b64` rejects before anything is emitted.
    if header.extra.contains_key("zip") {
        return Err(JoseError::InvalidHeader(
            "unsupported zip header: content compression is not supported".into(),
        ));
    }
    if let Some(name) = UNIMPLEMENTED_JWE_MEMBERS
        .iter()
        .find(|name| header.extra.contains_key(**name))
    {
        return Err(JoseError::InvalidHeader(format!(
            "unsupported JWE header member {name}: not implemented for JWE compact encryption"
        )));
    }

    // Rule 2: any `crit` is unsupported; distinguish the empty case so the
    // error points at the RFC violation rather than an unknown extension.
    if let Some(crit) = &header.crit {
        return Err(JoseError::InvalidHeader(if crit.is_empty() {
            "crit header must not be empty (RFC 7515 §4.1.11)".into()
        } else {
            format!("unsupported crit extensions: {crit:?}")
        }));
    }

    Ok(())
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
}

impl JweDecryptOptions {
    /// Construct options pinning an explicit allow-list.
    pub fn new(allowed_alg: Vec<JweAlgorithm>, allowed_enc: Vec<JweEncryption>) -> Self {
        Self {
            allowed_alg,
            allowed_enc,
            allow_all: false,
            max_plaintext: None,
        }
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
    encrypted_key_b64: &str,
    iv_b64: &str,
    ciphertext_b64: &str,
    tag_b64: &str,
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

    // RFC 7516 §4.1.13 / RFC 7515 §4.1.11: `crit` must be non-empty and may
    // name only extensions the library understands — none are supported.
    if let Some(crit) = &header.crit {
        if crit.is_empty() {
            return Err(JoseError::InvalidHeader(
                "crit header must not be empty (RFC 7515 §4.1.11)".into(),
            ));
        }
        return Err(JoseError::InvalidHeader(format!(
            "unsupported crit extensions: {crit:?}"
        )));
    }

    let alg = JweAlgorithm::from_str(&header.alg)?;
    let enc_str = header
        .enc
        .as_deref()
        .ok_or_else(|| JoseError::InvalidHeader("missing enc field".into()))?;
    let enc = JweEncryption::from_str(enc_str)?;

    let envelope = ParsedEnvelope {
        header_b64,
        alg,
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
    let cek_len = enc.cek_size();

    match alg {
        // Direct: the provided key *is* the CEK.
        JweAlgorithm::Dir => {
            if key.len() != cek_len {
                return Err(JoseError::Key(format!(
                    "dir: key length {} does not match required CEK size {}",
                    key.len(),
                    cek_len
                )));
            }
            Ok((Zeroizing::new(key.to_vec()), Vec::new()))
        }

        // AES Key Wrap.
        JweAlgorithm::A128KW | JweAlgorithm::A192KW | JweAlgorithm::A256KW => {
            check_kek_size(alg, key)?;
            let kw_alg = jwe_alg_to_keywrap(alg)?;
            let cek = Zeroizing::new(content::random_bytes(cek_len));
            let wrapped =
                kryptering::keywrap::wrap(kw_alg, key, &cek).map_err(JoseError::Crypto)?;
            Ok((cek, wrapped))
        }

        // RSA-OAEP.
        JweAlgorithm::RsaOaep256 => {
            let pub_key = parse_rsa_public_key(key)?;
            let kt_alg = jwe_alg_to_keytransport(alg)?;
            let cek = Zeroizing::new(content::random_bytes(cek_len));
            let encrypted = kryptering::keytransport::kt_encrypt(kt_alg, &pub_key, &cek, None)
                .map_err(JoseError::Crypto)?;
            Ok((cek, encrypted))
        }

        #[cfg(feature = "deprecated")]
        JweAlgorithm::RsaOaep => {
            let pub_key = parse_rsa_public_key(key)?;
            let kt_alg = jwe_alg_to_keytransport(alg)?;
            let cek = Zeroizing::new(content::random_bytes(cek_len));
            let encrypted = kryptering::keytransport::kt_encrypt(kt_alg, &pub_key, &cek, None)
                .map_err(JoseError::Crypto)?;
            Ok((cek, encrypted))
        }

        _ => Err(JoseError::UnsupportedAlgorithm(format!(
            "key management algorithm {} not yet implemented",
            alg.as_str()
        ))),
    }
}

// ---------------------------------------------------------------------------
// Key management: recover CEK (decrypt side)
// ---------------------------------------------------------------------------

pub(crate) fn recover_cek(
    key: &[u8],
    alg: JweAlgorithm,
    enc: JweEncryption,
    encrypted_key: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let cek_len = enc.cek_size();

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

pub(crate) fn jwe_alg_to_keywrap(alg: JweAlgorithm) -> Result<kryptering::KeyWrapAlgorithm> {
    use kryptering::{AesKeySize, KeyWrapAlgorithm};
    match alg {
        JweAlgorithm::A128KW => Ok(KeyWrapAlgorithm::AesKw(AesKeySize::Aes128)),
        JweAlgorithm::A192KW => Ok(KeyWrapAlgorithm::AesKw(AesKeySize::Aes192)),
        JweAlgorithm::A256KW => Ok(KeyWrapAlgorithm::AesKw(AesKeySize::Aes256)),
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
        _ => crate::jwk::JwkOp::WrapKey,
    }
}

/// Determine which `JwkOp` governs a JWE alg on the decrypt side.
pub(crate) fn jwe_alg_decrypt_op(alg: JweAlgorithm) -> crate::jwk::JwkOp {
    match alg {
        JweAlgorithm::Dir => crate::jwk::JwkOp::Decrypt,
        _ => crate::jwk::JwkOp::UnwrapKey,
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
