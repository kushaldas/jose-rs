//! Password-encrypted PKCS#8 key files (RFC 5958 §3, RFC 8018 §6.2) — I3.
//!
//! An `ENCRYPTED PRIVATE KEY` file is a PKCS#8 `PrivateKeyInfo` wrapped in
//! `EncryptedPrivateKeyInfo`: an `AlgorithmIdentifier` naming a password-based scheme, its
//! parameters (salt, iteration count, IV), and the ciphertext. Reading one means deriving a
//! key from a human's password, and writing one means choosing how much CPU the *next*
//! reader spends. Both ends need a policy, and neither end should be an ad hoc cipher.
//!
//! # The dependency is the allow-list
//!
//! Encryption and KDF work is done by the `pkcs5` crate's PBES2 implementation, reached
//! through `pkcs8`'s `encryption` feature. What makes that an *allow-list* rather than a
//! menu is how the dependency is compiled: HMAC-SHA1, DES and 3DES each live behind a
//! separately-named `-insecure`/`3des` feature that this crate does not enable, so they are
//! not reachable at runtime by any input, from any caller. Everything else this module
//! checks — the iteration budget, the PRF, refusing scrypt — is layered on top of a floor
//! that is enforced at compile time.
//!
//! # What this crate will and will not open
//!
//! * **PBES2 + PBKDF2 + HMAC-SHA256/384/512 + AES-128/256-CBC**, with an iteration count
//!   inside the work budget. That is what OpenSSL and `cryptography` emit.
//! * **PBES1 is refused** (RFC 8018 §6.1): its PRF is HMAC-SHA1-based and its ciphers are
//!   DES and RC2. Refusing is not timidity — the scheme has no configuration that reaches
//!   anything worth trusting.
//! * **scrypt is refused**, and that one is awkward, because `pkcs8`'s own default export
//!   form *is* scrypt+AES-256-CBC. The reason is the budget: scrypt's cost is set by the
//!   file's own parameters (log N, r, p) and this module's bound is an iteration count, so
//!   accepting scrypt would mean accepting a work cost it cannot bound. The consequence is
//!   stated plainly below: this crate will not emit what it will not read.
//! * **DES and 3DES are refused by name**, not as "unsupported OID", so the caller learns
//!   which knob of their tooling caused it.
//!
//! # The budget, and one number that is about the ecosystem
//!
//! [`PKCS8_MIN_ITERATIONS`] is 2 048, measured rather than chosen: OpenSSL 3.6's
//! `openssl pkcs8 -topk8` and `cryptography` 50's `BestAvailableEncryption` **both** emit
//! 2 048 by default. A floor above that would refuse every default-encrypted key file in
//! the wild, and a library that cannot open someone's key file has not improved their
//! security — it has destroyed their key. 2 048 is therefore the *interoperability* floor,
//! and the docs say so instead of pretending it is a recommendation.
//!
//! [`PKCS8_DEFAULT_ITERATIONS`] for files this crate writes is 600 000 (OWASP's current
//! figure for PBKDF2-HMAC-SHA256 against a password), and unlike JOSE's PBES2 there is no
//! peer ceiling to respect: a PKCS#8 reader computes whatever the file names. So the
//! emit-side default is free to be the careful number, and the read-side default budget
//! ([`PKCS8_DEFAULT_MAX_ITERATIONS`] = 10 000 000) is set from measured wall-clock cost so
//! that the worst thing a file can do to this process is under two seconds of CPU (measured:
//! <1 ms at 2 048, 175 ms at 600 000, 1 694 ms at 10 000 000; see the benchmark test).
//!
//! The budget is checked **before** deriving — refusing a file costs nothing, and a check
//! placed after the derivation would be a check placed after the denial of service.

use ::pkcs8::der::Decode;
use ::pkcs8::pkcs5::pbes2::{Kdf, Pbkdf2Prf};
use ::pkcs8::pkcs5::EncryptionScheme as Pkcs5Scheme;
use ::pkcs8::{EncryptedPrivateKeyInfo, PrivateKeyInfo};
use zeroize::Zeroizing;

use crate::error::{JoseError, Result};
use crate::jwk::Jwk;
use crate::password::Password;

/// The lowest PBKDF2 iteration count accepted when reading, and emitted when writing.
///
/// 2 048, measured: that is what `openssl pkcs8 -topk8 -v2 aes-256-cbc -v2prf
/// hmacWithSHA256` and `cryptography`'s `BestAvailableEncryption` both write by default
/// (both emit `0x0800`). It is the floor at which refusing still lets people open their
/// own keys, not a claim that 2 048 is enough work for a password.
///
/// A file below it is refused naming the count, because the only way to fix that file is to
/// re-export it — which needs the password, which the caller already has.
pub const PKCS8_MIN_ITERATIONS: u32 = 2_048;

/// The iteration count used when writing an encrypted key file.
///
/// 600 000: OWASP's current recommendation for PBKDF2-HMAC-SHA256 against a password. A
/// PKCS#8 reader computes whatever the file names — there is no peer-side ceiling as there
/// is in JOSE PBES2 — so the emitted default can be the careful number rather than the
/// intersection of what other implementations tolerate. It costs a fraction of a second to
/// unlock a key (175 ms measured), which is the point: file protection that is annoying gets
/// bypassed by the user storing the key unencrypted.
pub const PKCS8_DEFAULT_ITERATIONS: u32 = 600_000;

/// The highest PBKDF2 iteration count accepted by default when reading.
///
/// The file names this number and this process pays it, so an unbounded accepted count is a
/// denial of service in one file: `pkcs5`'s own ceiling is 100 000 000, which is minutes of
/// CPU spent before the ciphertext says the password was wrong anyway.
///
/// 10 000 000 keeps the worst case to about 1.7 s on the measured machine — the numbers are
/// 2 048 → <1 ms, 600 000 → 175 ms, 10 000 000 → 1 694 ms (see the benchmark test, which
/// produced them and can re-derive them elsewhere). Raise or lower it per call with
/// [`Pkcs8ReadOptions::with_max_iterations`]; a caller migrating a corpus of old files may
/// legitimately need to, and that is exactly why it is a per-call decision rather than a
/// library-wide one.
pub const PKCS8_DEFAULT_MAX_ITERATIONS: u32 = 10_000_000;

/// The scheme used when writing a password-encrypted PKCS#8 file.
///
/// Both variants are PBES2 with PBKDF2-HMAC-SHA256 and AES-CBC, differing in key size and
/// iteration count. There is no variant for SHA-1, DES, 3DES, RC2 or scrypt: this type *is*
/// the allow-list on the write side, and the read side refuses the same set — a library that
/// writes a form it refuses to read would be shipping its users files they cannot open
/// later.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pkcs8Encryption {
    /// AES-128-CBC with PBKDF2-HMAC-SHA256.
    Aes128CbcPbkdf2HmacSha256 {
        /// PBKDF2 iteration count; at least [`PKCS8_MIN_ITERATIONS`].
        iterations: u32,
    },
    /// AES-256-CBC with PBKDF2-HMAC-SHA256. The default.
    Aes256CbcPbkdf2HmacSha256 {
        /// PBKDF2 iteration count; at least [`PKCS8_MIN_ITERATIONS`].
        iterations: u32,
    },
}

impl Default for Pkcs8Encryption {
    fn default() -> Self {
        Pkcs8Encryption::Aes256CbcPbkdf2HmacSha256 {
            iterations: PKCS8_DEFAULT_ITERATIONS,
        }
    }
}

impl Pkcs8Encryption {
    /// The iteration count this scheme asks the reader to spend.
    pub fn iterations(self) -> u32 {
        match self {
            Pkcs8Encryption::Aes128CbcPbkdf2HmacSha256 { iterations } => iterations,
            Pkcs8Encryption::Aes256CbcPbkdf2HmacSha256 { iterations } => iterations,
        }
    }

    /// The same scheme with a different iteration count.
    pub fn with_iterations(self, iterations: u32) -> Self {
        match self {
            Pkcs8Encryption::Aes128CbcPbkdf2HmacSha256 { .. } => {
                Pkcs8Encryption::Aes128CbcPbkdf2HmacSha256 { iterations }
            }
            Pkcs8Encryption::Aes256CbcPbkdf2HmacSha256 { .. } => {
                Pkcs8Encryption::Aes256CbcPbkdf2HmacSha256 { iterations }
            }
        }
    }
}

/// How much CPU a caller is willing to let an encrypted key file bill to this process.
///
/// Built from [`Pkcs8ReadOptions::default`] (which is
/// [`PKCS8_DEFAULT_MAX_ITERATIONS`]) and adjusted per call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pkcs8ReadOptions {
    max_iterations: u32,
}

impl Default for Pkcs8ReadOptions {
    fn default() -> Self {
        Pkcs8ReadOptions {
            max_iterations: PKCS8_DEFAULT_MAX_ITERATIONS,
        }
    }
}

impl Pkcs8ReadOptions {
    /// Accept iteration counts up to `max_iterations`.
    ///
    /// The floor is not adjustable: [`PKCS8_MIN_ITERATIONS`] is a statement about the file's
    /// protection being real, not about this process's patience.
    pub fn with_max_iterations(mut self, max_iterations: u32) -> Self {
        self.max_iterations = max_iterations;
        self
    }

    /// The current ceiling.
    pub fn max_iterations(&self) -> u32 {
        self.max_iterations
    }
}

/// Import a [`Jwk`] from a password-encrypted PKCS#8 (`ENCRYPTED PRIVATE KEY`) DER document.
///
/// ```
/// use jose_rs::jwk::{
///     self, encrypted_pkcs8_der_from_jwk, jwk_from_encrypted_pkcs8_der, Password,
///     Pkcs8Encryption,
/// };
///
/// let key = jwk::generate_ec("P-256")?;
/// let password = Password::from_utf8("hunter2");
/// let der = encrypted_pkcs8_der_from_jwk(
///     &key,
///     &password,
///     &Pkcs8Encryption::Aes256CbcPbkdf2HmacSha256 { iterations: 4_096 },
/// )?;
/// let restored = jwk_from_encrypted_pkcs8_der(&der, &password)?;
/// assert_eq!(restored.crv.as_deref(), Some("P-256"));
/// assert_eq!(restored.d, key.d);
///
/// // The wrong password yields no key, and says so as a decryption failure.
/// let err = jwk_from_encrypted_pkcs8_der(&der, &Password::from_utf8("wrong")).unwrap_err();
/// assert!(err.to_string().contains("decryption failed"));
/// # Ok::<(), jose_rs::JoseError>(())
/// ```
///
/// The scheme named in the file is checked against this module's allow-list and the work
/// budget **before** any key is derived, then the file is decrypted and the resulting
/// PKCS#8 is imported by [`jwk_from_pkcs8_der`](crate::jwk::jwk_from_pkcs8_der) — so every
/// DER-level rule (RSA-PSS rejection, the modulus floor, curve dispatch) applies unchanged.
/// A wrong password surfaces as a decryption failure, not as a malformed key: the
/// ciphertext's PKCS#7 padding is what says whether the derived key was right.
///
/// # Errors
///
/// [`JoseError::Key`] for a scheme outside the allow-list (PBES1, scrypt, SHA-1/SHA-224
/// PRFs, DES/3DES), an iteration count outside the budget, a malformed file, a wrong
/// password, and anything the PKCS#8 importer refuses.
pub fn jwk_from_encrypted_pkcs8_der(der: &[u8], password: &Password) -> Result<Jwk> {
    jwk_from_encrypted_pkcs8_der_with_options(der, password, &Pkcs8ReadOptions::default())
}

/// [`jwk_from_encrypted_pkcs8_der`] with an explicit work budget.
pub fn jwk_from_encrypted_pkcs8_der_with_options(
    der: &[u8],
    password: &Password,
    options: &Pkcs8ReadOptions,
) -> Result<Jwk> {
    crate::ensure_emit_size(der.len())?;
    let info = EncryptedPrivateKeyInfo::from_der(der).map_err(|e| {
        // Schemes the dependency does not even compile — DES, 3DES, AES-192-CBC — fail to
        // *parse*, so the parse error is where their refusal surfaces. Naming the OID the
        // file actually contains is the difference between "your file uses 3DES" and
        // "your file is corrupt", and only ever sharpens a refusal: nothing is accepted on
        // the strength of this scan.
        if let Some(reason) = unsupported_oid_hint(der) {
            return JoseError::Key(reason);
        }
        JoseError::Key(format!("invalid EncryptedPrivateKeyInfo DER: {e}"))
    })?;

    // Before deriving: naming the scheme is free, computing it is not.
    describe_scheme(&info.encryption_algorithm, options.max_iterations())?;

    let plaintext = info.decrypt(password.as_bytes()).map_err(|_| {
        JoseError::Key(
            "PKCS#8 decryption failed (wrong password, or the file is not intact)".into(),
        )
    })?;
    super::import::jwk_from_pkcs8_der(plaintext.as_bytes())
}

/// Import a [`Jwk`] from a password-encrypted PKCS#8 PEM document.
///
/// The armor rules are the [`crate::jwk::pem`] module's, and the label is checked: a plain
/// `PRIVATE KEY` block handed to this function is refused rather than quietly imported.
/// That direction is not pedantry — a caller who asked for the password path and is handed
/// back a key from an *unencrypted* file would believe they hold a protected key.
///
/// # Errors
///
/// As [`jwk_from_encrypted_pkcs8_der`], plus armor refusals and a wrong-label refusal.
pub fn jwk_from_encrypted_pkcs8_pem(text: &str, password: &Password) -> Result<Jwk> {
    jwk_from_encrypted_pkcs8_pem_with_options(text, password, &Pkcs8ReadOptions::default())
}

/// [`jwk_from_encrypted_pkcs8_pem`] with an explicit work budget.
pub fn jwk_from_encrypted_pkcs8_pem_with_options(
    text: &str,
    password: &Password,
    options: &Pkcs8ReadOptions,
) -> Result<Jwk> {
    let (label, der) = super::pem::decompose(text)?;
    if label != super::pem::LABEL_ENCRYPTED_PRIVATE {
        return Err(JoseError::InvalidToken(format!(
            "expected a PEM \"ENCRYPTED PRIVATE KEY\" block and found \"{label}\"; an \
             unencrypted key must not be readable through the password path, or a caller \
             cannot tell whether their key is protected"
        )));
    }
    jwk_from_encrypted_pkcs8_der_with_options(&der, password, options)
}

/// Write a [`Jwk`] as a password-encrypted PKCS#8 DER document.
///
/// Deliberately separate from every other export: the plaintext-export functions are
/// [`private_pem_from_jwk`](crate::jwk::private_pem_from_jwk) and the DER importers, and
/// nothing here writes an unencrypted key "as a fallback". An **empty** password is refused
/// on the write side only, for the same reason PBES2 refuses it (ADR 0021): an unset secret
/// and a deliberately empty one are indistinguishable in the file, and a caller who means one
/// gets the other. Reading an empty-password file is not refused on that ground — the file is
/// the file, and the password either decrypts it or does not.
///
/// The salt and IV come from the operating-system RNG, and both are fresh per call: two
/// exports of one key with one password share no bytes, which is what stops an observer
/// comparing two files.
///
/// # Errors
///
/// [`JoseError::Key`] when the JWK has no private part or its algorithm has no PKCS#8 form,
/// when `iterations` is below [`PKCS8_MIN_ITERATIONS`], and on encryption failure.
pub fn encrypted_pkcs8_der_from_jwk(
    jwk: &Jwk,
    password: &Password,
    scheme: &Pkcs8Encryption,
) -> Result<Zeroizing<Vec<u8>>> {
    if password.is_empty() {
        return Err(JoseError::Key(
            "refusing to encrypt a key with an empty password: an unset secret and an \
             intentionally empty one produce indistinguishable files, and the caller cannot \
             tell them apart later"
                .into(),
        ));
    }
    let iterations = scheme.iterations();
    if iterations < PKCS8_MIN_ITERATIONS {
        return Err(JoseError::Key(format!(
            "PKCS#8 iteration count {iterations} is below the minimum of {PKCS8_MIN_ITERATIONS}; \
             that floor is what OpenSSL and cryptography emit by default, so a file below it is \
             one other tools will not read either"
        )));
    }

    let software = super::convert::jwk_to_software_key(jwk)?;
    // Normalized exactly as the plaintext PEM export normalizes it (`pkcs8_portable_form`):
    // the backend's Ed25519 export is a version-1 `OneAsymmetricKey`, which `cryptography`
    // refuses outright. Encrypting that key would wrap a payload the recipient cannot parse,
    // so the fix has to happen *before* encryption — after decryption is too late to help a
    // file already handed to a peer.
    let plain = super::pem::pkcs8_portable_form(software.export_private()?.as_ref())?;
    let info = PrivateKeyInfo::from_der(&plain).map_err(|e| {
        JoseError::Key(format!(
            "PKCS#8 export from the backend did not parse: {e:?}"
        ))
    })?;

    let mut rng = rand::rngs::OsRng;
    let mut salt = [0u8; 16];
    let mut iv = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rng, &mut salt);
    rand::RngCore::fill_bytes(&mut rng, &mut iv);

    let params = match scheme {
        Pkcs8Encryption::Aes128CbcPbkdf2HmacSha256 { .. } => {
            ::pkcs8::pkcs5::pbes2::Parameters::pbkdf2_sha256_aes128cbc(iterations, &salt, &iv)
        }
        Pkcs8Encryption::Aes256CbcPbkdf2HmacSha256 { .. } => {
            ::pkcs8::pkcs5::pbes2::Parameters::pbkdf2_sha256_aes256cbc(iterations, &salt, &iv)
        }
    }
    .map_err(|e| JoseError::Key(format!("PKCS#8 PBES2 parameters were rejected: {e:?}")))?;

    let encrypted = info
        .encrypt_with_params(params, password.as_bytes())
        .map_err(|e| JoseError::Key(format!("PKCS#8 encryption failed: {e:?}")))?;
    Ok(Zeroizing::new(encrypted.as_bytes().to_vec()))
}

/// Write a [`Jwk`] as a password-encrypted PKCS#8 PEM document (`ENCRYPTED PRIVATE KEY`).
///
/// The returned text is ciphertext: unlike a plaintext export, it is safe to log, and it is
/// what a user should be given when they ask for an "encrypted key file".
///
/// # Errors
///
/// As [`encrypted_pkcs8_der_from_jwk`].
pub fn encrypted_pkcs8_pem_from_jwk(
    jwk: &Jwk,
    password: &Password,
    scheme: &Pkcs8Encryption,
) -> Result<String> {
    let der = encrypted_pkcs8_der_from_jwk(jwk, password, scheme)?;
    super::pem::encode_with_label("ENCRYPTED PRIVATE KEY", der.as_ref())
}

/// Check a file's scheme against the allow-list and the work budget, before deriving.
///
/// Returns the iteration count it accepted, so a caller (or a test) can see what was paid.
fn describe_scheme(scheme: &Pkcs5Scheme<'_>, max_iterations: u32) -> Result<u32> {
    match scheme {
        Pkcs5Scheme::Pbes1(_) => Err(JoseError::Key(
            "PBES1 (RFC 8018 §6.1) encrypted PKCS#8 is unsupported: its PRF family is \
             HMAC-SHA1-based and its ciphers are DES and RC2, and no parameter choice brings \
             it up to what this crate will accept. Re-export the key with PBES2/AES-CBC"
                .into(),
        )),
        Pkcs5Scheme::Pbes2(params) => match (&params.kdf, &params.encryption) {
            (Kdf::Scrypt(_), _) => Err(JoseError::Key(
                "scrypt-based encrypted PKCS#8 is unsupported: scrypt's cost comes from the \
                 file's own (log N, r, p) parameters, and this crate's bound is a PBKDF2 \
                 iteration count, so accepting it would mean accepting a work cost it cannot \
                 bound. Note that this is also what `pkcs8`'s default export form uses, which \
                 is why this crate neither emits nor reads it"
                    .into(),
            )),
            (Kdf::Pbkdf2(kdf), cipher) => {
                match kdf.prf {
                    Pbkdf2Prf::HmacWithSha256
                    | Pbkdf2Prf::HmacWithSha384
                    | Pbkdf2Prf::HmacWithSha512 => {}
                    Pbkdf2Prf::HmacWithSha1 => {
                        return Err(JoseError::Key(
                            "PBKDF2 with HMAC-SHA1 is outside this crate's scheme allow-list; \
                             re-export the key with hmacWithSHA256 or better"
                                .into(),
                        ));
                    }
                    Pbkdf2Prf::HmacWithSha224 => {
                        return Err(JoseError::Key(
                            "PBKDF2 with HMAC-SHA224 is outside this crate's scheme allow-list \
                             (SHA-256, SHA-384, SHA-512)"
                                .into(),
                        ));
                    }
                    other => {
                        return Err(JoseError::Key(format!(
                            "PBKDF2 with an unknown PRF ({other:?}) is outside this crate's \
                             scheme allow-list (SHA-256, SHA-384, SHA-512)"
                        )));
                    }
                }
                match cipher {
                    ::pkcs8::pkcs5::pbes2::EncryptionScheme::Aes128Cbc { .. }
                    | ::pkcs8::pkcs5::pbes2::EncryptionScheme::Aes256Cbc { .. } => {}
                    // Reachable only if a future dependency adds a cipher variant; DES and
                    // 3DES do not appear here because they are not compiled in at all.
                    other => {
                        return Err(JoseError::Key(format!(
                            "PBES2 cipher {other:?} is outside this crate's scheme allow-list \
                             (AES-128-CBC and AES-256-CBC)"
                        )));
                    }
                }
                let iterations = kdf.iteration_count;
                if iterations < PKCS8_MIN_ITERATIONS {
                    return Err(JoseError::Key(format!(
                        "encrypted PKCS#8 names {iterations} PBKDF2 iterations, below the \
                         minimum of {PKCS8_MIN_ITERATIONS} (the count OpenSSL and cryptography \
                         emit by default); decrypt and re-export it with a real count"
                    )));
                }
                if iterations > max_iterations {
                    return Err(JoseError::Key(format!(
                        "encrypted PKCS#8 names {iterations} PBKDF2 iterations, above this \
                         call's budget of {max_iterations}; the file chooses this number and \
                         this process pays it, so it is bounded (raise it per call with \
                         Pkcs8ReadOptions::with_max_iterations)"
                    )));
                }
                Ok(iterations)
            }
            // A KDF this build does not know about is refused, not assumed to be PBKDF2-shaped.
            (other_kdf, _) => Err(JoseError::Key(format!(
                "encrypted PKCS#8 names a key derivation function this crate does not know \
                 ({other_kdf:?})"
            ))),
        },
        // A scheme this build does not know about is refused, never handed to a decryptor.
        other => Err(JoseError::Key(format!(
            "encrypted PKCS#8 names a password-based encryption scheme this crate does not \
             know ({other:?}); unknown means unimplemented, not acceptable"
        ))),
    }
}

/// DER-encoded OBJECT IDENTIFIER values worth naming in an error message.
///
/// Compared as raw bytes because the file may not parse far enough to ask. Each of these is
/// a *refusal* explanation; none of them is a reason to accept anything.
mod oids {
    /// `1.2.840.113549.1.5.1` … `.3` — PBES1 with MD2/MD5/SHA-1.
    pub const PBES1: [u8; 3] = [0x06, 0x09, 0x2A];
    /// `1.2.840.113549.1.5.*` prefix shared by PBES1, PBKDF2 and PBES2.
    pub const PKCS5_PBASE: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x05];
    /// `1.3.6.1.4.1.11591.4.11` — scrypt.
    pub const SCRYPT: &[u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x04, 0x0B];
    /// `1.2.840.113549.2.7` — hmacWithSHA1.
    pub const HMAC_WITH_SHA1: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x07];
    /// `1.2.840.113549.2.8` — hmacWithSHA224.
    pub const HMAC_WITH_SHA224: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x08];
    /// `1.2.840.113549.3.7` — des-ede3-cbc (3DES).
    pub const DES_EDE3_CBC: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x03, 0x07];
    /// `1.3.14.3.2.7` — des-cbc.
    pub const DES_CBC: &[u8] = &[0x2B, 0x0E, 0x03, 0x02, 0x07];
    /// `2.16.840.1.101.3.4.1.22` — aes-192-cbc.
    pub const AES_192_CBC: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x16];
}

/// Does this DER contain an OBJECT IDENTIFIER whose value is exactly `oid`?
///
/// Looks for the full `06 <length> <value>` encoding, so a shorter OID that is a *prefix* of
/// a longer one cannot match by accident.
fn contains_oid(der: &[u8], oid: &[u8]) -> bool {
    let mut needle = [0u8; 11];
    if oid.len() > 9 {
        return false;
    }
    needle[0] = 0x06;
    needle[1] = oid.len() as u8;
    needle[2..2 + oid.len()].copy_from_slice(oid);
    der.windows(2 + oid.len())
        .any(|w| w == &needle[..2 + oid.len()])
}

/// Explain a file this crate cannot parse, when the reason is a scheme it would refuse anyway.
fn unsupported_oid_hint(der: &[u8]) -> Option<String> {
    if contains_oid(der, oids::DES_EDE3_CBC) {
        return Some(
            "3DES-CBC encrypted PKCS#8 is unsupported — the dependency is compiled without \
             3DES, so the file cannot even be parsed far enough to refuse it politely. \
             Re-export the key with AES-CBC"
                .into(),
        );
    }
    if contains_oid(der, oids::DES_CBC) {
        return Some(
            "DES-CBC encrypted PKCS#8 is unsupported; re-export the key with AES-CBC".into(),
        );
    }
    if contains_oid(der, oids::AES_192_CBC) {
        return Some(
            "AES-192-CBC encrypted PKCS#8 is unsupported (AES-128-CBC and AES-256-CBC are); \
             re-export the key with one of those"
                .into(),
        );
    }
    if contains_oid(der, oids::HMAC_WITH_SHA1) {
        return Some(
            "PBKDF2 with HMAC-SHA1 is outside this crate's scheme allow-list; re-export the \
             key with hmacWithSHA256 or better"
                .into(),
        );
    }
    if contains_oid(der, oids::HMAC_WITH_SHA224) {
        return Some(
            "PBKDF2 with HMAC-SHA224 is outside this crate's scheme allow-list (SHA-256, \
             SHA-384, SHA-512)"
                .into(),
        );
    }
    if contains_oid(der, oids::SCRYPT) {
        return Some(
            "scrypt-based encrypted PKCS#8 is unsupported: its cost comes from the file's own \
             parameters, and this crate's bound is a PBKDF2 iteration count"
                .into(),
        );
    }
    // PBES1 files carry a `pbeWithMD2/MD5/SHA1AndDES-CBC` OID under the PKCS#5 pbe-with-*
    // arc and no PBES2 parameters at all.
    if !contains_oid(der, oids::PKCS5_PBASE) && der.starts_with(&[0x30]) {
        return Some(
            "encrypted PKCS#8 names an algorithm outside the PKCS#5 pbes2 arc; PBES1 \
             (RFC 8018 §6.1) is unsupported — its PRFs are MD2/MD5/HMAC-SHA1 and its cipher is \
             DES"
            .into(),
        );
    }
    let _ = oids::PBES1;
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jwk::{self};
    use std::time::Instant;

    fn ec_jwk() -> Jwk {
        crate::jwk::generate_ec("P-256").expect("generate")
    }

    #[test]
    fn round_trip_recovers_the_same_key_material() {
        let key = ec_jwk();
        let password = Password::from_utf8("hunter2");
        let der = encrypted_pkcs8_der_from_jwk(&key, &password, &Pkcs8Encryption::default())
            .expect("encrypt");
        let back = jwk_from_encrypted_pkcs8_der(&der, &password).expect("decrypt");

        assert_eq!(back.kty, key.kty);
        assert_eq!(back.crv, key.crv);
        assert_eq!(back.x, key.x);
        assert_eq!(back.d, key.d);
    }

    #[test]
    fn two_exports_of_one_key_share_no_prefix() {
        // Fresh salt and IV per call, so two files of one key under one password are
        // unrelated byte strings.
        let key = ec_jwk();
        let password = Password::from_utf8("same password");
        let a =
            encrypted_pkcs8_pem_from_jwk(&key, &password, &Pkcs8Encryption::default()).expect("a");
        let b =
            encrypted_pkcs8_pem_from_jwk(&key, &password, &Pkcs8Encryption::default()).expect("b");
        assert_ne!(a, b);
        assert!(a.starts_with("-----BEGIN ENCRYPTED PRIVATE KEY-----"));
        assert!(b.contains("-----END ENCRYPTED PRIVATE KEY-----\n"));
    }

    #[test]
    fn wrong_password_is_refused_not_misinterpreted() {
        let key = ec_jwk();
        let der = encrypted_pkcs8_der_from_jwk(
            &key,
            &Password::from_utf8("right"),
            &Pkcs8Encryption::default(),
        )
        .expect("encrypt");
        let err = jwk_from_encrypted_pkcs8_der(&der, &Password::from_utf8("wrong"))
            .expect_err("wrong password must not import");
        let msg = err.to_string();
        assert!(msg.contains("decryption failed"), "{msg}");
        // ...and must not leak the key either: no JWK comes back.
        assert!(!msg.contains("EC"), "{msg}");
    }

    #[test]
    fn tampered_ciphertext_is_refused() {
        let key = ec_jwk();
        let password = Password::from_utf8("password");
        let mut der = encrypted_pkcs8_der_from_jwk(&key, &password, &Pkcs8Encryption::default())
            .expect("encrypt");
        let last = der.len() - 5;
        der[last] ^= 0x01;
        let err = jwk_from_encrypted_pkcs8_der(&der, &password).expect_err("tampered");
        assert!(err.to_string().contains("decryption failed"), "{err}");
    }

    #[test]
    fn plaintext_forms_are_refused_without_a_fallback() {
        let pem = jwk::private_pem_from_jwk(&ec_jwk()).expect("plaintext PEM");
        let err = jwk_from_encrypted_pkcs8_pem(&pem, &Password::from_utf8("x"))
            .expect_err("the password path must not read an unencrypted file");
        let msg = err.to_string();
        assert!(msg.contains("ENCRYPTED PRIVATE KEY"), "{msg}");
        assert!(msg.contains("protected"), "{msg}");

        // The other direction: an encrypted file at the plaintext door.
        let encrypted = jwk::encrypted_pkcs8_pem_from_jwk(
            &ec_jwk(),
            &Password::from_utf8("x"),
            &Pkcs8Encryption::default(),
        )
        .expect("encrypt");
        let err = jwk::jwk_from_pem(&encrypted).expect_err("plaintext door must refuse");
        assert!(
            err.to_string().contains("jwk_from_encrypted_pkcs8_pem"),
            "{err}"
        );
    }

    #[test]
    fn iteration_budget_is_enforced_before_deriving() {
        let key = ec_jwk();
        let password = Password::from_utf8("x");
        let cheap = encrypted_pkcs8_der_from_jwk(
            &key,
            &password,
            &Pkcs8Encryption::Aes256CbcPbkdf2HmacSha256 { iterations: 4_096 },
        )
        .expect("4096 is above the floor");
        // Accepted, and the default budget accepts it comfortably.
        assert!(jwk_from_encrypted_pkcs8_der(&cheap, &password).is_ok());

        // A file naming more work than this call will pay is refused.
        let err = jwk_from_encrypted_pkcs8_der_with_options(
            &cheap,
            &password,
            &Pkcs8ReadOptions::default().with_max_iterations(2_048),
        )
        .expect_err("over budget");
        let msg = err.to_string();
        assert!(msg.contains("4096"), "{msg}");
        assert!(msg.contains("budget"), "{msg}");

        // Below the floor the file is refused whatever the budget says.
        let err = encrypted_pkcs8_der_from_jwk(
            &key,
            &password,
            &Pkcs8Encryption::Aes256CbcPbkdf2HmacSha256 { iterations: 1 },
        )
        .expect_err("one iteration is not protection");
        assert!(err.to_string().contains("2048"), "{err}");
    }

    #[test]
    fn rsa_and_ed25519_keys_round_trip_through_encrypted_pkcs8() {
        let password = Password::from_utf8("pass");
        for curve in ["RSA", "Ed25519"] {
            let key = if curve == "RSA" {
                crate::jwk::generate_rsa(2048).expect("rsa")
            } else {
                crate::jwk::generate_ed25519().expect("ed25519")
            };
            let der = encrypted_pkcs8_der_from_jwk(
                &key,
                &password,
                &Pkcs8Encryption::Aes128CbcPbkdf2HmacSha256 {
                    iterations: PKCS8_MIN_ITERATIONS,
                },
            )
            .expect("encrypt");
            let back = jwk_from_encrypted_pkcs8_der(&der, &password).expect("decrypt");
            assert_eq!(back.kty, key.kty, "{curve}");
            assert_eq!(back.crv, key.crv, "{curve}");
            assert_eq!(back.n, key.n, "{curve}");
            assert_eq!(back.d, key.d, "{curve}");
        }
    }

    #[test]
    fn public_only_jwks_cannot_be_exported_as_private_keys() {
        let public = ec_jwk().to_public_jwk();
        let err = encrypted_pkcs8_der_from_jwk(
            &public,
            &Password::from_utf8("x"),
            &Pkcs8Encryption::default(),
        )
        .expect_err("no private part");
        assert!(err.to_string().contains("no private material"), "{err}");
    }

    #[test]
    fn a_des_file_is_refused_by_name_not_as_corruption() {
        // openssl pkcs8 -topk8 -v2 des -v2prf hmacWithSHA1 ... cannot be produced by
        // OpenSSL 3 by default, so the fixture is a hand-written encrypted file from the
        // interop suite; here the byte-scan classifier is exercised directly with a
        // DER-shaped buffer carrying the 3DES OID.
        let mut der = vec![0x30, 0x00];
        der.extend_from_slice(&[0x06, 0x08, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x03, 0x07]);
        let hint = unsupported_oid_hint(&der).expect("named");
        assert!(hint.contains("3DES"), "{hint}");
        assert!(contains_oid(&der, oids::DES_EDE3_CBC));
        // A shorter OID that is a prefix of this one must not match it.
        assert!(!contains_oid(
            &[0x06, 0x07, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x03],
            oids::DES_EDE3_CBC
        ));
    }

    /// Regression: what we encrypt must be the *portable* PKCS#8 form, not version 1.
    ///
    /// The first version of this export encrypted the backend's bytes as-is, and `cryptography`
    /// rejected the resulting Ed25519 file — the inner payload was a version-1
    /// `OneAsymmetricKey`. The interop suite caught it; this test is the cheap version of that
    /// check, so the mistake cannot come back with a release that skips interop.
    #[test]
    fn ed25519_exports_encrypt_the_portable_form() {
        use ::pkcs8::der::Decode;
        use ::pkcs8::PrivateKeyInfo;

        for key in [
            crate::jwk::generate_ed25519().expect("ed25519"),
            crate::jwk::generate_ec("P-256").expect("ec"),
        ] {
            let password = Password::from_utf8("x");
            let der = encrypted_pkcs8_der_from_jwk(&key, &password, &Pkcs8Encryption::default())
                .expect("encrypt");
            let info = EncryptedPrivateKeyInfo::from_der(&der).expect("parse");
            let inner = info.decrypt(password.as_bytes()).expect("decrypt");
            let inner_info = PrivateKeyInfo::from_der(inner.as_bytes()).expect("inner pkcs8");
            assert!(
                inner_info.public_key.is_none(),
                "{}: encrypted payload still carries the OneAsymmetricKey publicKey attribute",
                key.crv.as_deref().unwrap_or("?")
            );
        }
    }

    /// scrypt is refused, and the fixture is the dependency's **own** default export form.
    ///
    /// This is the awkward case worth pinning: `pkcs8`'s `encrypt()` writes scrypt +
    /// AES-256-CBC, so a file produced by the very crate this module builds on is one this
    /// module will not open. The reason is stated in the refusal (an unboundable work cost),
    /// and the consequence — we do not emit what we will not read — is why this module's own
    /// export uses `encrypt_with_params` with PBKDF2 instead.
    #[test]
    fn scrypt_files_are_refused_even_though_pkcs8_writes_them() {
        use ::pkcs8::der::Decode;
        use ::pkcs8::PrivateKeyInfo;

        let key = ec_jwk();
        let plain = super::super::convert::jwk_to_software_key(&key)
            .expect("convert")
            .export_private()
            .expect("pkcs8");
        let info = PrivateKeyInfo::from_der(plain.as_ref()).expect("parse");
        let scrypt_file = info
            .encrypt(&mut rand::rngs::OsRng, b"hunter2")
            .expect("scrypt encrypt");

        let err =
            jwk_from_encrypted_pkcs8_der(scrypt_file.as_bytes(), &Password::from_utf8("hunter2"))
                .expect_err("scrypt must be refused");
        let msg = err.to_string();
        assert!(msg.contains("scrypt"), "{msg}");
        assert!(msg.contains("bound"), "{msg}");

        // And the byte-scan classifier gives the same answer when the file cannot parse.
        let hint = unsupported_oid_hint(scrypt_file.as_bytes()).expect("hint");
        assert!(hint.contains("scrypt"), "{hint}");
    }

    /// The measurement behind [`PKCS8_DEFAULT_MAX_ITERATIONS`].
    ///
    /// Run with `cargo test --release -- --ignored --nocapture pkcs8_work_budget_benchmark`.
    #[test]
    #[ignore = "wall-clock benchmark"]
    fn pkcs8_work_budget_benchmark() {
        let salt = [0x22u8; 16];
        let iv = [0x33u8; 16];
        for iterations in [
            PKCS8_MIN_ITERATIONS,
            PKCS8_DEFAULT_ITERATIONS,
            PKCS8_DEFAULT_MAX_ITERATIONS,
        ] {
            let params =
                ::pkcs8::pkcs5::pbes2::Parameters::pbkdf2_sha256_aes256cbc(iterations, &salt, &iv)
                    .expect("parameters");
            let started = Instant::now();
            params
                .encrypt(b"benchmark password", b"payload".as_slice())
                .expect("derive");
            println!(
                "PBES2 PBKDF2-HMAC-SHA256/AES-256-CBC {iterations:>10} iterations: {:?}",
                started.elapsed()
            );
        }
    }
}
