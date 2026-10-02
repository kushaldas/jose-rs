//! PEM (RFC 7468) import and export for [`Jwk`].
//!
//! PEM adds no cryptography. It is an encoding — base64 with BEGIN/END labels — and it
//! matters because keys live in files, and files are where implementations get to choose
//! how strict they are. This module wraps the DER import and export that already exist
//! ([`crate::jwk::jwk_from_pkcs8_der`], [`crate::jwk::jwk_from_spki_der`] and the
//! `SoftwareKey` exporters) in an armor reader that refuses the things a permissive one
//! would quietly accept.
//!
//! # What a single argument means here
//!
//! [`jwk_from_pem`] takes one `&str` and returns one [`Jwk`], so everything about that
//! call has a decided answer. These are the decisions, all of them tested:
//!
//! * **One block, or none.** A file holding two keys is a question, not a key: which one
//!   did the caller mean? The refusal says how many blocks were found. (A certificate
//!   chain is the legitimate multi-block case, and it will be a *label-specific* entry
//!   point when certificates are supported — not a relaxation of this rule for
//!   everything.)
//! * **No preamble.** RFC 7468 permits text before the BEGIN line — email bodies full of
//!   key material are exactly that — and this crate refuses it. Silently skipping leading
//!   prose means a file that contains an unrelated paragraph and a key is a key file, and
//!   a file where the key was deleted still parses as whatever the armor happens to
//!   contain. Trailing whitespace after the END line is fine; trailing text is not.
//! * **Canonical base64, both line endings accepted.** Padded, no trailing bits, no
//!   embedded whitespace beyond line breaks. CRLF is accepted because Windows files
//!   exist; `\r` anywhere else is not.
//! * **Legacy PEM headers are refused, not skipped.** `Proc-Type: 4,ENCRYPTED` /
//!   `DEK-Info: …` (the RFC 1423 OpenSSL-style encryption) marks a file whose key is
//!   encrypted under a password. Decrypting it is a separate, deliberate operation with
//!   its own dependency and scheme allow-list, so the refusal says where it leads rather
//!   than pretending the bytes are a key.
//! * **Labels are dispatched, not guessed.** `PRIVATE KEY` is PKCS#8 and `PUBLIC KEY` is
//!   SPKI. `RSA PRIVATE KEY` (PKCS#1), `EC PRIVATE KEY` (SEC1) and `CERTIFICATE` are
//!   refused **by name** with a pointer to the format-specific entry point — they are
//!   different structures, and the label is the only place the difference is written.
//! * **Private export is its own function.** [`private_pem_from_jwk`] is the only way to
//!   get a `PRIVATE KEY` block, and it requires private material;
//!   [`public_pem_from_jwk`] exports the SPKI public half and will not emit a private
//!   block under any input. Nothing here writes to disk, and no `Jwk` ever appears in
//!   `Debug` output with its secret parts (see [`crate::jwk::Jwk`]).
//!
//! # Examples
//!
//! ```
//! use jose_rs::jwk::{self, pem};
//!
//! let key = jwk::generate_ed25519()?;
//! let public_pem = pem::public_pem_from_jwk(&key)?;
//! assert!(public_pem.starts_with("-----BEGIN PUBLIC KEY-----"));
//! // The public half exports cleanly; asking for a private block from a public-only JWK
//! // is refused rather than answered with an empty or partial key.
//! let round_tripped = pem::jwk_from_pem(&public_pem)?;
//! assert_eq!(
//!     round_tripped.to_json()?,
//!     key.to_public_jwk().to_json()?
//! );
//! # Ok::<(), jose_rs::JoseError>(())
//! ```

use crate::error::{JoseError, Result};
use crate::jwk::Jwk;

/// The RFC 7468 type label for an unencrypted PKCS#8 private key.
const LABEL_PRIVATE: &str = "PRIVATE KEY";
/// The RFC 7468 type label for a SubjectPublicKeyInfo public key.
const LABEL_PUBLIC: &str = "PUBLIC KEY";

/// Labels this crate recognizes but does not yet parse, each with the reason a caller
/// needs.
///
/// Refusing by name is the point. These labels describe *different structures*, and the
/// label is the only place that difference is recorded: `EC PRIVATE KEY` is a SEC1
/// `ECPrivateKey`, not a PKCS#8 `PrivateKeyInfo`, and feeding it to a PKCS#8 parser
/// would either fail cryptically or — worse, for lengths that happen to line up —
/// succeed at the wrong thing.
const KNOWN_BUT_UNSUPPORTED: &[(&str, &str)] = &[
    (
        "RSA PRIVATE KEY",
        "PKCS#1 (RFC 8017), not PKCS#8; import through the PKCS#1 entry point",
    ),
    (
        "EC PRIVATE KEY",
        "SEC1 (RFC 5915), not PKCS#8; import through the SEC1 entry point",
    ),
    (
        "CERTIFICATE",
        "an X.509 certificate; extract the public key through the certificate entry point",
    ),
    (
        "NEW CERTIFICATE REQUEST",
        "a PKCS#10 certification request, not a key",
    ),
    (
        "PUBLIC KEY PARAMETERS",
        "an SPKI group parameter set, not a key",
    ),
];

/// Import a [`Jwk`] from a PEM document, choosing the format from the type label.
///
/// Accepts exactly one armor block: `PRIVATE KEY` (PKCS#8) or `PUBLIC KEY` (SPKI). Every
/// other outcome — two blocks, leading text before `BEGIN`, trailing text after `END`,
/// legacy `DEK-Info` headers, non-canonical base64, a recognized-but-unsupported label —
/// is refused with the reason, rather than resolved by guessing.
///
/// The returned JWK pins no `alg`, as the DER importers do: the same RSA key signs `RS256`
/// and `PS256`, and choosing between them is the caller's decision, not the file's.
///
/// # Errors
///
/// [`JoseError::InvalidToken`] for an armor-level problem (multiple blocks, preamble,
/// trailing data, bad base64, missing boundaries, legacy headers, a size beyond
/// [`crate::MAX_TOKEN_BYTES`]) and for an unsupported label; the underlying DER parsing
/// errors for a body that does not match its label.
///
/// ```
/// use jose_rs::jwk::pem;
///
/// // Two keys in one file is a question, not a key.
/// let two = "-----BEGIN PUBLIC KEY-----\nMFowDQYJYIZIAWUDBAIDBQ==\n-----END PUBLIC KEY-----\n-----BEGIN PUBLIC KEY-----\nMFowDQYJYIZIAWUDBAIDBQ==\n-----END PUBLIC KEY-----\n";
/// assert!(pem::jwk_from_pem(two).unwrap_err().to_string().contains("2 blocks"));
/// ```
pub fn jwk_from_pem(text: &str) -> Result<Jwk> {
    let (label, der) = decompose(text)?;
    match label {
        LABEL_PRIVATE => super::import::jwk_from_pkcs8_der(&der),
        LABEL_PUBLIC => super::import::jwk_from_spki_der(&der),
        other => Err(unsupported_label(other)),
    }
}

/// Import a [`Jwk`] from a PKCS#8 (`PRIVATE KEY`) PEM document specifically.
///
/// The explicit counterpart of [`jwk_from_pem`]: a `PUBLIC KEY` block is refused here
/// even though it is a perfectly good PEM document, because a caller who asked for a
/// private key and was handed a public one should not find out by accident.
///
/// # Errors
///
/// As [`jwk_from_pem`], plus a refusal when the label is not `PRIVATE KEY`.
pub fn jwk_from_pkcs8_pem(text: &str) -> Result<Jwk> {
    let (label, der) = decompose(text)?;
    if label != LABEL_PRIVATE {
        return Err(JoseError::InvalidToken(format!(
            "expected a PEM \"{LABEL_PRIVATE}\" block and found \"{label}\""
        )));
    }
    super::import::jwk_from_pkcs8_der(&der)
}

/// Import a [`Jwk`] from an SPKI (`PUBLIC KEY`) PEM document specifically.
///
/// Refuses a `PRIVATE KEY` block: a caller who wanted the public half of a private key
/// should say so by loading it and calling [`Jwk::to_public_jwk`], not by having the
/// importer quietly discard the part it was not asked for.
///
/// # Errors
///
/// As [`jwk_from_pem`], plus a refusal when the label is not `PUBLIC KEY`.
pub fn jwk_from_spki_pem(text: &str) -> Result<Jwk> {
    let (label, der) = decompose(text)?;
    if label != LABEL_PUBLIC {
        return Err(JoseError::InvalidToken(format!(
            "expected a PEM \"{LABEL_PUBLIC}\" block and found \"{label}\""
        )));
    }
    super::import::jwk_from_spki_der(&der)
}

/// Export a [`Jwk`] as a PKCS#8 `PRIVATE KEY` PEM document.
///
/// The only export that emits private material, and it requires private material: a
/// public-only JWK is refused rather than exported as an empty or partial key. Note that
/// the JWK's own metadata (`kid`, `use`, `alg`, …) does not survive the trip — PEM has
/// nowhere to put it — so round-tripping through this function loses it by design.
///
/// Post-quantum keys are refused: the backend's composite ML-DSA encoding has no PKCS#8
/// or SPKI representation, and inventing one would produce a file no one else can read.
///
/// # Errors
///
/// [`JoseError::Key`] when the JWK has no private part or its algorithm has no PKCS#8
/// representation, and the usual conversion errors for inconsistent key material.
pub fn private_pem_from_jwk(jwk: &Jwk) -> Result<String> {
    if !has_private_material(jwk) {
        return Err(JoseError::Key(
            "PEM private export needs a key with its private part; this JWK has none. Use \
             public_pem_from_jwk for the public half"
                .into(),
        ));
    }
    let key = super::convert::jwk_to_software_key(jwk)?;
    let der = key.export_private()?;
    encode(LABEL_PRIVATE, &pkcs8_portable_form(&der)?)
}

/// Re-encode a PKCS#8 private key as `PrivateKeyInfo` (version 0) when it came out as
/// `OneAsymmetricKey` (version 1).
///
/// The backend's Ed25519 export carries the public key as an `OneAsymmetricKey` attribute,
/// which makes the file version 1. That is legal (RFC 5958 §2), and OpenSSL reads it — but
/// `cryptography` refuses it outright, and a private key file that one popular library
/// cannot parse is a key the user has lost. The attribute is redundant: the public key is
/// computed from the seed, which is why the structure marks it OPTIONAL. Dropping it and
/// going back to version 0 loses nothing and is what every peer emits for these keys.
///
/// Keys that already have no attribute — RSA and the EC curves — pass through untouched,
/// byte for byte.
fn pkcs8_portable_form(der: &[u8]) -> Result<Vec<u8>> {
    use pkcs8::der::{Decode, Encode};
    let info = pkcs8::PrivateKeyInfo::from_der(der).map_err(|e| {
        JoseError::Key(format!(
            "PKCS#8 export from the backend did not parse: {e:?}"
        ))
    })?;
    if info.public_key.is_none() {
        return Ok(der.to_vec());
    }
    let slim = pkcs8::PrivateKeyInfo {
        algorithm: info.algorithm,
        private_key: info.private_key,
        public_key: None,
    };
    slim.to_der()
        .map_err(|e| JoseError::Key(format!("PKCS#8 re-encoding failed: {e:?}")))
}

/// Export the public half of a [`Jwk`] as an SPKI `PUBLIC KEY` PEM document.
///
/// Works on a private JWK too — exporting the public component is not a disclosure — but
/// it can never emit a `PRIVATE KEY` block, whatever it is given.
///
/// `OKP`/`X25519` is refused: this backend represents an X25519 public key as its bare
/// 32-octet `u` coordinate, and dressing raw bytes up with a hand-made SPKI wrapper would
/// write a file that announces a format it does not have. Ed25519 has a real SPKI encoding
/// and is exported normally — the distinction is the curve, not the `kty`.
///
/// # Errors
///
/// [`JoseError::Key`] for a key type with no SPKI representation (X25519, DH, composite
/// post-quantum keys), and the usual conversion errors.
pub fn public_pem_from_jwk(jwk: &Jwk) -> Result<String> {
    if let Some(refusal) = spki_refusal(jwk) {
        return Err(JoseError::Key(refusal));
    }
    let key = super::convert::jwk_to_software_key(jwk)?;
    let der = key.export_spki_der()?;
    encode(LABEL_PUBLIC, &der)
}

/// Why this key has no SPKI encoding, if it has none.
///
/// Decided from the key material rather than by asking the backend and paraphrasing its
/// failure afterwards: an unsupported export must not be discovered halfway through
/// writing a file, and "OKP" is not one answer — Ed25519 exports cleanly and X25519
/// cannot.
fn spki_refusal(jwk: &Jwk) -> Option<String> {
    let crv = jwk.crv.as_deref().unwrap_or("");
    match (jwk.kty.as_str(), crv) {
        // Raw-coordinate key types: the "public key" *is* the coordinate, with no algorithm
        // identifier and no DER structure around it.
        ("OKP", crv) if crv != "Ed25519" => Some(format!(
            "{crv} public keys have no SPKI encoding in this backend — the public value is a \
             bare coordinate, and wrapping it in a hand-made SPKI header would produce a file \
             that claims a structure it does not have"
        )),
        _ => None,
    }
}

/// Whether this JWK carries a private part.
///
/// Written as a field test rather than by attempting a conversion, so the error a caller
/// gets is "this key has no private part" instead of a conversion failure that mentions
/// whichever component happened to be missing first.
fn has_private_material(jwk: &Jwk) -> bool {
    match jwk.kty.as_str() {
        "RSA" | "EC" | "OKP" => jwk.d.is_some(),
        "oct" => jwk.k.is_some(),
        _ => false,
    }
}

/// The refusal for a label this crate recognizes but does not parse.
fn unsupported_label(label: &str) -> JoseError {
    match KNOWN_BUT_UNSUPPORTED
        .iter()
        .find(|(known, _)| *known == label)
    {
        Some((known, reason)) => JoseError::InvalidToken(format!(
            "PEM block \"{known}\" is {reason}; this crate reads \"{LABEL_PRIVATE}\" \
             (PKCS#8) and \"{LABEL_PUBLIC}\" (SPKI)"
        )),
        None => JoseError::InvalidToken(format!(
            "unrecognized PEM block \"{label}\"; this crate reads \"{LABEL_PRIVATE}\" \
             (PKCS#8) and \"{LABEL_PUBLIC}\" (SPKI)"
        )),
    }
}

/// Read one RFC 7468 armor block into its label and DER body.
///
/// The armor-level rules live here so all three import entry points share them; only the
/// label dispatch differs between them.
fn decompose(text: &str) -> Result<(&str, Vec<u8>)> {
    // Bound the input before parsing anything, as everywhere in this crate: PEM is text,
    // and a 4 GiB "key file" should be refused rather than allocated through.
    crate::ensure_emit_size(text.len())?;

    if let Some(reason) = armor_problem(text) {
        return Err(JoseError::InvalidToken(reason));
    }

    // RFC 7468's strict grammar tolerates no whitespace at all outside the encapsulation
    // boundaries — not even the trailing spaces an editor leaves behind. The policy above
    // already drew the line (whitespace around the block is fine, text is not), so the
    // decoder is handed the trimmed text and its own boundary errors stay meaningful for
    // everything else.
    let (label, der) = pem_rfc7468::decode_vec(text.trim().as_bytes()).map_err(armor_error)?;
    Ok((label, der))
}

/// Armor-level problems this crate refuses that the RFC 7468 decoder does not (or does
/// not explain). Returns the message, or `None` when the text is acceptable to try.
///
/// The two rules here are *stricter* than RFC 7468 on purpose: the grammar allows a
/// preamble, and a decoder that follows it will happily find a key inside an email. What
/// is relaxed relative to the grammar is whitespace around the block, which is an
/// artifact of how files are saved and not a claim about their contents.
fn armor_problem(text: &str) -> Option<String> {
    let begin = "-----BEGIN ";

    // No preamble. RFC 7468 allows text before the boundary; reading a key out of a file
    // that also contains prose is the kind of permissiveness that turns "which key is
    // this?" into a silent decision.
    let first_begin = text.find(begin).ok_or(0);
    let Ok(first_begin) = first_begin else {
        // No BEGIN line at all. Let the decoder produce its own boundary error, which
        // describes the shape that is missing.
        return None;
    };
    if !text[..first_begin].chars().all(char::is_whitespace) {
        return Some(
            "PEM input has text before the -----BEGIN line; this crate reads a key file, not \
             a document containing one"
                .into(),
        );
    }

    // Exactly one block. Counting the BEGIN boundaries is enough: a well-formed document
    // pairs each with an END, and anything else fails later on its own merits.
    let blocks = text.matches(begin).count();
    if blocks > 1 {
        return Some(format!(
            "PEM input contains {blocks} blocks; exactly one key is expected, so say which \
             one by passing one block"
        ));
    }

    // Trailing non-whitespace after the final END. `pem_rfc7468` reports this too, but as
    // a boundary error; naming it keeps a copy-paste accident from reading like corruption.
    if let Some(end_at) = text.rfind("-----END ") {
        let newline = text[end_at..].find('\n').map(|i| end_at + i);
        let tail = match newline {
            Some(after) => &text[after + 1..],
            None => "",
        };
        if !tail.chars().all(char::is_whitespace) {
            return Some(
                "PEM input has text after the -----END line; a key file ends with its key".into(),
            );
        }
    }

    None
}

/// Turn a PEM decoding failure into a message that says what to do about it.
fn armor_error(err: pem_rfc7468::Error) -> JoseError {
    use pem_rfc7468::Error as Pem;
    match err {
        // RFC 1423 headers (`Proc-Type: 4,ENCRYPTED`, `DEK-Info: …`) mean the key is
        // encrypted under a password with OpenSSL's legacy scheme. That is a different
        // operation, with a KDF and a scheme allow-list in front of it, and it is not
        // what this function does — so point at it instead of failing as if the file were
        // corrupt.
        Pem::HeaderDisallowed => JoseError::InvalidToken(
            "PEM headers (Proc-Type / DEK-Info) mark a password-encrypted key in the legacy \
             OpenSSL scheme; this crate does not decrypt that form"
                .into(),
        ),
        other => JoseError::InvalidToken(format!(
            "malformed RFC 7468 PEM input ({other:?}); one base64 block between \
             -----BEGIN and -----END, canonical padding, no text around it"
        )),
    }
}

/// Armor DER as a PEM document, with an RFC 7468 type label.
fn encode(label: &str, der: &[u8]) -> Result<String> {
    pem_rfc7468::encode_string(label, pem_rfc7468::LineEnding::LF, der)
        .map_err(|e| JoseError::Key(format!("PEM encoding failed: {e:?}")))
}
