//! A password, owned, zeroized, and distinguishable from a key at compile time.
//!
//! Two features in this crate take a password rather than a key, for the same reason:
//! PBES2 JWE key management (RFC 7518 §4.8, [`crate::jwe`]) and password-encrypted
//! PKCS#8 key files (RFC 5958, [`crate::jwk`]). Both derive a key from it, and neither
//! can accept a key in its place.
//!
//! A password outlives its derived key by design: the caller keeps typing it, and the
//! library derives, uses and forgets. [`Password`] owns its bytes in [`Zeroizing`], and
//! so does every derived value built from it. The guarantee is deliberately modest — a
//! password in a terminal or a config file is already not secret at rest — but the
//! derived value is the thing an attacker actually wants, and nothing here leaves it in
//! a plain `Vec`.
//!
//! The iteration-count constants are *not* here: they belong to the scheme that uses
//! them ([`PBES2_MIN_ITERATIONS`](crate::jwe::password::PBES2_MIN_ITERATIONS) and
//! friends for PBES2, [`PKCS8_MIN_ITERATIONS`](crate::jwk::PKCS8_MIN_ITERATIONS) for
//! PKCS#8), and they differ because the two schemes have different ecosystems and
//! different senders choosing the work.

use zeroize::Zeroizing;

/// A password, owned, zeroized, and distinguishable from a key at compile time.
///
/// RFC 7518 §4.8 defines the PBES2 password input as an octet sequence, and requires
/// that a password "represented as a text string" be UTF-8 encoded to get those
/// octets. Both forms are real — a human types text, an export file holds bytes — and
/// they are given separate constructors so the encoding decision is visible at the
/// call site rather than implicit in whichever `Into` happened to apply.
///
/// Two properties are worth knowing before using it:
///
/// * **Whitespace and non-ASCII are preserved exactly.** Normalizing, trimming or
///   case-folding a password is the caller's business and usually a bug: RFC 7520's
///   own PBES2 example password contains U+2013 EN DASH twice, and the recipient must
///   derive over the same octets the sender did.
/// * **It is not compared.** Nothing here offers equality; the password is fed to
///   PBKDF2 and the AES-KW integrity check on the wrapped key decides whether it was
///   right. A `PartialEq` on a secret invites the constant-time mistake.
///
/// # Examples
///
/// ```
/// use jose_rs::jwe::Password;
///
/// // Text, encoded as RFC 7518 §4.8 requires.
/// let password = Password::from_utf8("entrap\u{2013}peter_long\u{2013}credit_tun");
/// // Raw octets, exactly as supplied.
/// let from_bytes = Password::from_bytes(b"\x00\x01\x02password".as_slice());
/// // The characters are preserved, and the non-ASCII ones travel as their UTF-8
/// // octets — which is what a recipient has to reproduce byte for byte.
/// assert!(password.as_ref().windows(3).any(|w| w == [0xe2, 0x80, 0x93]));
/// assert_eq!(from_bytes.as_ref(), b"\x00\x01\x02password");
/// ```
#[derive(Clone)]
pub struct Password {
    secret: Zeroizing<Vec<u8>>,
}

impl Password {
    /// A password given as text, using the UTF-8 encoding RFC 7518 §4.8 mandates.
    ///
    /// No normalization, trimming or case folding is applied — the octets are exactly
    /// the string's UTF-8 bytes.
    pub fn from_utf8(text: &str) -> Self {
        Self {
            secret: Zeroizing::new(text.as_bytes().to_vec()),
        }
    }

    /// A password given as an octet sequence, used verbatim.
    ///
    /// This is the form RFC 7518 §4.8 calls the "octet sequence" input. Use
    /// [`Password::from_utf8`] when the password is text, so the encoding step is
    /// written down rather than assumed.
    pub fn from_bytes(bytes: impl AsRef<[u8]>) -> Self {
        Self {
            secret: Zeroizing::new(bytes.as_ref().to_vec()),
        }
    }

    /// Whether this is the empty password.
    ///
    /// Emitting with an empty password is refused: an unset secret looks exactly like
    /// an empty one, and PBES2 with `""` is a configuration bug far more often than a
    /// deliberate choice. Reading is *not* refused on this ground — a peer's message
    /// is not refused for the shape of its secret, and a wrong password fails the
    /// wrapped key's integrity check in the end anyway.
    pub fn is_empty(&self) -> bool {
        self.secret.is_empty()
    }

    /// The password's octets.
    ///
    /// `pub(crate)` on the field, and this accessor exists for the derivation code:
    /// nothing in the public API returns the bytes, and the type deliberately has no
    /// `Deref<Target = [u8]>` that would let one be read out by accident.
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.secret
    }
}

impl AsRef<[u8]> for Password {
    fn as_ref(&self) -> &[u8] {
        &self.secret
    }
}

impl From<&str> for Password {
    /// Text in, UTF-8 octets out — the encoding RFC 7518 §4.8 requires for a
    /// password "represented as a text string".
    fn from(text: &str) -> Self {
        Password::from_utf8(text)
    }
}

impl From<String> for Password {
    fn from(text: String) -> Self {
        Password::from_utf8(&text)
    }
}

/// `Debug` says how long the secret is and nothing else.
///
/// Length is kept because it is the diagnostic that matters ("the config file read an
/// empty password"), and it is not itself sensitive.
impl std::fmt::Debug for Password {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Password({} octets, redacted)", self.secret.len())
    }
}
