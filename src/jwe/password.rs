//! Password-based key management (`PBES2-HS256+A128KW`, `PBES2-HS384+A192KW`,
//! `PBES2-HS512+A256KW`, RFC 7518 §4.8) — the input type and the work budget.
//!
//! PBES2 is the one key-management family in RFC 7518 whose key material is not a
//! key: it is a *password*, an human-chosen secret with none of the properties a JWK
//! is assumed to have. That difference is why this module exists separately rather
//! than as another `&[u8]` accepted by the existing entry points.
//!
//! ## Why a distinct type instead of a string or an `oct` JWK
//!
//! The existing paths take `&[u8]` or [`crate::jwk::Jwk`], and both would *work*
//! mechanically: a password is bytes, and `JWK::from_password` is a thing other
//! libraries have shipped. Both would also be wrong, in the same way — they let a
//! caller hand a password to code whose job is to use a key, and the two are not
//! interchangeable in either direction:
//!
//! * a key is high-entropy and is used directly; **a password is low-entropy and is
//!   only ever an input to a key derivation function**. Passing one where a key is
//!   expected means someone, somewhere, uses `k` as a KEK without deriving anything,
//!   which is exactly the mistake PBES2's parameter names exist to prevent;
//! * a JWK carries policy that a password does not have — `alg`, `use`, `key_ops`,
//!   `kid`. A `Jwk` standing in for a password either leaves those empty (so the
//!   pinning checks that protect every other path silently stop applying) or fills
//!   them with something that pretends to be a key policy;
//! * and an `oct` JWK whose `k` holds a password would be *accepted* by the `A128KW`
//!   and `dir` paths too, so the same value would be usable both as a password and as
//!   a raw key — one secret with two completely different security arguments, which
//!   is a confusion, not a convenience.
//!
//! So a password arrives as [`Password`], and only the PBES2 paths accept it. The
//! algorithms that want a key refuse it, and vice versa: the type decides which
//! family a secret can enter, rather than a runtime check hoping the caller meant
//! what the header says.
//!
//! ## Zeroization
//!
//! A password outlives its derived key by design: the caller keeps typing it, and
//! the library derives, wraps and forgets. [`Password`] therefore owns its bytes in
//! [`Zeroizing`], and so does every derived key-encryption key this module produces.
//! The guarantee is deliberately modest — a password in a terminal or a config file
//! is already not secret at rest — but the derived KEK is the value an attacker
//! actually wants, and nothing here leaves it in a plain `Vec`.
//!
//! ## The work budget
//!
//! PBKDF2's iteration count is chosen by the **sender** and paid for by the
//! **recipient**: `p2c` says how much CPU the recipient must spend before it learns
//! whether the password was right. That is an odd asymmetry, and it needs a policy on
//! both ends, which is what the constants below are. [`crate::jwe::JweEncryptOptions`]
//! and [`crate::jwe::JweDecryptOptions`] expose the knobs.
//!
//! The numbers were chosen from measurements, not from precedent; see
//! `crate::jwe::internal::tests::pbes2_work_budget_benchmark`, which is the test that
//! produced them and can re-derive them on other hardware.

use zeroize::Zeroizing;

/// The lowest PBKDF2 iteration count this crate will emit or accept.
///
/// RFC 7518 §4.8.1.2 states "A minimum iteration count of 1000 is RECOMMENDED", so
/// refusing anything below it is the RFC's own floor rather than this crate's
/// opinion, and it costs nothing in interoperability: the peers this crate is tested
/// against emit 2048 (panva) and 8192 (jwcrypto).
///
/// The cryptographic floor is not the point. A count of 1 makes the salt the only
/// thing separating two messages under the same password, which turns PBES2 into
/// "AES-KW with a low-entropy key" — a different, much weaker construction that some
/// peers' history shows them producing when a caller overrides the default.
pub const PBES2_MIN_ITERATIONS: u32 = 1_000;

/// The iteration count used when the caller does not choose one.
///
/// 8 192, and the number is bounded from both sides in a way PBES2 is unusual about:
/// the **sender** chooses it and the **recipient** pays it, so a count is only
/// meaningful if the recipient is willing to do the work.
///
/// On the upper side, real verifiers cap what they will compute rather than let a
/// stranger bill them. panva refuses a `p2c` above 10 000 by default (`maxPBES2Count`,
/// which its source makes configurable), and jwcrypto's `default_max_pbkdf2_iterations`
/// is 16 384. A default of 100 000 — which is what a pure cost-based rule ("about a
/// tenth of a second of recipient work": 31 ms / 105 ms / 155 ms for the three
/// algorithms on the measured machine) would have produced — makes messages that
/// **both** peers refuse to read, which is worse than a slightly cheaper default: the
/// failure is not a refusal to interoperate on a corner case, it is every message this
/// crate emits being undecryptable. So the emit-side default lives inside the
/// intersection of what verifiers accept, 1 000 … 10 000, and does not pretend
/// otherwise.
///
/// Inside that window, 8 192 is four times panva's 2 048 default, equal to jwcrypto's
/// own, eight times the RFC's recommended floor, and costs the recipient at most about
/// 17 ms on the measured machine (2.9 ms / 7.9 ms / 16.6 ms for the three algorithms) —
/// cheap enough that nobody works around it, which is the real failure mode of
/// password-based crypto: an unlock that takes ten seconds gets replaced by a sticky
/// note.
///
/// A caller who controls both ends and wants more work per message can raise it with
/// [`crate::jwe::JweEncryptOptions::with_pbes2_iterations`], and should know from this
/// comment that they are spending someone's CPU.
pub const PBES2_DEFAULT_ITERATIONS: u32 = 8_192;

/// The highest PBKDF2 iteration count accepted by default when *reading*.
///
/// The sender picks this number and the recipient pays it, so an unbounded accepted
/// count is a one-message denial-of-service: a peer can name 100 000 000 iterations
/// (the backend's own ceiling) and make a receiver burn minutes of CPU per message
/// before the AES-KW integrity check says the password was wrong anyway.
///
/// The default is a per-message budget of about a second on the measured machine
/// (163 ms / 983 ms / 909 ms for the three algorithms) — enough headroom for a sender
/// who chose a count well above ours, tight enough that the worst case a peer can
/// impose is a pause rather than a stall.
///
/// It is deliberately **far above** [`PBES2_DEFAULT_ITERATIONS`], and the asymmetry is
/// the point: what we emit is limited by what other implementations are willing to
/// compute, while what we accept is limited only by our own patience. Refusing a
/// message because its sender was more careful than our default would be self-harm. Lower it with
/// [`crate::jwe::JweDecryptOptions::with_pbes2_max_iterations`] where latency matters;
/// raising it is a decision about how much CPU to let a stranger bill to this process,
/// which is why it takes an explicit call rather than a config default.
///
/// A caller that tries several passwords in a loop pays this per attempt. This crate
/// reads exactly one recipient element per PBES2 message, so a message cannot
/// multiply the cost; a keyring search can, and the caller bounds that loop.
pub const PBES2_DEFAULT_MAX_ITERATIONS: u32 = 1_000_000;

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
