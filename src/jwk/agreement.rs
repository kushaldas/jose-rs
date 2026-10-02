//! The key-agreement boundary: turning a JWK into something that can perform
//! ECDH, and nothing else (ADR 0016).
//!
//! Key agreement is a different operation from signing or key wrapping, and the
//! difference is not cosmetic:
//!
//! * an agreement **needs a private scalar**, but never sends or verifies
//!   anything — so `use`/`key_ops` must say *derive*, not *sign*;
//! * it is *two-party*: one's own key and a **peer** key, which for
//!   `ECDH-ES` arrives inside the message (`epk`) as attacker-chosen bytes;
//! * the curve is part of the identity of the operation. A P-256 secret
//!   multiplied against a P-384 point is either an error or, in a lax
//!   implementation, a silently different shared secret.
//!
//! So this module hands out two distinct types instead of a `SoftwareKey` and a
//! wish: [`AgreementKey`] (own key, private material enforced) and [`PeerKey`]
//! (public material only, point validated), and [`AgreementKey::agree`] refuses
//! a peer on a different curve.
//!
//! ```
//! use jose_rs::jwk::agreement::{agreement_key, peer_key};
//! use jose_rs::jwk::Jwk;
//!
//! let own: Jwk = serde_json::from_value(serde_json::json!({
//!     "kty": "EC", "crv": "P-256",
//!     "x": "weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ",
//!     "y": "e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck",
//!     "d": "VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw",
//!     "key_ops": ["deriveKey"],
//! })).unwrap();
//! let peer: Jwk = serde_json::from_value(serde_json::json!({
//!     "kty": "EC", "crv": "P-256",
//!     "x": "gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0",
//!     "y": "SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps",
//! })).unwrap();
//!
//! let own = agreement_key(&own).unwrap();
//! let peer = peer_key(&peer).unwrap();
//!
//! // The two halves are consumed by `derive_key`, which runs JOSE's Concat KDF
//! // so the shared secret never has to be handled as a key. These are RFC 7518
//! // Appendix C's own keys and expected output.
//! let cek = own
//!     .derive_key(&peer, "A128GCM", Some("QWxpY2U"), Some("Qm9i"), 16)
//!     .unwrap();
//! assert_eq!(jose_rs::base64url::encode(&cek), "VqqN6vgjbSBcIijNcacQGg");
//! ```

use zeroize::Zeroizing;

use crate::error::{JoseError, Result};
use crate::jwk::Jwk;

/// The curves this crate can perform key agreement on.
///
/// The list is deliberately short and it is a *type*, not a string: an
/// unsupported `crv` (X448, Brainpool, secp256k1) is refused here, at the
/// boundary, rather than becoming a downstream crypto error — or worse, being
/// silently reinterpreted as another curve.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AgreementCurve {
    /// NIST P-256 (`crv`: `P-256`).
    P256,
    /// NIST P-384 (`crv`: `P-384`).
    P384,
    /// NIST P-521 (`crv`: `P-521`).
    P521,
}

impl AgreementCurve {
    /// Coordinate length in bytes.
    #[must_use]
    pub fn coord_len(self) -> usize {
        match self {
            Self::P256 => 32,
            Self::P384 => 48,
            Self::P521 => 66,
        }
    }

    /// The backend curve.
    fn kryptering_curve(self) -> kryptering::EcCurve {
        match self {
            Self::P256 => kryptering::EcCurve::P256,
            Self::P384 => kryptering::EcCurve::P384,
            Self::P521 => kryptering::EcCurve::P521,
        }
    }

    /// Read `kty`/`crv` and reject every curve this crate cannot agree on.
    ///
    /// Curves are named explicitly rather than lumped into one message: an OKP
    /// key is not automatically an agreement key, and a signing curve arriving
    /// at this boundary is a mistake worth a specific error.
    fn from_jwk(jwk: &Jwk) -> Result<Self> {
        match (jwk.kty.as_str(), jwk.crv.as_deref()) {
            ("EC", Some("P-256")) => Ok(Self::P256),
            ("EC", Some("P-384")) => Ok(Self::P384),
            ("EC", Some("P-521")) => Ok(Self::P521),
            // Named separately from the signing curves, because it *is* an
            // agreement curve — the backend can do X25519 — but a JWK whose
            // `d` is an X25519 scalar cannot be imported yet, and importing it
            // without checking that `d` really derives `x` would let a JWK
            // publish one identity and agree with another.
            ("OKP", Some("X25519")) => Err(JoseError::Key(
                "X25519 agreement keys are not supported by this crate version".into(),
            )),
            ("OKP", Some(other)) => Err(JoseError::Key(format!(
                "OKP curve {other} is a signing curve, not a key-agreement curve"
            ))),
            ("EC", Some(other)) => Err(JoseError::Key(format!(
                "EC curve {other} is not supported for key agreement by this backend"
            ))),
            ("EC", None) => Err(JoseError::Key("missing crv for EC key".into())),
            (kty, _) => Err(JoseError::Key(format!(
                "kty {kty} cannot perform key agreement; expected EC or OKP"
            ))),
        }
    }
}

/// Key-management algorithms that use an agreement key, by `alg` value.
const AGREEMENT_ALGS: &[&str] = &[
    "ECDH-ES",
    "ECDH-ES+A128KW",
    "ECDH-ES+A192KW",
    "ECDH-ES+A256KW",
];

/// Own half of a key-agreement operation: a private scalar on a known curve.
#[derive(Debug, Clone)]
pub struct AgreementKey {
    key: kryptering::SoftwareKey,
    curve: AgreementCurve,
    /// This key's own public value in the encoding agreement expects:
    /// uncompressed SEC1 (`0x04 || X || Y`). Carried because a sender has to
    /// publish it as the `epk` member.
    public: Vec<u8>,
}

impl AgreementKey {
    /// The curve this key is on.
    #[must_use]
    pub fn curve(&self) -> AgreementCurve {
        self.curve
    }

    /// This key's public value, in the agreement encoding (needed to publish an
    /// ephemeral key as `epk`).
    #[must_use]
    pub fn public_bytes(&self) -> &[u8] {
        &self.public
    }

    /// Agree with `peer` and derive a key of `key_len` octets, in one step.
    ///
    /// This is the entry point everything should use: the raw shared secret
    /// never becomes a value the caller can hold, mis-handle, or use as a key.
    /// The derivation is JOSE's Concat KDF (RFC 7518 §4.6.2) with SHA-256 and
    /// the RFC's length-prefixed `OtherInfo`, so the result matches what every
    /// conformant implementation computes for the same inputs — including the
    /// RFC's own Appendix C vector, which the tests assert.
    ///
    /// `alg_id` is the ASCII `enc` value for direct key agreement and the ASCII
    /// `alg` value for key agreement with key wrapping; `apu` / `apv` are the
    /// base64url header values, if present.
    ///
    /// # Errors
    ///
    /// [`JoseError::Key`] for a curve mismatch or a rejected peer point,
    /// [`JoseError::InvalidHeader`] for a non-canonical or duplicated
    /// `apu`/`apv`, [`JoseError::Crypto`] if a primitive fails.
    pub fn derive_key(
        &self,
        peer: &PeerKey,
        alg_id: &str,
        apu: Option<&str>,
        apv: Option<&str>,
        key_len: usize,
    ) -> Result<Zeroizing<Vec<u8>>> {
        let z = self.agree(peer)?;
        crate::jwe::internal::concat_kdf(z.as_slice(), key_len, alg_id, apu, apv)
    }

    /// Perform agreement against `peer`, returning the raw shared secret `Z`.
    ///
    /// **`Z` is never a key.** It is the direct output of the scalar
    /// multiplication: biased, related to the peer's public value, and used
    /// directly by no JOSE algorithm — every JOSE key-management mode passes it
    /// through the Concat KDF first. Derive; do not consume this directly.
    ///
    /// # Errors
    ///
    /// [`JoseError::Key`] when the peer is on a different curve, or when the
    /// backend rejects the peer point or the agreement itself fails.
    pub fn agree(&self, peer: &PeerKey) -> Result<Zeroizing<Vec<u8>>> {
        if self.curve != peer.curve() {
            return Err(JoseError::Key(format!(
                "key agreement curve mismatch: own key is {:?}, peer is {:?}",
                self.curve,
                peer.curve()
            )));
        }
        let z = kryptering::software::keyagreement::agree(
            self.curve.kryptering_curve(),
            &peer.encoded,
            &self.key,
        )
        .map_err(JoseError::Crypto)?;
        if z.len() != self.curve.coord_len() {
            return Err(JoseError::Key(format!(
                "key agreement returned {} bytes, expected {} for {:?}",
                z.len(),
                self.curve.coord_len(),
                self.curve
            )));
        }
        Ok(Zeroizing::new(z))
    }
}

/// Peer half of a key-agreement operation: public material only, on a known
/// curve, with the point validated.
#[derive(Debug, Clone)]
pub struct PeerKey {
    curve: AgreementCurve,
    /// Uncompressed SEC1 point, `0x04 || X || Y`.
    encoded: Vec<u8>,
}

impl PeerKey {
    /// The curve the peer claims.
    #[must_use]
    pub fn curve(&self) -> AgreementCurve {
        self.curve
    }

    /// The peer's encoded public value.
    #[must_use]
    pub fn public_bytes(&self) -> &[u8] {
        &self.encoded
    }
}

/// Prepare a JWK as one's own key for key agreement.
///
/// Checks, in order: the key type and curve are agreement-capable; `use` and
/// `key_ops` permit `deriveKey` (RFC 7517 §4.3 — a key pinned to `sign` is not
/// an agreement key); an `alg` present on the key names a key-agreement
/// algorithm; and private material is present. Material validity (point on
/// curve, `d` consistent with `(x, y)`) is enforced by
/// [`crate::jwk::jwk_to_software_key`], which is also what stops a JWK from
/// publishing one identity while agreeing with another.
///
/// # Errors
///
/// [`JoseError::Key`] for any of the rejections above.
pub fn agreement_key(jwk: &Jwk) -> Result<AgreementKey> {
    let curve = AgreementCurve::from_jwk(jwk)?;
    // RFC 7517 §4.3: `deriveKey` is the operation an agreement key performs.
    // `use: "sig"` fails the category check, and a `key_ops` list that omits
    // `deriveKey` fails independently, so a key marked for signing cannot reach
    // the crypto layer by this route.
    jwk.check_op(crate::jwk::JwkOp::DeriveKey)?;
    if let Some(alg) = jwk.alg.as_deref() {
        if !AGREEMENT_ALGS.contains(&alg) {
            return Err(JoseError::Key(format!(
                "JWK alg {alg} is not a key-agreement algorithm; this key cannot be used for \
                 ECDH-ES (supported: {})",
                AGREEMENT_ALGS.join(", ")
            )));
        }
    }
    let key = crate::jwk::jwk_to_software_key(jwk)?;
    if !key.has_private_key() {
        return Err(JoseError::Key(
            "key agreement requires the private scalar; a public-only JWK is a peer key, not \
             an agreement key"
                .into(),
        ));
    }
    let public = encode_public(curve, jwk)?;
    Ok(AgreementKey { key, curve, public })
}

/// Prepare a JWK as the **peer** half of a key agreement.
///
/// The peer's key is data, not an identity: for `ECDH-ES` it is the `epk`
/// member of a message somebody chose. So no `use`/`key_ops`/`alg` check is
/// applied — the peer's own policy is nobody's business but its own — while two
/// things *are* enforced:
///
/// * **no private material**: an `epk` carrying `d` is a protocol error, and
///   accepting it would let a producer hand over a "public" key that something
///   else already knows the secret of;
/// * **a valid point on the named curve**, obtained by building the backend key
///   (which validates the point and the coordinate sizes) rather than by
///   trusting the coordinates' byte lengths.
///
/// Agreeing with an arbitrary, unauthenticated ephemeral key is exactly what
/// direct key agreement means, and it is why `ECDH-ES` authenticates *nothing*
/// about the sender (ADR 0016). The result of that agreement is only ever
/// consumable through the KDF, and the message still has to authenticate its
/// own content.
///
/// # Errors
///
/// [`JoseError::Key`] when the key type or curve is not agreement-capable, when
/// private material is present, or when the public value is not a valid point.
pub fn peer_key(jwk: &Jwk) -> Result<PeerKey> {
    let curve = AgreementCurve::from_jwk(jwk)?;
    if jwk.d.is_some() {
        return Err(JoseError::Key(
            "a peer key must carry public material only; the JWK has a private component `d`"
                .into(),
        ));
    }
    // Building the backend key is the point validation: `jwk_to_software_key`
    // rejects an off-curve or mismatched-length point before it produces
    // anything usable.
    crate::jwk::jwk_to_software_key(jwk)?;
    let encoded = encode_public(curve, jwk)?;
    Ok(PeerKey { curve, encoded })
}

/// Encode a JWK's public value as an uncompressed SEC1 point, `0x04 || X || Y`,
/// which is what the backend's agreement functions take.
///
/// Left-padding is applied to the coordinates (a JWK may omit leading zero
/// octets); [`crate::jwk::jwk_to_software_key`] has already rejected anything
/// longer than the field.
fn encode_public(curve: AgreementCurve, jwk: &Jwk) -> Result<Vec<u8>> {
    let coord_len = curve.coord_len();
    let x = coordinate(jwk, "x", coord_len)?;
    let y = coordinate(jwk, "y", coord_len)?;
    let mut point = Vec::with_capacity(1 + 2 * coord_len);
    point.push(0x04);
    point.extend_from_slice(&x);
    point.extend_from_slice(&y);
    Ok(point)
}

/// One base64url coordinate (`x` or `y`), left-padded to `coord_len`.
///
/// A JWK may legitimately omit leading zero octets, so short is fine and padded;
/// longer than the field is not. Coordinate *validity* (on-curve, consistent
/// with `d`) is enforced by the backend key import, not here.
fn coordinate(jwk: &Jwk, name: &str, coord_len: usize) -> Result<Vec<u8>> {
    let value = match name {
        "x" => jwk.x.as_deref(),
        "y" => jwk.y.as_deref(),
        _ => None,
    }
    .ok_or_else(|| JoseError::Key(format!("missing {name} for an agreement key")))?;
    let bytes = crate::base64url::decode(value)?;
    if bytes.len() > coord_len {
        return Err(JoseError::Key(format!(
            "{name} is {} octets, longer than the {coord_len}-octet field",
            bytes.len()
        )));
    }
    let mut padded = vec![0u8; coord_len - bytes.len()];
    padded.extend_from_slice(&bytes);
    Ok(padded)
}
