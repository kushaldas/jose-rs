//! RFC 8037 / RFC 8410 format glue. All Ed448 arithmetic stays in kryptering.
use super::Jwk;
use crate::{base64url, JoseError, Result};
use pkcs8::der::{
    asn1::{BitStringRef, OctetStringRef},
    Decode, Encode,
};
use pkcs8::spki::{AlgorithmIdentifierRef, SubjectPublicKeyInfoRef};
use zeroize::Zeroizing;

pub(crate) const OID: pkcs8::ObjectIdentifier = pkcs8::ObjectIdentifier::new_unwrap("1.3.101.113");
const ALGORITHM: AlgorithmIdentifierRef<'static> = AlgorithmIdentifierRef {
    oid: OID,
    parameters: None,
};

fn encoding_error(error: impl std::fmt::Display) -> JoseError {
    JoseError::Key(format!("invalid Ed448 key encoding: {error}"))
}

fn encode_secret(value: &impl Encode) -> Result<Zeroizing<Vec<u8>>> {
    let len =
        usize::try_from(value.encoded_len().map_err(encoding_error)?).map_err(encoding_error)?;
    let mut output = Zeroizing::new(vec![0; len]);
    value.encode_to_slice(&mut output).map_err(encoding_error)?;
    Ok(output)
}

pub(crate) fn from_seed(seed: &[u8]) -> Result<kryptering::SoftwareKey> {
    if seed.len() != 57 {
        return Err(JoseError::Key("Ed448 private key must be 57 bytes".into()));
    }
    // RFC 8410 §7: privateKey wraps a CurvePrivateKey OCTET STRING. This is
    // format encoding, not a local implementation of key derivation.
    let inner = encode_secret(&OctetStringRef::new(seed).map_err(encoding_error)?)?;
    let info = pkcs8::PrivateKeyInfoRef::new(
        ALGORITHM,
        OctetStringRef::new(&inner).map_err(encoding_error)?,
    );
    let der = encode_secret(&info)?;
    kryptering::SoftwareKey::from_pkcs8_der(kryptering::KeyAlgorithm::Ed448, &der)
        .map_err(Into::into)
}

pub(crate) fn from_jwk(jwk: &Jwk) -> Result<kryptering::SoftwareKey> {
    let x = jwk
        .x
        .as_deref()
        .ok_or_else(|| JoseError::Key("missing x for Ed448".into()))?;
    // Bound decoding before allocation, including attacker-controlled private material.
    if x.len() != 76 {
        return Err(JoseError::Key("Ed448 public key must be 57 bytes".into()));
    }
    let public = base64url::decode(x)?;
    let spki = SubjectPublicKeyInfoRef {
        algorithm: ALGORITHM,
        subject_public_key: BitStringRef::from_bytes(&public).map_err(encoding_error)?,
    }
    .to_der()
    .map_err(encoding_error)?;
    let public_key =
        kryptering::SoftwareKey::from_spki_der(kryptering::KeyAlgorithm::Ed448, &spki)?;
    if let Some(d) = jwk.d.as_deref() {
        if d.len() != 76 {
            return Err(JoseError::Key("Ed448 private key must be 57 bytes".into()));
        }
        let seed = Zeroizing::new(base64url::decode(d)?);
        let private = from_seed(&seed)?;
        // RFC 8037 §2: the independently supplied public and private fields
        // must describe one key, preventing key-substitution on import.
        if private.export_spki_der()? != public_key.export_spki_der()? {
            return Err(JoseError::Key(
                "Ed448 private key d does not match the public key x".into(),
            ));
        }
        Ok(private)
    } else {
        Ok(public_key)
    }
}

pub(crate) fn to_jwk(key: &kryptering::SoftwareKey) -> Result<Jwk> {
    let der = key.export_spki_der()?;
    let info = SubjectPublicKeyInfoRef::from_der(&der).map_err(encoding_error)?;
    let public = info
        .subject_public_key
        .as_bytes()
        .ok_or_else(|| JoseError::Key("Ed448 public key is not byte-aligned".into()))?;
    let mut jwk = super::convert::new_jwk("OKP");
    jwk.crv = Some("Ed448".into());
    jwk.x = Some(base64url::encode(public));
    if key.has_private_key() {
        let der = key.export_private()?;
        let info = pkcs8::PrivateKeyInfoRef::from_der(&der).map_err(encoding_error)?;
        let seed =
            <&OctetStringRef>::from_der(info.private_key.as_bytes()).map_err(encoding_error)?;
        if seed.as_bytes().len() != 57 {
            return Err(JoseError::Key(
                "Ed448 backend exported an invalid private seed".into(),
            ));
        }
        jwk.d = Some(base64url::encode(seed.as_bytes()));
    }
    Ok(jwk)
}
