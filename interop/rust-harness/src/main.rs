//! jose-interop — JSON-over-stdio CLI wrapper around jose-rs.
//!
//! Mirrors the subcommand surface exposed by `interop/js-harness/index.mjs`
//! so the orchestrator script can pipe output from one side into the other.
//!
//! Subcommands:
//!   gen-key        --alg <ALG> [--enc <ENC>] (stdin: -)      -> private JWK
//!       (JWE: --alg A128KW|A192KW|A256KW|A128GCMKW|..., or --alg dir --enc <ENC>)
//!   export-pub                             (stdin: private JWK) -> public JWK
//!   sign-compact   --alg <ALG>            (stdin: {jwk, payload_b64u, header?}) -> {jws}
//!   verify-compact --alg <ALG>            (stdin: {jwk, jws}) -> {ok, payload_b64u, protected_header}
//!   sign-compact-raw --alg <ALG>          (stdin: {jwk, header_raw, payload_b64u}) -> {jws}
//!       Signs over the caller's *exact* protected-header bytes, bypassing
//!       JoseHeader serialization. Used only to mint negative vectors (e.g. a
//!       header with a duplicated member) that jose-rs's API cannot emit.
//!   encrypt-compact --alg <ALG> --enc <ENC> (stdin: {jwk, plaintext_b64u, header?}) -> {jwe}
//!   decrypt-compact --alg <ALG> --enc <ENC> (stdin: {jwk, jwe}) -> {ok, plaintext_b64u, protected_header}
//!   encrypt-flattened --alg <ALG> --enc <ENC> (stdin: {jwk, plaintext_b64u, header?}) -> {jwe}
//!       Like encrypt-compact but emits the RFC 7516 §7.2.2 flattened JSON
//!       Serialization, as a JSON *string* in `jwe` (so the matrix plumbing is
//!       identical for both formats).
//!   decrypt-flattened --alg <ALG> --enc <ENC> (stdin: {jwk, jwe, aad_b64u?}) -> {ok, plaintext_b64u, protected_header}
//!       `jwe` is the flattened JSON Serialization text. Both flattened
//!       commands accept an optional `aad_b64u` (external additional
//!       authenticated data, RFC 7516 §7.2.1).
//!   encrypt-general  --alg <ALG> --enc <ENC> (stdin: {jwks, plaintext_b64u, header?, aad_b64u?}) -> {jwe}
//!       RFC 7516 §7.2.1 general JSON Serialization, one recipient per entry of
//!       `jwks`; `jwe` is again a JSON string.
//!   decrypt-general  --alg <ALG> --enc <ENC> (stdin: {jwk, jwe, recipient?, aad_b64u?}) -> {ok, plaintext_b64u, recipient, protected_header, unprotected_header, recipient_count}
//!       `recipient` names the array element to open; without it the harness
//!       resolves the element from the key's own `kid`, which is what
//!       `decrypt_general_with_jwk_by_kid` does.
//!   sign-jwt       --alg <ALG>            (stdin: {jwk, claims}) -> JWT
//!   verify-jwt     --alg <ALG>            (stdin: {jwk, jwt}) -> {ok, claims}
//!
//! All I/O is JSON on stdin/stdout; human-readable errors go to stderr and
//! the process exits non-zero on failure.

use anyhow::{anyhow, bail, Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use jose_rs::algorithm::{JweAlgorithm, JweEncryption, JwsAlgorithm};
use jose_rs::jwk::agreement::{agreement_key, peer_key};
use jose_rs::jwk::Jwk;
use jose_rs::jwt::{Claims, Validation};
use jose_rs::JoseHeader;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::io::{Read, Write};

fn main() {
    if let Err(e) = run() {
        eprintln!("jose-interop: {e:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let raw: Vec<String> = std::env::args().skip(1).collect();
    let cmd = raw
        .first()
        .ok_or_else(|| anyhow!("missing subcommand"))?
        .clone();
    let mut alg: Option<String> = None;
    let mut enc: Option<String> = None;
    let mut crv: Option<String> = None;
    let mut i = 1;
    while i < raw.len() {
        let a = &raw[i];
        if let Some(rest) = a.strip_prefix("--alg=") {
            alg = Some(rest.to_string());
            i += 1;
        } else if a == "--alg" {
            alg = raw.get(i + 1).cloned();
            i += 2;
        } else if let Some(rest) = a.strip_prefix("--enc=") {
            enc = Some(rest.to_string());
            i += 1;
        } else if a == "--enc" {
            enc = raw.get(i + 1).cloned();
            i += 2;
        } else if let Some(rest) = a.strip_prefix("--crv=") {
            crv = Some(rest.to_string());
            i += 1;
        } else if a == "--crv" {
            crv = raw.get(i + 1).cloned();
            i += 2;
        } else {
            i += 1;
        }
    }

    match cmd.as_str() {
        "gen-key" => gen_key(&require_alg(alg)?, enc.as_deref(), crv.as_deref()),
        "export-pub" => export_pub(),
        "agree" => agree(),
        "derive-key" => derive_key(),
        "sign-compact" => sign_compact(&require_alg(alg)?),
        "verify-compact" => verify_compact(&require_alg(alg)?),
        "sign-compact-raw" => sign_compact_raw(&require_alg(alg)?),
        "encrypt-compact" => encrypt_compact(&require_alg(alg)?, &require_enc(enc)?),
        "decrypt-compact" => decrypt_compact(&require_alg(alg)?, &require_enc(enc)?),
        "encrypt-flattened" => encrypt_flattened(&require_alg(alg)?, &require_enc(enc)?),
        "decrypt-flattened" => decrypt_flattened(&require_alg(alg)?, &require_enc(enc)?),
        "encrypt-compact-password" => {
            encrypt_compact_password(&require_alg(alg)?, &require_enc(enc)?)
        }
        "decrypt-compact-password" => {
            decrypt_compact_password(&require_alg(alg)?, &require_enc(enc)?)
        }
        "encrypt-general" => encrypt_general(&require_alg(alg)?, &require_enc(enc)?),
        "decrypt-general" => decrypt_general(&require_alg(alg)?, &require_enc(enc)?),
        "sign-jwt" => sign_jwt(&require_alg(alg)?),
        "verify-jwt" => verify_jwt(&require_alg(alg)?),
        other => bail!("unknown subcommand: {other}"),
    }
}

fn require_alg(alg: Option<String>) -> Result<String> {
    alg.ok_or_else(|| anyhow!("--alg is required"))
}

fn require_enc(enc: Option<String>) -> Result<String> {
    enc.ok_or_else(|| anyhow!("--enc is required"))
}

fn read_stdin() -> Result<String> {
    let mut buf = String::new();
    std::io::stdin()
        .read_to_string(&mut buf)
        .context("reading stdin")?;
    Ok(buf)
}

fn emit<T: Serialize>(v: &T) -> Result<()> {
    let s = serde_json::to_string(v)?;
    let stdout = std::io::stdout();
    let mut h = stdout.lock();
    h.write_all(s.as_bytes())?;
    h.write_all(b"\n")?;
    Ok(())
}

fn gen_key(alg: &str, enc: Option<&str>, crv: Option<&str>) -> Result<()> {
    let jwk: Jwk = match alg {
        "A128KW" | "A192KW" | "A256KW" | "A128GCMKW" | "A192GCMKW" | "A256GCMKW" => {
            jose_rs::jwk::generate_symmetric_for_alg(alg)?
        }
        "dir" => {
            let enc = enc.ok_or_else(|| anyhow!("gen-key --alg dir requires --enc"))?;
            // generate_direct_symmetric pins alg="dir" and sizes k to the CEK.
            jose_rs::jwk::generate_direct_symmetric(JweEncryption::from_str(enc)?)?
        }
        "ML-DSA-44" => jose_rs::jwk::generate_mldsa(kryptering::MlDsaVariant::MlDsa44)?,
        "ML-DSA-65" => jose_rs::jwk::generate_mldsa(kryptering::MlDsaVariant::MlDsa65)?,
        "ML-DSA-87" => jose_rs::jwk::generate_mldsa(kryptering::MlDsaVariant::MlDsa87)?,
        "ML-DSA-44-ES256" => {
            jose_rs::jwk::generate_composite_mldsa(kryptering::CompositeMlDsaVariant::MlDsa44Es256)?
        }
        "ML-DSA-65-ES256" => {
            jose_rs::jwk::generate_composite_mldsa(kryptering::CompositeMlDsaVariant::MlDsa65Es256)?
        }
        "ML-DSA-87-ES384" => {
            jose_rs::jwk::generate_composite_mldsa(kryptering::CompositeMlDsaVariant::MlDsa87Es384)?
        }
        "ML-DSA-44-Ed25519" => jose_rs::jwk::generate_composite_mldsa(
            kryptering::CompositeMlDsaVariant::MlDsa44Ed25519,
        )?,
        "ML-DSA-65-Ed25519" => jose_rs::jwk::generate_composite_mldsa(
            kryptering::CompositeMlDsaVariant::MlDsa65Ed25519,
        )?,
        "ML-DSA-87-Ed448" => {
            jose_rs::jwk::generate_composite_mldsa(kryptering::CompositeMlDsaVariant::MlDsa87Ed448)?
        }
        "EdDSA" | "Ed25519" => set_alg(jose_rs::jwk::generate_ed25519()?, alg),
        "ES256" => set_alg(jose_rs::jwk::generate_ec("P-256")?, "ES256"),
        "ES384" => set_alg(jose_rs::jwk::generate_ec("P-384")?, "ES384"),
        // An agreement recipient key: a key pair pinned for one of the ECDH-ES
        // algorithms, with `use: enc` because RFC 7517 §4.2 says a key used for
        // encryption must not claim `sig`. The curve is the caller's choice so one
        // family covers several curves without new cell scaffolding, and the pin is
        // what fixes the key-management mode. X25519 is the one curve whose key type
        // differs (OKP rather than EC), so it needs its own generator.
        "ECDH-ES" | "ECDH-ES+A128KW" | "ECDH-ES+A192KW" | "ECDH-ES+A256KW" => {
            let crv = crv.ok_or_else(|| anyhow!("gen-key --alg {alg} requires --crv"))?;
            let mut jwk = if crv == "X25519" {
                jose_rs::jwk::generate_x25519()?
            } else {
                jose_rs::jwk::generate_ec(crv)?
            };
            jwk.alg = Some(alg.to_string());
            jwk.use_ = Some("enc".to_string());
            jwk
        }
        other => bail!("unsupported alg for gen-key: {other}"),
    };
    emit(&jwk)
}

fn set_alg(mut jwk: Jwk, alg: &str) -> Jwk {
    jwk.alg = Some(alg.to_string());
    jwk
}

fn export_pub() -> Result<()> {
    let raw = read_stdin()?;
    let jwk: Jwk = serde_json::from_str(&raw).context("parsing private JWK from stdin")?;
    let pubj = jwk.to_public_jwk();
    emit(&pubj)
}

#[derive(Deserialize)]
struct AgreementInput {
    /// Own half: must carry the private scalar.
    own_jwk: Jwk,
    /// Peer half: public material only.
    peer_jwk: Jwk,
    /// AlgorithmID for the Concat KDF (ASCII `enc` or `alg` value).
    #[serde(default)]
    alg_id: Option<String>,
    #[serde(default)]
    apu: Option<String>,
    #[serde(default)]
    apv: Option<String>,
    /// Derived key length in octets; required with `alg_id`.
    #[serde(default)]
    key_len: Option<usize>,
}

/// Emit the raw ECDH shared secret `Z` for a key pair.
///
/// This exists so the Python side of the interop suite can compare this
/// crate's agreement against another implementation's — RFC 7518 §C publishes
/// both private keys and the resulting `Z`, so agreement, curve handling and
/// point encoding all become comparable. It is a test probe, not a
/// recommendation: `Z` is never a key, and `derive-key` below is what JOSE
/// actually consumes.
fn agree() -> Result<()> {
    let input: AgreementInput =
        serde_json::from_str(&read_stdin()?).context("parsing agreement input from stdin")?;
    let own = agreement_key(&input.own_jwk).map_err(anyhow::Error::from)?;
    let peer = peer_key(&input.peer_jwk).map_err(anyhow::Error::from)?;
    let z = own.agree(&peer).map_err(anyhow::Error::from)?;
    emit(&json!({
        "z_b64u": URL_SAFE_NO_PAD.encode(z.as_slice()),
        "curve": format!("{:?}", own.curve()),
    }))
}

/// Run the JOSE Concat KDF (RFC 7518 §4.6.2) over an ECDH shared secret.
fn derive_key() -> Result<()> {
    let input: AgreementInput =
        serde_json::from_str(&read_stdin()?).context("parsing derivation input from stdin")?;
    let alg_id = input
        .alg_id
        .as_deref()
        .context("derive-key needs alg_id (the ASCII enc or alg value)")?;
    let key_len = input.key_len.context("derive-key needs key_len (octets)")?;
    let own = agreement_key(&input.own_jwk).map_err(anyhow::Error::from)?;
    let peer = peer_key(&input.peer_jwk).map_err(anyhow::Error::from)?;
    let derived = own
        .derive_key(&peer, alg_id, input.apu.as_deref(), input.apv.as_deref(), key_len)
        .map_err(anyhow::Error::from)?;
    emit(&json!({
        "derived_b64u": URL_SAFE_NO_PAD.encode(derived.as_slice()),
        "curve": format!("{:?}", own.curve()),
    }))
}

#[derive(Deserialize)]
struct SignCompactInput {
    jwk: Jwk,
    #[serde(rename = "payload_b64u")]
    payload_b64u: String,
    /// Optional extra protected-header members (e.g. `kid`, `tenant`).
    /// `alg` is always taken from `--alg`.
    #[serde(default)]
    header: Option<serde_json::Map<String, Value>>,
}

/// Build a `JoseHeader` from `base` (the alg/enc skeleton) plus the caller's
/// optional member object. Typed members (`kid`, `typ`, ...) land in their
/// typed fields and anything else in `extra`, via the same serde path the
/// library uses to parse headers. The caller may not override `alg`/`enc`.
fn build_header(
    base: JoseHeader,
    members: Option<serde_json::Map<String, Value>>,
) -> Result<JoseHeader> {
    let Some(members) = members else {
        return Ok(base);
    };
    let mut obj = match serde_json::to_value(&base)? {
        Value::Object(m) => m,
        _ => bail!("JoseHeader did not serialize to an object"),
    };
    for (k, v) in members {
        if obj.contains_key(&k) {
            bail!("header input must not override `{k}`");
        }
        obj.insert(k, v);
    }
    serde_json::from_value(Value::Object(obj)).context("building protected header")
}

#[derive(Serialize)]
struct SignCompactOutput {
    jws: String,
}

fn sign_compact(alg: &str) -> Result<()> {
    let raw = read_stdin()?;
    let input: SignCompactInput = serde_json::from_str(&raw)?;
    let payload = URL_SAFE_NO_PAD
        .decode(input.payload_b64u.as_bytes())
        .context("decoding payload_b64u")?;
    let header = build_header(JoseHeader::new(alg), input.header)?;
    let jws = jose_rs::jws::compact::sign_with_jwk(&input.jwk, &payload, &header)?;
    emit(&SignCompactOutput { jws })
}

#[derive(Deserialize)]
struct SignCompactRawInput {
    jwk: Jwk,
    /// Exact protected-header JSON text; base64url-encoded verbatim.
    header_raw: String,
    payload_b64u: String,
}

/// Sign a compact JWS over hand-built protected-header bytes.
///
/// jose-rs's public API always serializes a `JoseHeader` and so can never
/// emit a header with a duplicated member. This builds the JWS Signing
/// Input by hand so the matrix can test how each side *parses* such a
/// header. The signature itself is genuine (kryptering SoftwareSigner).
fn sign_compact_raw(alg: &str) -> Result<()> {
    let raw = read_stdin()?;
    let input: SignCompactRawInput = serde_json::from_str(&raw)?;
    // Validate, but keep the payload segment byte-identical to the input.
    URL_SAFE_NO_PAD
        .decode(input.payload_b64u.as_bytes())
        .context("decoding payload_b64u")?;
    let sig_alg = JwsAlgorithm::from_str(alg)?.to_crypto()?;
    let sw_key = jose_rs::jwk::jwk_to_software_key(&input.jwk)?;
    let signer = kryptering::SoftwareSigner::new(sig_alg, sw_key)?;
    let signing_input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(input.header_raw.as_bytes()),
        input.payload_b64u
    );
    let sig = kryptering::Signer::sign(&signer, signing_input.as_bytes())?;
    let jws = format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(sig));
    emit(&SignCompactOutput { jws })
}

#[derive(Deserialize)]
struct VerifyCompactInput {
    jwk: Jwk,
    jws: String,
}

#[derive(Serialize)]
struct VerifyCompactOutput {
    ok: bool,
    #[serde(rename = "payload_b64u")]
    payload_b64u: String,
    /// The protected header as jose-rs parsed it (re-serialized).
    protected_header: JoseHeader,
}

fn verify_compact(alg: &str) -> Result<()> {
    let raw = read_stdin()?;
    let input: VerifyCompactInput = serde_json::from_str(&raw)?;
    // Sanity: the token header must declare the expected alg. This catches
    // matrix wiring bugs before we blame the crypto path.
    let header = jose_rs::jws::compact::decode_header(&input.jws)?;
    if header.alg != alg {
        bail!("token alg {} does not match expected {alg}", header.alg);
    }
    let payload = jose_rs::jws::compact::verify_with_jwk(&input.jwk, &input.jws)?;
    emit(&VerifyCompactOutput {
        ok: true,
        payload_b64u: URL_SAFE_NO_PAD.encode(&payload),
        protected_header: header,
    })
}

#[derive(Deserialize)]
struct SignJwtInput {
    jwk: Jwk,
    claims: Claims,
}

#[derive(Serialize)]
struct SignJwtOutput {
    jwt: String,
}

fn sign_jwt(alg: &str) -> Result<()> {
    let raw = read_stdin()?;
    let input: SignJwtInput = serde_json::from_str(&raw)?;
    let header = JoseHeader::jwt(alg);
    let jwt = jose_rs::jwt::encode_with_jwk(&input.jwk, &header, &input.claims)?;
    emit(&SignJwtOutput { jwt })
}

#[derive(Deserialize)]
struct VerifyJwtInput {
    jwk: Jwk,
    jwt: String,
}

#[derive(Serialize)]
struct VerifyJwtOutput {
    ok: bool,
    claims: Claims,
}

fn verify_jwt(alg: &str) -> Result<()> {
    let raw = read_stdin()?;
    let input: VerifyJwtInput = serde_json::from_str(&raw)?;
    let header = jose_rs::jws::compact::decode_header(&input.jwt)?;
    if header.alg != alg {
        bail!("token alg {} does not match expected {alg}", header.alg);
    }
    // Permissive validation: interop tests care about signature + wire format,
    // not iss/aud/exp. The caller sets whatever claims it wants.
    let validation = Validation::new().with_leeway(300);
    let claims = jose_rs::jwt::decode_with_jwk(&input.jwk, &input.jwt, &validation)?;
    emit(&VerifyJwtOutput { ok: true, claims })
}

#[derive(Deserialize)]
struct EncryptCompactInput {
    jwk: Jwk,
    plaintext_b64u: String,
    /// Optional external AAD (base64url), JSON serialization only.
    #[serde(default)]
    aad_b64u: Option<String>,
    /// Private header parameters the caller implements, licensed to appear in
    /// `crit` (ADR 0015).
    #[serde(default)]
    understood_crit: Option<Vec<String>>,
    /// Optional extra protected-header members (e.g. `kid`, `tenant`).
    /// `alg` / `enc` are always taken from `--alg` / `--enc`.
    #[serde(default)]
    header: Option<serde_json::Map<String, Value>>,
}

#[derive(Serialize)]
struct EncryptCompactOutput {
    jwe: String,
}

fn encrypt_compact(alg: &str, enc: &str) -> Result<()> {
    let raw = read_stdin()?;
    let input: EncryptCompactInput = serde_json::from_str(&raw)?;
    let plaintext = URL_SAFE_NO_PAD
        .decode(input.plaintext_b64u.as_bytes())
        .context("decoding plaintext_b64u")?;
    if input.jwk.alg.as_deref() != Some(alg) {
        bail!("JWK alg {:?} does not match expected {alg}", input.jwk.alg);
    }
    let enc_v = JweEncryption::from_str(enc)?;
    let header = build_header(
        JoseHeader::for_jwe(JweAlgorithm::from_str(alg)?, enc_v),
        input.header,
    )?;
    let jwe = jose_rs::jwe::encrypt_with_jwk_header(&input.jwk, header, &plaintext, enc_v)?;
    emit(&EncryptCompactOutput { jwe })
}

#[derive(Deserialize)]
struct EncryptCompactPasswordInput {
    password: String,
    plaintext_b64u: String,
    #[serde(default)]
    header: Option<serde_json::Map<String, serde_json::Value>>,
    /// PBKDF2 iteration count to publish as `p2c`. Omitted means jose-rs's
    /// default, which is far above the peer defaults and slow in a debug build; the
    /// matrix passes a small value so the cell stays quick.
    #[serde(default)]
    p2c: Option<u32>,
}

#[derive(Deserialize)]
struct DecryptCompactPasswordInput {
    password: String,
    jwe: String,
}

/// Encrypt with a password (RFC 7518 §4.8), compact serialization.
///
/// There is no `gen-key` counterpart: a password is not generated, it is supplied.
/// The matrix therefore fixes one for both sides, exactly as the RFCs fix one for
/// their examples.
fn encrypt_compact_password(alg: &str, enc: &str) -> Result<()> {
    let raw = read_stdin()?;
    let input: EncryptCompactPasswordInput = serde_json::from_str(&raw)?;
    let plaintext = URL_SAFE_NO_PAD
        .decode(input.plaintext_b64u.as_bytes())
        .context("decoding plaintext_b64u")?;
    let enc_v = JweEncryption::from_str(enc)?;
    let alg_v = JweAlgorithm::from_str(alg)?;
    let header = build_header(JoseHeader::for_jwe(alg_v, enc_v), input.header)?;
    let mut opts = jose_rs::jwe::JweEncryptOptions::new();
    if let Some(p2c) = input.p2c {
        opts = opts.with_pbes2_iterations(p2c);
    }
    let jwe = jose_rs::jwe::encrypt_with_password_header_options(
        &jose_rs::jwe::Password::from_utf8(&input.password),
        header,
        &plaintext,
        alg_v,
        enc_v,
        &opts,
    )?;
    emit(&EncryptCompactOutput { jwe })
}

/// Decrypt a password-protected compact JWE, reporting the protected header.
///
/// The header is the interesting output for these cells: `p2s` and `p2c` have to be
/// *there* (authenticated) rather than in an unprotected member, and the matrix
/// asserts their presence and types on the consuming side.
fn decrypt_compact_password(alg: &str, enc: &str) -> Result<()> {
    let raw = read_stdin()?;
    let input: DecryptCompactPasswordInput = serde_json::from_str(&raw)?;
    let header = jose_rs::jwe::compact::decode_header(&input.jwe)?;
    if header.alg != alg {
        bail!("token alg {} does not match expected {alg}", header.alg);
    }
    if header.enc.as_deref() != Some(enc) {
        bail!("token enc {:?} does not match expected {enc}", header.enc);
    }
    let plaintext = jose_rs::jwe::decrypt_with_password(
        &jose_rs::jwe::Password::from_utf8(&input.password),
        &input.jwe,
    )?;
    emit(&DecryptCompactOutput {
        ok: true,
        plaintext_b64u: URL_SAFE_NO_PAD.encode(&plaintext),
        protected_header: header,
        unprotected_header: None,
    })
}

/// Encrypt into the flattened JSON Serialization (RFC 7516 §7.2.2).
///
/// Same header construction and same `jose_rs::jwe` policy as
/// [`encrypt_compact`]; only the serialization differs, which is exactly the
/// property the matrix is checking.
fn encrypt_flattened(alg: &str, enc: &str) -> Result<()> {
    let raw = read_stdin()?;
    let input: EncryptCompactInput = serde_json::from_str(&raw)?;
    let plaintext = URL_SAFE_NO_PAD
        .decode(input.plaintext_b64u.as_bytes())
        .context("decoding plaintext_b64u")?;
    if input.jwk.alg.as_deref() != Some(alg) {
        bail!("JWK alg {:?} does not match expected {alg}", input.jwk.alg);
    }
    let enc_v = JweEncryption::from_str(enc)?;
    let header = build_header(
        JoseHeader::for_jwe(JweAlgorithm::from_str(alg)?, enc_v),
        input.header,
    )?;
    // External AAD, when the driver supplied any, is decoded once and handed
    // to the encrypt options; the harness would otherwise have no way to prove
    // the two implementations build the same AAD input.
    let mut opts = jose_rs::jwe::JweEncryptOptions::new();
    if let Some(aad_b64u) = &input.aad_b64u {
        let aad = URL_SAFE_NO_PAD
            .decode(aad_b64u.as_bytes())
            .context("decoding aad_b64u")?;
        opts = opts.with_external_aad(aad);
    }
    if let Some(crit) = &input.understood_crit {
        opts = opts.with_understood_crit(crit.iter().cloned());
    }
    let jwe = jose_rs::jwe::json::encrypt_flattened_with_jwk_header_options(
        &input.jwk, header, &plaintext, enc_v, &opts,
    )?;
    emit(&EncryptCompactOutput {
        jwe: jwe.to_json()?,
    })
}

/// Decrypt a flattened JSON Serialization.
fn decrypt_flattened(alg: &str, enc: &str) -> Result<()> {
    let raw = read_stdin()?;
    let input: DecryptCompactInput = serde_json::from_str(&raw)?;
    let jwe = jose_rs::jwe::json::FlattenedJwe::from_json(&input.jwe)?;
    let header = jose_rs::jwe::json::decode_header(&jwe)?
        .ok_or_else(|| anyhow!("flattened JWE has no protected header"))?;
    // RFC 7516 §7.2.1 lets `alg` ride in an unprotected member, so the harness
    // sanity check looks at the union the recipient actually sees. jose-rs
    // itself still demands the key's pinned `alg` matches; this only stops the
    // driver blaming the wrong thing for a wiring mistake.
    let reported_alg = match header.alg.as_str() {
        "" => jwe.unprotected_alg().unwrap_or_default().to_string(),
        other => other.to_string(),
    };
    if reported_alg != alg {
        bail!("token alg {reported_alg} does not match expected {alg}");
    }
    if header.enc.as_deref() != Some(enc) {
        bail!("token enc {:?} does not match expected {enc}", header.enc);
    }
    // With a caller-declared extension list the options API is the only one
    // that can express it; without one, the plain entry point is used, so the
    // harness exercises the same default policy a new caller would hit.
    let plaintext = if let Some(crit) = &input.understood_crit {
        let mut options = jose_rs::jwe::JweDecryptOptions::pinned_to_jwk(&input.jwk)?
            .with_understood_crit(crit.iter().cloned());
        if let Some(aad_b64u) = &input.aad_b64u {
            options = options.with_external_aad(
                URL_SAFE_NO_PAD
                    .decode(aad_b64u.as_bytes())
                    .context("decoding aad_b64u")?,
            );
        }
        jose_rs::jwe::json::decrypt_flattened_with_jwk_options(&input.jwk, &jwe, &options)?
    } else if let Some(aad_b64u) = &input.aad_b64u {
        jose_rs::jwe::json::decrypt_flattened_with_jwk_and_aad(
            &input.jwk,
            &jwe,
            &URL_SAFE_NO_PAD
                .decode(aad_b64u.as_bytes())
                .context("decoding aad_b64u")?,
        )?
    } else {
        jose_rs::jwe::json::decrypt_flattened_with_jwk(&input.jwk, &jwe)?
    };
    let mut unprotected_header = serde_json::Map::new();
    for location in [&jwe.unprotected, &jwe.header] {
        if let Some(location) = location {
            unprotected_header.extend(location.clone());
        }
    }
    emit(&DecryptCompactOutput {
        ok: true,
        plaintext_b64u: URL_SAFE_NO_PAD.encode(&plaintext),
        protected_header: header,
        unprotected_header: (!unprotected_header.is_empty()).then_some(unprotected_header),
    })
}

#[derive(Deserialize)]
struct DecryptCompactInput {
    jwk: Jwk,
    jwe: String,
    /// Optional external AAD (base64u), JSON serialization only.
    #[serde(default)]
    aad_b64u: Option<String>,
    /// Private header parameters the caller implements, which `crit` may then
    /// name (ADR 0015).
    #[serde(default)]
    understood_crit: Option<Vec<String>>,
}

#[derive(Serialize)]
struct DecryptCompactOutput {
    ok: bool,
    plaintext_b64u: String,
    /// The protected header as jose-rs parsed it (re-serialized).
    protected_header: JoseHeader,
    /// The unprotected header members the message carried, merged
    /// (`unprotected` then per-recipient `header`). Present only for a JSON
    /// message that had them — the consumer read them as *data*, which is what
    /// the `jwe-json-unprot` cells assert.
    #[serde(skip_serializing_if = "Option::is_none")]
    unprotected_header: Option<serde_json::Map<String, serde_json::Value>>,
}

fn decrypt_compact(alg: &str, enc: &str) -> Result<()> {
    let raw = read_stdin()?;
    let input: DecryptCompactInput = serde_json::from_str(&raw)?;
    let header = jose_rs::jwe::compact::decode_header(&input.jwe)?;
    if header.alg != alg {
        bail!("token alg {} does not match expected {alg}", header.alg);
    }
    if header.enc.as_deref() != Some(enc) {
        bail!("token enc {:?} does not match expected {enc}", header.enc);
    }
    let plaintext = jose_rs::jwe::decrypt_with_jwk(&input.jwk, &input.jwe)?;
    emit(&DecryptCompactOutput {
        ok: true,
        plaintext_b64u: URL_SAFE_NO_PAD.encode(&plaintext),
        protected_header: header,
        unprotected_header: None,
    })
}


// ---------------------------------------------------------------------------
// General JWE JSON Serialization (RFC 7516 §7.2.1)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct EncryptGeneralInput {
    jwks: Vec<Jwk>,
    plaintext_b64u: String,
    #[serde(default)]
    aad_b64u: Option<String>,
    #[serde(default)]
    understood_crit: Option<Vec<String>>,
    #[serde(default)]
    header: Option<serde_json::Map<String, Value>>,
}

#[derive(Deserialize)]
struct DecryptGeneralInput {
    jwk: Jwk,
    jwe: String,
    /// Which `recipients` element to open. Absent means "resolve from the key's
    /// own `kid`", exercising the library's kid selection.
    #[serde(default)]
    recipient: Option<usize>,
    #[serde(default)]
    aad_b64u: Option<String>,
    #[serde(default)]
    understood_crit: Option<Vec<String>>,
}

#[derive(Serialize)]
struct DecryptGeneralOutput {
    ok: bool,
    plaintext_b64u: String,
    /// The element that was opened, so the driver can assert which recipient it
    /// reached rather than trusting that the right one was chosen.
    recipient: usize,
    recipient_count: usize,
    protected_header: JoseHeader,
    /// The union of shared and per-recipient unprotected members that this
    /// recipient computes its header from — reported as data.
    #[serde(skip_serializing_if = "Option::is_none")]
    unprotected_header: Option<serde_json::Map<String, serde_json::Value>>,
}

/// Encrypt to every key in `jwks`, each getting its own `recipients` element.
fn encrypt_general(alg: &str, enc: &str) -> Result<()> {
    let raw = read_stdin()?;
    let input: EncryptGeneralInput = serde_json::from_str(&raw)?;
    let plaintext = URL_SAFE_NO_PAD
        .decode(input.plaintext_b64u.as_bytes())
        .context("decoding plaintext_b64u")?;
    for jwk in &input.jwks {
        if jwk.alg.as_deref() != Some(alg) {
            bail!("JWK alg {:?} does not match expected {alg}", jwk.alg);
        }
    }
    let enc_v = JweEncryption::from_str(enc)?;
    let header = build_header(
        JoseHeader::for_jwe(JweAlgorithm::from_str(alg)?, enc_v),
        input.header,
    )?;
    let mut opts = jose_rs::jwe::JweEncryptOptions::new();
    if let Some(aad_b64u) = &input.aad_b64u {
        let aad = URL_SAFE_NO_PAD
            .decode(aad_b64u.as_bytes())
            .context("decoding aad_b64u")?;
        opts = opts.with_external_aad(aad);
    }
    if let Some(crit) = &input.understood_crit {
        opts = opts.with_understood_crit(crit.iter().cloned());
    }
    let refs: Vec<&Jwk> = input.jwks.iter().collect();
    let jwe = jose_rs::jwe::general::encrypt_general_with_jwks_options(
        &header, &refs, &plaintext, enc_v, &opts,
    )?;
    emit(&EncryptCompactOutput {
        jwe: jwe.to_json()?,
    })
}

/// Open one recipient of a general JSON Serialization.
fn decrypt_general(alg: &str, enc: &str) -> Result<()> {
    let raw = read_stdin()?;
    let input: DecryptGeneralInput = serde_json::from_str(&raw)?;
    let jwe = jose_rs::jwe::general::GeneralJwe::from_json(&input.jwe)?;

    // Which element to open: the driver's choice, or the key's own `kid`.
    let index = match input.recipient {
        Some(index) => index,
        None => jwe
            .recipient_kids()
            .iter()
            .position(|kid| *kid == input.jwk.kid.as_deref())
            .ok_or_else(|| anyhow!("no recipient carries this key's kid"))?,
    };

    // Wiring sanity for the driver only: jose-rs itself enforces the key's
    // pinned `alg` against whatever the recipient's header claims.
    let header = jwe
        .peek_jose_header_for(index)?
        .get("alg")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    if header != alg {
        bail!("recipient {index} alg {header} does not match expected {alg}");
    }
    let reported_enc = jwe
        .peek_jose_header_for(index)?
        .get("enc")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    if reported_enc != enc {
        bail!("recipient {index} enc {reported_enc} does not match expected {enc}");
    }

    let plaintext = if let Some(crit) = &input.understood_crit {
        let mut options = jose_rs::jwe::JweDecryptOptions::pinned_to_jwk(&input.jwk)?
            .with_understood_crit(crit.iter().cloned());
        if let Some(aad_b64u) = &input.aad_b64u {
            options = options.with_external_aad(
                URL_SAFE_NO_PAD
                    .decode(aad_b64u.as_bytes())
                    .context("decoding aad_b64u")?,
            );
        }
        jose_rs::jwe::general::decrypt_general_with_jwk_options(&input.jwk, &jwe, index, &options)?
    } else if let Some(aad_b64u) = &input.aad_b64u {
        jose_rs::jwe::general::decrypt_general_with_jwk_and_aad(
            &input.jwk,
            &jwe,
            index,
            &URL_SAFE_NO_PAD
                .decode(aad_b64u.as_bytes())
                .context("decoding aad_b64u")?,
        )?
    } else {
        jose_rs::jwe::general::decrypt_general_with_jwk(&input.jwk, &jwe, index)?
    };

    let protected = jose_rs::jwe::general::decode_header(&jwe)?
        .ok_or_else(|| anyhow!("general JWE carries no protected header"))?;
    // Only the genuinely unauthenticated members, merged the way the recipient
    // sees them: shared `unprotected` first, then this element's `header`.
    let flat = jwe.flatten_for(index)?;
    let mut merged = serde_json::Map::new();
    if let Some(unprotected) = &flat.unprotected {
        merged.extend(unprotected.clone());
    }
    if let Some(per_recipient) = &flat.header {
        merged.extend(per_recipient.clone());
    }
    emit(&DecryptGeneralOutput {
        ok: true,
        plaintext_b64u: URL_SAFE_NO_PAD.encode(&plaintext),
        recipient: index,
        recipient_count: jwe.recipient_count(),
        protected_header: protected,
        unprotected_header: (!merged.is_empty()).then_some(merged),
    })
}
