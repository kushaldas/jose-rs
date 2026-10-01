//! jose-interop — JSON-over-stdio CLI wrapper around jose-rs.
//!
//! Mirrors the subcommand surface exposed by `interop/js-harness/index.mjs`
//! so the orchestrator script can pipe output from one side into the other.
//!
//! Subcommands:
//!   gen-key        --alg <ALG> [--enc <ENC>] (stdin: -)      -> private JWK
//!       (JWE: --alg A128KW|A192KW|A256KW, or --alg dir --enc <ENC>)
//!   export-pub                             (stdin: private JWK) -> public JWK
//!   sign-compact   --alg <ALG>            (stdin: {jwk, payload_b64u, header?}) -> {jws}
//!   verify-compact --alg <ALG>            (stdin: {jwk, jws}) -> {ok, payload_b64u, protected_header}
//!   sign-compact-raw --alg <ALG>          (stdin: {jwk, header_raw, payload_b64u}) -> {jws}
//!       Signs over the caller's *exact* protected-header bytes, bypassing
//!       JoseHeader serialization. Used only to mint negative vectors (e.g. a
//!       header with a duplicated member) that jose-rs's API cannot emit.
//!   encrypt-compact --alg <ALG> --enc <ENC> (stdin: {jwk, plaintext_b64u, header?}) -> {jwe}
//!   decrypt-compact --alg <ALG> --enc <ENC> (stdin: {jwk, jwe}) -> {ok, plaintext_b64u, protected_header}
//!   sign-jwt       --alg <ALG>            (stdin: {jwk, claims}) -> JWT
//!   verify-jwt     --alg <ALG>            (stdin: {jwk, jwt}) -> {ok, claims}
//!
//! All I/O is JSON on stdin/stdout; human-readable errors go to stderr and
//! the process exits non-zero on failure.

use anyhow::{anyhow, bail, Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use jose_rs::algorithm::{JweAlgorithm, JweEncryption, JwsAlgorithm};
use jose_rs::jwk::Jwk;
use jose_rs::jwt::{Claims, Validation};
use jose_rs::JoseHeader;
use serde::{Deserialize, Serialize};
use serde_json::Value;
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
        } else {
            i += 1;
        }
    }

    match cmd.as_str() {
        "gen-key" => gen_key(&require_alg(alg)?, enc.as_deref()),
        "export-pub" => export_pub(),
        "sign-compact" => sign_compact(&require_alg(alg)?),
        "verify-compact" => verify_compact(&require_alg(alg)?),
        "sign-compact-raw" => sign_compact_raw(&require_alg(alg)?),
        "encrypt-compact" => encrypt_compact(&require_alg(alg)?, &require_enc(enc)?),
        "decrypt-compact" => decrypt_compact(&require_alg(alg)?, &require_enc(enc)?),
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

fn gen_key(alg: &str, enc: Option<&str>) -> Result<()> {
    let jwk: Jwk = match alg {
        "A128KW" | "A192KW" | "A256KW" => jose_rs::jwk::generate_symmetric_for_alg(alg)?,
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
struct DecryptCompactInput {
    jwk: Jwk,
    jwe: String,
}

#[derive(Serialize)]
struct DecryptCompactOutput {
    ok: bool,
    plaintext_b64u: String,
    /// The protected header as jose-rs parsed it (re-serialized).
    protected_header: JoseHeader,
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
    })
}
