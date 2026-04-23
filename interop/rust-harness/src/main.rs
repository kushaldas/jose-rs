//! jose-interop — JSON-over-stdio CLI wrapper around jose-rs.
//!
//! Mirrors the subcommand surface exposed by `interop/js-harness/index.mjs`
//! so the orchestrator script can pipe output from one side into the other.
//!
//! Subcommands:
//!   gen-key        --alg <ALG>            (stdin: -)         -> private JWK
//!   export-pub                             (stdin: private JWK) -> public JWK
//!   sign-compact   --alg <ALG>            (stdin: {jwk, payload_b64u}) -> compact JWS
//!   verify-compact --alg <ALG>            (stdin: {jwk, jws}) -> {ok, payload_b64u}
//!   sign-jwt       --alg <ALG>            (stdin: {jwk, claims}) -> JWT
//!   verify-jwt     --alg <ALG>            (stdin: {jwk, jwt}) -> {ok, claims}
//!
//! All I/O is JSON on stdin/stdout; human-readable errors go to stderr and
//! the process exits non-zero on failure.

use anyhow::{anyhow, bail, Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use jose_rs::jwk::Jwk;
use jose_rs::jwt::{Claims, Validation};
use jose_rs::JoseHeader;
use serde::{Deserialize, Serialize};
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
    let mut i = 1;
    while i < raw.len() {
        let a = &raw[i];
        if let Some(rest) = a.strip_prefix("--alg=") {
            alg = Some(rest.to_string());
            i += 1;
        } else if a == "--alg" {
            alg = raw.get(i + 1).cloned();
            i += 2;
        } else {
            i += 1;
        }
    }

    match cmd.as_str() {
        "gen-key" => gen_key(&require_alg(alg)?),
        "export-pub" => export_pub(),
        "sign-compact" => sign_compact(&require_alg(alg)?),
        "verify-compact" => verify_compact(&require_alg(alg)?),
        "sign-jwt" => sign_jwt(&require_alg(alg)?),
        "verify-jwt" => verify_jwt(&require_alg(alg)?),
        other => bail!("unknown subcommand: {other}"),
    }
}

fn require_alg(alg: Option<String>) -> Result<String> {
    alg.ok_or_else(|| anyhow!("--alg is required"))
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

fn gen_key(alg: &str) -> Result<()> {
    let jwk: Jwk = match alg {
        "ML-DSA-44" => jose_rs::jwk::generate_mldsa(kryptering::MlDsaVariant::MlDsa44)?,
        "ML-DSA-65" => jose_rs::jwk::generate_mldsa(kryptering::MlDsaVariant::MlDsa65)?,
        "ML-DSA-87" => jose_rs::jwk::generate_mldsa(kryptering::MlDsaVariant::MlDsa87)?,
        "EdDSA" => set_alg(jose_rs::jwk::generate_ed25519()?, "EdDSA"),
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
    let header = JoseHeader::new(alg);
    let jws = jose_rs::jws::compact::sign_with_jwk(&input.jwk, &payload, &header)?;
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
