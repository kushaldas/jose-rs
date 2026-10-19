//! Regenerate the fuzz seed corpus under `fuzz/seeds/`.
//!
//! ```sh
//! cargo run --example fuzz_seeds             # write the corpus
//! cargo run --example fuzz_seeds -- --check  # fail if the checked-in corpus is stale
//! ```
//!
//! # Why seeds, when libFuzzer generates inputs too
//!
//! Coverage-guided fuzzing starts from nothing and has to *discover* that a
//! certificate is four nested sequences before it can reach the positional walk
//! inside one. Random bytes reach shallow refusals almost immediately and deeper
//! code almost never. The seeds are the part of the input space a fuzzer cannot
//! find by luck: real armor around real DER, a General JWE with a recipient, a
//! claims object whose duplicate member is the third of five.
//!
//! # Why the corpus is checked in
//!
//! A crash found in a long run is reproducible only if the input that produced it
//! can be re-run next week, and the corpus that found it is under test as much as
//! the code is. `tests/fuzz_regressions.rs` replays every seed — plus mutations of
//! it — on stable Rust, and `--check` fails when regeneration disagrees with what
//! is committed, the same drift discipline as `docs/capabilities.md`.
//!
//! # Determinism, and the honest exception
//!
//! Output is byte-stable wherever it can be: key-file seeds are copies of
//! `tests/fixtures/**` plus DER decoded from that same armor; JWK, JWK Set, claims
//! and HMAC-signed token seeds come from fixed key material and a fixed payload, so
//! the signature is fixed too. No key generation, no RNG in that path.
//!
//! AEAD-backed documents are the exception, and pretending otherwise would be the
//! kind of claim a test exists to catch. `A256GCM` picks a fresh random IV per
//! encryption, so `jwe_json_flattened/`, `jwe_json_general/` and `jwe_decrypt/`
//! differ on every regeneration — as they must; a fixed IV would be a vulnerability
//! written into a test fixture. `--check` therefore verifies those directories
//! structurally (same file names) and the rest bytewise, and `NON_DETERMINISTIC`
//! names the exception in code so it cannot silently widen.

use std::fs;
use std::path::{Path, PathBuf};

use jose_rs::jwe::general;
use jose_rs::jwe::json;
use jose_rs::jwk::Jwk;
use jose_rs::jwt::Claims;
use jose_rs::{JoseHeader, JweEncryption};

/// Fixed `dir` content key for A256GCM documents; public by construction.
const DIR_KEY_BYTES: [u8; 32] = [0x5a; 32];

/// Fixed HMAC key for JWK Set seeds; public by construction.
const HMAC_KEY: &str = "fuzz-hmac-key-0000000000000000000000000";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let check = std::env::args().any(|arg| arg == "--check");
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let corpus = root.join("fuzz/seeds");
    let out = if check {
        let dir = root.join("target").join("fuzz-seeds-check");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir)?;
        dir
    } else {
        corpus.clone()
    };

    key_file_seeds(&root, &out)?;
    token_seeds(&out)?;
    jwk_json_seeds(&out)?;
    jwkset_seeds(&out)?;
    jwe_seeds(&out)?;
    claims_seeds(&out)?;

    if !check {
        println!("wrote seed corpus to {}", out.display());
        return Ok(());
    }

    let drift = diff_trees(&corpus, &out)?;
    let _ = fs::remove_dir_all(&out);
    if drift.is_empty() {
        println!("fuzz seeds are up to date");
        return Ok(());
    }
    eprintln!("fuzz/seeds is stale; regenerate with `cargo run --example fuzz_seeds`");
    for line in drift {
        eprintln!("  {line}");
    }
    Err("fuzz seed corpus drifted from its generator".into())
}

/// Seeds for `jwk_from_pem`, `jwk_from_der`, `certificate_extract` and
/// `encrypted_pkcs8`: checked-in key files, plus the DER inside their armor.
///
/// Names are stable across regenerations so a crash stays attributable.
fn key_file_seeds(root: &Path, out: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let files: &[(&str, &str, &str)] = &[
        (
            "tests/fixtures/pem/ec_pkcs8.pem",
            "jwk_from_pem",
            "ec-pkcs8.pem",
        ),
        (
            "tests/fixtures/cert/ec256_key.pem",
            "jwk_from_pem",
            "ec256-sec1.pem",
        ),
        (
            "tests/fixtures/cert/ec256_spki.pem",
            "jwk_from_pem",
            "ec256-spki.pem",
        ),
        (
            "tests/fixtures/cert/rsa_spki.pem",
            "jwk_from_pem",
            "rsa-spki.pem",
        ),
        (
            "tests/fixtures/cert/rsa_key.pem",
            "jwk_from_pem",
            "rsa-pkcs8.pem",
        ),
        (
            "tests/fixtures/cert/rsa_pss_spki.pem",
            "jwk_from_pem",
            "rsa-pss-spki.pem",
        ),
        (
            "tests/fixtures/cert/rsa2_spki.pem",
            "jwk_from_pem",
            "rsa-512-spki.pem",
        ),
        (
            "tests/fixtures/cert/ed_spki.pem",
            "jwk_from_pem",
            "ed25519-spki.pem",
        ),
        (
            "tests/fixtures/cert/ec256_cert.pem",
            "certificate_extract",
            "ec256-cert.pem",
        ),
        (
            "tests/fixtures/cert/rsa_cert.pem",
            "certificate_extract",
            "rsa-cert.pem",
        ),
        (
            "tests/fixtures/cert/rsa_cert_decoy.pem",
            "certificate_extract",
            "rsa-cert-decoy.pem",
        ),
        (
            "tests/fixtures/cert/rsa_cert_v1.pem",
            "certificate_extract",
            "rsa-cert-v1.pem",
        ),
        (
            "tests/fixtures/cert/rsa_cert_truncated.pem",
            "certificate_extract",
            "rsa-cert-truncated.pem",
        ),
        (
            "tests/fixtures/cert/rsa_cert_ber_outer.pem",
            "certificate_extract",
            "rsa-cert-ber-outer.pem",
        ),
        (
            "tests/fixtures/cert/chain.pem",
            "certificate_extract",
            "chain.pem",
        ),
        (
            "tests/fixtures/cert/dsa_cert.pem",
            "certificate_extract",
            "dsa-cert.pem",
        ),
        (
            "tests/fixtures/cert/bp_cert.pem",
            "certificate_extract",
            "brainpool-cert.pem",
        ),
        (
            "tests/fixtures/pkcs8/enc_low_iter.pem",
            "encrypted_pkcs8",
            "enc-low-iter.pem",
        ),
        (
            "tests/fixtures/pkcs8/enc_pbkdf2_sha256_aes256.pem",
            "encrypted_pkcs8",
            "enc-sha256-aes256.pem",
        ),
        (
            "tests/fixtures/pkcs8/enc_pbkdf2_sha1_aes256.pem",
            "encrypted_pkcs8",
            "enc-sha1-aes256.pem",
        ),
        (
            "tests/fixtures/pkcs8/enc_rsa_des3.pem",
            "encrypted_pkcs8",
            "enc-des3.pem",
        ),
    ];

    for (fixture, target, name) in files {
        // A partial checkout must not fail the corpus build: skip a missing
        // fixture, since `--check` compares whatever both sides produced.
        let Ok(text) = fs::read_to_string(root.join(fixture)) else {
            continue;
        };
        write_seed(out, target, name, text.as_bytes())?;

        // The armor's payload, for the DER-side targets. This is what lets
        // `certificate_extract` reach the positional walk instead of stopping at
        // base64 decoding, and lets `jwk_from_der` see real PKCS#8/SPKI/SEC1.
        let Some(der) = pem_payload(&text) else {
            continue;
        };
        write_seed(out, target, &format!("{name}.der"), &der)?;
        write_seed(out, "jwk_from_der", &format!("{name}.der"), &der)?;

        // A certificate under a *key* label is the wrong-dispatch case the PEM
        // importer must refuse by name.
        if *target == "certificate_extract" {
            write_seed(out, "jwk_from_pem", name, text.as_bytes())?;
        }
        // And a key file under a certificate label, the other direction.
        if *target == "jwk_from_pem" {
            write_seed(out, "certificate_extract", name, text.as_bytes())?;
        }
    }

    // The one DER-only fixture, straight in.
    if let Ok(der) = fs::read(root.join("tests/fixtures/cert/rsa_cert.der")) {
        write_seed(out, "certificate_extract", "rsa-cert.der", &der)?;
    }
    Ok(())
}

/// Seeds for the compact-wire harnesses (`jws_decode_header`, `jws_verify`,
/// `jwe_decrypt`, `jwt_decode_unverified`, `base64url_decode`): real tokens built
/// through the real sign/encrypt paths, so a fuzzer starts past the base64 layer.
fn token_seeds(out: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let hmac = hmac_jwk(Some("hmac-a"))?;
    let payload = b"seed corpus payload";
    let claims = br#"{"iss":"https://issuer.example","sub":"fuzz-seed","exp":4100000000}"#;

    let jws = jose_rs::jws::compact::sign_with_jwk(&hmac, payload, &JoseHeader::new("HS256"))?;
    write_seed(out, "jws_decode_header", "hs256.txt", jws.as_bytes())?;
    write_seed(out, "jws_verify", "hs256.txt", jws.as_bytes())?;

    let jwt = jose_rs::jws::compact::sign_with_jwk(&hmac, claims, &JoseHeader::new("HS256"))?;
    write_seed(out, "jwt_decode_unverified", "hs256.txt", jwt.as_bytes())?;

    // Detached and single-segment shapes: the segments a caller may re-join
    // wrongly.
    let parts: Vec<&str> = jws.split('.').collect();
    write_seed(
        out,
        "jws_decode_header",
        "detached.txt",
        format!("{}.{}", parts[0], parts[2]).as_bytes(),
    )?;
    write_seed(
        out,
        "jws_decode_header",
        "one-segment.txt",
        parts[0].as_bytes(),
    )?;
    write_seed(out, "jws_decode_header", "empty.txt", b"")?;

    // `alg: none`, the shape that must never verify but must still parse.
    let none_header = base64url_payload(br#"{"alg":"none"}"#);
    let unsecured = format!("{none_header}.{}.", base64url_payload(claims));
    write_seed(
        out,
        "jwt_decode_unverified",
        "alg-none.txt",
        unsecured.as_bytes(),
    )?;

    // Compact JWE in `dir` mode with a fixed CEK.
    let jwe = jose_rs::jwe::compact::encrypt(
        &DIR_KEY_BYTES,
        payload,
        jose_rs::JweAlgorithm::Dir,
        JweEncryption::A256GCM,
    )?;
    write_seed(out, "jwe_decrypt", "dir-a256gcm.txt", jwe.as_bytes())?;
    let jwe_parts: Vec<&str> = jwe.split('.').collect();
    write_seed(
        out,
        "jwe_decrypt",
        "missing-tag.txt",
        format!(
            "{}.{}.{}.{}",
            jwe_parts[0], jwe_parts[1], jwe_parts[2], jwe_parts[3]
        )
        .as_bytes(),
    )?;

    // base64url alphabet edges, for the decoder's own harness.
    for (name, value) in [
        ("empty.txt", ""),
        ("padded.txt", "QUJDRA=="),
        ("standard-alphabet.txt", "QUJD/R5+"),
        ("url-safe.txt", "QUJD_R5-"),
        ("odd-length.txt", "QUJCR"),
        ("with-newline.txt", "QUJD\nRA"),
        ("unicode.txt", "\u{0e}ff"),
    ] {
        write_seed(out, "base64url_decode", name, value.as_bytes())?;
    }
    Ok(())
}

/// Seeds for the JWK-JSON harnesses (`jwk_from_json`, `jwk_thumbprint`).
fn jwk_json_seeds(out: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let mut seeds: Vec<(String, String)> = Vec::new();
    for (name, jwk) in [
        ("oct-hs256.json", hmac_jwk(Some("hmac-a"))?),
        ("dir-key.json", dir_jwk()?),
        ("kid-less.json", hmac_jwk(None)?),
    ] {
        seeds.push((name.to_string(), jwk.to_json()?));
    }
    seeds.extend([
        ("missing-k.json", r#"{"kty":"oct","alg":"HS256"}"#),
        ("unknown-kty.json", r#"{"kty":"nope","k":"YQ"}"#),
        ("bad-base64.json", r#"{"kty":"oct","k":"@@@@"}"#),
        (
            "duplicate-member.json",
            r#"{"kty":"oct","kty":"oct","k":"YQ"}"#,
        ),
        (
            "use-mismatch.json",
            r#"{"kty":"oct","alg":"HS256","use":"enc","k":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}"#,
        ),
        (
            "key-ops-empty.json",
            r#"{"kty":"oct","alg":"HS256","key_ops":[],"k":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}"#,
        ),
        ("array.json", "[1,2,3]"),
        ("empty.json", ""),
    ]
    .into_iter()
    .map(|(name, doc)| (name.to_string(), doc.to_string())));
    for (name, doc) in &seeds {
        write_seed(out, "jwk_from_json", name, doc.as_bytes())?;
        write_seed(out, "jwk_thumbprint", name, doc.as_bytes())?;
    }
    Ok(())
}

/// Seeds for `jwkset_select`: the shapes the selection policy exists for —
/// addressable sets, a kid-less set, duplicate kids, unusable entries, and a set
/// over the entry budget.
fn jwkset_seeds(out: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let json = hmac_jwk(Some("key-a"))?.to_json()?;
    let other = r#"{"kty":"oct","alg":"HS256","kid":"key-b","k":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}"#;

    write_seed(
        out,
        "jwkset_select",
        "two-keys.json",
        format!(r#"{{"keys":[{json},{other}]}}"#).as_bytes(),
    )?;
    write_seed(
        out,
        "jwkset_select",
        "kid-less.json",
        format!(r#"{{"keys":[{json}]}}"#).as_bytes(),
    )?;
    write_seed(
        out,
        "jwkset_select",
        "duplicate-kid.json",
        format!(r#"{{"keys":[{json},{json}]}}"#).as_bytes(),
    )?;
    write_seed(
        out,
        "jwkset_select",
        "unusable-entry.json",
        format!(r#"{{"keys":[{json},{{"kty":"oct"}}]}}"#).as_bytes(),
    )?;
    write_seed(
        out,
        "jwkset_select",
        "short-hmac-key.json",
        r#"{"keys":[{"kty":"oct","alg":"HS256","k":"YQ"}]}"#.as_bytes(),
    )?;

    // Over `DEFAULT_MAX_SET_ENTRIES`: the budget must refuse before any entry is
    // converted, so this seed is a *resource* case, not a correctness one.
    let many: Vec<&str> = vec![json.as_str(); 1_100];
    let many = many.join(",");
    write_seed(
        out,
        "jwkset_select",
        "over-entry-limit.json",
        format!(r#"{{"keys":[{many}]}}"#).as_bytes(),
    )?;
    write_seed(
        out,
        "jwkset_select",
        "not-a-set.json",
        br#"{"keys":"nope"}"#,
    )?;
    Ok(())
}

/// Seeds for `jwe_json_flattened` and `jwe_json_general`, built through the real
/// encrypt path so the shallow layers are already behind a fuzzer.
fn jwe_seeds(out: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let jwk = dir_jwk()?;
    let plaintext = b"fuzz plaintext for the seed corpus";

    // A `dir` key pins `alg` but not `enc`, so the protected header is built
    // explicitly — `enc` must be integrity-protected, never inferred.
    let header = JoseHeader {
        alg: "dir".into(),
        enc: Some("A256GCM".into()),
        kid: Some("fuzz-dir-key".into()),
        ..JoseHeader::new("dir")
    };
    let flattened = json::encrypt_flattened_with_jwk_header(
        &jwk,
        header.clone(),
        plaintext,
        JweEncryption::A256GCM,
    )?;
    let text = flattened.to_json()?;
    write_seed(out, "jwe_json_flattened", "valid.json", text.as_bytes())?;

    // `alg` copied into the unprotected header: the member this crate accepts
    // only from the protected place (ADR 0013).
    let mut duplicated = flattened.clone();
    duplicated.unprotected = Some(serde_json::Map::from_iter([(
        "alg".into(),
        serde_json::Value::String("dir".into()),
    )]));
    let duplicated = duplicated.to_json()?;
    write_seed(
        out,
        "jwe_json_flattened",
        "unprotected-alg.json",
        duplicated.as_bytes(),
    )?;

    // The protected header rewritten after encryption — what the on-path
    // attacker actually sends.
    let rewritten = text.replace("\"protected\":\"", "\"protected\":\"AAAA");
    write_seed(
        out,
        "jwe_json_flattened",
        "protected-rewritten.json",
        rewritten.as_bytes(),
    )?;

    // The JWK's `kid` is emitted in the recipient header. Keep it out of the
    // protected header so the three JOSE header locations remain disjoint.
    let mut general_header = header.clone();
    general_header.kid = None;
    let general = general::encrypt_general_with_jwks(
        &general_header,
        &[&jwk],
        plaintext,
        JweEncryption::A256GCM,
    )?;
    let general_text = general.to_json()?;
    write_seed(
        out,
        "jwe_json_general",
        "valid-one-recipient.json",
        general_text.as_bytes(),
    )?;
    write_seed(
        out,
        "jwe_json_general",
        "recipient-without-key.json",
        general_text
            .replace("\"encrypted_key\":", "\"encrypted_key_x\":")
            .as_bytes(),
    )?;
    // A general document whose shared header is duplicated into a recipient.
    write_seed(
        out,
        "jwe_json_general",
        "recipient-unprotected-alg.json",
        general_text
            .replacen(
                "\"recipients\":[{",
                r#""recipients":[{"unprotected":{"alg":"dir"},"#,
                1,
            )
            .as_bytes(),
    )?;
    Ok(())
}

/// Seeds for `jwt_claims`: the duplicate-member shapes ADR 0029 refuses, plus the
/// numeric-precision and null-versus-absent cases.
fn claims_seeds(out: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let docs: &[(&str, &str)] = &[
        ("duplicate-exp.json", r#"{"sub":"a","exp":1,"exp":2}"#),
        ("duplicate-iat.json", r#"{"iat":1,"iat":2}"#),
        ("duplicate-sub.json", r#"{"sub":"a","sub":"b"}"#),
        (
            "duplicate-aud.json",
            r#"{"aud":["a"],"aud":"b","iss":"https://issuer.example"}"#,
        ),
        ("duplicate-deep.json", r#"{"sub":"a","x":{"y":1,"y":2}}"#),
        (
            "huge-numeric.json",
            r#"{"iat":9007199254740993,"exp":18446744073709551616}"#,
        ),
        (
            "fractional.json",
            r#"{"iat":1700000000.5,"nbf":1700000000.25,"exp":1800000000.125}"#,
        ),
        (
            "nulls.json",
            r#"{"sub":null,"exp":null,"iss":null,"custom":null}"#,
        ),
        (
            "valid.json",
            r#"{"iss":"https://issuer.example","sub":"subject","aud":["audience"],"exp":4100000000}"#,
        ),
        ("empty.json", "{}"),
        ("array.json", "[1,2,3]"),
        ("scalar.json", "42"),
        ("truncated.json", r#"{"sub":"a","#),
        ("control-bytes.json", "\u{0}\u{1}not json at all"),
    ];
    for (name, doc) in docs {
        write_seed(out, "jwt_claims", name, doc.as_bytes())?;
    }

    // Something this crate emitted, so the happy path is in the corpus too and
    // not only the refusals.
    let claims = Claims {
        sub: Some("subject".into()),
        exp: Some(u64::MAX.into()),
        ..Default::default()
    };
    write_seed(out, "jwt_claims", "emitted.json", &claims.to_json_vec()?)?;
    Ok(())
}

fn base64url_payload(payload: &[u8]) -> String {
    jose_rs::base64url::encode(payload)
}

fn dir_jwk() -> Result<Jwk, Box<dyn std::error::Error>> {
    let k = jose_rs::base64url::encode(&DIR_KEY_BYTES);
    Ok(Jwk::from_json(&format!(
        r#"{{"kty":"oct","alg":"dir","kid":"fuzz-dir-key","k":"{k}"}}"#
    ))?)
}

fn hmac_jwk(kid: Option<&str>) -> Result<Jwk, Box<dyn std::error::Error>> {
    let k = jose_rs::base64url::encode(HMAC_KEY.as_bytes());
    let kid = kid
        .map(|kid| format!(r#""kid":"{kid}","#))
        .unwrap_or_default();
    Ok(Jwk::from_json(&format!(
        r#"{{"kty":"oct","alg":"HS256",{kid}"k":"{k}"}}"#
    ))?)
}

fn write_seed(
    out: &Path,
    target: &str,
    name: &str,
    bytes: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = out.join(target);
    fs::create_dir_all(&dir)?;
    fs::write(dir.join(name), bytes)?;
    Ok(())
}

/// The first PEM block's body, base64-decoded from the *standard* alphabet
/// (RFC 7468 §3), which is not the base64url alphabet the JOSE wire uses.
///
/// Hand-rolled on purpose: the crate's decoder rejects padded, non-URL-safe input
/// by design, and an example must not weaken it to suit a corpus builder.
fn pem_payload(text: &str) -> Option<Vec<u8>> {
    let mut body = String::new();
    let mut inside = false;
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with("-----BEGIN ") {
            inside = true;
            continue;
        }
        if line.starts_with("-----END ") {
            break;
        }
        if !inside {
            continue;
        }
        // Armor header lines (`Proc-Type:`, `DEK-Info:`) are not part of the body.
        if line.contains(':') || line.is_empty() {
            continue;
        }
        body.push_str(line);
    }

    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut bits = 0u32;
    let mut filled = 0u8;
    let mut out = Vec::new();
    for byte in body.into_bytes() {
        let value = ALPHABET.iter().position(|&c| c == byte)? as u32;
        bits = (bits << 6) | value;
        filled += 6;
        if filled >= 8 {
            filled -= 8;
            out.push((bits >> filled) as u8);
        }
    }
    (out.len() > 16).then_some(out)
}

/// Harness directories whose contents legitimately change every run, because the
/// document embeds a fresh AEAD IV. Listed here rather than discovered, so a new
/// non-deterministic directory is a deliberate edit to this list.
const NON_DETERMINISTIC: &[&str] = &["jwe_json_flattened", "jwe_json_general", "jwe_decrypt"];

/// Compare two directory trees by relative path and content.
///
/// Two things are deliberately out of scope. Files sitting at the corpus root
/// (`README.md`) are documentation, not generated output. And anything under a
/// [`NON_DETERMINISTIC`] directory is compared by *name* only: a committed AEAD
/// document cannot be byte-reproducible without hard-coding an IV, which is exactly
/// the bug this corpus must not encode.
fn is_non_deterministic(path: &Path) -> bool {
    path.components()
        .next()
        .and_then(|part| part.as_os_str().to_str())
        .is_some_and(|first| NON_DETERMINISTIC.contains(&first))
}
fn diff_trees(a: &Path, b: &Path) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let mut left = Vec::new();
    let mut right = Vec::new();
    collect(a, a, &mut left)?;
    collect(b, b, &mut right)?;
    left.sort();
    right.sort();

    let mut out = Vec::new();
    let mut i = 0;
    let mut j = 0;
    while i < left.len() && j < right.len() {
        let (la, ab) = &left[i];
        let (rb, bb) = &right[j];
        match la.cmp(rb) {
            std::cmp::Ordering::Equal => {
                if ab != bb {
                    out.push(format!("content differs: {}", la.display()));
                }
                i += 1;
                j += 1;
            }
            std::cmp::Ordering::Less => {
                out.push(format!("only in fuzz/seeds: {}", la.display()));
                i += 1;
            }
            std::cmp::Ordering::Greater => {
                out.push(format!("missing from fuzz/seeds: {}", rb.display()));
                j += 1;
            }
        }
    }
    for (path, _) in &left[i..] {
        out.push(format!("only in fuzz/seeds: {}", path.display()));
    }
    for (path, _) in &right[j..] {
        out.push(format!("missing from fuzz/seeds: {}", path.display()));
    }
    Ok(out)
}

fn collect(
    root: &Path,
    dir: &Path,
    out: &mut Vec<(PathBuf, Vec<u8>)>,
) -> Result<(), Box<dyn std::error::Error>> {
    if !dir.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() {
            collect(root, &path, out)?;
        } else if path.parent() == Some(root) {
            // Root-level files are prose (README.md), not generator output.
        } else {
            let relative = path.strip_prefix(root)?.to_path_buf();
            let bytes = if is_non_deterministic(&relative) {
                // Compare presence only; content changes every run by design.
                Vec::new()
            } else {
                fs::read(&path)?
            };
            out.push((relative, bytes));
        }
    }
    Ok(())
}
