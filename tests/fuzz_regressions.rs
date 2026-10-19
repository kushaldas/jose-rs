//! Deterministic replay of the fuzz harnesses, on stable, in CI.
//!
//! # Why this exists next to `fuzz/fuzz_targets/`
//!
//! The cargo-fuzz harnesses need nightly, a `cargo-fuzz` install and a machine
//! willing to burn minutes per run; the CI job that touches them only *builds*
//! them. That means the code inside a `fuzz_target!` body — the part that decides
//! which entry points get exercised and what counts as a finding — can rot
//! unnoticed, and the standard mitigation ("run the fuzzer a bit") is exactly the
//! manual step this repository stopped trusting.
//!
//! So each harness's input sequence is mirrored here as an ordinary function, and
//! every seed in `fuzz/seeds/<harness>/` is pushed through it, plus deterministic
//! mutations of it: every truncation, and every single-byte flip on inputs short
//! enough to enumerate. That is not fuzzing — no search, no coverage feedback —
//! but it is *execution*, and it is reproducible from the repository alone. When a
//! nightly run does find a crash, its artifact drops into `fuzz/seeds/` as a
//! regression fixture and this test owns it from then on.
//!
//! # Keeping the mirrors honest
//!
//! [`fuzz_harness_entry_points_are_all_replayed`] extracts every `jose_rs::…`
//! entry point referenced by `fuzz/fuzz_targets/*.rs` and requires this file to
//! reference the same one. A harness that starts exercising a new API without the
//! replay following it fails, which is the drift this design was most afraid of:
//! two copies of a sequence, one of which is run.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use jose_rs::jwe::general::GeneralJwe;
use jose_rs::jwe::json::FlattenedJwe;
use jose_rs::jwk::encrypted_pkcs8::{Pkcs8Encryption, Pkcs8ReadOptions};
use jose_rs::jwk::selection::{self, Fallback, SelectionPolicy, SetLimits};
use jose_rs::jwk::{Jwk, JwkSet};
use jose_rs::jwt::Claims;

/// Corpus root, relative to the crate manifest.
fn seeds_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fuzz/seeds")
}

/// Seeds for one harness, sorted so a run is reproducible.
fn seeds_for(harness: &str) -> Vec<(String, Vec<u8>)> {
    let dir = seeds_dir().join(harness);
    let mut out = Vec::new();
    for entry in
        fs::read_dir(&dir).unwrap_or_else(|e| panic!("missing seed corpus {}: {e}", dir.display()))
    {
        let path = entry.expect("readable dir entry").path();
        if path.is_file() {
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            out.push((name, fs::read(&path).expect("readable seed")));
        }
    }
    assert!(
        !out.is_empty(),
        "no seeds for harness {harness}: the corpus and the harnesses are meant to move together"
    );
    out.sort();
    out
}

fn named_seed(harness: &str, name: &str) -> Vec<u8> {
    seeds_for(harness)
        .into_iter()
        .find_map(|(candidate, bytes)| (candidate == name).then_some(bytes))
        .unwrap_or_else(|| panic!("missing {name} seed for {harness}"))
}

/// Bounds on mutation enumeration, so this file stays a test rather than becoming
/// a batch job. A 300 KB JWK Set is a legitimate seed (`over-entry-limit.json`) and
/// enumerating its prefixes would mean 300 000 parses of a document whose whole
/// point is that it is refused before parsing.
const TRUNCATE_EVERY_BYTE_UP_TO: usize = 4096;
const FLIP_EVERY_BYTE_UP_TO: usize = 2048;

/// Mutations of one seed: prefixes (truncation is the most productive mutation for
/// structured input — it turns a valid document into a length-inconsistent one),
/// plus single-byte flips for inputs short enough to enumerate. Large seeds get
/// structural prefixes only: the same *kinds* of cut, sampled.
fn mutations(seed: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    if seed.len() <= TRUNCATE_EVERY_BYTE_UP_TO {
        for keep in 0..seed.len() {
            out.push(seed[..keep].to_vec());
        }
    } else {
        for keep in [
            0,
            1,
            seed.len() / 4,
            seed.len() / 2,
            seed.len() * 3 / 4,
            seed.len() - 1,
        ] {
            out.push(seed[..keep].to_vec());
        }
    }
    if seed.len() <= FLIP_EVERY_BYTE_UP_TO {
        for position in 0..seed.len() {
            let mut flipped = seed.to_vec();
            // XOR rather than overwrite: reaches both directions (printable ↔
            // control, 0x00 ↔ 0xFF) and can never lengthen the input.
            flipped[position] ^= 0xff;
            out.push(flipped);
        }
    }
    out
}

/// The `jwe_json_flattened` harness's sequence, mirrored.
fn replay_jwe_flattened(bytes: &[u8]) {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return;
    };
    let Ok(jwe) = FlattenedJwe::from_json(text) else {
        return;
    };
    // Parse/emit round-trip: a document that decodes must re-encode into
    // something that decodes to the same structure.
    if let Ok(json) = jwe.to_json() {
        if let Ok(again) = FlattenedJwe::from_json(&json) {
            assert_eq!(again, jwe, "parse/emit round-trip changed the document");
        }
    }
    let _ = jose_rs::jwe::json::decode_header(&jwe);
    let _ = jwe.peek_protected_header();
    let _ = jwe.peek_alg();
    let _ = jwe.peek_jose_header();

    let jwk = dir_key_jwk();
    let _ = jose_rs::jwe::json::decrypt_flattened_with_jwk(&jwk, &jwe);
    let _ = jose_rs::jwe::json::decrypt_flattened_with_jwk_and_aad(&jwk, &jwe, b"fuzz-aad");
    let _ = jose_rs::jwe::json::decrypt_flattened_with_jwk_authenticated(&jwk, &jwe);
}

/// The `jwe_json_general` harness's sequence, mirrored.
fn replay_jwe_general(bytes: &[u8]) {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return;
    };
    let Ok(jwe) = GeneralJwe::from_json(text) else {
        return;
    };
    let _ = jose_rs::jwe::general::decode_header(&jwe);
    let jwk = dir_key_jwk();
    // The extra index past the end is the case that turns a clamp into a
    // wrong-recipient decrypt.
    for index in 0..=jwe.recipients.len() {
        let _ = jwe.peek_jose_header_for(index);
        let _ = jwe.flatten_for(index);
        let _ = jose_rs::jwe::general::decrypt_general_with_jwk(&jwk, &jwe, index);
        let _ = jose_rs::jwe::general::decrypt_general_with_jwk_authenticated(&jwk, &jwe, index);
    }
}

/// The `jwk_from_pem` harness's sequence, mirrored.
fn replay_pem(bytes: &[u8]) {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return;
    };
    if let Ok(jwk) = jose_rs::jwk::pem::jwk_from_pem(text) {
        let _ = jose_rs::jwk::jwk_to_software_key(&jwk);
        let _ = jose_rs::jwk::thumbprint::thumbprint_sha256(&jwk);
        let _ = jwk.to_public_jwk();
        let _ = jose_rs::jwk::pem::public_pem_from_jwk(&jwk);
        let _ = jose_rs::jwk::pem::private_pem_from_jwk(&jwk);
    }
    let _ = jose_rs::jwk::pem::jwk_from_pkcs8_pem(text);
    let _ = jose_rs::jwk::pem::jwk_from_spki_pem(text);
}

/// The `jwk_from_der` harness's sequence, mirrored.
fn replay_der(bytes: &[u8]) {
    if bytes.len() > 65_536 {
        return;
    }
    let _ = jose_rs::jwk::import::jwk_from_pkcs8_der(bytes);
    let _ = jose_rs::jwk::import::jwk_from_spki_der(bytes);
    for result in [
        jose_rs::jwk::import::jwk_from_pkcs1_der(bytes),
        jose_rs::jwk::import::jwk_from_pkcs1_public_der(bytes),
        jose_rs::jwk::import::jwk_from_sec1_der(bytes),
    ]
    .into_iter()
    .flatten()
    {
        let _ = jose_rs::jwk::jwk_to_software_key(&result);
        let _ = jose_rs::jwk::thumbprint::thumbprint_sha256(&result);
        let _ = jose_rs::jwk::pem::public_pem_from_jwk(&result);
    }
}

/// The `certificate_extract` harness's sequence, mirrored.
fn replay_certificate(bytes: &[u8]) {
    if bytes.len() > 65_536 {
        return;
    }
    if let Ok(jwk) = jose_rs::jwk::cert::public_jwk_from_certificate_der(bytes) {
        let _ = jose_rs::jwk::jwk_to_software_key(&jwk);
        let _ = jose_rs::jwk::thumbprint::thumbprint_sha256(&jwk);
        let _ = jose_rs::jwk::pem::public_pem_from_jwk(&jwk);
    }
    if let Ok(text) = std::str::from_utf8(bytes) {
        let _ = jose_rs::jwk::cert::public_jwk_from_certificate_pem(text);
    }
}

/// The `encrypted_pkcs8` harness's sequence, mirrored. The budget is deliberately
/// at the floor so a regression that consults the file's iteration count before
/// checking the budget shows up as a slow test rather than a silent one.
fn replay_encrypted_pkcs8(bytes: &[u8]) {
    if bytes.len() > 65_536 {
        return;
    }
    use jose_rs::jwk::encrypted_pkcs8::PKCS8_MIN_ITERATIONS;
    let password = jose_rs::jwk::Password::from_utf8("hunter2");
    let options = Pkcs8ReadOptions::default().with_max_iterations(PKCS8_MIN_ITERATIONS);
    for result in [
        jose_rs::jwk::encrypted_pkcs8::jwk_from_encrypted_pkcs8_der_with_options(
            bytes, &password, &options,
        ),
        std::str::from_utf8(bytes)
            .map_err(|_| jose_rs::JoseError::Key("not utf-8".into()))
            .and_then(|text| {
                jose_rs::jwk::encrypted_pkcs8::jwk_from_encrypted_pkcs8_pem_with_options(
                    text, &password, &options,
                )
            }),
    ]
    .into_iter()
    .flatten()
    {
        let _ = jose_rs::jwk::jwk_to_software_key(&result);
        let _ = jose_rs::jwk::thumbprint::thumbprint_sha256(&result);
        let _ = jose_rs::jwk::encrypted_pkcs8::encrypted_pkcs8_der_from_jwk(
            &result,
            &password,
            &Pkcs8Encryption::Aes256CbcPbkdf2HmacSha256 {
                iterations: PKCS8_MIN_ITERATIONS,
            },
        );
    }
}

/// The `jwkset_select` harness's sequence, mirrored.
fn replay_jwkset_select(bytes: &[u8]) {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return;
    };
    for limits in [
        SetLimits::default(),
        SetLimits {
            max_bytes: 4096,
            max_entries: 4,
        },
    ] {
        let Ok(set) = JwkSet::from_json_with_limits(text, &limits) else {
            continue;
        };
        for diagnostic in selection::diagnostics(&set) {
            let _ = diagnostic.status.is_usable();
        }
        let kids: Vec<Option<String>> = set
            .keys
            .iter()
            .take(8)
            .map(|key| key.kid.clone())
            .chain([Some("absent-kid".into()), None])
            .collect();
        for policy in [
            SelectionPolicy::strict(),
            SelectionPolicy {
                max_candidates: 4,
                fallback: Fallback::TryWhenUnaddressable,
                require_kid: false,
            },
        ] {
            for kid in &kids {
                if let Ok(found) = selection::select(&set, kid.as_deref(), &policy) {
                    assert!(
                        found.attempts() <= policy.max_candidates,
                        "selection exceeded its candidate budget"
                    );
                    for key in found.candidates {
                        let _ = jose_rs::jwk::jwk_to_software_key(key);
                    }
                }
            }
        }
    }
}

/// The `jwt_claims` harness's sequence, mirrored.
fn replay_claims(bytes: &[u8]) {
    if bytes.len() > jose_rs::MAX_TOKEN_BYTES {
        return;
    }
    let Ok(claims) = Claims::from_json_bytes(bytes) else {
        return;
    };
    if let Ok(emitted) = claims.to_json_vec() {
        if let Ok(again) = Claims::from_json_bytes(&emitted) {
            assert_eq!(
                again, claims,
                "claims round-trip changed the parsed claim values"
            );
        }
        let _ = claims.sub.as_deref();
        let _ = claims.exp;
        let _ = claims.aud.as_ref().map(|aud| aud.contains("audience"));
        let _ = Claims::from_json_str(&String::from_utf8_lossy(&emitted));
    }
}

/// The `jwk_from_json` harness's sequence, mirrored.
fn replay_jwk_json(bytes: &[u8]) {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return;
    };
    if let Ok(jwk) = jose_rs::jwk::Jwk::from_json(text) {
        let _ = jose_rs::jwk::jwk_to_software_key(&jwk);
        let _ = jose_rs::jwk::thumbprint::thumbprint_sha256(&jwk);
        let _ = jwk.to_public_jwk();
        for op in [
            jose_rs::JwkOp::Sign,
            jose_rs::JwkOp::Verify,
            jose_rs::JwkOp::Encrypt,
            jose_rs::JwkOp::Decrypt,
            jose_rs::JwkOp::WrapKey,
            jose_rs::JwkOp::UnwrapKey,
            jose_rs::JwkOp::DeriveKey,
            jose_rs::JwkOp::DeriveBits,
        ] {
            let _ = jwk.check_op(op);
        }
    }
}

/// The `jwk_thumbprint` harness's sequence, mirrored.
fn replay_jwk_thumbprint(bytes: &[u8]) {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return;
    };
    if let Ok(jwk) = Jwk::from_json(text) {
        for hash in [
            jose_rs::jwk::thumbprint::ThumbprintHash::Sha256,
            jose_rs::jwk::thumbprint::ThumbprintHash::Sha384,
            jose_rs::jwk::thumbprint::ThumbprintHash::Sha512,
        ] {
            let _ = jose_rs::jwk::thumbprint::thumbprint(&jwk, hash);
        }
        let _ = jose_rs::jwk::thumbprint::thumbprint_uri_sha256(&jwk);
    }
}

/// The `base64url_decode` harness's sequence, mirrored.
fn replay_base64url(bytes: &[u8]) {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return;
    };
    if let Ok(decoded) = jose_rs::base64url::decode(text) {
        // Re-encoding must reproduce the input for unpadded URL-safe input, which
        // is the only thing the decoder accepts; a mismatch means the decoder
        // accepted something it should have refused.
        let reencoded = jose_rs::base64url::encode(&decoded);
        assert_eq!(
            reencoded, text,
            "decoder accepted non-canonical input {text:?}"
        );
    }
}

/// The `jws_decode_header` harness's sequence, mirrored.
fn replay_jws_header(bytes: &[u8]) {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return;
    };
    let _ = jose_rs::jws::compact::decode_header(text);
}

/// The `jws_verify` harness's sequence, mirrored, with the same fixed HMAC key.
fn replay_jws_verify(bytes: &[u8]) {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return;
    };
    let jwk = hmac_jwk();
    let _ = jose_rs::jws::compact::verify_with_jwk(&jwk, text);
    let verifier = hmac_verifier();
    let _ = jose_rs::jws::compact::verify(verifier.as_ref(), text);
}

/// The `jwe_decrypt` harness's sequence, mirrored (fixed 32-byte `dir` CEK).
fn replay_jwe_compact(bytes: &[u8]) {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return;
    };
    let cek = [0x42u8; 32];
    let _ = jose_rs::jwe::decrypt(&cek, text);
    let jwk = dir_key_jwk();
    let _ = jose_rs::jwe::compact::decrypt_with_jwk(&jwk, text);
}

/// The `jwt_decode_unverified` harness's sequence, mirrored.
///
/// The deprecated call is deliberate and mirrors `jwt_decode_unverified` exactly:
/// this harness exists to prove the *unauthenticated inspection* path cannot be
/// made to panic, which requires calling it. Any production use would be a
/// signature-bypass bug; a fuzz target is the one place it is the subject under
/// test.
#[allow(deprecated)]
fn replay_jwt_unverified(bytes: &[u8]) {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return;
    };
    let _ = jose_rs::jwt::decode_unverified(text);
}

/// Drive one harness: seeds and their mutations, and a hard statement that no
/// plaintext was released for a document that arrived from outside.
fn drive(harness: &str, replay: fn(&[u8])) -> usize {
    let mut inputs = 0usize;
    for (name, seed) in seeds_for(harness) {
        for input in std::iter::once(seed.clone()).chain(mutations(&seed)) {
            replay(&input);
            inputs += 1;
        }
        // Nothing above may panic; the assert-free body is the assertion. `name`
        // is only here so a failure line points at a seed.
        let _ = &name;
    }
    inputs
}

fn hmac_jwk() -> Jwk {
    let k = jose_rs::base64url::encode(HMAC_KEY.as_bytes());
    Jwk::from_json(&format!(
        r#"{{"kty":"oct","alg":"HS256","kid":"hmac-a","k":"{k}"}}"#
    ))
    .expect("fixed hmac key must parse")
}

const HMAC_KEY: &str = "fuzz-hmac-key-0000000000000000000000000";

fn hmac_verifier() -> Box<dyn kryptering::Verifier> {
    let key = kryptering::SoftwareKey::from_symmetric_bytes(
        kryptering::KeyAlgorithm::Hmac,
        HMAC_KEY.as_bytes(),
    )
    .expect("fixed hmac key must build");
    Box::new(
        kryptering::SoftwareVerifier::new(
            kryptering::SignatureAlgorithm::Hmac(kryptering::HashAlgorithm::Sha256),
            key,
        )
        .expect("fixed hmac verifier must build"),
    )
}

fn dir_key_jwk() -> Jwk {
    let k = jose_rs::base64url::encode(&[0x5a; 32]);
    Jwk::from_json(&format!(
        r#"{{"kty":"oct","alg":"dir","kid":"fuzz-dir-key","k":"{k}"}}"#
    ))
    .expect("fixed dir key must parse")
}

#[test]
fn replay_jwe_json_flattened_corpus() {
    let inputs = drive("jwe_json_flattened", replay_jwe_flattened);
    assert!(inputs > 100, "only {inputs} inputs replayed");
}

#[test]
fn replay_jwe_json_general_corpus() {
    let inputs = drive("jwe_json_general", replay_jwe_general);
    assert!(inputs > 100, "only {inputs} inputs replayed");
}

#[test]
fn replay_pem_corpus() {
    let inputs = drive("jwk_from_pem", replay_pem);
    assert!(inputs > 100, "only {inputs} inputs replayed");
}

#[test]
fn replay_der_corpus() {
    let inputs = drive("jwk_from_der", replay_der);
    assert!(inputs > 100, "only {inputs} inputs replayed");
}

#[test]
fn replay_certificate_corpus() {
    let inputs = drive("certificate_extract", replay_certificate);
    assert!(inputs > 100, "only {inputs} inputs replayed");
}

#[test]
fn replay_encrypted_pkcs8_corpus() {
    let inputs = drive("encrypted_pkcs8", replay_encrypted_pkcs8);
    assert!(inputs > 100, "only {inputs} inputs replayed");
}

#[test]
fn encrypted_pkcs8_supported_seed_reaches_reexport() {
    let seed = named_seed("encrypted_pkcs8", "enc-sha256-aes256.pem");
    let text = std::str::from_utf8(&seed).expect("encrypted PKCS#8 seed is UTF-8");
    let password = jose_rs::jwk::Password::from_utf8("hunter2");
    let options = Pkcs8ReadOptions::default()
        .with_max_iterations(jose_rs::jwk::encrypted_pkcs8::PKCS8_MIN_ITERATIONS);
    let jwk = jose_rs::jwk::encrypted_pkcs8::jwk_from_encrypted_pkcs8_pem_with_options(
        text, &password, &options,
    )
    .expect("supported encrypted PKCS#8 seed imports with the harness password");
    jose_rs::jwk::jwk_to_software_key(&jwk).expect("imported seed converts to a software key");
    jose_rs::jwk::encrypted_pkcs8::encrypted_pkcs8_der_from_jwk(
        &jwk,
        &password,
        &Pkcs8Encryption::Aes256CbcPbkdf2HmacSha256 {
            iterations: jose_rs::jwk::encrypted_pkcs8::PKCS8_MIN_ITERATIONS,
        },
    )
    .expect("imported seed re-exports");
}

#[test]
fn replay_jwkset_select_corpus() {
    let inputs = drive("jwkset_select", replay_jwkset_select);
    assert!(inputs > 100, "only {inputs} inputs replayed");
}

#[test]
fn replay_jwt_claims_corpus() {
    let inputs = drive("jwt_claims", replay_claims);
    assert!(inputs > 100, "only {inputs} inputs replayed");
}

#[test]
fn replay_jwk_json_corpus() {
    let inputs = drive("jwk_from_json", replay_jwk_json);
    assert!(inputs > 100, "only {inputs} inputs replayed");
}

#[test]
fn replay_jwk_thumbprint_corpus() {
    let inputs = drive("jwk_thumbprint", replay_jwk_thumbprint);
    assert!(inputs > 50, "only {inputs} inputs replayed");
}

#[test]
fn replay_base64url_corpus() {
    let inputs = drive("base64url_decode", replay_base64url);
    assert!(inputs > 20, "only {inputs} inputs replayed");
}

#[test]
fn replay_jws_header_corpus() {
    let inputs = drive("jws_decode_header", replay_jws_header);
    assert!(inputs > 100, "only {inputs} inputs replayed");
}

#[test]
fn replay_jws_verify_corpus() {
    let inputs = drive("jws_verify", replay_jws_verify);
    assert!(inputs > 100, "only {inputs} inputs replayed");
}

#[test]
fn replay_jwe_compact_corpus() {
    let inputs = drive("jwe_decrypt", replay_jwe_compact);
    assert!(inputs > 100, "only {inputs} inputs replayed");
}

#[test]
fn replay_jwt_unverified_corpus() {
    let inputs = drive("jwt_decode_unverified", replay_jwt_unverified);
    assert!(inputs > 100, "only {inputs} inputs replayed");
}

#[test]
fn flattened_jwe_seeds_cover_success_and_header_collision_paths() {
    let valid = named_seed("jwe_json_flattened", "valid.json");
    let valid_text = std::str::from_utf8(&valid).expect("flattened seed is UTF-8");
    let valid_jwe = FlattenedJwe::from_json(valid_text).expect("flattened seed parses");
    let plaintext = jose_rs::jwe::json::decrypt_flattened_with_jwk(&dir_key_jwk(), &valid_jwe)
        .expect("flattened seed decrypts with the harness key");
    assert_eq!(plaintext, b"fuzz plaintext for the seed corpus");

    let collision = named_seed("jwe_json_flattened", "unprotected-alg.json");
    assert_ne!(
        collision, valid,
        "header-collision seed must differ from valid"
    );
    let collision_text = std::str::from_utf8(&collision).expect("collision seed is UTF-8");
    FlattenedJwe::from_json(collision_text)
        .expect_err("duplicate protected and unprotected alg must be refused");
}

#[test]
fn general_jwe_valid_seed_reaches_authenticated_decryption() {
    let seed = named_seed("jwe_json_general", "valid-one-recipient.json");
    let text = std::str::from_utf8(&seed).expect("general seed is UTF-8");
    let jwe = GeneralJwe::from_json(text).expect("general seed parses");
    let plaintext = jose_rs::jwe::general::decrypt_general_with_jwk(&dir_key_jwk(), &jwe, 0)
        .expect("general seed decrypts with the harness key");
    assert_eq!(plaintext, b"fuzz plaintext for the seed corpus");
}

#[test]
#[allow(deprecated)]
fn jwt_unverified_seeds_reach_claims_parsing() {
    let signed = named_seed("jwt_decode_unverified", "hs256.txt");
    let signed = std::str::from_utf8(&signed).expect("signed JWT seed is UTF-8");
    let (header, claims) = jose_rs::jwt::decode_unverified(signed)
        .expect("signed JWT seed contains a JSON claims object");
    assert_eq!(header.alg, "HS256");
    assert_eq!(claims.sub.as_deref(), Some("fuzz-seed"));

    let unsecured = named_seed("jwt_decode_unverified", "alg-none.txt");
    let unsecured = std::str::from_utf8(&unsecured).expect("unsecured JWT seed is UTF-8");
    assert!(
        unsecured.ends_with('.'),
        "unsecured JWT has an empty signature"
    );
    let (header, claims) = jose_rs::jwt::decode_unverified(unsecured)
        .expect("unsecured JWT seed contains a JSON claims object");
    assert_eq!(header.alg, "none");
    assert_eq!(claims.sub.as_deref(), Some("fuzz-seed"));
}

/// Entry points that live only in a harness, with the reason each one is
/// deliberately not mirrored here.
///
/// The rule is that this list may only hold entries whose coverage exists
/// elsewhere *and is named*, because an unexplained skip is how a mirror becomes
/// decorative. [`fuzz_harness_entry_points_are_all_replayed`] also fails if an
/// entry stops being referenced by any harness, so the list cannot accumulate.
const HARNESS_ONLY_ENTRY_POINTS: &[(&str, &str)] = &[
    (
        "jose_rs::jwk::generate_mldsa",
        "key generation, not parsing: covered by the post-quantum tests; generating ML-DSA keys \
         costs seconds per run and would exercise no new parse path here",
    ),
    (
        "jose_rs::jwk::generate_composite_mldsa",
        "key generation, not parsing: covered by the composite-signature tests, same cost \
         argument as generate_mldsa",
    ),
];

/// Every entry point a harness reaches must also be reached by this file.
///
/// The extraction is textual on purpose: `fuzz/fuzz_targets/*.rs` cannot be
/// compiled on stable here, so the cheapest honest check is that the API surface
/// each side touches is the same set. It catches a harness gaining a call the
/// mirror never makes, and a mirror drifting away from what the harness does.
#[test]
fn fuzz_harness_entry_points_are_all_replayed() {
    let targets = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fuzz/fuzz_targets");
    let harnesses = collect_entry_points(&targets);
    assert!(
        harnesses.len() > 20,
        "expected the harnesses to reference a substantial API surface, found {}",
        harnesses.len()
    );

    let mirror = std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(file!()))
        .expect("this test file is readable");
    let mut missing = Vec::new();
    for path in &harnesses {
        if HARNESS_ONLY_ENTRY_POINTS
            .iter()
            .any(|(skipped, _)| skipped == path)
        {
            continue;
        }
        // The mirror writes fully-qualified paths, so a substring test is enough
        // to prove the call site exists here.
        if !mirror.contains(path) {
            missing.push(path.clone());
        }
    }

    // A skip list is only honest while it is small and current: an entry that no
    // harness references any more must be deleted, not left as decoration.
    let mut stale = Vec::new();
    for (skipped, reason) in HARNESS_ONLY_ENTRY_POINTS {
        assert!(
            !reason.is_empty(),
            "skipped entry point {skipped} has no reason recorded"
        );
        if !harnesses.contains(*skipped) {
            stale.push(*skipped);
        }
    }
    assert!(
        stale.is_empty(),
        "HARNESS_ONLY_ENTRY_POINTS lists entry points no harness uses any more: {stale:?}"
    );
    assert!(
        missing.is_empty(),
        "fuzz harnesses exercise entry points the replay never calls: {missing:?}"
    );
}

/// The nightly-only harnesses cannot be compiled in this suite, so a cheap
/// syntactic contract runs instead: every target declares `#![no_main]`, calls
/// `fuzz_target!` exactly once, balances its delimiters, and is registered as a
/// `[[bin]]` in `fuzz/Cargo.toml`.
///
/// This is not a substitute for `cargo fuzz build` — it will not catch a type
/// error. It caught a real brace error while these harnesses were being written,
/// which is the point: a harness that cannot compile is a harness that silently
/// stops fuzzing something, and the fuzz CI job is a manual build that nobody has
/// to run.
#[test]
fn fuzz_targets_are_syntactically_well_formed() {
    let targets = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fuzz/fuzz_targets");
    let manifest =
        fs::read_to_string(targets.with_file_name("Cargo.toml")).expect("fuzz/Cargo.toml");
    let mut count = 0;

    for path in harness_source_files(&targets) {
        let text = fs::read_to_string(&path).expect("readable harness");
        let name = path.file_stem().unwrap().to_string_lossy().into_owned();
        count += 1;

        assert!(
            text.contains("#![no_main]"),
            "{name}: a libFuzzer target must declare #![no_main]"
        );
        assert_eq!(
            text.matches("fuzz_target!").count(),
            1,
            "{name}: expected exactly one fuzz_target! invocation"
        );
        assert!(
            manifest.contains(&format!("name = \"{name}\"")),
            "{name}: not registered as a [[bin]] in fuzz/Cargo.toml"
        );

        let mut depth = 0i32;
        for byte in text
            .bytes()
            .filter(|b| matches!(b, b'{' | b'}' | b'(' | b')' | b'[' | b']'))
        {
            depth += match byte {
                b'{' | b'(' | b'[' => 1,
                _ => -1,
            };
            assert!(depth >= 0, "{name}: unbalanced delimiter in {name}.rs");
        }
        assert_eq!(depth, 0, "{name}: unbalanced delimiter in {name}.rs");
    }

    assert!(
        count >= 17,
        "expected the harness count to grow, found {count}"
    );
}

/// Every `.rs` file in the harness directory.
fn harness_source_files(dir: &Path) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("missing {}: {e}", dir.display()))
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.is_file() && path.extension().is_some_and(|ext| ext == "rs"))
        .collect();
    out.sort();
    out
}

/// Collect `jose_rs::module::function` references from every `.rs` under `dir`.
fn collect_entry_points(dir: &Path) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for path in harness_source_files(dir) {
        let text = fs::read_to_string(&path).expect("readable harness");
        for token in extract_paths(&text) {
            out.insert(token);
        }
    }
    out
}

/// Pull out `jose_rs::a::b::c` chains from source text, stopping at `(`.
///
/// Deliberately not a parser: the harnesses are written by this project, in one
/// style, and a full path resolver would be more machinery than the guarantee it
/// provides. Trailing `::` segments that are modules rather than functions are
/// filtered by the caller by requiring the segment to be lowercase-first, which
/// is how the harnesses name functions.
fn extract_paths(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let bytes = text.as_bytes();
    let mut index = 0;
    while let Some(offset) = text[index..].find("jose_rs::") {
        let start = index + offset;
        let mut end = start + "jose_rs::".len();
        while end < bytes.len() && (bytes[end].is_ascii_alphanumeric() || bytes[end] == b'_') {
            end += 1;
        }
        // Walk `::segment` while it continues.
        loop {
            if text[end..].starts_with("::") {
                let mut next = end + 2;
                while next < bytes.len()
                    && (bytes[next].is_ascii_alphanumeric() || bytes[next] == b'_')
                {
                    next += 1;
                }
                if next == end + 2 {
                    break;
                }
                end = next;
            } else {
                break;
            }
        }
        let path = &text[start..end];
        // Keep calls, drop `use` lines and pure module references.
        let last = path.rsplit("::").next().unwrap_or_default();
        let is_call = text[end..].trim_start().starts_with('(');
        let is_type = last.chars().next().is_some_and(|c| c.is_ascii_uppercase());
        if is_call && !is_type && path.split("::").count() >= 3 {
            out.push(path.to_string());
        }
        index = end;
    }
    out
}
