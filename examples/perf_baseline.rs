//! Reproducible performance baseline for the paths this crate can make slow.
//!
//! ```sh
//! cargo run --release --example perf_baseline              # markdown table
//! cargo run --release --example perf_baseline -- --json    # machine-readable
//! cargo run --release --example perf_baseline -- --slow    # include the expensive settings
//! ```
//!
//! # Why a harness in the repo and numbers in the pull request
//!
//! A committed baseline table is a table about one machine. It goes stale on the
//! next CPU and, worse, reads like a contract while measuring a laptop. So the
//! *procedure* is versioned here and the numbers belong in the PR that changes
//! them — `docs/performance-baseline.md` explains what to run and what to compare.
//! What the repository does enforce in code is shape, not speed: see
//! `tests/perf_baselines.rs` for the invariants that hold on any machine.
//!
//! # Reading the table
//!
//! Each row is `median` of `--repeats` timed runs after one warm-up, on a single
//! thread, with the value under test kept alive so the optimizer cannot delete the
//! work. `per unit` divides by the row's `n` where that is meaningful (recipients,
//! iterations, keys), which is the column worth comparing across a change.

use std::fmt::Write as _;
use std::hint::black_box;
use std::time::{Duration, Instant};

use jose_rs::jwe::general::{self, GeneralJwe};
use jose_rs::jwk::selection::{self, SelectionPolicy, SetLimits};
use jose_rs::jwk::{self, Jwk, JwkSet};
use jose_rs::jws::compact;
use jose_rs::{JoseHeader, JweAlgorithm, JweEncryption};

/// Timed runs per row. Enough that the median is stable for millisecond-scale
/// work without turning the run into a benchmark suite.
const REPEATS: usize = 9;

struct Row {
    group: &'static str,
    label: String,
    n: usize,
    median: Duration,
    best: Duration,
    note: &'static str,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let json_output = args.iter().any(|a| a == "--json");
    let slow = args.iter().any(|a| a == "--slow");

    let mut rows = Vec::new();
    signature_rows(&mut rows)?;
    jwe_rows(&mut rows)?;
    recipient_rows(&mut rows)?;
    conversion_rows(&mut rows)?;
    parse_rows(&mut rows)?;
    password_rows(&mut rows, slow)?;
    #[cfg(feature = "post-quantum")]
    post_quantum_rows(&mut rows)?;

    if json_output {
        let mut out = String::from("[\n");
        for (index, row) in rows.iter().enumerate() {
            let _ = writeln!(
                out,
                "  {{\"group\":\"{}\",\"label\":\"{}\",\"n\":{},\"median_us\":{},\"best_us\":{},\"note\":\"{}\"}}{}",
                row.group,
                row.label,
                row.n,
                row.median.as_micros(),
                row.best.as_micros(),
                row.note,
                if index + 1 == rows.len() { "" } else { "," }
            );
        }
        out.push_str("]\n");
        print!("{out}");
    } else {
        println!("# jose-rs performance baseline");
        println!();
        println!(
            "repeats = {REPEATS} (median of best-effort runs, single thread, release profile)"
        );
        println!();
        let mut group = "";
        for row in &rows {
            if row.group != group {
                group = row.group;
                println!();
                println!("## {group}");
                println!();
                println!("| case | n | median | best | per unit | note |");
                println!("|---|---:|---:|---:|---:|---|");
            }
            let per_unit = if row.n > 1 {
                format!("{:.1} µs", row.median.as_micros() as f64 / row.n as f64)
            } else {
                String::from("—")
            };
            println!(
                "| {} | {} | {} µs | {} µs | {} | {} |",
                row.label,
                row.n,
                row.median.as_micros(),
                row.best.as_micros(),
                per_unit,
                row.note,
            );
        }
        println!();
        println!("_Numbers describe the machine that printed them. Compare rows within");
        println!("one run; do not diff this table across machines._");
    }
    Ok(())
}

fn measure(
    rows: &mut Vec<Row>,
    group: &'static str,
    label: impl Into<String>,
    n: usize,
    note: &'static str,
    mut work: impl FnMut(),
) {
    // Warm-up: allocator and branch predictors, plus the first touch of any
    // lazily-initialized tables in the backend.
    work();
    let mut timings = Vec::with_capacity(REPEATS);
    for _ in 0..REPEATS {
        let start = Instant::now();
        work();
        timings.push(start.elapsed());
    }
    timings.sort_unstable();
    rows.push(Row {
        group,
        label: label.into(),
        n,
        median: timings[timings.len() / 2],
        best: timings[0],
        note,
    });
}

fn signature_rows(rows: &mut Vec<Row>) -> Result<(), Box<dyn std::error::Error>> {
    let payload = vec![0x11u8; 1024];
    for (label, crv_or_size) in [("HS256", ""), ("ES256", ""), ("Ed25519", "")] {
        let key = signature_key(label, crv_or_size)?;
        let header = JoseHeader::new(label);
        let token = compact::sign_with_jwk(&key, &payload, &header)?;

        measure(
            rows,
            "sign / verify",
            format!("{label} sign"),
            1,
            "1 KiB payload",
            || {
                let token = compact::sign_with_jwk(&key, black_box(&payload), &header).unwrap();
                black_box(token);
            },
        );
        measure(
            rows,
            "sign / verify",
            format!("{label} verify"),
            1,
            "1 KiB payload",
            || {
                let payload = compact::verify_with_jwk(&key, black_box(&token)).unwrap();
                black_box(payload);
            },
        );
    }
    Ok(())
}

fn jwe_rows(rows: &mut Vec<Row>) -> Result<(), Box<dyn std::error::Error>> {
    let plaintext = vec![0x22u8; 4096];
    for (label, enc) in [
        ("A128GCM", JweEncryption::A128GCM),
        ("A256GCM", JweEncryption::A256GCM),
        ("A256CBC-HS512", JweEncryption::A256CbcHs512),
    ] {
        // `dir` uses the CEK directly, so the key *is* the content key: its
        // length is dictated by `enc`, not by a fixed fixture.
        let cek = vec![0x5au8; enc.cek_size()];
        let header = JoseHeader {
            alg: "dir".into(),
            enc: Some(label.into()),
            ..JoseHeader::new("dir")
        };
        let token = jose_rs::jwe::compact::encrypt_with_header(
            header.clone(),
            &cek,
            &plaintext,
            JweAlgorithm::Dir,
            enc,
        )?;

        measure(
            rows,
            "JWE compact",
            format!("dir {label} encrypt"),
            1,
            "4 KiB plaintext",
            || {
                let token = jose_rs::jwe::compact::encrypt_with_header(
                    header.clone(),
                    &cek,
                    black_box(&plaintext),
                    JweAlgorithm::Dir,
                    enc,
                )
                .unwrap();
                black_box(token);
            },
        );
        measure(
            rows,
            "JWE compact",
            format!("dir {label} decrypt"),
            1,
            "4 KiB plaintext",
            || {
                let plaintext =
                    jose_rs::jwe::compact::decrypt(black_box(&cek), black_box(&token)).unwrap();
                black_box(plaintext);
            },
        );
    }
    Ok(())
}

/// Recipient count is the axis the plan calls out: a general JWE with N recipients
/// costs N key-management operations, and the cost of *finding* one recipient must
/// not grow with the ones you did not address.
fn recipient_rows(rows: &mut Vec<Row>) -> Result<(), Box<dyn std::error::Error>> {
    for count in [1usize, 8, 32] {
        // AES-KW is the algorithm family the general form supports: `A128GCMKW`
        // needs an `iv` and `tag` per recipient and RFC 7516 gives a recipient
        // element no protected header of its own to carry them in, so that
        // combination is refused for multi-recipient documents (the refusal is the
        // reason this row measures A128KW).
        let kek: Vec<Jwk> = (0..count)
            .map(|index| oct_key(16, "A128KW").map(|key| key.with_kid(&format!("k{index}"))))
            .collect::<Result<_, _>>()?;
        let header = JoseHeader {
            alg: "A128KW".into(),
            enc: Some("A256GCM".into()),
            ..JoseHeader::new("A128KW")
        };
        let plaintext = vec![0x33u8; 1024];
        let refs: Vec<&Jwk> = kek.iter().collect();
        let document =
            general::encrypt_general_with_jwks(&header, &refs, &plaintext, JweEncryption::A256GCM)?;
        let text = document.to_json()?;

        measure(
            rows,
            "general JWE",
            format!("encrypt, {count} recipients"),
            count,
            "1 KiB plaintext, A128KW",
            || {
                let refs: Vec<&Jwk> = kek.iter().collect();
                let document = general::encrypt_general_with_jwks(
                    &header,
                    black_box(&refs),
                    black_box(&plaintext),
                    JweEncryption::A256GCM,
                )
                .unwrap();
                black_box(document);
            },
        );

        let parsed = GeneralJwe::from_json(&text)?;
        measure(
            rows,
            "general JWE",
            format!("decrypt one of {count}"),
            count,
            "recipient 0 only",
            || {
                let plaintext =
                    general::decrypt_general_with_jwk(black_box(&kek[0]), black_box(&parsed), 0)
                        .unwrap();
                black_box(plaintext);
            },
        );
    }
    Ok(())
}

/// Repeated key conversion: the shape of "caller has a JWK and needs a key twice".
fn conversion_rows(rows: &mut Vec<Row>) -> Result<(), Box<dyn std::error::Error>> {
    let key = signature_key("ES256", "")?;
    measure(
        rows,
        "key conversion",
        "JWK → SoftwareKey (EC P-256)",
        1,
        "one conversion",
        || {
            let converted = jwk::jwk_to_software_key(black_box(&key)).unwrap();
            black_box(converted);
        },
    );

    let set = jwk_set(64)?;
    measure(
        rows,
        "JWK Set",
        "diagnostics, 64 entries",
        64,
        "classify every entry",
        || {
            let report = selection::diagnostics(black_box(&set));
            black_box(report.len());
        },
    );
    measure(
        rows,
        "JWK Set",
        "select by kid, 64 entries",
        64,
        "exact match, strict policy",
        || {
            let found =
                selection::select(black_box(&set), Some("k7"), &SelectionPolicy::strict()).unwrap();
            black_box(found.attempts());
        },
    );
    let big = jwk_set(512)?;
    measure(
        rows,
        "JWK Set",
        "parse + limit check, 512 entries",
        512,
        "within budget",
        || {
            let text = set_text(&big);
            let parsed =
                JwkSet::from_json_with_limits(black_box(&text), &SetLimits::default()).unwrap();
            black_box(parsed.keys.len());
        },
    );
    Ok(())
}

fn parse_rows(rows: &mut Vec<Row>) -> Result<(), Box<dyn std::error::Error>> {
    let Ok(pem) = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/cert/rsa_cert.pem"
    )) else {
        return Ok(());
    };
    let der = jose_rs::jwk::cert::public_jwk_from_certificate_pem(&pem).ok();
    let _ = der;
    let pem_for_cert = pem.clone();
    measure(
        rows,
        "parse",
        "certificate PEM → JWK",
        1,
        "RSA-2048, no validation",
        || {
            let extracted =
                jwk::cert::public_jwk_from_certificate_pem(black_box(&pem_for_cert)).unwrap();
            black_box(extracted);
        },
    );

    let Ok(key_pem) = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/pem/ec_pkcs8.pem"
    )) else {
        return Ok(());
    };
    let key_pem = key_pem.clone();
    measure(
        rows,
        "parse",
        "PKCS#8 PEM → JWK (P-256)",
        1,
        "armor + DER + checks",
        || {
            let parsed = jwk::pem::jwk_from_pem(black_box(&key_pem)).unwrap();
            black_box(parsed);
        },
    );

    let claims = br#"{"iss":"https://issuer.example","sub":"subject","aud":["a","b"],"exp":4100000000,"custom":"x"}"#;
    measure(
        rows,
        "parse",
        "claims parse (duplicate-member walk)",
        1,
        "one top-level scan",
        || {
            let parsed = jose_rs::jwt::Claims::from_json_bytes(black_box(claims)).unwrap();
            black_box(parsed);
        },
    );
    Ok(())
}

fn password_rows(rows: &mut Vec<Row>, slow: bool) -> Result<(), Box<dyn std::error::Error>> {
    let password = jose_rs::jwk::Password::from_utf8("baseline-password");
    let plaintext = vec![0x44u8; 256];
    let mut settings = vec![2_048u32, 65_536];
    if slow {
        // The emitted default, and the interop ceiling: two settings that take
        // ~0.2 s and ~1.7 s per derivation, so they are opt-in.
        settings.push(600_000);
    }
    for iterations in settings {
        let opts = jose_rs::jwe::JweEncryptOptions::new().with_pbes2_iterations(iterations);
        measure(
            rows,
            "PBES2",
            format!("PBES2-HS256+A128KW, {iterations} iterations"),
            iterations as usize,
            "cost is the point of the row",
            || {
                let token = jose_rs::jwe::compact::encrypt_with_password_options(
                    black_box(&password),
                    black_box(&plaintext),
                    JweAlgorithm::Pbes2Hs256A128kw,
                    JweEncryption::A256GCM,
                    &opts,
                )
                .unwrap();
                black_box(token);
            },
        );
    }
    Ok(())
}

#[cfg(feature = "post-quantum")]
fn post_quantum_rows(rows: &mut Vec<Row>) -> Result<(), Box<dyn std::error::Error>> {
    let key = jwk::generate_mldsa(kryptering::MlDsaVariant::MlDsa65)?;
    let header = JoseHeader::new("ML-DSA-65");
    let payload = vec![0x55u8; 1024];
    measure(
        rows,
        "post-quantum",
        "ML-DSA-65 sign",
        1,
        "large signature",
        || {
            let token = compact::sign_with_jwk(&key, black_box(&payload), &header).unwrap();
            black_box(token);
        },
    );
    let token = compact::sign_with_jwk(&key, &payload, &header)?;
    measure(
        rows,
        "post-quantum",
        "ML-DSA-65 verify",
        1,
        "large signature",
        || {
            let payload = compact::verify_with_jwk(&key, black_box(&token)).unwrap();
            black_box(payload);
        },
    );
    Ok(())
}

fn signature_key(alg: &str, _unused: &str) -> Result<Jwk, Box<dyn std::error::Error>> {
    let mut key = match alg {
        "HS256" => oct_key(32, "HS256")?,
        "ES256" => jwk::generate_ec("P-256")?,
        "Ed25519" => jwk::generate_ed25519()?,
        other => return Err(format!("unsupported baseline algorithm {other}").into()),
    };
    key.alg = Some(alg.into());
    Ok(key)
}

fn oct_key(len: usize, alg: &str) -> Result<Jwk, Box<dyn std::error::Error>> {
    let material = vec![0x5au8; len];
    let encoded = jose_rs::base64url::encode(&material);
    Ok(Jwk::from_json(&format!(
        r#"{{"kty":"oct","alg":"{alg}","k":"{encoded}"}}"#
    ))?)
}

trait WithKid {
    fn with_kid(self, kid: &str) -> Self;
}

impl WithKid for Jwk {
    fn with_kid(mut self, kid: &str) -> Self {
        self.kid = Some(kid.into());
        self
    }
}

fn jwk_set(count: usize) -> Result<JwkSet, Box<dyn std::error::Error>> {
    let text = set_text_for(count);
    Ok(JwkSet::from_json_with_limits(&text, &SetLimits::default())?)
}

fn set_text(set: &JwkSet) -> String {
    let entries: Vec<String> = set.keys.iter().map(|key| key.to_json().unwrap()).collect();
    format!(r#"{{"keys":[{}]}}"#, entries.join(","))
}

fn set_text_for(count: usize) -> String {
    let material = jose_rs::base64url::encode(&[0x5au8; 32]);
    let entries: Vec<String> = (0..count)
        .map(|index| format!(r#"{{"kty":"oct","alg":"HS256","kid":"k{index}","k":"{material}"}}"#))
        .collect();
    format!(r#"{{"keys":[{}]}}"#, entries.join(","))
}
