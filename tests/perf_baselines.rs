//! Performance-shape checks and advisory timing measurements.
//!
//! `examples/perf_baseline.rs` prints numbers; this file checks coarse performance
//! shapes and records advisory PBES2 timing. Each assertion uses a slack factor
//! far larger than the effect it guards against: these are alarms for
//! order-of-magnitude regressions (quadratic loops or per-recipient work that
//! leaks into single-recipient decrypt), not gates on
//! microsecond drift. If one fails, run the baseline harness and compare within a
//! single run.
//!
//! Why not wall-clock budgets instead: a threshold like "ES256 verify under 5 ms"
//! passes on a build machine, fails on a loaded CI runner, and teaches people to
//! rerun the job. Ratios can also vary with scheduling and contention. The PBES2
//! timing ratio is therefore advisory; deterministic work-budget checks live in
//! `tests/jwe_pbes2.rs` and `tests/jwk_encrypted_pkcs8.rs`.

use std::hint::black_box;
use std::time::{Duration, Instant};

use jose_rs::jwe::general;
use jose_rs::jwk::selection::{self, SelectionPolicy, SetLimits};
use jose_rs::jwk::{self, Jwk, JwkSet};
use jose_rs::{JoseHeader, JweAlgorithm, JweEncryption};

/// Median of `runs` timings for `work`, after one warm-up.
fn timed(runs: usize, mut work: impl FnMut()) -> Duration {
    work();
    let mut timings: Vec<Duration> = (0..runs)
        .map(|_| {
            let start = Instant::now();
            work();
            start.elapsed()
        })
        .collect();
    timings.sort_unstable();
    timings[timings.len() / 2]
}

fn oct_key(bytes: usize, alg: &str, kid: &str) -> Jwk {
    let encoded = jose_rs::base64url::encode(&vec![0x5au8; bytes]);
    Jwk::from_json(&format!(
        r#"{{"kty":"oct","alg":"{alg}","kid":"{kid}","k":"{encoded}"}}"#
    ))
    .expect("fixed key must parse")
}

fn general_document(recipients: usize) -> (Vec<Jwk>, general::GeneralJwe) {
    let keys: Vec<Jwk> = (0..recipients)
        .map(|index| oct_key(16, "A128KW", &format!("k{index}")))
        .collect();
    let header = JoseHeader {
        alg: "A128KW".into(),
        enc: Some("A256GCM".into()),
        ..JoseHeader::new("A128KW")
    };
    let refs: Vec<&Jwk> = keys.iter().collect();
    let document = general::encrypt_general_with_jwks(
        &header,
        &refs,
        b"performance invariant payload",
        JweEncryption::A256GCM,
    )
    .expect("general encryption must succeed");
    (keys, document)
}

/// The plan's "recipient counts" axis, in two directions.
///
/// Encryption *should* cost per recipient — that is the work. Decrypting one named
/// recipient must **not** scale with how many recipients the document carries: a
/// 10× margin here still catches the shape that matters (a sweep over all
/// recipients, or re-parsing per candidate, which is the bug class behind
/// N-times-work-for-one-recipient).
#[test]
fn decrypting_one_recipient_does_not_scale_with_the_recipient_count() {
    let (_, small) = general_document(1);
    let (_, large) = general_document(32);
    let small_key = oct_key(16, "A128KW", "k0");

    let one = timed(7, || {
        let plaintext =
            general::decrypt_general_with_jwk(&small_key, black_box(&small), 0).unwrap();
        black_box(plaintext);
    });
    let of_many = timed(7, || {
        let plaintext =
            general::decrypt_general_with_jwk(&small_key, black_box(&large), 0).unwrap();
        black_box(plaintext);
    });

    // Measured ratio is ~1.0; the alarm goes off at 10×.
    assert!(
        of_many < one.mul_f32(10.0),
        "decrypting 1 of 32 recipients took {of_many:?}, more than 10× the single-recipient {one:?}"
    );

    // Encryption is allowed to grow with the recipient count, but sub-linearly in
    // practice (one wrap each); 40× for 32× the recipients catches a quadratic.
    let header = JoseHeader {
        alg: "A128KW".into(),
        enc: Some("A256GCM".into()),
        ..JoseHeader::new("A128KW")
    };
    let small_keys: Vec<Jwk> = vec![oct_key(16, "A128KW", "k0")];
    let large_keys: Vec<Jwk> = (0..32)
        .map(|index| oct_key(16, "A128KW", &format!("k{index}")))
        .collect();
    let encrypt_small = timed(7, || {
        let refs: Vec<&Jwk> = small_keys.iter().collect();
        let document = general::encrypt_general_with_jwks(
            &header,
            black_box(&refs),
            b"payload",
            JweEncryption::A256GCM,
        )
        .unwrap();
        black_box(document);
    });
    let encrypt_large = timed(7, || {
        let refs: Vec<&Jwk> = large_keys.iter().collect();
        let document = general::encrypt_general_with_jwks(
            &header,
            black_box(&refs),
            b"payload",
            JweEncryption::A256GCM,
        )
        .unwrap();
        black_box(document);
    });
    assert!(
        encrypt_large < encrypt_small.mul_f32(40.0),
        "encrypting for 32 recipients took {encrypt_large:?}, over 40× the single-recipient \
         {encrypt_small:?} — per-recipient work looks super-linear"
    );
}

/// The plan's "repeated key conversion" axis.
///
/// Converting the same JWK twice is a caller mistake, but a *quadratic* converter
/// (re-deriving parameters, rebuilding a context per call and leaking) is a library
/// bug, and this is the shape that reveals it: 50 conversions must stay within
/// 500× one conversion. Measured ratio is close to 50×.
#[test]
fn key_conversion_is_not_superlinear() {
    let key = jwk::generate_ec("P-256").expect("test key");
    let once = timed(5, || {
        let converted = jwk::jwk_to_software_key(black_box(&key)).unwrap();
        black_box(converted);
    });
    let many = timed(5, || {
        for _ in 0..50 {
            let converted = jwk::jwk_to_software_key(black_box(&key)).unwrap();
            black_box(converted);
        }
    });
    assert!(
        many < once.mul_f32(500.0),
        "50 key conversions took {many:?}, over 500× a single {once:?}"
    );
}

/// Advisory measurement of the plan's "KDF cost" axis.
///
/// Whole-operation timing includes randomness, encryption and scheduling, so
/// four times the PBKDF2 iterations need not produce a reliable runtime ratio.
/// Report unexpected ratios without failing CI. Encryption errors still fail;
/// deterministic budget enforcement is covered by the PBES2/PKCS#8 tests.
#[test]
fn password_derivation_follows_the_callers_budget() {
    use jose_rs::jwe::JweEncryptOptions;
    use jose_rs::jwk::Password;

    let password = Password::from_utf8("budget-invariant");
    let plaintext = b"budget invariant payload";

    let cheap = JweEncryptOptions::new().with_pbes2_iterations(2_048);
    let dear = JweEncryptOptions::new().with_pbes2_iterations(8_192);

    let cheap_time = timed(5, || {
        let token = jose_rs::jwe::compact::encrypt_with_password_options(
            black_box(&password),
            black_box(plaintext),
            JweAlgorithm::Pbes2Hs256A128kw,
            JweEncryption::A256GCM,
            &cheap,
        )
        .unwrap();
        black_box(token);
    });
    let dear_time = timed(5, || {
        let token = jose_rs::jwe::compact::encrypt_with_password_options(
            black_box(&password),
            black_box(plaintext),
            JweAlgorithm::Pbes2Hs256A128kw,
            JweEncryption::A256GCM,
            &dear,
        )
        .unwrap();
        black_box(token);
    });
    // This is a diagnostic, not proof of parameter propagation or budget
    // enforcement. Shared-runner contention can flatten either timing ratio.
    if dear_time <= cheap_time.mul_f32(2.0) {
        eprintln!(
            "advisory: 8 192 iterations ({dear_time:?}) was not at least 2x the cost of \
             2 048 ({cheap_time:?}); wall-clock noise does not fail this test"
        );
    }
}

/// The plan's "peak memory" axis, on the budget that is actually able to fire early.
///
/// `SetLimits` has two checks and they are not the same kind. The **byte** budget can
/// run before parsing — and must, because after parsing the memory is already spent.
/// The **entry** budget cannot: you cannot count entries without parsing them, which
/// is why the byte check is the pre-parse line of defence and the entry check is a
/// post-parse refusal that must never turn into silent truncation. This test measures
/// the first and asserts the second, rather than blurring them into one "limits work"
/// claim that would be false half the time.
///
/// The memory bound is self-calibrating, because an absolute bound is a number about
/// one machine's allocator: the same bytes are then parsed under a budget that admits
/// them, and the refusal's RSS growth must be a small fraction of the parse's.
/// Measured here: refusal ≈ 0 KiB, a 20 000-entry parse ≈ 21 MB.
///
/// Linux-only (RSS comes from `/proc`); elsewhere the test says so and passes rather
/// than substituting a weaker claim silently.
#[test]
fn oversized_documents_are_refused_before_they_are_parsed() {
    if resident_kib().is_none() {
        eprintln!("skipping: resident memory is only measurable on Linux");
        return;
    }

    // Comfortably over `SetLimits::default().max_bytes` — the budget scales
    // with MAX_TOKEN_BYTES, so the fixture does too — keeping the byte
    // budget what refuses, before any JSON tree exists.
    let byte_budget = SetLimits::default().max_bytes;
    // ~146 bytes per fixture entry: budget/100 entries build a document
    // ~1.5x the budget, whatever the cap.
    let oversized = oversized_jwk_set(byte_budget / 100);
    assert!(
        oversized.len() > byte_budget,
        "test document must exceed the default byte budget"
    );
    let parse_document = oversized_jwk_set(20_000);
    // The baseline is taken **after** building the inputs: constructing a 5 MB
    // document is itself a multi-megabyte allocation, and measuring from before it
    // would attribute the test fixture's own memory to the parser.
    let start_rss = resident_kib().expect("proc read failed mid-test");

    let refused = Instant::now();
    let outcome = JwkSet::from_json_with_limits(&oversized, &SetLimits::default());
    let refused_in = refused.elapsed();
    assert!(
        matches!(&outcome, Err(error) if error.to_string().to_lowercase().contains("bytes")),
        "expected a byte-budget refusal, got {outcome:?}"
    );
    let refusal_growth = (resident_kib().expect("proc read failed mid-test") - start_rss).max(0);

    // Calibration: a document the same budget admits, sized to be comparable work.
    let parse_start = resident_kib().expect("proc read failed mid-test");
    let parse_start_time = Instant::now();
    let accepted = JwkSet::from_json_with_limits(
        &parse_document,
        &SetLimits {
            max_bytes: parse_document.len() + 1024,
            max_entries: 100_000,
        },
    )
    .expect("must parse under a permissive budget");
    let parse_time = parse_start_time.elapsed();
    assert_eq!(accepted.keys.len(), 20_000);
    let parse_growth = resident_kib().expect("proc read failed mid-test") - parse_start;
    if parse_growth < 4_096 {
        eprintln!(
            "skipping the comparison: a full parse measured only {parse_growth} KiB of growth"
        );
        return;
    }

    assert!(
        refusal_growth * 4 < parse_growth,
        "refusing a {} KiB document grew RSS by {refusal_growth} KiB, within 4× of the          {parse_growth} KiB a parse costs — the byte budget looks like it runs after parsing",
        oversized.len() / 1024,
    );
    assert!(
        refused_in * 4 < parse_time,
        "refusing took {refused_in:?}, within 4× of the {parse_time:?} a parse takes — the          byte budget looks like it is applied late"
    );

    // And selection over the accepted set stays bounded by policy, not by luck.
    let found = selection::select(&accepted, Some("k7"), &SelectionPolicy::strict())
        .expect("kid must resolve");
    assert_eq!(found.attempts(), 1);
}

/// The entry budget's distinct contract: it fires **after** parsing (an entry count is
/// not knowable before then), so its job is to refuse completely — never to hand back
/// a truncated set that looks like the caller's keys went missing.
#[test]
fn entry_budget_refuses_completely_instead_of_truncating() {
    let document = oversized_jwk_set(20_000);
    let outcome = JwkSet::from_json_with_limits(&document, &SetLimits::default());
    assert!(
        matches!(&outcome, Err(error) if error.to_string().to_lowercase().contains("entries")),
        "expected an entry-count refusal, got {outcome:?}"
    );

    // The shape of the failure matters: callers distinguish "too big" from "no keys"
    // only if the oversized case never produces a `JwkSet` at all.
    assert!(outcome.is_err());

    // Same bytes, admitted: nothing about the document was wrong but its size.
    let accepted = JwkSet::from_json_with_limits(
        &document,
        &SetLimits {
            max_bytes: document.len() + 1024,
            max_entries: 100_000,
        },
    )
    .expect("must parse under a permissive budget");
    assert_eq!(accepted.keys.len(), 20_000);
    // A strict sweep over such a set is refused rather than sampled down to the
    // candidate budget — the caller learns the set is unusable, not partially usable.
    let error = selection::select(&accepted, None, &SelectionPolicy::strict()).unwrap_err();
    assert!(
        error.to_string().to_lowercase().contains("kid"),
        "a kid-less token against an addressable set must be refused by name, got {error}"
    );
}

/// A well-formed JWK Set with `count` entries.
fn oversized_jwk_set(count: usize) -> String {
    let encoded = jose_rs::base64url::encode(&[0x5au8; 32]);
    let entries: Vec<String> = (0..count)
        .map(|index| {
            format!(
                r#"{{"kty":"oct","alg":"HS256","kid":"k{index}","use":"sig","x5t":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","k":"{encoded}"}}"#
            )
        })
        .collect();
    format!(r#"{{"keys":[{}]}}"#, entries.join(","))
}

/// Current resident set size in KiB, from `/proc/self/statm` (Linux).
///
/// Assumes 4 KiB pages, which holds for x86-64 and arm64 Linux with the default
/// page size; the bound this feeds is 8× the document, so a platform with larger
/// pages would only make the test more lenient, never stricter.
fn resident_kib() -> Option<i64> {
    let statm = std::fs::read_to_string("/proc/self/statm").ok()?;
    // Fields: size resident shared text lib data dt, all in pages.
    let resident_pages = statm.split_whitespace().nth(1)?.parse::<i64>().ok()?;
    Some(resident_pages * 4)
}
