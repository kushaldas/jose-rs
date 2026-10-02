#![no_main]

use libfuzzer_sys::fuzz_target;

use jose_rs::jwk::selection::{self, SelectionPolicy, SetLimits};
use jose_rs::jwk::JwkSet;

// JWK Set parsing, diagnostics and selection.
//
// This is the one path where attacker-controlled data decides *how many keys
// we try*, so the bounds are the product under test:
//
//   * `SetLimits` is checked against the raw bytes before parsing and against
//     the entry count after — a limit checked only after parsing is memory
//     already spent;
//   * `SelectionPolicy::max_candidates` makes an over-wide sweep an error
//     rather than a silent truncation;
//   * `diagnostics` runs the *real* key converter over every entry, so a
//     malformed entry is classified here rather than exploding later in a
//     caller's loop.
//
// The fuzzer supplies the document and the token `kid`. It does not supply the
// policy: a caller choosing `Fallback::TryAll` is a decision this crate must be
// able to refuse *without* being talked into it, so the harness uses the strict
// policy and the `TryAll` one is exercised (also refusing) only through
// `tests/jwk_selection.rs`, where the expectation is explicit.
fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };

    // Two limit settings: the shipped defaults, and a tight pair that should
    // refuse most inputs. Both must return, not hang or crash.
    for limits in [SetLimits::default(), SetLimits { max_bytes: 4096, max_entries: 4 }] {
        let Ok(set) = JwkSet::from_json_with_limits(text, &limits) else {
            continue;
        };

        // Classification of every entry, including unusable ones.
        for diagnostic in selection::diagnostics(&set) {
            let _ = diagnostic.status.is_usable();
        }

        // Selection over a kid drawn from the set, plus a kid that is not in
        // it, plus no kid at all — the three shapes a real token arrives as.
        let kids: Vec<Option<String>> = set
            .keys
            .iter()
            .take(8)
            .map(|key| key.kid.clone())
            .chain([Some("absent-kid".into()), None])
            .collect();
        // `strict()` already allows one candidate, so the second policy varies
        // the other two dials: a fallback sweep is permitted, but still bounded.
        for policy in [
            SelectionPolicy::strict(),
            SelectionPolicy {
                max_candidates: 4,
                fallback: selection::Fallback::TryWhenUnaddressable,
                require_kid: false,
            },
        ] {
            for kid in &kids {
                if let Ok(selection) = selection::select(&set, kid.as_deref(), &policy) {
                    // Attempt counts are a caller-visible bound and must be
                    // internally consistent.
                    assert!(selection.attempts() <= policy.max_candidates);
                    for key in selection.candidates {
                        let _ = jose_rs::jwk::jwk_to_software_key(key);
                    }
                }
            }
        }
    }
});
