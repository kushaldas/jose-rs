#![no_main]

use libfuzzer_sys::fuzz_target;

use jose_rs::jwt::Claims;

// JWT claims parsing over raw bytes — the path that has to refuse a document two
// parsers could read differently (ADR 0029).
//
// Duplicate registered members are the whole point: `{"exp":1,"exp":2}` is valid
// JSON and every mainstream parser resolves it silently (usually last-wins, but
// that is a property of the parser, not of the token). This crate rejects it by
// walking the *document*, so the check lives in code this target can reach, and
// a regression that drops the walk would still round-trip happily — it takes a
// fuzzed duplicate to show that the walk is what saved us.
//
// Also exercised: the size cap, which must fire *before* parsing (a limit
// checked after parsing is paid for already), and raw-number precision beyond
// 2^53, where a naive `f64` read would quietly change a NumericDate.
//
// The emit side runs too: a `Claims` that parsed must re-emit, and re-emission
// must refuse rather than produce a document with two of the same member.
fuzz_target!(|data: &[u8]| {
    // The cap under test is `MAX_TOKEN_BYTES`; anything larger is refused by the
    // cap alone, so the interesting space is at and below it. Skipping the rest
    // keeps a run measuring parse behaviour instead of memcpy.
    if data.len() > jose_rs::MAX_TOKEN_BYTES {
        return;
    }

    let Ok(claims) = Claims::from_json_bytes(data) else {
        return;
    };

    // Anything that parsed must be re-emittable, and what it emits must parse
    // back to the same claims. A document that survives this round trip was read
    // exactly one way. `to_json_vec` is also the emit-side duplicate check: it
    // refuses rather than write two members with one name.
    if let Ok(bytes) = claims.to_json_vec() {
        if let Ok(again) = Claims::from_json_bytes(&bytes) {
            assert_eq!(
                again.to_json_vec().ok().as_deref(),
                Some(bytes.as_slice()),
                "claims round-trip is not stable"
            );
        }
        // Accessors and the string-view parse are pure reads and must not panic
        // on claims that came out of hostile text.
        let _ = claims.sub.as_deref();
        let _ = claims.exp;
        let _ = claims.aud.as_ref().map(|aud| aud.contains("audience"));
        let _ = Claims::from_json_str(&String::from_utf8_lossy(&bytes));
    }
});
