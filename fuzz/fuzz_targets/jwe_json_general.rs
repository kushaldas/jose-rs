#![no_main]

use libfuzzer_sys::fuzz_target;

use jose_rs::jwe::general::GeneralJwe;
use jose_rs::jwk::Jwk;

// General JSON JWE: several recipients, one document, and a recipient index the
// *caller* chooses.
//
// This target's reason for existing is the boundary between "recipient" and
// "key". `decrypt_general_with_jwk` takes an index, so a document can name a
// recipient that does not exist, a recipient whose `encrypted_key` belongs to a
// different algorithm, or a recipient whose per-recipient unprotected header
// disagrees with the shared one. Each of those must be a refusal that leaves no
// plaintext behind, and `flatten_for(index)` — the step that turns a general
// document into the flattened shape the shared decrypt path consumes — must
// refuse an out-of-range index rather than clamp it.
//
// Recipient count is also the resource bound this crate owns (`MAX_RECIPIENTS`):
// a document claiming thousands of recipients is refused at parse time, so the
// index loop below can never be driven into an unbounded sweep.
fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };

    let Ok(jwe) = GeneralJwe::from_json(text) else {
        return;
    };

    let _ = jose_rs::jwe::general::decode_header(&jwe);
    let jwk = content_key_jwk();

    // One extra index beyond the end: the out-of-range case is the one that
    // turns a clamp into a wrong-recipient decrypt.
    let indices = 0..=(jwe.recipients.len());
    for index in indices {
        let _ = jwe.peek_jose_header_for(index);
        let _ = jwe.flatten_for(index);
        let _ = jose_rs::jwe::general::decrypt_general_with_jwk(&jwk, &jwe, index);
        let _ = jose_rs::jwe::general::decrypt_general_with_jwk_authenticated(&jwk, &jwe, index);
    }
});

/// A `dir` + A256GCM content key as a JWK; see `jwe_json_flattened`.
fn content_key_jwk() -> Jwk {
    let encoded = jose_rs::base64url::encode(&[0x5au8; 32]);
    let text = format!(r#"{{"kty":"oct","alg":"dir","kid":"fuzz-dir-key","k":"{encoded}"}}"#);
    // Fixed bytes, so this cannot fail; `expect` here is a statement about the
    // harness, not about attacker input.
    Jwk::from_json(&text).expect("fixed dir key must parse")
}
