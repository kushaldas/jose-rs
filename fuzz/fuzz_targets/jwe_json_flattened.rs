#![no_main]

use libfuzzer_sys::fuzz_target;

use jose_rs::jwe::json::FlattenedJwe;
use jose_rs::jwk::Jwk;

// Flattened JSON JWE, end to end: parse the document, read the headers that are
// *not* authenticated, then decrypt.
//
// The interesting failures here are not "bad bytes cause an error" — they are
// the header-union rules. `FlattenedJwe` carries `protected`, `unprotected` and
// the top-level `header` bag, and the same member may legitimately appear in
// one and not twice. A document can therefore arrive that says `alg` in two
// places, or puts `epk`/`iv`/`tag`/`p2c` in cleartext where only the protected
// copy is authoritative. Every one of those rules is a refusal in this crate,
// and the refusal must fire before any key material is consulted.
//
// The key is a fixed `dir` content key for A256GCM, built once per iteration
// (cheap: it is a 32-byte symmetric key). AEAD failure is the expected outcome
// for most inputs; a panic, or plaintext released by a document whose protected
// header was tampered with, is the finding.
fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };

    let Ok(jwe) = FlattenedJwe::from_json(text) else {
        return;
    };

    // Round-trip the parse: a document that decodes must re-encode into
    // something that decodes to the same structure. That is how a
    // representation bug (a dropped member, a reordered duplicate) shows up
    // without needing a second, independent parser to agree with the first.
    if let Ok(json) = jwe.to_json() {
        if let Ok(again) = FlattenedJwe::from_json(&json) {
            assert_eq!(again, jwe, "parse/emit round-trip changed the document");
        }
    }

    // Header reads that must be pure functions over the document.
    let _ = jose_rs::jwe::json::decode_header(&jwe);
    let _ = jwe.peek_protected_header();
    let _ = jwe.peek_alg();
    let _ = jwe.peek_jose_header();

    let jwk = match content_key_jwk() {
        Some(jwk) => jwk,
        None => return,
    };
    let _ = jose_rs::jwe::json::decrypt_flattened_with_jwk(&jwk, &jwe);
    let _ =
        jose_rs::jwe::json::decrypt_flattened_with_jwk_and_aad(&jwk, &jwe, b"fuzz-external-aad");
});

/// A `dir` + A256GCM content key as a JWK, from fixed bytes.
fn content_key_jwk() -> Option<Jwk> {
    // Public corpus material, intentionally identical to the seed generator
    // and stable replay key so valid seeds reach authenticated decryption.
    let material = [0x5au8; 32];
    let encoded = jose_rs::base64url::encode(&material);
    let text = format!(r#"{{"kty":"oct","alg":"dir","kid":"fuzz-dir-key","k":"{encoded}"}}"#);
    Jwk::from_json(&text).ok()
}
