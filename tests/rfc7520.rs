//! RFC 7520 Examples of Protecting Content Using JOSE — interop test vectors.
//!
//! RFC 7520 is the standards-track companion to RFC 7515/7516/7517/7518
//! that provides worked examples for every JOSE operation. Matching
//! these byte-for-byte is the canonical interop check against other
//! JOSE implementations; every mainstream JOSE library ships the same
//! vectors in its test suite.
//!
//! Covered:
//! - §4.1, §4.2, §4.3, §4.4 — JWS verify (RS256, PS384, ES512, HS256) and
//!   HS256 byte-for-byte roundtrip.
//! - §5.6 (dir + A128GCM), §5.8 (A128KW + A128GCM) — JWE decrypt under
//!   default features.
//! - §5.2 (RSA-OAEP + A256GCM) — JWE decrypt under the `deprecated`
//!   feature (RSA-OAEP uses SHA-1, gated by design).
//!
//! Skipped algorithms this library does not implement: RSA1_5 (§5.1),
//! PBES2 (§5.3), ECDH-ES family (§5.4, §5.5), A*GCMKW (§5.7), zlib
//! compression (§5.9), caller-supplied AAD (§5.10), JSON serialization
//! variants (§5.11–§5.13, §4.5–§4.8).

use jose_rs::jwk::Jwk;
use jose_rs::jws;

/// Strip every ASCII whitespace character (space, tab, CR, LF) from a
/// string. The RFC prints long base64url values across multiple
/// indented lines for readability; section 1.1 of the RFC states that
/// this whitespace is pedagogical and not part of the actual value.
///
/// For the JSON keys here this is safe because the JSON fields we care
/// about contain no whitespace that should be preserved — they are
/// base64url strings plus a handful of short ASCII identifiers.
#[allow(dead_code)]
fn strip_ws(s: &str) -> String {
    s.chars().filter(|c| !c.is_ascii_whitespace()).collect()
}

/// The shared payload used across every JWS example in RFC 7520 §4.
///
/// Note the quote styles: "It’s" and "there’s" use curly right single
/// quotes (U+2019) but "don't" uses a plain ASCII apostrophe. This is
/// exactly how the RFC's base64url encodes the bytes, so the payload
/// must mirror that precisely.
const PAYLOAD: &str = "It\u{2019}s a dangerous business, Frodo, going out your door. You step onto the road, and if you don't keep your feet, there\u{2019}s no knowing where you might be swept off to.";

// ── §4.1: RSA v1.5 Signature, SHA-256 (RS256) ──────────────────────────────

/// RSA public key from RFC 7520 Figure 3.
const RSA_JWK_JSON: &str = r#"{
  "kty": "RSA",
  "kid": "bilbo.baggins@hobbiton.example",
  "use": "sig",
  "n": "n4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8_KuKPEHLd4rHVTeT-O-XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz_AJmSCpMaJMRBSFKrKb2wqVwGU_NsYOYL-QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj-oBHqFEHYpPe7Tpe-OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde3uhGqC0ZCuEHg8lhzwOHrtIQbS0FVbb9k3-tVTU4fg_3L_vniUFAKwuCLqKnS2BYwdq_mzSnbLY7h_qixoR7jig3__kRhuaxwUkRz5iaiQkqgc5gHdrNP5zw",
  "e": "AQAB"
}"#;

/// Compact JWS output from RFC 7520 Figure 13.
const RS256_COMPACT: &str = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImJpbGJvLmJhZ2dpbnNAaG9iYml0b24uZXhhbXBsZSJ9.SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBkb24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcmUgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4.MRjdkly7_-oTPTS3AXP41iQIGKa80A0ZmTuV5MEaHoxnW2e5CZ5NlKtainoFmKZopdHM1O2U4mwzJdQx996ivp83xuglII7PNDi84wnB-BDkoBwA78185hX-Es4JIwmDLJK3lfWRa-XtL0RnltuYv746iYTh_qHRD68BNt1uSNCrUCTJDt5aAE6x8wW1Kt9eRo4QPocSadnHXFxnt8Is9UzpERV0ePPQdLuW3IS_de3xyIrDaLGdjluPxUAhb6L2aXic1U12podGU0KLUQSE_oI-ZnmKJ3F4uOZDnd6QZWJushZ41Axf_fcIe8u9ipH84ogoree7vjbU5y18kDquDg";

#[test]
fn rfc7520_4_1_rs256_verify() {
    let mut jwk = Jwk::from_json(RSA_JWK_JSON).unwrap();
    // The RFC JWK has use=sig, which is what verify_with_jwk requires.
    // Set alg so the JWK-based verify confirms header/jwk alg agreement too.
    jwk.alg = Some("RS256".into());
    let payload = jws::compact::verify_with_jwk(&jwk, RS256_COMPACT).unwrap();
    assert_eq!(String::from_utf8(payload).unwrap(), PAYLOAD);
}

// ── §4.2: RSA-PSS Signature, SHA-384 (PS384) ───────────────────────────────

/// Compact JWS output from RFC 7520 Figure 20.
const PS384_COMPACT: &str = "eyJhbGciOiJQUzM4NCIsImtpZCI6ImJpbGJvLmJhZ2dpbnNAaG9iYml0b24uZXhhbXBsZSJ9.SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBkb24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcmUgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4.cu22eBqkYDKgIlTpzDXGvaFfz6WGoz7fUDcfT0kkOy42miAh2qyBzk1xEsnk2IpN6-tPid6VrklHkqsGqDqHCdP6O8TTB5dDDItllVo6_1OLPpcbUrhiUSMxbbXUvdvWXzg-UD8biiReQFlfz28zGWVsdiNAUf8ZnyPEgVFn442ZdNqiVJRmBqrYRXe8P_ijQ7p8Vdz0TTrxUeT3lm8d9shnr2lfJT8ImUjvAA2Xez2Mlp8cBE5awDzT0qI0n6uiP1aCN_2_jLAeQTlqRHtfa64QQSUmFAAjVKPbByi7xho0uTOcbH510a6GYmJUAfmWjwZ6oD4ifKo8DYM-X72Eaw";

#[test]
fn rfc7520_4_2_ps384_verify() {
    let mut jwk = Jwk::from_json(RSA_JWK_JSON).unwrap();
    jwk.alg = Some("PS384".into());
    let payload = jws::compact::verify_with_jwk(&jwk, PS384_COMPACT).unwrap();
    assert_eq!(String::from_utf8(payload).unwrap(), PAYLOAD);
}

// ── §4.3: ECDSA P-521 Signature (ES512) ────────────────────────────────────

/// EC public key from RFC 7520 Figure 1.
const EC_P521_JWK_JSON: &str = r#"{
  "kty": "EC",
  "kid": "bilbo.baggins@hobbiton.example",
  "use": "sig",
  "crv": "P-521",
  "x": "AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt",
  "y": "AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVySsUdaQkAgDPrwQrJmbnX9cwlGfP-HqHZR1"
}"#;

/// Compact JWS output from RFC 7520 Figure 27.
const ES512_COMPACT: &str = "eyJhbGciOiJFUzUxMiIsImtpZCI6ImJpbGJvLmJhZ2dpbnNAaG9iYml0b24uZXhhbXBsZSJ9.SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBkb24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcmUgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4.AE_R_YZCChjn4791jSQCrdPZCNYqHXCTZH0-JZGYNlaAjP2kqaluUIIUnC9qvbu9Plon7KRTzoNEuT4Va2cmL1eJAQy3mtPBu_u_sDDyYjnAMDxXPn7XrT0lw-kvAD890jl8e2puQens_IEKBpHABlsbEPX6sFY8OcGDqoRuBomu9xQ2";

#[test]
fn rfc7520_4_3_es512_verify() {
    let mut jwk = Jwk::from_json(EC_P521_JWK_JSON).unwrap();
    jwk.alg = Some("ES512".into());
    let payload = jws::compact::verify_with_jwk(&jwk, ES512_COMPACT).unwrap();
    assert_eq!(String::from_utf8(payload).unwrap(), PAYLOAD);
}

// ── §4.4: HMAC-SHA2 Integrity Protection (HS256) ───────────────────────────

/// Symmetric key from RFC 7520 Figure 5.
const HMAC_JWK_JSON: &str = r#"{
  "kty": "oct",
  "kid": "018c0ae5-4d9b-471b-bfd6-eef314bc7037",
  "use": "sig",
  "alg": "HS256",
  "k": "hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg"
}"#;

/// Compact JWS output from RFC 7520 Figure 34.
const HS256_COMPACT: &str = "eyJhbGciOiJIUzI1NiIsImtpZCI6IjAxOGMwYWU1LTRkOWItNDcxYi1iZmQ2LWVlZjMxNGJjNzAzNyJ9.SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBkb24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcmUgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4.s0h6KThzkfBBBkLspW1h84VsJZFTsPPqMDA7g1Md7p0";

#[test]
fn rfc7520_4_4_hs256_verify() {
    let jwk = Jwk::from_json(HMAC_JWK_JSON).unwrap();
    let payload = jws::compact::verify_with_jwk(&jwk, HS256_COMPACT).unwrap();
    assert_eq!(String::from_utf8(payload).unwrap(), PAYLOAD);
}

/// HS256 is deterministic: signing the same payload with the same key
/// must produce byte-for-byte the same compact JWS as the RFC. This is
/// the strongest interop check we can run (RSA-PSS, ECDSA, and RSA-OAEP
/// are randomized so only the verify side round-trips).
#[test]
fn rfc7520_4_4_hs256_deterministic_roundtrip() {
    let jwk = Jwk::from_json(HMAC_JWK_JSON).unwrap();

    // Rebuild the RFC's protected header exactly — same field order matters
    // for byte-equality since we'd hash `base64url(header_json)`.
    let header_json = r#"{"alg":"HS256","kid":"018c0ae5-4d9b-471b-bfd6-eef314bc7037"}"#;
    let header_b64 = jose_rs::base64url::encode(header_json.as_bytes());
    let payload_b64 = jose_rs::base64url::encode(PAYLOAD.as_bytes());
    let signing_input = format!("{header_b64}.{payload_b64}");

    use kryptering::{HashAlgorithm, SignatureAlgorithm, Signer, SoftwareKey, SoftwareSigner};
    let k = jose_rs::base64url::decode(
        jose_rs::jwk::Jwk::from_json(HMAC_JWK_JSON)
            .unwrap()
            .k
            .as_ref()
            .unwrap(),
    )
    .unwrap();
    let signer = SoftwareSigner::new(
        SignatureAlgorithm::Hmac(HashAlgorithm::Sha256),
        SoftwareKey::Hmac(k),
    )
    .unwrap();
    let sig = signer.sign(signing_input.as_bytes()).unwrap();
    let produced = format!("{signing_input}.{}", jose_rs::base64url::encode(&sig));

    assert_eq!(
        produced, HS256_COMPACT,
        "HMAC signing must match RFC byte-for-byte"
    );

    // And the JWK-based verify must recognise the produced token too.
    let _ = jws::compact::verify_with_jwk(&jwk, &produced).unwrap();
}

// ──────────────────────────────────────────────────────────────────────────
// JWE vectors
// ──────────────────────────────────────────────────────────────────────────

/// The shared JWE plaintext from RFC 7520 §5 (Figure 72). U+2013 EN DASH
/// is substituted for the `\xe2\x80\x93` escape noted in the RFC.
const JWE_PLAINTEXT: &str = "You can trust us to stick with you through thick and thin\u{2013}to the bitter end. And you can trust us to keep any secret of yours\u{2013}closer than you keep it yourself. But you cannot trust us to let you face trouble alone, and go off without a word. We are your friends, Frodo.";

// ── §5.6: Direct Encryption Using AES-GCM (dir + A128GCM) ─────────────────

/// AES-128 symmetric key from RFC 7520 Figure 130.
const JWE_5_6_JWK_JSON: &str = r#"{
  "kty": "oct",
  "kid": "77c7e2b8-6e13-45cf-8672-617b5b45243a",
  "use": "enc",
  "alg": "A128GCM",
  "k": "XctOhJAkA-pD9Lh7ZgW_2A"
}"#;

/// Compact JWE from RFC 7520 Figure 136 (line-break whitespace stripped).
const JWE_5_6_COMPACT: &str = "eyJhbGciOiJkaXIiLCJraWQiOiI3N2M3ZTJiOC02ZTEzLTQ1Y2YtODY3Mi02MTdiNWI0NTI0M2EiLCJlbmMiOiJBMTI4R0NNIn0..refa467QzzKx6QAB.JW_i_f52hww_ELQPGaYyeAB6HYGcR559l9TYnSovc23XJoBcW29rHP8yZOZG7YhLpT1bjFuvZPjQS-m0IFtVcXkZXdH_lr_FrdYt9HRUYkshtrMmIUAyGmUnd9zMDB2n0cRDIHAzFVeJUDxkUwVAE7_YGRPdcqMyiBoCO-FBdE-Nceb4h3-FtBP-c_BIwCPTjb9o0SbdcdREEMJMyZBH8ySWMVi1gPD9yxi-aQpGbSv_F9N4IZAxscj5g-NJsUPbjk29-s7LJAGb15wEBtXphVCgyy53CoIKLHHeJHXex45Uz9aKZSRSInZI-wjsY0yu3cT4_aQ3i1o-tiE-F8Ios61EKgyIQ4CWao8PFMj8TTnp.vbb32Xvllea2OtmHAdccRQ";

#[test]
fn rfc7520_5_6_dir_a128gcm_decrypt() {
    // The RFC's JWK advertises alg=A128GCM — that's a content-encryption
    // algorithm, not a key-management one. For our `decrypt_with_jwk`
    // we need the JWK's alg to be the *key management* alg, here "dir".
    let mut jwk = Jwk::from_json(JWE_5_6_JWK_JSON).unwrap();
    jwk.alg = Some("dir".into());

    let recovered = jose_rs::jwe::decrypt_with_jwk(&jwk, JWE_5_6_COMPACT).unwrap();
    assert_eq!(String::from_utf8(recovered).unwrap(), JWE_PLAINTEXT);
}

// ── §5.8: A128KW + A128GCM ────────────────────────────────────────────────

/// AES-128 KEK from RFC 7520 Figure 151.
const JWE_5_8_JWK_JSON: &str = r#"{
  "kty": "oct",
  "kid": "81b20965-8332-43d9-a468-82160ad91ac8",
  "use": "enc",
  "alg": "A128KW",
  "k": "GZy6sIZ6wl9NJOKB-jnmVQ"
}"#;

/// Compact JWE from RFC 7520 Figure 159-style (§5.8 output, whitespace stripped).
const JWE_5_8_COMPACT: &str = "eyJhbGciOiJBMTI4S1ciLCJraWQiOiI4MWIyMDk2NS04MzMyLTQzZDktYTQ2OC04MjE2MGFkOTFhYzgiLCJlbmMiOiJBMTI4R0NNIn0.CBI6oDw8MydIx1IBntf_lQcw2MmJKIQx.Qx0pmsDa8KnJc9Jo.AwliP-KmWgsZ37BvzCefNen6VTbRK3QMA4TkvRkH0tP1bTdhtFJgJxeVmJkLD61A1hnWGetdg11c9ADsnWgL56NyxwSYjU1ZEHcGkd3EkU0vjHi9gTlb90qSYFfeF0LwkcTtjbYKCsiNJQkcIp1yeM03OmuiYSoYJVSpf7ej6zaYcMv3WwdxDFl8REwOhNImk2Xld2JXq6BR53TSFkyT7PwVLuq-1GwtGHlQeg7gDT6xW0JqHDPn_H-puQsmthc9Zg0ojmJfqqFvETUxLAF-KjcBTS5dNy6egwkYtOt8EIHK-oEsKYtZRaa8Z7MOZ7UGxGIMvEmxrGCPeJa14slv2-gaqK0kEThkaSqdYw0FkQZF.ER7MWJZ1FBI_NKvn7Zb1Lw";

#[test]
fn rfc7520_5_8_a128kw_a128gcm_decrypt() {
    let jwk = Jwk::from_json(JWE_5_8_JWK_JSON).unwrap();
    let recovered = jose_rs::jwe::decrypt_with_jwk(&jwk, JWE_5_8_COMPACT).unwrap();
    assert_eq!(String::from_utf8(recovered).unwrap(), JWE_PLAINTEXT);
}

// ── §5.2: RSA-OAEP + A256GCM (gated — SHA-1 OAEP is under `deprecated`) ───

/// RSA-4096 private key from RFC 7520 Figure 84. Preserved verbatim
/// from the RFC (including the indent-whitespace continuations) so the
/// test text mirrors the RFC exactly; `strip_ws` removes the whitespace
/// at runtime before parsing. Gated behind the `deprecated` feature
/// because the example uses RSA-OAEP (SHA-1).
#[cfg(feature = "deprecated")]
const JWE_5_2_RSA_JWK_RAW: &str = r#"{
  "kty": "RSA",
  "kid": "samwise.gamgee@hobbiton.example",
  "use": "enc",
  "n": "wbdxI55VaanZXPY29Lg5hdmv2XhvqAhoxUkanfzf2-5zVUxa6prHRr
      I4pP1AhoqJRlZfYtWWd5mmHRG2pAHIlh0ySJ9wi0BioZBl1XP2e-C-Fy
      XJGcTy0HdKQWlrfhTm42EW7Vv04r4gfao6uxjLGwfpGrZLarohiWCPnk
      Nrg71S2CuNZSQBIPGjXfkmIy2tl_VWgGnL22GplyXj5YlBLdxXp3XeSt
      sqo571utNfoUTU8E4qdzJ3U1DItoVkPGsMwlmmnJiwA7sXRItBCivR4M
      5qnZtdw-7v4WuR4779ubDuJ5nalMv2S66-RPcnFAzWSKxtBDnFJJDGIU
      e7Tzizjg1nms0Xq_yPub_UOlWn0ec85FCft1hACpWG8schrOBeNqHBOD
      FskYpUc2LC5JA2TaPF2dA67dg1TTsC_FupfQ2kNGcE1LgprxKHcVWYQb
      86B-HozjHZcqtauBzFNV5tbTuB-TpkcvJfNcFLlH3b8mb-H_ox35FjqB
      SAjLKyoeqfKTpVjvXhd09knwgJf6VKq6UC418_TOljMVfFTWXUxlnfhO
      OnzW6HSSzD1c9WrCuVzsUMv54szidQ9wf1cYWf3g5qFDxDQKis99gcDa
      iCAwM3yEBIzuNeeCa5dartHDb1xEB_HcHSeYbghbMjGfasvKn0aZRsnT
      yC0xhWBlsolZE",
  "e": "AQAB",
  "alg": "RSA-OAEP",
  "d": "n7fzJc3_WG59VEOBTkayzuSMM780OJQuZjN_KbH8lOZG25ZoA7T4Bx
      cc0xQn5oZE5uSCIwg91oCt0JvxPcpmqzaJZg1nirjcWZ-oBtVk7gCAWq
      -B3qhfF3izlbkosrzjHajIcY33HBhsy4_WerrXg4MDNE4HYojy68TcxT
      2LYQRxUOCf5TtJXvM8olexlSGtVnQnDRutxEUCwiewfmmrfveEogLx9E
      A-KMgAjTiISXxqIXQhWUQX1G7v_mV_Hr2YuImYcNcHkRvp9E7ook0876
      DhkO8v4UOZLwA1OlUX98mkoqwc58A_Y2lBYbVx1_s5lpPsEqbbH-nqIj
      h1fL0gdNfihLxnclWtW7pCztLnImZAyeCWAG7ZIfv-Rn9fLIv9jZ6r7r
      -MSH9sqbuziHN2grGjD_jfRluMHa0l84fFKl6bcqN1JWxPVhzNZo01yD
      F-1LiQnqUYSepPf6X3a2SOdkqBRiquE6EvLuSYIDpJq3jDIsgoL8Mo1L
      oomgiJxUwL_GWEOGu28gplyzm-9Q0U0nyhEf1uhSR8aJAQWAiFImWH5W
      _IQT9I7-yrindr_2fWQ_i1UgMsGzA7aOGzZfPljRy6z-tY_KuBG00-28
      S_aWvjyUc-Alp8AUyKjBZ-7CWH32fGWK48j1t-zomrwjL_mnhsPbGs0c
      9WsWgRzI-K8gE",
  "p": "7_2v3OQZzlPFcHyYfLABQ3XP85Es4hCdwCkbDeltaUXgVy9l9etKgh
      vM4hRkOvbb01kYVuLFmxIkCDtpi-zLCYAdXKrAK3PtSbtzld_XZ9nlsY
      a_QZWpXB_IrtFjVfdKUdMz94pHUhFGFj7nr6NNxfpiHSHWFE1zD_AC3m
      Y46J961Y2LRnreVwAGNw53p07Db8yD_92pDa97vqcZOdgtybH9q6uma-
      RFNhO1AoiJhYZj69hjmMRXx-x56HO9cnXNbmzNSCFCKnQmn4GQLmRj9s
      fbZRqL94bbtE4_e0Zrpo8RNo8vxRLqQNwIy85fc6BRgBJomt8QdQvIgP
      gWCv5HoQ",
  "q": "zqOHk1P6WN_rHuM7ZF1cXH0x6RuOHq67WuHiSknqQeefGBA9PWs6Zy
      KQCO-O6mKXtcgE8_Q_hA2kMRcKOcvHil1hqMCNSXlflM7WPRPZu2qCDc
      qssd_uMbP-DqYthH_EzwL9KnYoH7JQFxxmcv5An8oXUtTwk4knKjkIYG
      RuUwfQTus0w1NfjFAyxOOiAQ37ussIcE6C6ZSsM3n41UlbJ7TCqewzVJ
      aPJN5cxjySPZPD3Vp01a9YgAD6a3IIaKJdIxJS1ImnfPevSJQBE79-EX
      e2kSwVgOzvt-gsmM29QQ8veHy4uAqca5dZzMs7hkkHtw1z0jHV90epQJ
      JlXXnH8Q",
  "dp": "19oDkBh1AXelMIxQFm2zZTqUhAzCIr4xNIGEPNoDt1jK83_FJA-xn
      x5kA7-1erdHdms_Ef67HsONNv5A60JaR7w8LHnDiBGnjdaUmmuO8XAxQ
      J_ia5mxjxNjS6E2yD44USo2JmHvzeeNczq25elqbTPLhUpGo1IZuG72F
      ZQ5gTjXoTXC2-xtCDEUZfaUNh4IeAipfLugbpe0JAFlFfrTDAMUFpC3i
      XjxqzbEanflwPvj6V9iDSgjj8SozSM0dLtxvu0LIeIQAeEgT_yXcrKGm
      pKdSO08kLBx8VUjkbv_3Pn20Gyu2YEuwpFlM_H1NikuxJNKFGmnAq9Lc
      nwwT0jvoQ",
  "dq": "S6p59KrlmzGzaQYQM3o0XfHCGvfqHLYjCO557HYQf72O9kLMCfd_1
      VBEqeD-1jjwELKDjck8kOBl5UvohK1oDfSP1DleAy-cnmL29DqWmhgwM
      1ip0CCNmkmsmDSlqkUXDi6sAaZuntyukyflI-qSQ3C_BafPyFaKrt1fg
      dyEwYa08pESKwwWisy7KnmoUvaJ3SaHmohFS78TJ25cfc10wZ9hQNOrI
      ChZlkiOdFCtxDqdmCqNacnhgE3bZQjGp3n83ODSz9zwJcSUvODlXBPc2
      AycH6Ci5yjbxt4Ppox_5pjm6xnQkiPgj01GpsUssMmBN7iHVsrE7N2iz
      nBNCeOUIQ",
  "qi": "FZhClBMywVVjnuUud-05qd5CYU0dK79akAgy9oX6RX6I3IIIPckCc
      iRrokxglZn-omAY5CnCe4KdrnjFOT5YUZE7G_Pg44XgCXaarLQf4hl80
      oPEf6-jJ5Iy6wPRx7G2e8qLxnh9cOdf-kRqgOS3F48Ucvw3ma5V6KGMw
      QqWFeV31XtZ8l5cVI-I3NzBS7qltpUVgz2Ju021eyc7IlqgzR98qKONl
      27DuEES0aK0WE97jnsyO27Yp88Wa2RiBrEocM89QZI1seJiGDizHRUP4
      UZxw9zsXww46wy0P6f9grnYp7t8LkyDDk8eoI4KX6SNMNVcyVS9IWjlq
      8EzqZEKIA"
}"#;

/// Compact JWE from RFC 7520 Figure 92. Multi-line with whitespace
/// preserved; stripped at runtime.
#[cfg(feature = "deprecated")]
const JWE_5_2_COMPACT_RAW: &str = "
eyJhbGciOiJSU0EtT0FFUCIsImtpZCI6InNhbXdpc2UuZ2FtZ2VlQGhvYmJpdG
9uLmV4YW1wbGUiLCJlbmMiOiJBMjU2R0NNIn0
.
rT99rwrBTbTI7IJM8fU3Eli7226HEB7IchCxNuh7lCiud48LxeolRdtFF4nzQi
beYOl5S_PJsAXZwSXtDePz9hk-BbtsTBqC2UsPOdwjC9NhNupNNu9uHIVftDyu
cvI6hvALeZ6OGnhNV4v1zx2k7O1D89mAzfw-_kT3tkuorpDU-CpBENfIHX1Q58
-Aad3FzMuo3Fn9buEP2yXakLXYa15BUXQsupM4A1GD4_H4Bd7V3u9h8Gkg8Bpx
KdUV9ScfJQTcYm6eJEBz3aSwIaK4T3-dwWpuBOhROQXBosJzS1asnuHtVMt2pK
IIfux5BC6huIvmY7kzV7W7aIUrpYm_3H4zYvyMeq5pGqFmW2k8zpO878TRlZx7
pZfPYDSXZyS0CfKKkMozT_qiCwZTSz4duYnt8hS4Z9sGthXn9uDqd6wycMagnQ
fOTs_lycTWmY-aqWVDKhjYNRf03NiwRtb5BE-tOdFwCASQj3uuAgPGrO2AWBe3
8UjQb0lvXn1SpyvYZ3WFc7WOJYaTa7A8DRn6MC6T-xDmMuxC0G7S2rscw5lQQU
06MvZTlFOt0UvfuKBa03cxA_nIBIhLMjY2kOTxQMmpDPTr6Cbo8aKaOnx6ASE5
Jx9paBpnNmOOKH35j_QlrQhDWUN6A2Gg8iFayJ69xDEdHAVCGRzN3woEI2ozDR
s
.
-nBoKLH0YkLZPSI9
.
o4k2cnGN8rSSw3IDo1YuySkqeS_t2m1GXklSgqBdpACm6UJuJowOHC5ytjqYgR
L-I-soPlwqMUf4UgRWWeaOGNw6vGW-xyM01lTYxrXfVzIIaRdhYtEMRBvBWbEw
P7ua1DRfvaOjgZv6Ifa3brcAM64d8p5lhhNcizPersuhw5f-pGYzseva-TUaL8
iWnctc-sSwy7SQmRkfhDjwbz0fz6kFovEgj64X1I5s7E6GLp5fnbYGLa1QUiML
7Cc2GxgvI7zqWo0YIEc7aCflLG1-8BboVWFdZKLK9vNoycrYHumwzKluLWEbSV
maPpOslY2n525DxDfWaVFUfKQxMF56vn4B9QMpWAbnypNimbM8zVOw
.
UCGiqJxhBI3IFVdPalHHvA
";

#[cfg(feature = "deprecated")]
#[test]
fn rfc7520_5_2_rsa_oaep_a256gcm_decrypt() {
    let jwk_json = strip_ws(JWE_5_2_RSA_JWK_RAW);
    let compact = strip_ws(JWE_5_2_COMPACT_RAW);
    let jwk = Jwk::from_json(&jwk_json).unwrap();
    let recovered = jose_rs::jwe::decrypt_with_jwk(&jwk, &compact).unwrap();
    assert_eq!(String::from_utf8(recovered).unwrap(), JWE_PLAINTEXT);
}
