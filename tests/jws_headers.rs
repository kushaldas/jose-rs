//! Emit-side header policy for every public JWS / JWT signing entry point.
//!
//! `JoseHeader::extra` is flattened into the same JSON object as the typed
//! fields, so a shadowing entry used to serialize as a duplicate member, e.g.
//! `{"alg":"HS256","alg":"none"}`. The sign-side checks (header/signer `alg`
//! agreement, `crit` policy) only see the typed field, while last-key-wins
//! JSON parsers on the verify side read the `extra` value instead.
//!
//! The same entry points must also refuse key-reference members (`jku`,
//! `jwk`, `x5u`, `x5c`) without an explicit opt-in, refuse headers and
//! tokens larger than this crate's decoders accept, and (for the JSON
//! serializations) refuse unprotected headers that contradict or extend the
//! protected one in ways RFC 7515 forbids.
//!
//! They also refuse JWE-only members (RFC 7516 §9, IANA JOSE header
//! registry) and the `crit` contents RFC 7515 §4.1.11 forbids producers to
//! emit: registered header parameter names and duplicate names.

use jose_rs::jws::json::{self, GeneralSigner};
use jose_rs::jws::SignOptions;
use jose_rs::jwt::{self, Claims};
use jose_rs::{jwk, jws, JoseError, JoseHeader, JweAlgorithm, JweEncryption, JwsAlgorithm};
use serde_json::{json, Value};

/// Keys shared by all entry points: an HS256 JWK (and a signer built from
/// it) for the JWS layer, and a `dir` key for the nested-JWT JWE layer.
struct Keys {
    sig_jwk: jwk::Jwk,
    signer: kryptering::SoftwareSigner,
    enc_jwk: jwk::Jwk,
    enc_raw: Vec<u8>,
}

impl Keys {
    fn new() -> Self {
        let sig_jwk = jwk::generate_symmetric_for_alg("HS256").unwrap();
        let signer = kryptering::SoftwareSigner::new(
            JwsAlgorithm::HS256.to_crypto().unwrap(),
            jwk::jwk_to_software_key(&sig_jwk).unwrap(),
        )
        .unwrap();
        let enc_jwk = jwk::generate_direct_symmetric(JweEncryption::A128GCM).unwrap();
        let enc_raw = jose_rs::base64url::decode(enc_jwk.k.as_deref().unwrap()).unwrap();
        Self {
            sig_jwk,
            signer,
            enc_jwk,
            enc_raw,
        }
    }
}

/// Signature shared by the entry-point table: sign `header` with `opts`
/// (ignored by entry points that take no options) and discard the output.
type SignFn = Box<dyn Fn(&Keys, &JoseHeader, &SignOptions) -> jose_rs::Result<()>>;

/// One public signing entry point.
struct EntryPoint {
    name: &'static str,
    /// Whether the entry point accepts caller-supplied `SignOptions`. Those
    /// that do not always apply `SignOptions::new()`.
    takes_options: bool,
    sign: SignFn,
}

fn ok<T>(result: jose_rs::Result<T>) -> jose_rs::Result<()> {
    result.map(|_| ())
}

/// Every public function that turns a caller-supplied `JoseHeader` into a
/// signed artifact. A new signing path should be added here so its header
/// handling is exercised by every test below.
fn entry_points() -> Vec<EntryPoint> {
    const P: &[u8] = b"payload";
    fn e(name: &'static str, takes_options: bool, sign: SignFn) -> EntryPoint {
        EntryPoint {
            name,
            takes_options,
            sign,
        }
    }
    vec![
        e(
            "jws::compact::sign",
            false,
            Box::new(|k, h, _| ok(jws::compact::sign(&k.signer, P, h))),
        ),
        e(
            "jws::compact::sign_with_options",
            true,
            Box::new(|k, h, o| ok(jws::compact::sign_with_options(&k.signer, P, h, o))),
        ),
        e(
            "jws::compact::sign_with_jwk",
            false,
            Box::new(|k, h, _| ok(jws::compact::sign_with_jwk(&k.sig_jwk, P, h))),
        ),
        e(
            "jws::compact::sign_with_jwk_options",
            true,
            Box::new(|k, h, o| ok(jws::compact::sign_with_jwk_options(&k.sig_jwk, P, h, o))),
        ),
        e(
            "json::sign_flattened",
            false,
            Box::new(|k, h, _| ok(json::sign_flattened(&k.signer, P, h))),
        ),
        e(
            "json::sign_flattened_opts",
            true,
            Box::new(|k, h, o| ok(json::sign_flattened_opts(&k.signer, P, h, None, o))),
        ),
        e(
            "json::sign_flattened_detached",
            false,
            Box::new(|k, h, _| ok(json::sign_flattened_detached(&k.signer, P, h))),
        ),
        e(
            "json::sign_flattened_detached_opts",
            true,
            Box::new(|k, h, o| ok(json::sign_flattened_detached_opts(&k.signer, P, h, None, o))),
        ),
        e(
            "json::sign_general",
            false,
            Box::new(|k, h, _| {
                let signer: &dyn kryptering::Signer = &k.signer;
                ok(json::sign_general(&[(signer, h)], P))
            }),
        ),
        e(
            "json::sign_general_full",
            true,
            Box::new(|k, h, o| {
                let entry = GeneralSigner {
                    options: o.clone(),
                    ..GeneralSigner::new(&k.signer, h)
                };
                ok(json::sign_general_full(&[entry], P, true))
            }),
        ),
        e(
            "jwt::encode",
            false,
            Box::new(|k, h, _| ok(jwt::encode(&k.signer, h, &Claims::default()))),
        ),
        e(
            "jwt::encode_with_options",
            true,
            Box::new(|k, h, o| {
                ok(jwt::encode_with_options(
                    &k.signer,
                    h,
                    &Claims::default(),
                    o,
                ))
            }),
        ),
        e(
            "jwt::encode_with_jwk",
            false,
            Box::new(|k, h, _| ok(jwt::encode_with_jwk(&k.sig_jwk, h, &Claims::default()))),
        ),
        e(
            "jwt::encode_with_jwk_options",
            true,
            Box::new(|k, h, o| {
                ok(jwt::encode_with_jwk_options(
                    &k.sig_jwk,
                    h,
                    &Claims::default(),
                    o,
                ))
            }),
        ),
        e(
            "jwt::encode_nested",
            false,
            Box::new(|k, h, _| {
                ok(jwt::encode_nested(
                    &k.signer,
                    h,
                    &Claims::default(),
                    &k.enc_raw,
                    JweAlgorithm::Dir,
                    JweEncryption::A128GCM,
                ))
            }),
        ),
        e(
            "jwt::encode_nested_with_options",
            true,
            Box::new(|k, h, o| {
                ok(jwt::encode_nested_with_options(
                    &k.signer,
                    h,
                    &Claims::default(),
                    &k.enc_raw,
                    JweAlgorithm::Dir,
                    JweEncryption::A128GCM,
                    o,
                ))
            }),
        ),
        e(
            "jwt::encode_nested_with_jwk_options",
            true,
            Box::new(|k, h, o| {
                ok(jwt::encode_nested_with_jwk_options(
                    &k.sig_jwk,
                    h,
                    &Claims::default(),
                    &k.enc_jwk,
                    JweEncryption::A128GCM,
                    o,
                ))
            }),
        ),
        e(
            "jwt::encode_nested_with_jwk",
            false,
            Box::new(|k, h, _| {
                ok(jwt::encode_nested_with_jwk(
                    &k.sig_jwk,
                    h,
                    &Claims::default(),
                    &k.enc_jwk,
                    JweEncryption::A128GCM,
                ))
            }),
        ),
    ]
}

/// Assert that every entry point refuses `header` under default options.
fn assert_all_reject(keys: &Keys, header: &JoseHeader, what: &str) {
    for ep in entry_points() {
        let result = (ep.sign)(keys, header, &SignOptions::new());
        assert!(
            matches!(result, Err(JoseError::InvalidHeader(_))),
            "{} accepted {what}: {result:?}",
            ep.name
        );
    }
}

fn hs256_header() -> JoseHeader {
    JoseHeader::jwt_for_alg(JwsAlgorithm::HS256)
}

fn allow_key_references() -> SignOptions {
    SignOptions::new().with_key_reference_headers(true)
}

/// Every member name produced by a typed `JoseHeader` field, paired with a
/// value that would change the header's meaning if a peer read it.
fn shadowing_members() -> Vec<(&'static str, Value)> {
    vec![
        ("alg", json!("none")),
        ("enc", json!("A256GCM")),
        ("kid", json!("other")),
        ("typ", json!("at+jwt")),
        ("cty", json!("JWT")),
        ("jku", json!("https://example.com/jwks")),
        ("jwk", json!({"kty": "oct"})),
        ("x5u", json!("https://example.com/cert")),
        ("x5c", json!(["AA"])),
        ("x5t", json!("AA")),
        ("x5t#S256", json!("AA")),
        // Would also smuggle an unvalidated critical extension past the
        // sign-side `crit` policy.
        ("crit", json!(["unknown"])),
    ]
}

/// Regression: every public JWS/JWT signing entry point rejects a shadowing
/// `extra` member before signing.
#[test]
fn extra_members_cannot_shadow_typed_header_fields_when_signing() {
    let keys = Keys::new();
    for (name, value) in shadowing_members() {
        let mut header = hs256_header();
        header.extra.insert(name.into(), value);
        assert_all_reject(&keys, &header, &format!("extra[{name:?}]"));
    }
}

/// Non-shadowing extension members (including RFC 7797 `b64`, which has no
/// typed field) are still carried and signed normally.
#[test]
fn non_shadowing_extra_members_are_still_signed() {
    let key = jwk::generate_symmetric_for_alg("HS256").unwrap();
    let mut header = hs256_header();
    header.extra.insert("tenant".into(), json!("one"));

    let token = jws::compact::sign_with_jwk(&key, b"payload", &header).unwrap();
    let decoded = jws::compact::decode_header(&token).unwrap();
    assert_eq!(decoded.extra.get("tenant"), Some(&json!("one")));
    assert_eq!(
        jws::compact::verify_with_jwk(&key, &token).unwrap(),
        b"payload"
    );
}

/// Every key-reference member, set through its typed field.
fn key_reference_headers() -> Vec<(&'static str, JoseHeader)> {
    let mut jku = hs256_header();
    jku.jku = Some("https://example.com/jwks".into());
    let mut jwk_header = hs256_header();
    jwk_header.jwk = Some(json!({"kty": "oct"}));
    let mut x5u = hs256_header();
    x5u.x5u = Some("https://example.com/cert".into());
    let mut x5c = hs256_header();
    x5c.x5c = Some(vec!["AA".into()]);
    vec![
        ("jku", jku),
        ("jwk", jwk_header),
        ("x5u", x5u),
        ("x5c", x5c),
    ]
}

/// Regression (M-1): `jku`, `jwk`, `x5u` and `x5c` are refused by every entry
/// point by default and accepted by every options-taking entry point once
/// `allow_key_reference_headers` is set.
#[test]
fn key_reference_members_require_opt_in() {
    let keys = Keys::new();
    let allow = allow_key_references();
    for (name, header) in key_reference_headers() {
        assert_all_reject(&keys, &header, name);
        for ep in entry_points().into_iter().filter(|ep| ep.takes_options) {
            if let Err(e) = (ep.sign)(&keys, &header, &allow) {
                panic!("{} refused opted-in {name}: {e}", ep.name);
            }
        }
    }
}

/// Regression (M-2): a protected header too large for this crate's decoders
/// is refused by every entry point before signing.
#[test]
fn oversized_header_is_rejected_when_signing() {
    let keys = Keys::new();
    let mut header = hs256_header();
    header
        .extra
        .insert("blob".into(), "A".repeat(jose_rs::MAX_TOKEN_BYTES).into());
    assert_all_reject(&keys, &header, "an oversized header");
}

/// Regression (M-2): payloads that would push an emitted token or JSON
/// payload member past `MAX_TOKEN_BYTES` are refused with `InvalidToken`,
/// and a token just under the limit is emitted and verifies.
#[test]
fn emitted_tokens_respect_max_token_bytes() {
    let keys = Keys::new();
    let header = JoseHeader::for_alg(JwsAlgorithm::HS256);
    let too_big = vec![b'a'; jose_rs::MAX_TOKEN_BYTES];
    let signer: &dyn kryptering::Signer = &keys.signer;
    for (api, result) in [
        (
            "compact::sign",
            ok(jws::compact::sign(signer, &too_big, &header)),
        ),
        (
            "json::sign_flattened",
            ok(json::sign_flattened(signer, &too_big, &header)),
        ),
        (
            "json::sign_general",
            ok(json::sign_general(&[(signer, &header)], &too_big)),
        ),
    ] {
        assert!(
            matches!(result, Err(JoseError::InvalidToken(_))),
            "{api} emitted an oversized artifact: {result:?}"
        );
    }

    // Leaves room for the header and signature segments.
    let fits = vec![b'a'; jose_rs::MAX_TOKEN_BYTES / 4 * 3 - 1024];
    let token = jws::compact::sign_with_jwk(&keys.sig_jwk, &fits, &header).unwrap();
    assert!(token.len() <= jose_rs::MAX_TOKEN_BYTES);
    assert_eq!(
        jws::compact::verify_with_jwk(&keys.sig_jwk, &token).unwrap(),
        fits
    );
    let flattened = json::sign_flattened(signer, &fits, &header).unwrap();
    let verifier = kryptering::SoftwareVerifier::new(
        JwsAlgorithm::HS256.to_crypto().unwrap(),
        jwk::jwk_to_software_key(&keys.sig_jwk).unwrap(),
    )
    .unwrap();
    assert_eq!(json::verify_flattened(&verifier, &flattened).unwrap(), fits);
}

/// Sign `unprotected` as the per-signature header through every JSON entry
/// point that accepts one.
fn sign_with_unprotected(
    keys: &Keys,
    header: &JoseHeader,
    unprotected: Value,
    opts: &SignOptions,
) -> Vec<(&'static str, jose_rs::Result<()>)> {
    let entry = GeneralSigner {
        unprotected: Some(unprotected.clone()),
        options: opts.clone(),
        ..GeneralSigner::new(&keys.signer, header)
    };
    vec![
        (
            "json::sign_flattened_opts",
            ok(json::sign_flattened_opts(
                &keys.signer,
                b"payload",
                header,
                Some(unprotected.clone()),
                opts,
            )),
        ),
        (
            "json::sign_flattened_detached_opts",
            ok(json::sign_flattened_detached_opts(
                &keys.signer,
                b"payload",
                header,
                Some(unprotected),
                opts,
            )),
        ),
        (
            "json::sign_general_full",
            ok(json::sign_general_full(&[entry], b"payload", true)),
        ),
    ]
}

/// Regression (M-3): an unprotected header must be a JSON object that is
/// disjoint from the protected header (RFC 7515 §7.2.1), must not carry
/// members that have to be integrity protected (`crit`, RFC 7515 §4.1.11;
/// `b64`, RFC 7797 §3) or that are JWE-only (`zip`, `enc`, `epk`, ...;
/// RFC 7516 §9), and follows the key-reference opt-in.
#[test]
fn unprotected_header_cannot_contradict_protected_header() {
    let keys = Keys::new();
    let mut header = hs256_header();
    header.kid = Some("signer".into());
    let default_opts = SignOptions::new();

    for (what, unprotected) in [
        ("a non-object", json!(["alg", "none"])),
        ("a contradicting alg", json!({"alg": "none"})),
        ("a contradicting kid", json!({"kid": "attacker"})),
        ("a repeated typ", json!({"typ": "JWT"})),
        ("crit", json!({"crit": ["b64"]})),
        ("b64", json!({"b64": false})),
        ("zip", json!({"zip": "DEF"})),
        ("enc", json!({"enc": "A256GCM"})),
        ("epk", json!({"epk": {"kty": "EC"}})),
        ("x5c without opt-in", json!({"x5c": ["AA"]})),
        (
            "jku without opt-in",
            json!({"jku": "https://example.com/jwks"}),
        ),
    ] {
        for (api, result) in sign_with_unprotected(&keys, &header, unprotected, &default_opts) {
            assert!(
                matches!(result, Err(JoseError::InvalidHeader(_))),
                "{api} accepted an unprotected header with {what}: {result:?}"
            );
        }
    }

    // Allowed: application members such as JAdES `etsiU`, and key-reference
    // members once opted in.
    for (unprotected, opts) in [
        (json!({"etsiU": ["AA"]}), SignOptions::new()),
        (json!({"x5c": ["AA"]}), allow_key_references()),
    ] {
        for (api, result) in sign_with_unprotected(&keys, &header, unprotected.clone(), &opts) {
            if let Err(e) = result {
                panic!("{api} refused a valid unprotected header {unprotected}: {e}");
            }
        }
    }
}

/// Every JWE-only header member (IANA JOSE header registry, usage location
/// "JWE"), each paired with a plausible value.
fn jwe_only_members() -> Vec<(&'static str, Value)> {
    vec![
        ("zip", json!("DEF")),         // RFC 7516 §4.1.3
        ("epk", json!({"kty": "EC"})), // RFC 7518 §4.6.1.1
        ("apu", json!("AA")),          // RFC 7518 §4.6.1.2
        ("apv", json!("AA")),          // RFC 7518 §4.6.1.3
        ("iv", json!("AA")),           // RFC 7518 §4.7.1.1
        ("tag", json!("AA")),          // RFC 7518 §4.7.1.2
        ("p2s", json!("AA")),          // RFC 7518 §4.8.1.1
        ("p2c", json!(1000)),          // RFC 7518 §4.8.1.2
    ]
}

/// Regression (L-2): no signing entry point emits a JWS protected header
/// carrying a JWE-only member.
///
/// RFC 7516 §9: "The JOSE Header for a JWS can also be distinguished from
/// the JOSE Header for a JWE by determining whether an `enc` (encryption
/// algorithm) member exists. If the `enc` member exists, it is a JWE;
/// otherwise, it is a JWS." A signed header carrying `enc` therefore claims
/// to be a JWE. The other members (RFC 7516 §4.1.3, RFC 7518 §4.6.1,
/// §4.7.1, §4.8.1) describe compression or key management that a JWS never
/// performs. Every entry point must refuse them, including with options.
#[test]
fn jwe_only_members_are_rejected_when_signing() {
    let keys = Keys::new();
    let mut with_enc = hs256_header();
    with_enc.enc = Some("A256GCM".into());
    let mut cases = vec![("enc".to_string(), with_enc)];
    for (name, value) in jwe_only_members() {
        let mut header = hs256_header();
        header.extra.insert(name.into(), value);
        cases.push((name.to_string(), header));
    }
    let permissive = allow_key_references();
    for (name, header) in cases {
        assert_all_reject(&keys, &header, &name);
        for ep in entry_points().into_iter().filter(|ep| ep.takes_options) {
            let result = (ep.sign)(&keys, &header, &permissive);
            assert!(
                matches!(&result, Err(JoseError::InvalidHeader(m)) if m.contains("JWE-only")),
                "{} accepted JWE-only {name}: {result:?}",
                ep.name
            );
        }
    }
}

/// Registered header parameters of RFC 7515 that can be set on a JWS
/// header, each present in the header so that only the `crit` producer rule
/// can reject it.
fn registered_crit_cases() -> Vec<(&'static str, JoseHeader)> {
    let mut cases = Vec::new();
    let mut add = |name: &'static str, set: &dyn Fn(&mut JoseHeader)| {
        let mut header = hs256_header();
        set(&mut header);
        header.crit = Some(vec![name.into()]);
        cases.push((name, header));
    };
    add("alg", &|_| {});
    add("typ", &|_| {});
    add("kid", &|h| h.kid = Some("k".into()));
    add("cty", &|h| h.cty = Some("JWT".into()));
    add("jku", &|h| h.jku = Some("https://example.com/jwks".into()));
    add("jwk", &|h| h.jwk = Some(json!({"kty": "oct"})));
    add("x5u", &|h| h.x5u = Some("https://example.com/cert".into()));
    add("x5c", &|h| h.x5c = Some(vec!["AA".into()]));
    add("x5t", &|h| h.x5t = Some("AA".into()));
    add("x5t#S256", &|h| h.x5t_s256 = Some("AA".into()));
    add("crit", &|_| {});
    cases
}

/// Regression (I-3): RFC 7515 §4.1.11 — "Producers MUST NOT include Header
/// Parameter names defined by this specification or [JWA] for use with JWS
/// ... in the `crit` list".
///
/// Every entry point refuses such a `crit`, even when the caller lists the
/// name in `understood_crit` and opts in to key-reference members, so the
/// only rule that can reject it is the producer rule.
#[test]
fn registered_names_in_crit_are_rejected_when_signing() {
    let keys = Keys::new();
    for (name, header) in registered_crit_cases() {
        assert_all_reject(&keys, &header, &format!("crit [{name:?}]"));
        let opts = allow_key_references().with_understood_crit([name]);
        for ep in entry_points().into_iter().filter(|ep| ep.takes_options) {
            let result = (ep.sign)(&keys, &header, &opts);
            assert!(
                matches!(&result, Err(JoseError::InvalidHeader(m))
                    if m.contains("registered header parameter")),
                "{} accepted crit [{name:?}]: {result:?}",
                ep.name
            );
        }
    }
}

/// Regression (I-3): RFC 7515 §4.1.11 — producers MUST NOT include
/// "duplicate names" in the `crit` list. A single, understood extension
/// name is still accepted by every options-taking entry point.
#[test]
fn duplicate_names_in_crit_are_rejected_when_signing() {
    let keys = Keys::new();
    let opts = SignOptions::new().with_understood_crit(["etsiU"]);
    let mut header = hs256_header();
    header.extra.insert("etsiU".into(), json!(["AA"]));

    header.crit = Some(vec!["etsiU".into()]);
    for ep in entry_points().into_iter().filter(|ep| ep.takes_options) {
        if let Err(e) = (ep.sign)(&keys, &header, &opts) {
            panic!("{} refused crit [\"etsiU\"]: {e}", ep.name);
        }
    }

    header.crit = Some(vec!["etsiU".into(), "etsiU".into()]);
    for ep in entry_points().into_iter().filter(|ep| ep.takes_options) {
        let result = (ep.sign)(&keys, &header, &opts);
        assert!(
            matches!(&result, Err(JoseError::InvalidHeader(m)) if m.contains("more than once")),
            "{} accepted a duplicate crit name: {result:?}",
            ep.name
        );
    }
}

/// Regression (L-1): a nested JWT (RFC 7519 §5.2, sign then encrypt) can
/// carry an `x5c` chain (RFC 7515 §4.1.6) in its inner JWS header once the
/// caller opts in, and the emitted token decrypts, verifies and validates.
/// Without the opt-in the nested encoders refuse it like every other
/// signing path.
#[test]
fn nested_jwt_carries_key_reference_members_with_opt_in() {
    let keys = Keys::new();
    let mut header = hs256_header();
    header.x5c = Some(vec!["AA".into()]);
    let claims = Claims {
        iss: Some("nested".into()),
        ..Claims::default()
    };
    let validation = jwt::Validation::new().with_issuer("nested");

    assert!(matches!(
        jwt::encode_nested_with_jwk(
            &keys.sig_jwk,
            &header,
            &claims,
            &keys.enc_jwk,
            JweEncryption::A128GCM
        ),
        Err(JoseError::InvalidHeader(_))
    ));

    let token = jwt::encode_nested_with_jwk_options(
        &keys.sig_jwk,
        &header,
        &claims,
        &keys.enc_jwk,
        JweEncryption::A128GCM,
        &allow_key_references(),
    )
    .unwrap();
    let decoded =
        jwt::decode_nested_with_jwk(&keys.enc_jwk, &keys.sig_jwk, &token, &validation).unwrap();
    assert_eq!(decoded.iss.as_deref(), Some("nested"));

    let inner = jose_rs::jwe::decrypt_with_jwk(&keys.enc_jwk, &token).unwrap();
    let inner_header = jws::compact::decode_header(std::str::from_utf8(&inner).unwrap()).unwrap();
    assert_eq!(inner_header.x5c, header.x5c);

    let token = jwt::encode_nested_with_options(
        &keys.signer,
        &header,
        &claims,
        &keys.enc_raw,
        JweAlgorithm::Dir,
        JweEncryption::A128GCM,
        &allow_key_references(),
    )
    .unwrap();
    let verifier = kryptering::SoftwareVerifier::new(
        JwsAlgorithm::HS256.to_crypto().unwrap(),
        jwk::jwk_to_software_key(&keys.sig_jwk).unwrap(),
    )
    .unwrap();
    let decoded = jwt::decode_nested(&keys.enc_raw, &verifier, &token, &validation).unwrap();
    assert_eq!(decoded.iss.as_deref(), Some("nested"));
}
