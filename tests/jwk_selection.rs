//! Bounded JWK Set selection (plan L3), at the JWT boundary.
//!
//! The unit tests in `src/jwk/selection.rs` cover the selection function. These cover what a
//! caller actually experiences: a token, a set, and a policy — and the two failure modes the
//! module exists to prevent (fall-through to an unrelated key, and silent filtering of entries
//! this build cannot use).

use jose_rs::jwk::selection::{EntryStatus, Fallback, SelectionPolicy, SetLimits};
use jose_rs::jwk::{self, Jwk, JwkSet};
use jose_rs::jwt::{self, Claims, Validation};
use jose_rs::JoseError;
use jose_rs::JoseHeader;

fn signer(kid: &str) -> Jwk {
    let mut jwk = jwk::generate_ed25519().expect("generate");
    jwk.alg = Some("EdDSA".into());
    jwk.kid = Some(kid.into());
    jwk
}

fn token_from(signer: &Jwk) -> String {
    // The JWK's `kid` is *not* copied into the header by the library — the signer states what the
    // header says — so tests that care about kid selection put it there explicitly.
    let mut header = JoseHeader::new("EdDSA");
    header.kid = signer.kid.clone();
    jwt::encode_with_jwk(signer, &header, &Claims::default()).expect("sign")
}

/// A JWT whose header names `kid`, signed by `signer`. Used to build the "the name is a lie,
/// the signature is real" tokens — and it must go through the JWT encoder, because a raw JWS
/// payload is not a claims document and the claim parser is right to refuse it.
fn token_with_kid(signer: &Jwk, kid: Option<&str>) -> String {
    let mut header = JoseHeader::new("EdDSA");
    header.kid = kid.map(str::to_string);
    jwt::encode_with_jwk(signer, &header, &Claims::default()).expect("sign")
}

fn public_set(keys: &[&Jwk]) -> JwkSet {
    JwkSet {
        keys: keys.iter().map(|k| k.to_public_jwk()).collect(),
    }
}

fn decode(set: &JwkSet, token: &str, policy: &SelectionPolicy) -> Result<Claims, JoseError> {
    jwt::decode_with_jwkset_policy(set, token, &Validation::default(), policy)
}

#[test]
fn a_named_key_is_selected_among_many() {
    let a = signer("a");
    let b = signer("b");
    let c = signer("c");
    let set = public_set(&[&a, &b, &c]);
    let token = token_from(&b);

    let claims = decode(&set, &token, &SelectionPolicy::default());
    assert!(claims.is_ok(), "{claims:?}");

    // `strict()` also works: the token names its key, so exact-match-only is satisfied.
    assert!(decode(&set, &token, &SelectionPolicy::strict()).is_ok());
}

#[test]
fn an_unknown_kid_never_authenticates_under_a_key_that_is_present() {
    // The heart of the feature. `b` is in the set and *would* verify a token that named it;
    // this token names `ghost`. Accepting it would mean a signature by any key in the set can
    // authenticate a token that named a different one — which is what makes kid pinning, and
    // every rotation or tenancy policy built on it, decorative.
    let b = signer("b");
    let set = public_set(&[&b]);

    // A token legitimately signed by `b`, whose header names a key that is not in the set. The
    // signature is real; only the name is a lie — which is precisely the case a permissive
    // implementation gets wrong.
    let forged = token_with_kid(&b, Some("ghost"));

    for fallback in [Fallback::Refuse, Fallback::TryWhenUnaddressable] {
        let policy = SelectionPolicy {
            fallback,
            ..Default::default()
        };
        let err = decode(&set, &forged, &policy).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("ghost"), "{msg}");
        assert!(
            msg.contains("refusing") || msg.contains("forbids") || msg.contains("no JWK"),
            "the refusal must not read as a search that happened to fail: {msg}"
        );
    }
}

#[test]
fn the_try_all_escape_hatch_is_real_and_documented() {
    // If the dangerous policy did not actually work, its documentation would be a lie — and the
    // point of documenting it is that it is *visible* rather than something a caller stumbles
    // into by default.
    let b = signer("b");
    let set = public_set(&[&b]);
    let forged = token_with_kid(&b, Some("ghost"));

    let policy = SelectionPolicy {
        fallback: Fallback::TryAll,
        ..Default::default()
    };
    assert!(
        decode(&set, &forged, &policy).is_ok(),
        "TryAll is defined to sweep, so this must verify"
    );
}

#[test]
fn duplicate_kids_are_refused_at_the_jwt_level_too() {
    let a = signer("dup");
    let set = public_set(&[&a, &a]);
    let token = token_from(&a);
    let err = decode(&set, &token, &SelectionPolicy::default()).unwrap_err();
    assert!(err.to_string().contains("multiple"), "{err}");
}

#[test]
fn the_candidate_budget_errors_rather_than_truncating() {
    // Sixty-five kid-less keys, one of which signed the token. Truncating at 64 would turn a
    // working configuration into "signature verification failed" — a key problem that isn't.
    let signers: Vec<Jwk> = (0..65).map(|i| signer(&format!("k{i}"))).collect();
    let refs: Vec<&Jwk> = signers.iter().collect();
    let mut set = public_set(&refs);
    // Strip kids so the set is unaddressable and the fallback path applies.
    for key in &mut set.keys {
        key.kid = None;
        key.alg = Some("EdDSA".into());
    }
    let token = {
        let mut key = signers[64].clone();
        key.kid = None;
        token_with_kid(&key, None)
    };

    let tight = SelectionPolicy {
        max_candidates: 64,
        fallback: Fallback::TryAll,
        require_kid: false,
    };
    let err = decode(&set, &token, &tight).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("budget"), "{msg}");
    assert!(
        msg.contains("65"),
        "the message names the real count: {msg}"
    );

    let loose = SelectionPolicy {
        max_candidates: 128,
        ..tight
    };
    assert!(decode(&set, &token, &loose).is_ok());
}

#[test]
fn require_kid_refuses_before_any_key_is_tried() {
    let a = signer("a");
    let set = public_set(&[&a]);
    // A token that names no key.
    let keyless = {
        let mut key = a.clone();
        key.kid = None;
        token_with_kid(&key, None)
    };

    let err = decode(&set, &keyless, &SelectionPolicy::strict()).unwrap_err();
    assert!(matches!(err, JoseError::InvalidHeader(_)), "{err:?}");

    // Even the permissive default refuses to sweep an *addressable* set for a kid-less token.
    let err = decode(&set, &keyless, &SelectionPolicy::default()).unwrap_err();
    assert!(err.to_string().contains("addressable"), "{err}");

    // A kid-less set is the one place the sweep is legitimate, since nothing could have been
    // named instead.
    let anonymous = JwkSet {
        keys: vec![{
            let mut key = a.to_public_jwk();
            key.kid = None;
            key
        }],
    };
    assert!(decode(&anonymous, &keyless, &SelectionPolicy::default()).is_ok());
}

#[test]
fn the_legacy_entry_point_keeps_its_unbounded_behaviour() {
    // L3 adds budgets; it does not move anybody's existing defaults. A kid-less set larger than
    // the new policy default must still decode through `decode_with_jwkset`.
    let signers: Vec<Jwk> = (0..70).map(|i| signer(&format!("k{i}"))).collect();
    let mut set = JwkSet {
        keys: signers.iter().map(Jwk::to_public_jwk).collect(),
    };
    for key in &mut set.keys {
        key.kid = None;
    }
    let token = {
        let mut key = signers[69].clone();
        key.kid = None;
        token_with_kid(&key, None)
    };
    assert!(jwt::decode_with_jwkset(&set, &token, &Validation::default()).is_ok());
}

#[test]
fn unsupported_entries_are_described_not_dropped() {
    // A set mixing a working key with things this build cannot use: the unsupported entries must
    // remain visible (with their kids) and must not be re-labelled as malformed data.
    let good = signer("current");
    let set_json = format!(
        r#"{{"keys":[
            {},
            {{"kty":"EC","crv":"secp256k1","kid":"bitcoin","x":"AA","y":"AA"}},
            {{"kty":"RSA","kid":"broken","n":"not-base64url!!","e":"AQAB"}}
        ]}}"#,
        good.to_public_jwk().to_json().unwrap()
    );
    let set = JwkSet::from_json(&set_json).expect("set parses");
    let report = set.diagnostics();
    assert_eq!(report.len(), 3, "diagnostics may not drop entries");

    let statuses: Vec<&str> = report
        .iter()
        .map(|e| match e.status {
            EntryStatus::Usable => "usable",
            EntryStatus::Unsupported { .. } => "unsupported",
            EntryStatus::Invalid { .. } => "invalid",
        })
        .collect();
    assert_eq!(statuses, vec!["usable", "unsupported", "invalid"]);
    let kids: Vec<Option<&str>> = report.iter().map(|e| e.kid.as_deref()).collect();
    assert_eq!(kids, vec![Some("current"), Some("bitcoin"), Some("broken")]);

    // And the addressable key still works: filtering was never needed to get there.
    let token = token_from(&good);
    assert!(decode(&set, &token, &SelectionPolicy::default()).is_ok());
}

#[test]
fn import_budgets_are_checked_before_the_work() {
    let good = signer("a");
    let text = public_set(&[&good]).to_json().unwrap();

    let by_bytes = SetLimits {
        max_bytes: 16,
        ..Default::default()
    };
    let err = JwkSet::from_json_with_limits(&text, &by_bytes).unwrap_err();
    assert!(err.to_string().contains("bytes"), "{err}");

    let by_entries = SetLimits {
        max_entries: 0,
        ..Default::default()
    };
    let err = JwkSet::from_json_with_limits(&text, &by_entries).unwrap_err();
    assert!(err.to_string().contains("entries"), "{err}");

    // Default limits accept an ordinary set.
    assert_eq!(
        JwkSet::from_json_with_limits(&text, &SetLimits::default())
            .unwrap()
            .keys
            .len(),
        1
    );
}

#[test]
fn selection_is_deterministic_so_a_choice_is_auditable() {
    let keys: Vec<Jwk> = (0..5).map(|i| signer(&format!("k{i}"))).collect();
    let key_refs: Vec<&Jwk> = keys.iter().collect();
    let mut set = public_set(&key_refs);
    for key in &mut set.keys {
        key.kid = None;
    }
    let policy = SelectionPolicy {
        fallback: Fallback::TryAll,
        ..Default::default()
    };
    let first = set.select(None, &policy).unwrap();
    let second = set.select(None, &policy).unwrap();
    assert_eq!(first.attempts(), 5);
    assert_eq!(first.set_size, 5);
    assert!(!first.matched_by_kid);
    let order_a: Vec<Option<&str>> = first
        .candidates
        .iter()
        .map(|k| k.kid.as_deref())
        .zip(second.candidates.iter().map(|k| k.kid.as_deref()))
        .map(|(x, _)| x)
        .collect();
    assert!(order_a.iter().all(Option::is_none));
    assert_eq!(first.candidates.len(), second.candidates.len());
}
