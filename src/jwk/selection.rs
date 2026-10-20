//! Bounded, explicit JWK Set selection and diagnostics (plan L3).
//!
//! A JWK Set is attacker-adjacent input: it is fetched, published, rotated, and
//! edited by people who are not you, and the document that arrives can name keys
//! this build cannot use. Two failure modes follow from handling it casually, and
//! both are security failures rather than ergonomic ones:
//!
//! * **Fall-through.** A token pins `kid=legit`, the set does not contain it, and
//!   the implementation "helpfully" tries the other keys until one works. Now a
//!   signature made by an unrelated key authenticates a token that named
//!   something else, and every key-pinning policy above it is decorative.
//! * **Silent filtering.** An entry is dropped because this build cannot use it,
//!   turning a set that *addresses* keys by name into an unlabelled pile, and
//!   making "no key matched" indistinguishable from "the key is fine, your build
//!   is too old".
//!
//! This module therefore refuses rather than guesses, and reports instead of
//! filtering: [`select`] resolves a `kid` under an explicit [`SelectionPolicy`]
//! and returns a bounded candidate list in document order, while
//! [`diagnostics`] describes **every** entry — including the unusable ones — with
//! the reason, keeping identifiers intact.
//!
//! Existing entry points keep their current semantics: [`JwkSet::find_unique_by_kid`]
//! still refuses ambiguous `kid`s and `jwt::decode_with_jwkset` still falls back
//! to trying every key when the set is kid-less. What is added here is the
//! parameterised version — budgets, an explicit fallback policy, and diagnostics —
//! for callers who want to state what they mean.
//!
//! ```
//! use jose_rs::jwk::{self, JwkSet};
//! use jose_rs::jwk::selection::{EntryStatus, Fallback, SelectionPolicy};
//!
//! let set = JwkSet::from_json(r#"{"keys":[
//!     {"kty":"EC","crv":"P-256","kid":"a","x":"AAAA","y":"AAAA"},
//!     {"kty":"EC","crv":"secp256k1","kid":"b","x":"AAAA","y":"AAAA"}
//! ]}"#)?;
//!
//! // Nothing is dropped: the unsupported entry is still there, with a reason.
//! let report = jwk::selection::diagnostics(&set);
//! assert_eq!(report.len(), 2);
//! assert!(matches!(report[1].status, EntryStatus::Unsupported { .. }));
//!
//! // A kid that is not in the set is a refusal, never a search for another key.
//! let policy = SelectionPolicy::default();
//! assert!(jwk::selection::select(&set, Some("missing"), &policy).is_err());
//! # Ok::<(), jose_rs::JoseError>(())
//! ```

use super::{Jwk, JwkSet};
use crate::error::{JoseError, Result};

/// Default ceiling on the number of keys a Set import will accept.
///
/// Not applied by [`JwkSet::from_json`] — that entry point's behaviour is
/// unchanged, because a limit introduced silently is a breaking change wearing
/// a compatibility mask. It is the default in [`SetLimits`], used by
/// [`JwkSet::from_json_with_limits`].
pub const DEFAULT_MAX_SET_ENTRIES: usize = 1024;

/// Default ceiling on cryptographic attempts a selection may produce.
///
/// Matching this to `jws::json::MAX_CANDIDATE_KEYS` is deliberate: a selection
/// that outlives the verification loop's own bound would only move the refusal
/// somewhere less useful.
pub const DEFAULT_MAX_CANDIDATES: usize = 64;

/// Key kinds this build can potentially use, by `kty`.
///
/// `AKP` is listed because the struct and parser accept it unconditionally;
/// whether it is *usable* depends on the `post-quantum` feature, which
/// [`diagnostics`] resolves through the real converter rather than a guess.
const SUPPORTED_KTY: [&str; 5] = ["RSA", "EC", "OKP", "oct", "AKP"];

/// Curves this build can potentially use, per `kty`.
const SUPPORTED_OKP_CRV: [&str; 2] = ["Ed25519", "X25519"];
const SUPPORTED_EC_CRV: [&str; 3] = ["P-256", "P-384", "P-521"];

/// Import-time budgets for a JWK Set.
///
/// Both limits exist because the cost of *parsing* a JWK Set is paid before any
/// key is used: a 200 MB set of 200 million entries is a denial of service at
/// import time, and none of it is a signature anyone has to check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SetLimits {
    /// Maximum size of the serialized set, in bytes.
    pub max_bytes: usize,
    /// Maximum number of entries in `keys`.
    pub max_entries: usize,
}

impl Default for SetLimits {
    fn default() -> Self {
        Self {
            // A JWK Set is JSON text; the token cap is the right order of
            // magnitude and four times it comfortably holds a few hundred
            // RSA-4096 public keys without admitting anything absurd.
            max_bytes: 4 * crate::MAX_TOKEN_BYTES,
            max_entries: DEFAULT_MAX_SET_ENTRIES,
        }
    }
}

impl SetLimits {
    /// Check a raw document against these limits, before it is parsed.
    ///
    /// The byte check *must* run first: after parsing, the memory is already
    /// spent, and a limit checked afterwards is a limit that never fires.
    ///
    /// # Errors
    ///
    /// [`JoseError::Key`] naming which limit was exceeded.
    pub fn check_bytes(&self, len: usize) -> Result<()> {
        if len > self.max_bytes {
            return Err(JoseError::Key(format!(
                "JWK Set document of {len} bytes exceeds the {} byte limit",
                self.max_bytes
            )));
        }
        Ok(())
    }

    /// Check a parsed entry count against these limits.
    pub fn check_entries(&self, len: usize) -> Result<()> {
        if len > self.max_entries {
            return Err(JoseError::Key(format!(
                "JWK Set with {len} entries exceeds the {} entry limit",
                self.max_entries
            )));
        }
        Ok(())
    }
}

/// What [`diagnostics`] concluded about one entry.
///
/// The three unsuccessful states are *not* interchangeable, and the difference is
/// the actionable part:
///
/// * [`EntryStatus::Unsupported`] — this build does not implement that kind of
///   key (secp256k1, Ed448, Brainpool). The entry is fine; the operator's
///   expectation may not be. Nothing is wrong with the data.
/// * [`EntryStatus::Invalid`] — the kind *is* supported and the material is
///   broken. This is the one to alert on: it means someone published something
///   malformed, not that a feature is off.
/// * [`EntryStatus::Usable`] — the real converter accepted it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryStatus {
    /// The key converted successfully and can be used for its declared operation.
    Usable,
    /// This build does not implement this key kind or curve.
    Unsupported {
        /// What is missing, e.g. `curve secp256k1 is not supported`.
        reason: String,
    },
    /// The kind is supported but the material did not convert.
    Invalid {
        /// The converter's own message, kept verbatim where possible.
        reason: String,
    },
}

impl EntryStatus {
    /// `true` for [`EntryStatus::Usable`].
    pub fn is_usable(&self) -> bool {
        matches!(self, EntryStatus::Usable)
    }
}

/// One entry of a JWK Set, described rather than filtered out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryDiagnostic {
    /// Position in `keys`, which is the only stable identity a kid-less entry has.
    pub index: usize,
    /// The entry's `kid`, exactly as published (`None` if it carried none).
    pub kid: Option<String>,
    /// The entry's `kty` as published. Kept as the raw string, including kinds
    /// this build has never heard of — a diagnostic that discards what it does
    /// not understand is not a diagnostic.
    pub kty: Option<String>,
    /// The entry's `crv` as published, if any.
    pub crv: Option<String>,
    /// The entry's `alg`, if any.
    pub alg: Option<String>,
    /// The entry's `use`, if any.
    pub use_: Option<String>,
    /// What this build concluded about the entry.
    pub status: EntryStatus,
}

/// Describe every entry in a set, in document order, keeping identifiers.
///
/// The result length always equals `set.keys.len()`: this function *cannot* drop
/// an entry, which is the property that keeps an addressable set addressable.
/// `Usable` is decided by running the real conversion, not by re-implementing the
/// rules, so the report cannot disagree with what the verifier will do later.
pub fn diagnostics(set: &JwkSet) -> Vec<EntryDiagnostic> {
    set.keys
        .iter()
        .enumerate()
        .map(|(index, key)| EntryDiagnostic::new(key, index))
        .collect()
}

impl EntryDiagnostic {
    /// Describe `key` at position `index` of its set.
    ///
    /// The index is a parameter because position *is* part of the information: for
    /// a kid-less entry it is the only stable identity it has.
    pub fn new(key: &Jwk, index: usize) -> Self {
        let status = classify(key);
        Self {
            index,
            kid: key.kid.clone(),
            kty: Some(key.kty.clone()),
            crv: key.crv.clone(),
            alg: key.alg.clone(),
            use_: key.use_.clone(),
            status,
        }
    }
}

/// Decide whether this build could use `key`, and say why not if it cannot.
fn classify(key: &Jwk) -> EntryStatus {
    if !SUPPORTED_KTY.contains(&key.kty.as_str()) {
        return EntryStatus::Unsupported {
            reason: format!("key type {:?} is not supported by this build", key.kty),
        };
    }
    if key.kty == "EC" {
        let crv = key.crv.as_deref().unwrap_or("");
        if !SUPPORTED_EC_CRV.contains(&crv) {
            return EntryStatus::Unsupported {
                reason: format!("curve {crv:?} is not supported by this build"),
            };
        }
    }
    if key.kty == "OKP" {
        let crv = key.crv.as_deref().unwrap_or("");
        if !SUPPORTED_OKP_CRV.contains(&crv) {
            return EntryStatus::Unsupported {
                reason: format!("curve {crv:?} is not supported by this build"),
            };
        }
    }

    // Kind and curve are in scope, so anything left is the material itself.
    // Asking the real converter is what keeps "unsupported" and "invalid" from
    // drifting apart from reality: this is the same call the verifier will make.
    match super::convert::jwk_to_software_key(key) {
        Ok(_) => EntryStatus::Usable,
        Err(err) => EntryStatus::Invalid {
            reason: err.to_string(),
        },
    }
}

/// What to do when the token's `kid` does not resolve to a key.
///
/// This is the one knob in this module that changes what a *valid* signature can
/// authenticate, so it is a policy the caller states rather than a default the
/// library implies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Fallback {
    /// Only an exact, unique `kid` match may be used. A token with no `kid`, or a
    /// `kid` the set does not contain, is refused. Strictest; the right choice
    /// wherever keys differ in trust or tenancy.
    Refuse,
    /// Try every key only when the set cannot be addressed by name at all — that
    /// is, when **no** entry carries a `kid`. This is the existing
    /// `jwt::decode_with_jwkset` behaviour and the default here, because
    /// kid-less sets from single-key issuers are common and there is no key the
    /// token could have named instead.
    #[default]
    TryWhenUnaddressable,
    /// Try every key whenever no `kid` match exists, even for a set whose other
    /// entries *are* named.
    ///
    /// This is what it sounds like: a signature by an unrelated key will
    /// authenticate a token that named a different one. It exists for callers
    /// dealing with producers that emit unreliable `kid`s, and it should be
    /// paired with a small [`SelectionPolicy::max_candidates`] so the blast
    /// radius is at least bounded.
    TryAll,
}

/// How to turn a set plus a token's `kid` into a bounded candidate list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectionPolicy {
    /// Maximum number of candidates a selection may return. Exceeding it is an
    /// error, never a silent truncation: a caller who asked to be able to use 500
    /// keys and quietly got the first 64 would fail in a way that looks like a
    /// key problem.
    pub max_candidates: usize,
    /// What to do when the `kid` does not resolve. See [`Fallback`].
    pub fallback: Fallback,
    /// Require the token to carry a `kid` at all, even when the set is kid-less.
    pub require_kid: bool,
}

impl Default for SelectionPolicy {
    fn default() -> Self {
        Self {
            max_candidates: DEFAULT_MAX_CANDIDATES,
            // Matches `jwt::decode_with_jwkset`'s long-standing behaviour, so the
            // parameterised entry point defaults to what callers already have.
            fallback: Fallback::default(),
            require_kid: false,
        }
    }
}

impl SelectionPolicy {
    /// The strictest useful policy: exact `kid` matches only, bounded attempts.
    pub fn strict() -> Self {
        Self {
            max_candidates: 1,
            fallback: Fallback::Refuse,
            require_kid: true,
        }
    }
}

/// The outcome of a selection: which keys may be tried, and what it cost to say so.
#[derive(Debug, Clone)]
pub struct Selection<'a> {
    /// Candidate keys, in document order. Deterministic: the same set and `kid`
    /// always produce the same list, which is what makes a selection auditable.
    pub candidates: Vec<&'a Jwk>,
    /// The `kid` that resolved, when one did.
    pub matched_kid: Option<String>,
    /// `true` when the list came from a `kid` match rather than a fallback sweep.
    pub matched_by_kid: bool,
    /// How many entries the set held. Kept so a caller can log "3 of 214 entries
    /// were candidates" without re-walking the set.
    pub set_size: usize,
}

impl<'a> Selection<'a> {
    /// Number of cryptographic attempts this selection authorizes.
    pub fn attempts(&self) -> usize {
        self.candidates.len()
    }
}

/// Resolve a token's `kid` against a set under an explicit policy.
///
/// # Errors
///
/// * [`JoseError::InvalidHeader`] when `require_kid` is set and the token names no key.
/// * [`JoseError::Key`] when the `kid` matches nothing (in an addressable set),
///   matches more than one entry, or when a fallback would exceed
///   `max_candidates`. Every such message says which limit or which `kid` was at
///   issue, because "no key matched" without a `kid` is not a diagnosable report.
///
/// ```
/// use jose_rs::jwk::{self, JwkSet};
/// use jose_rs::jwk::selection::{Fallback, SelectionPolicy};
///
/// let set = JwkSet::from_json(r#"{"keys":[
///     {"kty":"oct","kid":"a","k":"AAAA"},
///     {"kty":"oct","kid":"b","k":"AAAA"}
/// ]}"#)?;
///
/// let exact = jwk::selection::select(&set, Some("b"), &SelectionPolicy::default())?;
/// assert_eq!(exact.candidates.len(), 1);
/// assert!(exact.matched_by_kid);
///
/// // A named key that is not in the set never falls through to another key.
/// assert!(jwk::selection::select(&set, Some("c"), &SelectionPolicy::default()).is_err());
///
/// // A kid-less set is unaddressable, so the bounded sweep is allowed there.
/// let anonymous = JwkSet::from_json(r#"{"keys":[{"kty":"oct","k":"AAAA"}]}"#)?;
/// let swept = jwk::selection::select(&anonymous, None, &SelectionPolicy::default())?;
/// assert_eq!(swept.candidates.len(), 1);
/// assert!(!swept.matched_by_kid);
///
/// // ...and the same sweep is refused when the policy says exact matches only.
/// let strict = SelectionPolicy { fallback: Fallback::Refuse, ..Default::default() };
/// assert!(jwk::selection::select(&anonymous, None, &strict).is_err());
/// # Ok::<(), jose_rs::JoseError>(())
/// ```
pub fn select<'a>(
    set: &'a JwkSet,
    token_kid: Option<&str>,
    policy: &SelectionPolicy,
) -> Result<Selection<'a>> {
    if set.keys.is_empty() {
        return Err(JoseError::Key("JWK Set is empty".into()));
    }
    if policy.require_kid && token_kid.is_none() {
        return Err(JoseError::InvalidHeader(
            "missing required kid header".into(),
        ));
    }

    // An "addressable" set is one where at least one entry carries a `kid`: the
    // producer chose to name its keys, so a token that names one is entitled to
    // have that name respected.
    let addressable = set.keys.iter().any(|key| key.kid.is_some());

    if let Some(kid) = token_kid {
        let mut matches = set
            .keys
            .iter()
            .enumerate()
            .filter(|(_, key)| key.kid.as_deref() == Some(kid));
        let first = matches.next();
        let second = matches.next();

        match (first, second) {
            (Some((_, key)), None) => {
                if 1 > policy.max_candidates {
                    return Err(JoseError::Key(format!(
                        "candidate budget of {} cannot accommodate even the single key named by \
                         kid {kid:?}",
                        policy.max_candidates
                    )));
                }
                return Ok(Selection {
                    candidates: vec![key],
                    matched_kid: Some(kid.to_string()),
                    matched_by_kid: true,
                    set_size: set.keys.len(),
                });
            }
            (Some(_), Some(_)) => {
                // Duplicate identifiers are refused even if the material is identical:
                // "which key signed this?" must have exactly one answer. Preserved
                // from `find_unique_by_kid`, and deliberately *not* resolved by
                // filtering unsupported entries out first.
                return Err(JoseError::Key(format!(
                    "multiple JWKs in the set match kid {kid:?}"
                )));
            }
            // No entry carries this `kid`.
            (None, _) => {
                let sweep_allowed = match policy.fallback {
                    // Never: a named key that is absent is a refusal, not a hint.
                    Fallback::Refuse => false,
                    // Only when nothing in the set could have been named instead.
                    Fallback::TryWhenUnaddressable => !addressable,
                    Fallback::TryAll => true,
                };
                if !sweep_allowed {
                    return Err(JoseError::Key(if addressable {
                        format!(
                            "no JWK in the set matches the token's kid {kid:?}; refusing to try \
                             unrelated keys"
                        )
                    } else {
                        format!(
                            "no JWK in the set matches the token's kid {kid:?} and the policy \
                             forbids trying unnamed keys"
                        )
                    }));
                }
                return bounded_sweep(set, Some(kid), policy, false);
            }
        }
    }

    // No `kid` in the token.
    match policy.fallback {
        Fallback::Refuse => Err(JoseError::InvalidHeader(
            "the token names no key and the policy requires an exact kid match".into(),
        )),
        // A kid-less token against an *addressable* set is the other half of the
        // same trap: the producer names its keys, the token declined to say which,
        // and sweeping would guess.
        Fallback::TryWhenUnaddressable if addressable => Err(JoseError::Key(
            "the token names no key and the set is addressable by kid; refusing to try every key"
                .into(),
        )),
        Fallback::TryWhenUnaddressable | Fallback::TryAll => {
            bounded_sweep(set, None, policy, addressable)
        }
    }
}

/// Shared tail of the fallback paths, enforcing the attempt budget.
fn bounded_sweep<'a>(
    set: &'a JwkSet,
    token_kid: Option<&str>,
    policy: &SelectionPolicy,
    addressable: bool,
) -> Result<Selection<'a>> {
    if set.keys.len() > policy.max_candidates {
        return Err(JoseError::Key(format!(
            "fallback selection would try {} keys, exceeding the candidate budget of {}{}",
            set.keys.len(),
            policy.max_candidates,
            match token_kid {
                Some(kid) if addressable =>
                    format!(" (kid {kid:?} matched no entry in an addressable set)"),
                _ => String::new(),
            }
        )));
    }
    Ok(Selection {
        candidates: set.keys.iter().collect(),
        matched_kid: None,
        matched_by_kid: false,
        set_size: set.keys.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set_of(json: &str) -> JwkSet {
        JwkSet::from_json(json).expect("set parses")
    }

    /// 32 bytes of key material, base64url: a length an `oct` key may actually have.
    const K32: &str = "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE";

    const TWO_NAMED: &str = r#"{"keys":[
        {"kty":"oct","kid":"a","k":"AAAA"},
        {"kty":"oct","kid":"b","k":"AAAA"}]}"#;

    #[test]
    fn an_unknown_kid_never_falls_through() {
        let set = set_of(TWO_NAMED);
        for fallback in [
            Fallback::Refuse,
            Fallback::TryWhenUnaddressable,
            Fallback::TryAll,
        ] {
            let policy = SelectionPolicy {
                fallback,
                ..Default::default()
            };
            match fallback {
                // The explicit escape hatch is the only one that sweeps, and the doc
                // comment says so loudly.
                Fallback::TryAll => {
                    assert_eq!(
                        select(&set, Some("c"), &policy).unwrap().candidates.len(),
                        2,
                        "TryAll is documented to sweep"
                    );
                }
                // The other two must refuse, naming the kid and saying they refused.
                _ => {
                    let msg = select(&set, Some("c"), &policy).unwrap_err().to_string();
                    assert!(msg.contains("kid"), "{msg}");
                    assert!(
                        msg.contains("refusing") || msg.contains("forbids"),
                        "the refusal must say it refused rather than searched: {msg}"
                    );
                }
            }
        }
    }

    #[test]
    fn a_kid_less_token_against_an_addressable_set_is_refused_by_default() {
        let set = set_of(TWO_NAMED);
        let err = select(&set, None, &SelectionPolicy::default()).unwrap_err();
        assert!(err.to_string().contains("addressable"), "{err}");
        // Strict mode refuses it too, earlier and as a header problem.
        let err = select(&set, None, &SelectionPolicy::strict()).unwrap_err();
        assert!(
            matches!(err, JoseError::InvalidHeader(_)),
            "require_kid fires before any key is touched: {err:?}"
        );
    }

    #[test]
    fn duplicate_kids_are_refused_even_when_identical_or_unusable() {
        // Identical material: still two answers to "which key signed this?".
        let set = set_of(
            r#"{"keys":[{"kty":"oct","kid":"a","k":"AAAA"},{"kty":"oct","kid":"a","k":"AAAA"}]}"#,
        );
        let err = select(&set, Some("a"), &SelectionPolicy::default()).unwrap_err();
        assert!(err.to_string().contains("multiple"), "{err}");

        // And filtering does not rescue it: an unsupported twin is still a duplicate.
        let set = set_of(
            r#"{"keys":[
                {"kty":"oct","kid":"a","k":"AAAA"},
                {"kty":"EC","crv":"secp256k1","kid":"a","x":"AA","y":"AA"}]}"#,
        );
        let err = select(&set, Some("a"), &SelectionPolicy::default()).unwrap_err();
        assert!(err.to_string().contains("multiple"), "{err}");
    }

    #[test]
    fn the_attempt_budget_errors_instead_of_truncating() {
        let keys: Vec<String> = (0..10)
            .map(|i| format!(r#"{{"kty":"oct","k":"AAAA{i}"}}"#))
            .collect();
        let set = set_of(&format!(r#"{{"keys":[{}]}}"#, keys.join(",")));
        let policy = SelectionPolicy {
            max_candidates: 4,
            fallback: Fallback::TryAll,
            require_kid: false,
        };
        let err = select(&set, None, &policy).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("budget"), "{msg}");
        assert!(
            msg.contains("10"),
            "the message states the real count: {msg}"
        );

        // Within budget, all ten are candidates.
        let policy = SelectionPolicy {
            max_candidates: 16,
            ..policy
        };
        assert_eq!(select(&set, None, &policy).unwrap().attempts(), 10);
    }

    #[test]
    fn diagnostics_keep_every_entry_with_its_identifier() {
        let set = set_of(&format!(
            r#"{{"keys":[
                {{"kty":"oct","kid":"good","k":"{K32}"}},
                {{"kty":"EC","crv":"secp256k1","kid":"curve","x":"AA","y":"AA"}},
                {{"kty":"RSA","kid":"broken","n":"not-base64url!!","e":"AQAB"}},
                {{"kty":"TooCool","kid":"future"}}]}}"#,
        ));
        let report = diagnostics(&set);
        assert_eq!(report.len(), 4, "diagnostics cannot drop entries");
        let kids: Vec<Option<&str>> = report.iter().map(|e| e.kid.as_deref()).collect();
        assert_eq!(
            kids,
            vec![Some("good"), Some("curve"), Some("broken"), Some("future")]
        );

        assert!(report[0].status.is_usable(), "{:?}", report[0]);
        // Unsupported: the build lacks the curve. Nothing is wrong with the entry.
        let EntryStatus::Unsupported { reason } = &report[1].status else {
            panic!("expected unsupported, got {:?}", report[1].status)
        };
        assert!(reason.contains("secp256k1"), "{reason}");
        // Invalid: the kind is supported and the material is broken. The two are
        // never conflated, which is the whole point of three states.
        let EntryStatus::Invalid { reason } = &report[2].status else {
            panic!("expected invalid, got {:?}", report[2].status)
        };
        assert!(!reason.is_empty(), "{:?}", report[2]);
        // Unknown kty is unsupported, not invalid.
        assert!(matches!(report[3].status, EntryStatus::Unsupported { .. }));
        assert_eq!(report[3].kty.as_deref(), Some("TooCool"));
    }

    #[test]
    fn diagnostics_agree_with_the_converter_that_will_be_used() {
        // A "usable" report that the verifier then rejects would make the whole
        // exercise theatre, so usability is defined as "the real conversion
        // succeeded" and this checks the report still says exactly that.
        let set = set_of(&format!(
            r#"{{"keys":[
                {{"kty":"oct","k":"{K32}"}},
                {{"kty":"oct","k":"AAAA"}},
                {{"kty":"oct"}},
                {{"kty":"EC","crv":"secp256k1","kid":"x","x":"AA","y":"AA"}}]}}"#,
        ));
        // One of each: usable, invalid (too short), invalid (no material), unsupported.
        let report = diagnostics(&set);
        assert!(report[0].status.is_usable(), "{:?}", report[0]);
        assert!(matches!(report[1].status, EntryStatus::Invalid { .. }));
        assert!(matches!(report[2].status, EntryStatus::Invalid { .. }));
        assert!(matches!(report[3].status, EntryStatus::Unsupported { .. }));
        for (key, entry) in set.keys.iter().zip(diagnostics(&set)) {
            let convertible = super::super::convert::jwk_to_software_key(key).is_ok();
            assert_eq!(
                entry.status.is_usable(),
                convertible,
                "report said {:?} for {key:?}",
                entry.status
            );
        }
    }

    #[test]
    fn import_limits_are_enforced_before_parsing() {
        let text = r#"{"keys":[{"kty":"oct","k":"AAAA"}]}"#;
        let limits = SetLimits {
            max_bytes: 10,
            ..Default::default()
        };
        let err = JwkSet::from_json_with_limits(text, &limits).unwrap_err();
        assert!(err.to_string().contains("bytes"), "{err}");

        let limits = SetLimits {
            max_entries: 0,
            ..Default::default()
        };
        let err = JwkSet::from_json_with_limits(text, &limits).unwrap_err();
        assert!(err.to_string().contains("entries"), "{err}");

        // Unbounded entry point is unchanged.
        assert_eq!(JwkSet::from_json(text).unwrap().keys.len(), 1);
    }

    #[test]
    fn selection_is_deterministic_in_document_order() {
        let set = set_of(
            r#"{"keys":[
                {"kty":"oct","k":"AAAA"},
                {"kty":"oct","k":"BBBB"},
                {"kty":"oct","k":"CCCC"}]}"#,
        );
        let policy = SelectionPolicy {
            fallback: Fallback::TryAll,
            ..Default::default()
        };
        let first = select(&set, None, &policy).unwrap();
        let second = select(&set, None, &policy).unwrap();
        let keys: Vec<Option<&str>> = first.candidates.iter().map(|k| k.k.as_deref()).collect();
        assert_eq!(keys, vec![Some("AAAA"), Some("BBBB"), Some("CCCC")]);
        assert_eq!(
            first.candidates.len(),
            second.candidates.len(),
            "the same input must produce the same selection"
        );
        assert_eq!(first.set_size, 3);
    }
}
