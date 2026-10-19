//! JWT Claims set (RFC 7519 §4.1)
//!
//! [`Claims`] holds the seven registered claims in typed fields and everything else in
//! [`Claims::extra`]. Two properties are enforced rather than left to serde, because both
//! are places where a JWT can be *ambiguous* — a token two honest verifiers read
//! differently — and ambiguity in a security token is not a formatting detail:
//!
//! * **Emitting cannot produce a duplicate member.** An `extra` entry named `iss` would
//!   serialize next to the typed `iss` and produce two `iss` members; readers disagree about
//!   which wins (RFC 8725 §3.5 exists for this reason). [`Claims::ensure_no_duplicate_members`]
//!   refuses such a struct *before* serialization, so the byte stream leaving this crate has
//!   one member per name. The same rule already protects JWS/JWE headers
//!   (`JoseHeader::ensure_no_duplicate_members`); this is the JWT half.
//! * **Parsing refuses duplicate members.** `serde_json` silently lets the later value win, so
//!   a payload with two `exp` members would be verified against one expiry and read by a peer
//!   against another. [`Claims::from_json_bytes`] scans the top-level members first and rejects
//!   the token naming the duplicated name.
//!
//! Also fixed by design, and tested in `tests/jwt_claims.rs`:
//!
//! * **Numbers keep their precision.** Registered timestamps are [`NumericDate`], which parses
//!   decimal text rather than going through `f64`; unregistered claims are kept as
//!   [`serde_json::Value`], which preserves `u64`/`i64` exactly. A claim larger than 2^53 is not
//!   quietly rounded.
//! * **Absent and null are the same thing for optional claims.** `"exp": null` and no `exp`
//!   member both mean "no expiration". This is stated because it is *not* the JSON convention
//!   elsewhere in this crate — header members are strictly typed and a `null` `crit` is an
//!   error — and because a caller who expects `Some(Null)` in `extra` will be surprised: a
//!   registered name is never in `extra`, with a value or without one.
//! * **The payload is size-bounded** by [`crate::MAX_TOKEN_BYTES`], like every other
//!   untrusted input this crate parses.

use crate::error::{JoseError, Result};
use crate::jwt::numeric_date::NumericDate;
use crate::MAX_TOKEN_BYTES;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The registered claim names that map onto typed [`Claims`] fields.
///
/// A name in this list may not also appear in [`Claims::extra`] — see
/// [`Claims::ensure_no_duplicate_members`] — which is what keeps serialized payloads free of
/// duplicate members.
pub const REGISTERED_CLAIMS: [&str; 7] = ["iss", "sub", "aud", "exp", "nbf", "iat", "jti"];

/// JWT Claims set (RFC 7519 §4.1).
///
/// See the [module documentation](self) for the duplicate-member, precision and null
/// semantics this type enforces.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Claims {
    /// Issuer (`iss`)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,

    /// Subject (`sub`)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,

    /// Audience (`aud`) — can be a single string or array of strings
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<Audience>,

    /// Expiration Time (`exp`) — NumericDate (seconds since epoch)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exp: Option<NumericDate>,

    /// Not Before (`nbf`) — NumericDate (seconds since epoch)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nbf: Option<NumericDate>,

    /// Issued At (`iat`) — NumericDate (seconds since epoch)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iat: Option<NumericDate>,

    /// JWT ID (`jti`)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,

    /// Custom claims
    #[serde(flatten)]
    pub extra: std::collections::HashMap<String, Value>,
}

/// Audience can be a single string or an array of strings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Audience {
    /// A single audience string.
    Single(String),
    /// Multiple acceptable audience strings.
    Multiple(Vec<String>),
}

impl Audience {
    /// Check if this audience contains the given value.
    pub fn contains(&self, value: &str) -> bool {
        match self {
            Audience::Single(s) => s == value,
            Audience::Multiple(v) => v.iter().any(|s| s == value),
        }
    }
}

/// Collect the top-level member names of a JSON object, refusing duplicates.
///
/// Values are skipped (`serde::de::IgnoredAny`), so this is a cheap pre-pass: it costs a scan,
/// not a second parse of the tree. Only the top level is examined — registered claims are
/// top-level members, and a duplicate inside an `aud` array element's object is that object's
/// business, not the claims set's.
///
/// Nested values are still *skipped* rather than validated here, so deeply nested payloads are
/// not a risk from this pass; the real nesting limit is serde_json's own recursion check during
/// the following parse.
fn ensure_unique_top_level_members(bytes: &[u8]) -> Result<()> {
    struct UniqueMembers;

    impl<'de> serde::Deserialize<'de> for UniqueMembers {
        fn deserialize<D>(deserializer: D) -> std::prelude::v1::Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            use serde::de::{MapAccess, Visitor};

            struct MapVisitor;

            impl<'de> Visitor<'de> for MapVisitor {
                type Value = UniqueMembers;

                fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    f.write_str("a JSON object of claims")
                }

                fn visit_map<A>(self, mut map: A) -> std::prelude::v1::Result<Self::Value, A::Error>
                where
                    A: MapAccess<'de>,
                {
                    // Names are small and the payload is already size-bounded, so owning them is
                    // cheaper to reason about than borrowing through the map access lifetime —
                    // and it avoids the `Box::leak` "optimization" that a first draft of this
                    // function needed and that no library should ship.
                    let mut seen = std::collections::HashSet::new();
                    while let Some(key) = map.next_key::<String>()? {
                        if !seen.insert(key.clone()) {
                            // Naming the duplicate is the whole point: "your token has two
                            // meanings" is only actionable if the caller can see which member.
                            return Err(serde::de::Error::custom(format!(
                                "duplicate JSON member {key}"
                            )));
                        }
                        // Values are skipped here and parsed once, properly, by the typed parse
                        // that follows.
                        map.next_value::<serde::de::IgnoredAny>()?;
                    }
                    Ok(UniqueMembers)
                }
            }

            // `deserialize_map`, not `deserialize_any`: a claims set is an object, and anything
            // else is refused here rather than by a confusing error three layers down.
            deserializer.deserialize_map(MapVisitor)
        }
    }

    serde_json::from_slice::<UniqueMembers>(bytes)
        .map(|_| ())
        .map_err(|err| JoseError::InvalidClaims(err.to_string()))
}

impl Claims {
    /// Refuse to serialize a claim set that would emit a registered name twice.
    ///
    /// `#[serde(flatten)]` writes `extra` after the typed fields and serde does not deduplicate
    /// members, so without this check a claim set carrying `extra["exp"]` alongside `exp` would
    /// produce a payload with two `exp` members — one token, two readings, and the verifier's
    /// choice of expiry would depend on its parser.
    ///
    /// Named [`JoseError::InvalidClaims`] because the claim set, not the wire, is what is wrong.
    ///
    /// ```
    /// use jose_rs::jwt::Claims;
    /// use serde_json::json;
    ///
    /// let mut claims = Claims::default();
    /// claims.iss = Some("issuer".into());
    /// claims.extra.insert("exp".into(), json!(1));
    /// let err = claims.ensure_no_duplicate_members().unwrap_err();
    /// assert!(format!("{err}").contains("exp"));
    /// ```
    pub fn ensure_no_duplicate_members(&self) -> Result<()> {
        for name in REGISTERED_CLAIMS {
            if self.extra.contains_key(name) {
                return Err(JoseError::InvalidClaims(format!(
                    "extra claim {name} duplicates the typed {name} field, which would serialize \
                     the member twice"
                )));
            }
        }
        Ok(())
    }

    /// Serialize to canonical, unambiguous JSON bytes.
    ///
    /// This is the only serialization path that is guaranteed duplicate-free;
    /// calling `serde_json::to_vec(claims)` directly bypasses the check (the JWT encoding
    /// functions in this crate use this path).
    ///
    /// # Errors
    ///
    /// [`JoseError::InvalidClaims`] for a typed/`extra` collision, `Json` for a serialization
    /// failure.
    pub fn to_json_vec(&self) -> Result<Vec<u8>> {
        self.ensure_no_duplicate_members()?;
        serde_json::to_vec(self).map_err(Into::into)
    }

    /// Parse a claims payload from untrusted bytes.
    ///
    /// Enforces the size bound ([`crate::MAX_TOKEN_BYTES`]), rejects duplicate top-level members
    /// before any typed field is read, and then deserializes. Note the order: a duplicate is a
    /// property of the *document*, and `serde_json`'s map type would have merged it away before
    /// a value-level check could ever see it.
    ///
    /// # Errors
    ///
    /// [`JoseError::InvalidClaims`] when oversized or containing a duplicate member (naming it),
    /// `Json` when the payload is not a well-formed claims object.
    ///
    /// ```
    /// use jose_rs::jwt::Claims;
    ///
    /// let claims = Claims::from_json_bytes(br#"{"iss":"a","exp":100.5,"scope":"read"}"#).unwrap();
    /// assert_eq!(claims.iss.as_deref(), Some("a"));
    /// assert_eq!(claims.exp.unwrap().subsec_nanos(), 500_000_000);
    /// assert_eq!(claims.extra["scope"], serde_json::json!("read"));
    ///
    /// // Two `exp` members is one token with two meanings, so it is not a token at all.
    /// let err = Claims::from_json_bytes(br#"{"exp":1,"exp":2}"#).unwrap_err();
    /// assert!(format!("{err}").contains("exp"));
    /// # Ok::<(), jose_rs::JoseError>(())
    /// ```
    pub fn from_json_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_TOKEN_BYTES {
            return Err(JoseError::InvalidClaims(format!(
                "claims payload of {} bytes exceeds the {} byte limit",
                bytes.len(),
                MAX_TOKEN_BYTES
            )));
        }
        ensure_unique_top_level_members(bytes)?;
        serde_json::from_slice(bytes).map_err(Into::into)
    }

    /// Parse from a UTF-8 string slice. See [`Claims::from_json_bytes`].
    pub fn from_json_str(text: &str) -> Result<Self> {
        Self::from_json_bytes(text.as_bytes())
    }

    /// Adopt an already-parsed [`Value`] as a claim set.
    ///
    /// A `serde_json::Value` object cannot *hold* duplicate members — its map merged them on the
    /// way in, last value winning — so this cannot detect what it was given. That is the whole
    /// reason the JWT entry points in this crate parse from bytes: a caller holding a `Value` has
    /// already chosen a reading of any duplicate, and this function documents that the choice was
    /// made before, not here. Prefer [`Claims::from_json_bytes`] whenever the original bytes are
    /// available.
    pub fn from_json_value(value: &Value) -> Result<Self> {
        serde_json::from_value(value.clone()).map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn registered_names_may_not_appear_in_extra() {
        let mut claims = Claims {
            exp: Some(100_u64.into()),
            ..Default::default()
        };
        claims.extra.insert("exp".into(), json!(999));
        let err = claims.ensure_no_duplicate_members().unwrap_err();
        assert!(matches!(err, JoseError::InvalidClaims(_)));
        assert!(err.to_string().contains("exp"));

        // Unregistered names are fine, however close they look.
        let mut claims = Claims::default();
        claims.extra.insert("expiries".into(), json!([1, 2]));
        claims.extra.insert("audience".into(), json!("x"));
        claims.ensure_no_duplicate_members().unwrap();
    }

    #[test]
    fn serialization_is_duplicate_free() {
        let mut claims = Claims {
            iss: Some("issuer".into()),
            ..Default::default()
        };
        claims.extra.insert("scope".into(), json!("read write"));
        let bytes = claims.to_json_vec().unwrap();
        // Re-reading our own output through the strict path must succeed: that is the claim.
        let back = Claims::from_json_bytes(&bytes).unwrap();
        assert_eq!(back.iss.as_deref(), Some("issuer"));
        assert_eq!(back.extra["scope"], json!("read write"));
    }

    #[test]
    fn duplicate_members_are_refused_by_name() {
        let err = Claims::from_json_bytes(br#"{"iss":"a","iss":"b"}"#).unwrap_err();
        assert!(err.to_string().contains("iss"), "{err}");

        // Any duplicate, wherever it sits, and including a registered name duplicated in a way
        // that would otherwise be resolved silently by field order.
        for payload in [
            br#"{"x":1,"x":2}"#.as_slice(),
            br#"{"exp":1,"nbf":2,"exp":3}"#.as_slice(),
            br#"{"sub":"a","extra":{},"sub":"b"}"#.as_slice(),
        ] {
            let err = Claims::from_json_bytes(payload).unwrap_err();
            assert!(matches!(err, JoseError::InvalidClaims(_)), "{err}");
        }
    }

    #[test]
    fn duplicates_nested_inside_a_value_are_not_the_claims_sets_problem() {
        // The claims set owns its top level. An object *inside* an unregistered claim keeps its
        // own meaning; refusing here would be inventing a rule RFC 7519 does not state.
        let claims = Claims::from_json_bytes(br#"{"meta":{"a":1,"a":2}}"#).unwrap();
        assert!(claims.extra.contains_key("meta"));
    }

    #[test]
    fn null_and_absent_are_the_same_claim() {
        let explicit_null = Claims::from_json_bytes(br#"{"exp":null,"iss":null,"jti":null}"#)
            .expect("nulls are absent, not errors");
        assert!(explicit_null.exp.is_none());
        assert!(explicit_null.iss.is_none());
        assert!(explicit_null.jti.is_none());
        assert!(explicit_null.extra.is_empty());
    }

    #[test]
    fn numbers_keep_their_precision_in_both_directions() {
        // Beyond 2^53 an f64 could not hold this; `Value` and `NumericDate` both can.
        let payload = br#"{"iat":18446744073709551615,"scope":"x","nbf":122.592736}"# as &[u8];
        let claims = Claims::from_json_bytes(payload).unwrap();
        assert_eq!(claims.nbf.unwrap().subsec_nanos(), 592_736_000);
        let big = Claims {
            iat: Some(claims.iat.unwrap()),
            ..Default::default()
        };
        let bytes = big.to_json_vec().unwrap();
        assert!(
            String::from_utf8(bytes.clone())
                .unwrap()
                .contains("18446744073709551615"),
            "{}",
            String::from_utf8_lossy(&bytes)
        );
    }

    #[test]
    fn oversized_payloads_are_refused_before_parsing() {
        let filler = "a".repeat(MAX_TOKEN_BYTES);
        let payload = format!(r#"{{"jti":"{filler}"}}"#);
        let err = Claims::from_json_bytes(payload.as_bytes()).unwrap_err();
        assert!(err.to_string().contains("exceeds"), "{err}");
    }

    #[test]
    fn many_unique_claim_names_remain_acceptable() {
        let payload = format!(
            "{{{}}}",
            (0..4096)
                .map(|index| format!(r#""claim-{index}":{index}"#))
                .collect::<Vec<_>>()
                .join(",")
        );
        let claims = Claims::from_json_bytes(payload.as_bytes()).unwrap();
        assert_eq!(claims.extra.len(), 4096);
    }

    #[test]
    fn value_conversion_documents_a_choice_already_made() {
        // A Value cannot carry a duplicate; from_json_value must not claim it checked for one.
        let value = json!({"iss": "a"});
        let claims = Claims::from_json_value(&value).unwrap();
        assert_eq!(claims.iss.as_deref(), Some("a"));
    }
}
