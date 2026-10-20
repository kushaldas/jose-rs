//! Strict JSON object member handling shared by the JOSE parsers.
//!
//! `serde_json`'s `Value` (and any `HashMap`/`BTreeMap` target) applies
//! last-key-wins to a JSON object that repeats a member name, which is
//! exactly the ambiguity this crate refuses everywhere else: two peers that
//! parse the same bytes differently is a confused-deputy vector (see
//! `interop/README.md`, cells `dup-kid`/`dup-alg`, and the header rule in
//! RFC 7515 §4 / RFC 7516 §5.2 step 4).
//!
//! [`MemberMap`] deserializes an object while preserving member order and
//! rejecting repeated names, and it hands the caller the members it did not
//! consume so "additional members MUST be ignored" (RFC 7516 §7.2.1) can be
//! honoured deliberately instead of by accident.

use serde::de::{MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::HashSet;

use crate::error::{JoseError, Result};

/// The JSON member names of one object, in document order, with duplicates
/// rejected at parse time.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct MemberMap {
    members: Vec<(String, serde_json::Value)>,
}

impl MemberMap {
    /// Build a map from `(name, value)` pairs, refusing duplicate names.
    pub(crate) fn new(members: Vec<(String, serde_json::Value)>) -> Result<Self> {
        let mut seen = HashSet::with_capacity(members.len());
        for (name, _) in &members {
            if !seen.insert(name.as_str()) {
                return Err(JoseError::InvalidToken(format!(
                    "duplicate JSON member {name}"
                )));
            }
        }
        Ok(MemberMap { members })
    }

    /// `true` when `name` is present.
    pub(crate) fn contains(&self, name: &str) -> bool {
        self.get(name).is_some()
    }

    /// The value bound to `name`, if any.
    pub(crate) fn get(&self, name: &str) -> Option<&serde_json::Value> {
        self.members.iter().find(|(n, _)| n == name).map(|(_, v)| v)
    }

    /// Remove and return the value bound to `name`.
    pub(crate) fn take(&mut self, name: &str) -> Option<serde_json::Value> {
        let index = self.members.iter().position(|(n, _)| n == name)?;
        Some(self.members.remove(index).1)
    }

    /// Remove `name` and require its value to be a JSON string.
    ///
    /// # Errors
    ///
    /// [`JoseError::InvalidToken`] when the member is present but is not a
    /// string — a type error, not a missing member.
    pub(crate) fn take_string(&mut self, name: &str) -> Result<Option<String>> {
        match self.take(name) {
            None => Ok(None),
            Some(serde_json::Value::String(s)) => Ok(Some(s)),
            Some(_) => Err(JoseError::InvalidToken(format!(
                "JSON member {name} must be a string"
            ))),
        }
    }

    /// Remove and return every remaining member as `(name, value)` pairs.
    pub(crate) fn drain_leftovers(&mut self) -> Vec<(String, serde_json::Value)> {
        std::mem::take(&mut self.members)
    }

    /// Serialize into `map`, refusing to overwrite a name the caller already
    /// inserted.
    ///
    /// This is the emit-side half of the duplicate rule: a JOSE JSON object
    /// never carries the same member twice, so a consumer cannot read a
    /// different value than the one this crate authenticated.
    ///
    /// # Errors
    ///
    /// [`JoseError::InvalidToken`] naming the first colliding member.
    pub(crate) fn write_into(
        &self,
        map: &mut serde_json::Map<String, serde_json::Value>,
    ) -> Result<()> {
        for (name, value) in &self.members {
            if map.insert(name.clone(), value.clone()).is_some() {
                return Err(JoseError::InvalidToken(format!(
                    "duplicate JSON member {name}"
                )));
            }
        }
        Ok(())
    }
}

impl MemberMap {
    /// Parse a JSON object into a member map.
    ///
    /// # Errors
    ///
    /// [`JoseError::InvalidToken`] for a duplicate member name, and
    /// [`JoseError::Json`] when `text` is not a JSON object at all.
    pub(crate) fn from_json(text: &str) -> Result<Self> {
        serde_json::from_str(text).map_err(JoseError::from)
    }
}

/// `MemberMap` always rejects duplicate names, including when it is nested
/// inside another `Deserialize` implementation.
impl<'de> Deserialize<'de> for MemberMap {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct MemberMapVisitor;

        impl<'de> Visitor<'de> for MemberMapVisitor {
            type Value = MemberMap;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a JSON object")
            }

            fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                // `MapAccess` streams the document, so a repeated key is
                // observed here even though `Value`/`Map` targets would
                // silently collapse it.
                let mut members: Vec<(String, serde_json::Value)> = Vec::new();
                let mut seen = HashSet::new();
                while let Some((name, value)) = map.next_entry::<String, serde_json::Value>()? {
                    if !seen.insert(name.clone()) {
                        return Err(serde::de::Error::custom(format!(
                            "duplicate JSON member {name}"
                        )));
                    }
                    members.push((name, value));
                }
                Ok(MemberMap { members })
            }
        }

        deserializer.deserialize_map(MemberMapVisitor)
    }
}

impl Serialize for MemberMap {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(Some(self.members.len()))?;
        for (name, value) in &self.members {
            map.serialize_entry(name, value)?;
        }
        map.end()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_in_document_order() {
        let mut map = MemberMap::from_json(r#"{"b":1,"a":2}"#).unwrap();
        // This crate's own serializer keeps document order.
        assert_eq!(
            serde_json::to_string(&map).unwrap(),
            r#"{"b":1,"a":2}"#,
            "member order must survive for callers that re-emit members"
        );

        // `write_into` transfers every member; a JSON map has no order
        // guarantee of its own (serde_json sorts by key).
        let mut out = serde_json::Map::new();
        map.write_into(&mut out).unwrap();
        assert_eq!(serde_json::to_string(&out).unwrap(), r#"{"a":2,"b":1}"#);

        assert_eq!(map.take("b"), Some(serde_json::json!(1)));
        assert_eq!(map.take("a"), Some(serde_json::json!(2)));
        assert!(map.take("missing").is_none());
    }

    /// The whole point of the type: a repeated member is a hard error, not a
    /// silent last-key-wins.
    #[test]
    fn rejects_duplicate_members() {
        let err = MemberMap::from_json(r#"{"kid":"a","kid":"b"}"#).unwrap_err();
        assert!(
            err.to_string().contains("duplicate JSON member kid"),
            "{err}"
        );
        let err = MemberMap::new(vec![
            ("k".into(), serde_json::json!(1)),
            ("k".into(), serde_json::json!(2)),
        ])
        .unwrap_err();
        assert!(err.to_string().contains("duplicate JSON member k"), "{err}");
    }

    #[test]
    fn rejects_non_objects() {
        for text in ["[]", "\"x\"", "5", "null", "not json"] {
            assert!(
                MemberMap::from_json(text).is_err(),
                "{text} must not parse as a JOSE JSON object"
            );
        }
    }

    #[test]
    fn take_string_checks_the_type() {
        let mut map = MemberMap::from_json(r#"{"a":"s","n":1}"#).unwrap();
        assert_eq!(map.take_string("a").unwrap().as_deref(), Some("s"));
        assert_eq!(map.take_string("missing").unwrap(), None);
        let err = map.take_string("n").unwrap_err();
        assert!(err.to_string().contains("must be a string"), "{err}");
    }

    #[test]
    fn write_into_refuses_overwriting_a_present_member() {
        let mut outer = serde_json::Map::new();
        outer.insert("kid".into(), serde_json::json!("taken"));
        let inner = MemberMap::from_json(r#"{"kid":"other","x":1}"#).unwrap();
        let err = inner.write_into(&mut outer).unwrap_err();
        assert!(
            err.to_string().contains("duplicate JSON member kid"),
            "{err}"
        );
    }

    #[test]
    fn roundtrips_through_serialize() {
        let map = MemberMap::from_json(r#"{"a":1,"b":"two"}"#).unwrap();
        let text = serde_json::to_string(&map).unwrap();
        assert_eq!(MemberMap::from_json(&text).unwrap(), map);
        // Order survives this crate's own serializer.
        assert_eq!(text, r#"{"a":1,"b":"two"}"#);
    }

    #[test]
    fn accepts_many_unique_members_and_rejects_a_late_duplicate() {
        let members = (0..4096)
            .map(|index| (format!("member-{index}"), serde_json::json!(index)))
            .collect::<Vec<_>>();
        assert_eq!(MemberMap::new(members.clone()).unwrap().members.len(), 4096);

        let mut with_duplicate = members;
        with_duplicate.push(("member-0".into(), serde_json::json!("duplicate")));
        assert!(MemberMap::new(with_duplicate).is_err());
    }
}
