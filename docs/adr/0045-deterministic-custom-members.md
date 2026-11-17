# ADR 0045 — Custom header and claim members serialize in sorted order

- Date: 2026-11-17
- Status: Accepted
- Release: 0.12.0

## Context

HashMap iteration makes otherwise identical signed statements differ between runs.
Consumers need repeatable snapshots and readable diffs, without any change to the
bytes authenticated during verification.

## Decision

Use `BTreeMap<String, serde_json::Value>` for `Claims.extra` and
`JoseHeader.extra`. Custom members serialize in lexicographic order; registered
members retain their struct declaration order. Existing nested `serde_json::Value`
objects keep their existing serde_json map representation. No dependency or JSON
preserve_order feature is added.

## Security boundaries

This is deterministic emission, not JSON canonicalization or insertion-order
preservation. It never reserializes a received protected header to construct the
verification input. Typed/custom collisions and duplicate JSON members remain
refused on the existing processing paths.

## Consequences

Public field types change, requiring a minor pre-1.0 version bump. Convert an
existing HashMap using `old.into_iter().collect()`. Newly emitted signatures may
change due to the now-stable custom-member ordering; previously emitted tokens
remain verifiable against their original bytes. JWK's separate `extra` field is
unchanged. Regression tests compare opposite insertion orders and wire output.
