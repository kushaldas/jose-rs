# ADR 0031 — Selection refuses; it does not guess, and it does not filter

## Date

2026-07-28

## Status

Accepted

## Context

A JWK Set is input that somebody else edits. It is published, rotated, cached and
re-published by people who are not you, and the document that arrives will contain keys this
build cannot use. Casual handling produces two failures, and both are security failures:

* **Fall-through.** The token pins `kid=legit`, the set does not contain it, and the
  implementation "helpfully" tries the remaining keys until one works. From then on, a
  signature by *any* key in the set authenticates a token that named a *different* one, and
  every rotation or tenancy policy built on `kid` is decorative.
* **Silent filtering.** Entries that this build cannot use are dropped before matching. The set
  stops being addressable, "no key matched" becomes indistinguishable from "your build is too
  old", and a duplicate `kid` can be quietly resolved by discarding one of the twins.

`decode_with_jwkset` already refused an unknown `kid` in an addressable set, and
`find_unique_by_kid` already refused duplicates. What it lacked was a way to *state* a policy, a
budget on attempts, and any way to ask "what is in this set and why can't I use it?".

## Decision

### `src/jwk/selection.rs`: explicit policy, bounded attempts, no fall-through by default

[`select`](crate::jwk::selection::select) resolves a token's `kid` into a candidate list under a
caller-supplied [`SelectionPolicy`](crate::jwk::selection::SelectionPolicy):

* `Fallback::Refuse` — exact, unique `kid` matches only.
* `Fallback::TryWhenUnaddressable` — the default, and the existing
  `decode_with_jwkset` behaviour: sweep only when **no** entry in the set carries a `kid`, i.e.
  when the token could not have named anything instead.
* `Fallback::TryAll` — the named escape hatch, documented as what it does ("a signature by an
  unrelated key will authenticate a token that named a different one"), and asserted working in
  tests so the documentation cannot rot into fiction.

An unknown `kid` in an addressable set is a refusal under the first two policies, with the `kid`
and the reason in the message. A `kid`-less token against an addressable set is *also* refused by
default — that is the same trap approached from the other side: the producer named its keys, the
token declined to say which, and sweeping would be guessing.

`max_candidates` is an error, never a truncation. A caller configured for 500 keys who silently
got the first 64 would see "signature verification failed" — a key problem that does not exist.
The budget matches `jws::json::MAX_CANDIDATE_KEYS` so the two bounds cannot disagree about who
refuses first.

Diagnostics are three-state and computed by the real converter:

* `Usable` — `jwk_to_software_key` accepted it, so the report cannot promise what the verifier
  would refuse;
* `Unsupported { reason }` — this build lacks the kind or curve (`secp256k1`, `Ed448`, an unknown
  `kty`). The entry is fine; the expectation is not;
* `Invalid { reason }` — the kind **is** supported and the material is broken. This is the state
  to alert on, and conflating it with the previous one is how a malformed publication becomes a
  silent gap.

`diagnostics(&set).len() == set.keys.len()` always: the function *cannot* drop an entry, and it
keeps `kid`/`kty`/`crv` as published, including kinds it has never heard of.

### Existing defaults stay exactly where they were

`JwkSet::from_json` is unchanged — unbounded. The budgets live in
`from_json_with_limits(text, &SetLimits)` and in `SelectionPolicy`. Likewise
`jwt::decode_with_jwkset` keeps its unbounded try-every-key behaviour and is **not** redefined in
terms of the new `decode_with_jwkset_policy`. A limit appearing quietly inside a working
verification path is a breaking change, and this repo's rule is that those get their own approved
release, not a refactor. `tests/jwk_selection.rs::the_legacy_entry_point_keeps_its_unbounded_behaviour`
pins it: a 70-key kid-less set still verifies through the old entry point while the policy entry
point refuses at 64.

Byte and entry budgets are checked **before** parsing entries. After parsing, the memory is
already spent and the budget is theatre.

### No fetching, no caching, no issuer lookup

`select` takes a set that is already in memory. Refresh, `jku` retrieval and issuer discovery are
separate systems with their own trust and caching problems; folding them into a selection
function would hide a network call inside what looks like a lookup.

## Consequences

* Selection is deterministic (document order) and its outcome carries `matched_by_kid`,
  `matched_kid` and `set_size`, so a log line can say "3 of 214 entries were candidates for kid
  X" — the sentence an operator needs.
* Callers who want budgets must ask for them. That is the conservative direction: nothing breaks
  today, and the strictness is available before it is needed.
* `Fallback::TryAll` exists and is reachable. Removing dangerous options is not the same as
  removing the *unknown* dangerous option; this one is named, bounded, and documented with its
  failure mode.
* Duplicate-`kid` refusal is deliberately not improved by filtering unsupported twins. "Which key
  signed this?" must have one answer; two entries with the same name is a publication bug and the
  error says so.
