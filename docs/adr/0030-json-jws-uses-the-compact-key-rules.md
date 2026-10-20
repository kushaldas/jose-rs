# ADR 0030 — The JSON serialization uses the compact path's key rules, literally

## Date

2026-07-28

## Status

Accepted

## Context

`compact::{sign_with_jwk, verify_with_jwk}` had spent several rounds of review accumulating a set
of key rules that are not obvious: the algorithm comes from `jwk.alg` when signing and from the
*token* when verifying; a pinned `jwk.alg` must match the header's spelling exactly; `use`/`key_ops`
must permit the operation; and strength is checked against the algorithm actually in play, so a
32-byte HMAC secret cannot be used on an HS512 token by editing the header.

The JSON serializations (flattened and general) had none of that. Their entry points took
`&dyn kryptering::Signer` / `&dyn kryptering::Verifier`, which is the right low-level boundary (an
HSM-backed signer belongs there), but a caller holding a `Jwk` had to convert it themselves — and
every caller who did so wrote their own copy of the rules above. That is how a reviewed rule set
becomes an unreviewed one.

## Decision

### Same function, not same behaviour

`compact::signer_from_jwk` and `compact::verifier_from_jwk` are `pub(crate)` functions holding the
rule set; `compact::sign_with_jwk`/`verify_with_jwk` call them, and so do the new
`json::sign_flattened_with_jwk`, `json::sign_flattened_with_jwk_opts`,
`json::sign_flattened_detached_with_jwk[_opts]`, `json::verify_flattened_with_jwk`,
`json::verify_flattened_detached_with_jwk`, `json::verify_flattened_with_jwk_opts`,
`json::sign_general_with_jwk_pairs`, `json::sign_general_with_jwks`,
`json::verify_general_with_jwks` and the `_any`/`_all` conveniences.

"Consistent behaviour" is a claim you can test only by accident; one implementation is a claim you
cannot break by editing the wrong file. `tests/jws_jwk_json.rs` still asserts the parity
*observable*: for the same key and token, the compact and JSON paths must refuse with the *same
message*, so adding a rule to one side trips a test.

The low-level `&dyn Signer`/`&dyn Verifier` APIs are untouched. This is an additional door, not a
narrowing of the HSM boundary.

### The success policy for multi-signature documents is the caller's to state

`verify_general_with_jwks` takes a `SignaturePolicy`: `Any` (at least one signature verifies) or
`All` (every signature must verify). A library that silently picks one will eventually pick the
wrong one for someone — JAdES-style validation wants `All`; a "was this signed by a key I trust"
check wants `Any`.

The interop run pinned what the ecosystem does: **jwcrypto's `JWS.verify(key)` is any-of.** With a
two-signature document whose second signature is corrupted, jwcrypto happily verifies it given the
key that made the intact one. So `Any` matches the peer, `All` is the stricter option we expose,
and neither choice is hidden. (Also pinned, as an observation rather than a model: jwcrypto's
`JWKSet` selection cannot drive a multi-`kid` General JWS at all — it raises "No working key found
in key set" when the set contains both signing keys.)

### The report distinguishes "rejected" from "not attempted"

`JwkSignatureResult` carries `verified`, `attempted`, `key_index` and `error`. Under `Any` the loop
stops at the first valid signature, so a later entry can legitimately be `verified: false,
attempted: false`. Reporting that as a failure — with the *wrong verifier's* algorithm-mismatch
message as the reason — would describe a check that never happened and send a reader hunting for a
defect in a signature that was fine. Reasons are therefore tiered: a failure from a verifier whose
algorithm matched outranks a key-rule refusal, which outranks an algorithm-mismatch note; if the
signature was never reached, the message says so explicitly rather than quoting the note.

### Attempts are bounded

`MAX_CANDIDATE_KEYS = 64`, on top of the existing `MAX_GENERAL_SIGNATURES = 64`, because "which of
these keys signed it?" is work an attacker sizes: they supply the document, and if the caller pastes
in a scraped JWK Set, they size the cost too. Selection *policy* (kid matching, ordering, fallback)
is L3's job; this is only the ceiling.

### Signatures are not spent on a doomed document

`sign_general_with_jwks` builds *every* signer — running every key rule — before the first
signature is produced, matching `sign_general_full`'s existing "validate all headers up front"
behaviour. With an HSM-backed key in the list, a rejected later entry must not cost an earlier
signature.

## Consequences

* A caller with a `Jwk` no longer leaves the JWK-aware API to use flattened/general JWS, so the
  key rules travel with the key instead of being re-derived per project.
* The general-verify API returns a report rather than a bare payload, because per-signature truth
  (`which key? which failed? was it even tried?`) is the difference between diagnosable and
  mysterious.
* `SignaturePolicy` makes multi-signature acceptance a decision that appears in the caller's code,
  where it can be reviewed, instead of a library default nobody chose.
* Cost: two more public types (`SignaturePolicy`, `JwkSignatureResult`, `GeneralVerifyReport`,
  `GeneralJwkSigner`) and one more public constant. The payoff is that the reviewed rule set has
  one home.
