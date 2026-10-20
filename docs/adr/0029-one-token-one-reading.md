# ADR 0029 — One token, one reading: duplicate claim members are refused

## Date

2026-07-28

## Status

Accepted

## Context

`Claims` keeps seven registered claims in typed fields and everything else in a
`#[serde(flatten)] HashMap`. That layout is convenient and quietly ambiguous in two directions:

* **Inbound.** `{"exp":4102444800,"exp":1}` is a valid JSON document; `serde_json`'s map lets the
  later value win, so the token verifies against one expiry and is read by a peer against another.
  Nothing in the JWS layer objects — the signature covers the bytes, and the bytes are fine.
  RFC 8725 §3.5 exists because producers emit these and consumers disagree.
* **Outbound.** An `extra` entry named `exp` sitting next to `exp: Some(..)` serializes as *two*
  `exp` members. serde does not deduplicate, and `flatten` writes `extra` after the typed fields.
  Without a check, this crate would be the producer.

The headers had already been given this treatment (`JoseHeader::ensure_no_duplicate_members`, the
`jws-dup` matrix cells); JWT payloads were the remaining place where a token could mean two things.

## Decision

### Refuse duplicates on the way in, and make them unconstructable on the way out

`Claims::from_json_bytes` scans the top-level member names *before* the typed parse and rejects the
token with `InvalidClaims` naming the first duplicate. It has to be a scan of the document: a
`serde_json::Value` has already merged the duplicate away by the time it exists, which is also why
`Claims::from_json_value` is documented as adopting a choice somebody else already made rather than
pretending to re-check it.

`Claims::to_json_vec` refuses to serialize a claim set whose `extra` map holds a registered name.
The JWT encode functions use this path, so no entry point can produce a payload with two members of
the same name. The `extra`-collision refusal is `InvalidClaims`, naming the member: the claim set is
what is wrong, not the wire.

### The refusal is only real if a peer accepts the token

`interop/tests/jwt_claims_jwcrypto.py` therefore asserts the *peer's* acceptance first — jwcrypto's
JWS layer signs and verifies a duplicate-member payload, and Python's `json` resolves it
last-value-wins — and only then asserts our refusal. A negative test against a parser that also
refuses would prove nothing about the ambiguity being real rather than imaginary. The raw bytes
reach a signed token through `JWS(payload=…).add_signature(…)`, because a dictionary — in either
language — cannot hold the key twice.

### Nested and inspection paths use the same code

`decode_nested*`, `decode_with_jwk*` and even the deprecated `decode_unverified` all parse through
`Claims::from_json_bytes`, so the consistency is structural rather than a rule to remember. The
test `decode_unverified_is_as_strict_as_decode` exists because "inspection-only" paths are exactly
where a second, laxer parser tends to appear.

### Numbers are not allowed to become floats

Registered timestamps are `NumericDate` (decimal text, never an intermediate `f64`) and unregistered
claims stay `serde_json::Value`, so `9007199254740993` and `1700000000.123456789` survive a token
round trip in text. Rounding at the second boundary is a validity decision, not a cosmetic one.

### Absent and null are stated to be the same claim

`"exp": null` deserializes to `None` exactly as an absent member does, and `null` for a *registered*
name never reaches `extra`. That is the JSON convention, but it is worth writing down because (a)
headers are stricter (a `null` typed header member is an error) and (b) a peer that keeps the null
— jwcrypto does, asserted in the interop suite — has a different notion of "present". Unregistered
claims keep their `null` value: the equivalence is a statement about typed fields, not a general
"nulls are dropped" rule.

### Deliberately not done

* **No duplicate rejection inside nested objects.** The claims set owns its top level. A duplicate
  inside an object under `extra` is that object's business; inventing a rule RFC 7519 does not state
  would break tokens that are unambiguous for the claim set.
* **No canonical (sorted-key) payload encoding.** Emitting members in a fixed order would make
  byte-level deduplication easier to check but would change every token this crate produces for no
  additional safety — the guarantee is one member per name, not a canonical byte string.
* **No claim-size knobs.** The payload inherits `MAX_TOKEN_BYTES`, checked before parsing, and the
  oversized-token path is tested on both sides of the wire (the signer also refuses to *emit* a
  token it would refuse to read).
* **No OIDC/OAuth claim profiles** (`auth_time`, `nonce`, `at_hash`, …). Those are separate
  specifications with their own validation semantics.

## Consequences

* A JWT that two parsers could read differently is rejected rather than silently resolved, at the
  cost of refusing tokens some permissive ecosystems do emit. That is the intended trade: a token
  with two meanings has no correct handling.
* `Claims::to_json_vec` / `from_json_bytes` are now the paths to use; `serde_json::to_vec(claims)`
  still exists and bypasses the emit check, which the rustdoc says out loud rather than hiding.
* The emit-side check makes previously-silent misuse (`extra["iss"] = …` alongside `iss`) an error.
  Nothing in this crate's own tests did that, and the error names the member, so a caller hitting
  it knows precisely which map entry to drop.
