# ADR 0027 — A thumbprint URI is a format, so the RFC's example is the test

## Date

2026-07-28

## Status

Accepted

## Context

RFC 9278 defines a URI form (`urn:ietf:params:oauth:jwk-thumbprint:<hash-name>:<thumbprint>`) used
as an identifier — notably in SIOPv2, where the identifier has to be a URI. Two details decide
whether an implementation interoperates, and neither is a matter of taste:

* **the hash identifier's spelling**, which §4 pins to the IANA "Named Information Hash Algorithm
  Registry" *Hash Name String* — `sha-256`, with a hyphen — while the neighbouring convention in
  JOSE code is the unhyphenated `sha256`; and
* **who validates it**, because §4 says a URI with an unrecognised identifier "is not considered
  valid and applications will need to detect and handle this error", i.e. the burden is on us.

The same commit carries the second half of plan item L5: typed generation options. Both halves
share one rule — an option this crate cannot honour is refused by name, never ignored.

## Decision

### Build it, and make the RFC's own example the assertion

`thumbprint_uri(jwk, hash)` and `thumbprint_uri_sha256(jwk)`. The test is not "our output looks
right" but byte equality with the complete URI printed in RFC 9278 §6
(`…:sha-256:NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs`), computed from the RFC 7638 §3.1 example
key already pinned in the thumbprint tests. A format claim that is tested against the
implementation's own behaviour tests nothing.

SHA-256 stays the default everywhere (`ThumbprintHash::default()`), matching RFC 9278 §5's
mandatory-to-implement algorithm; SHA-384/SHA-512 are available and their identifiers come from
the same table, so the digest and the name cannot drift apart.

Independent confirmation: `jose` implements this URI too, and `interop/js-harness/thumbprint-uri.mjs`
compares the two implementations' output **as text** for RSA, EC P-256/P-384/P-521, Ed25519 and an
`oct` key, at all three digests — 68 checks. It also checks the "decorated" JWK (extra `kid`,
`use`, `alg`) yields the identical URI on both sides, which is the required-members rule doing
real work.

### Parsing is a type, because §4 makes validation somebody's job and it might as well be ours

`JwkThumbprintUri::parse` checks the prefix, the registry spelling of the identifier, that the
value is unpadded base64url, and that its decoded length equals the digest the URI names. That
last check is the one a stringly-typed comparison never does: a 48-byte SHA-384 value under a
`sha-256` identifier is *the same shape* and a different fact, and accepting it silently compares
two different things.

Unrecognised identifiers are refused listing what is accepted (`sha-256`, `sha-384`, `sha-512`).
That includes `sha256` and `SHA-256`: this is the one place in the crate where a near-miss is not
normalized, because the identifier is not a local label but a registry value, and a URI that
claims a hash it does not carry is exactly the error §4 tells applications to detect. Callers who
want leniency have the input in hand and can map it explicitly.

`matches(&jwk)` compares under the algorithm the URI itself named — never under a caller's default
— and its docs say it is a comparison, not an authorization: RFC 9278 §7's advice stands, that
what binds an identifier to a key is how it was conveyed.

### Typed generation, with the enum carrying the validation

`KeyGeneration` (`Rsa { bits }`, `Ec { curve }`, `Ed25519`, `X25519`, `Oct { size }`) plus
`generate_key`, for callers who hold the choice as configuration. Two decisions inside it:

* **`EcCurve` is an enum, not a string.** secp256k1 and Brainpool have no variant, so asking for
  one is a type error, and a typo arriving as text is refused by `TryFrom<&str>` naming what it was
  given — no case folding, no aliases, because a caller who wrote `p-256` should learn that here
  rather than in a verification failure later.
* **`Oct { size }` accepts only 16/24/32/48/64 bytes.** `generate_symmetric` accepts any length and
  stays that way for compatibility; a typed *options* API that accepted 20 bytes would advertise a
  key no algorithm in this crate can use. The refusal names `generate_symmetric` as the door for
  deliberate cases.

Everything else reuses the existing generators, so the RSA bit floor and the curve set are not
restated — one rule, one place.

### No post-quantum variant, and that is a deliberate gap

Adding `#[cfg(feature = "post-quantum")] MlDsa { … }` would make every caller's `match`
non-exhaustive depending on a feature flag they may not control — a worse API than the two doors it
would have unified. `generate_mldsa` remains the entry point, and the enum's rustdoc says why.

## Consequences

* The URI can be produced and consumed; a caller receiving one from a counterparty gets validation
  instead of a string, and the length check catches values that "look right".
* One more place where the crate is stricter than the loosest peer, in the one direction the RFC
  itself directs. The spelling is not a guess: the RFC's example, `jose`'s output and our own
  output agree.
* `KeyGeneration` is convenience, not a replacement — the per-type functions keep their signatures,
  so nothing migrated.
