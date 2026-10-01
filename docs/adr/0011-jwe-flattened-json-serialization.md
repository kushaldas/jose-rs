# 0011 — Flattened JWE JSON Serialization requires a protected header

- Status: Accepted
- Date: 2026-07-16
- Applies to: `jose_rs::jwe::json`

## Context

RFC 7516 §7.2 defines a JSON Serialization for JWE with three header
locations — `protected`, a shared `unprotected`, and a per-recipient `header`
— and RFC 7516 §7.2.2 defines the *flattened* single-recipient syntax as a
JSON object carrying five base64url members (`protected`, `encrypted_key`,
`iv`, `ciphertext`, `tag`) plus `aad` and the two unprotected maps.

The library previously supported only the compact serialization, so
interoperability with any JWE that is not a five-part dot string was a hard
gap: the RFC's own RFC 7516 §A.5 example, the general syntax, and every JWT-in-
JWE-in-JSON deployment could not be read at all.

The whole header design so far (ADR 0009) is that the **header is the trust
decision**: `alg` selects the key-management algorithm and must be integrity
protected, because an attacker who controls it unselected can steer which key
material is used to unwrap a CEK. That rule was free in the compact
serialization, where there is exactly one header and it is always protected.
The JSON syntax offers two unprotected places, so "the header is authenticated"
is no longer automatic.

## Decision

Implement the **flattened** JSON Serialization (`jose_rs::jwe::json`) for the
key-management and content algorithms already supported by the crate, with all
header parameters in the integrity-protected `protected` member.

1. **`protected` is mandatory to parse and to decrypt.** RFC 7516 §7.2.1
   permits an absent `protected` member when the protected header is empty;
   this implementation rejects that shape, because `alg` (and `enc`) then have
   no authenticated home. The compact serialization already has the same
   requirement, so this is parity, not a new restriction.
2. **`unprotected`, `header`, `recipients` and `aad` are refused by name**,
   with a message naming the member and the reason. They are registered
   members; ignoring them would silently discard header parameters that change
   how the ciphertext must be interpreted. Unrecognized *private* members are
   ignored during processing as RFC 7516 §7.2.1 requires — but retained (see
   §5).
3. **The `protected` string is stored verbatim** and used as the AAD prefix
   from those exact bytes. Nothing in the decrypt path re-serializes a parsed
   header. The two syntaxes produce identical ciphertext and tag for identical
   header bytes (RFC 7516 §7.2.1: "each … is identical to the value that would
   have been computed for … the JWE Compact Serialization") only if the AAD is
   byte-identical, and member order is not canonicalizable: `{"alg":…,"enc":…}`
   and `{"enc":…,"alg":…}` encode differently. Re-serializing would authenticate
   something different, and the RFC's §A.3 vector is exactly the case a
   re-serializing implementation gets wrong.
4. **Encryption and policy run through the shared internal core**
   (`crate::jwe::internal`, created by the preceding refactor): the same emit
   guard set, the same decrypt allow-list, the same `crit`/`zip`/`b64` rules,
   the same key-management code, the same exact plaintext-size limit. The JSON
   layer adds serialization structure and nothing else. This is deliberate: a
   second serialization is the most likely way for a library to grow a
   weaker path.
5. **Retained private members block lossy conversion.** `to_json()` re-emits
   them; `to_compact()` refuses a message that carries them rather than
   silently dropping information that some other implementation may treat as
   meaningful.
6. **The parser is strict**: duplicate member names are rejected (a JSON map
   with the same name twice has no defined meaning and `serde_json`'s default
   last-key-wins silently picks one), member values must be JSON strings,
   `ciphertext` is required, an empty `protected` is rejected, base64url values
   must be canonical, and inputs larger than `MAX_TOKEN_BYTES` are refused
   before parsing.

## Consequences

- The crate can now read and write the serialization that JWT-in-JWE, most
  JWE-over-HTTP APIs and the RFC's own JSON examples use, in both directions
  with the compact form (`to_compact` / `from_compact`).
- RFC 7516 §A.5's flattened example (which carries `alg` in the *unprotected*
  header) is deliberately **not** accepted by this change, and a test asserts
  the specific refusal. Accepting it is ADR 0012/0013's job, not an oversight
  here.
- A message that RFC 7516 permits (no protected header at all) is rejected.
  Senders in that shape get a clear error naming the member.
- `FlattenedJwe` exposes the parsed-but-unauthenticated protected header
  through `peek_protected_header`, documented as inspection-only: no return
  value attests to it until decryption succeeds.
- Strict duplicate-member rejection is stricter than `serde_json`'s default
  and stricter than some producers. That is the intended trade: ambiguity in
  the header is where header-injection bugs are born.
- General syntax (multiple recipients), external AAD and unprotected headers
  remain unimplemented and are covered by ADR 0012 (aad), ADR 0013
  (unprotected headers) and ADR 0014 (general syntax / multiple recipients).
