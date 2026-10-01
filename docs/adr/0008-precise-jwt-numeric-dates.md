# ADR 0008 - Preserve fractional JWT timestamps

- **Status:** Accepted
- **Date:** 2026-10-01
- **Component:** `src/jwt`

## Context

Claims stored dates as u64 seconds and floored fractional JSON values. The
validator also floored the system clock. This loses information during
serialization and changes expiration, not-before, future-iat, and age
decisions near subsecond boundaries. RFC 7519 permits fractional NumericDate
values and requires the current time to be strictly before expiration.

## Decision

Use a public `NumericDate` with private u64 seconds and u32 nanoseconds.
Construction enforces nanoseconds below one billion. Date fields become
`Option<NumericDate>`: Rust callers migrate `Some(seconds)` to
`Some(seconds.into())`. This intentional API change avoids two representations
of the same claim that could become inconsistent after mutation.

Enable serde_json's `raw_value` feature to parse decimal number tokens directly
without f64 rounding. Accept exact values through nanosecond precision,
scientific notation with an i32 exponent, and insignificant trailing zeros.
Reject negative values including negative zero, nonzero subnanosecond digits,
encodings over 128 bytes, and values beyond u64 seconds plus 999,999,999 ns.
Processing of the decimal exponent is bounded, with no exponent-sized loops
or allocations. Serialization emits exact JSON numbers, normalizing spelling.

The type represents JSON NumericDate, not a general-purpose timestamp format.
Callers that already parsed numbers into floating-point values cannot recover
lost precision; exact preservation requires parsing original JSON into Claims.
Missing and null optional claims retain their existing absence semantics.

Add `Validation::validate_at(claims, header, now)` as the common validation
implementation. Normal entry points supply the full system-clock duration
since the epoch. The explicit clock must be trusted application input.
Authenticated headers retain all existing policy checks; passing None has
the same header-check semantics as existing `validate`.

## Boundaries and arithmetic

Convert timestamps and u64 second limits to u128 nanoseconds for comparison.
The sum of a timestamp, leeway, and max age fits without wrapping or saturation.

| Check | Rejection condition |
|-------|---------------------|
| Expiration | now >= exp + leeway |
| Not-before | now + leeway < nbf |
| Future iat | iat > now + leeway |
| Maximum age | now > iat + max_age + leeway |

Leeway and maximum-age configuration stay in whole seconds. Presence,
algorithm, type, issuer, audience, and subject policies are unchanged.
Subnanosecond values fail explicitly instead of being rounded into a weaker
decision. Pre-epoch system clocks still fail closed.

## Consequences and validation

The Rust field-type change requires a compatible release and downstream
migration. Existing examples/tests use explicit integer conversion. Tokens
at the exact expiration boundary now fail, including integer-only dates.
Supported fractional values roundtrip without loss; more precise values need
an explicit future representation decision.

`tests/numeric_dates.rs` covers exact decimal/scientific roundtrips, large
integers, precision/range/type rejection, missing/null dates, all time-check
boundaries and leeway, overflow resistance, header policy, and signed claims.
It replaces the former flooring-oriented unit tests in `claims.rs`.
Runnable rustdoc covers NumericDate construction and explicit-clock validation.
`interop/tests/numeric_dates_jwcrypto.py` checks signed fractional JWT claims
against jwcrypto 1.6.1 in both directions using disposable keys.

Reference: [RFC 7519 sections 2 and 4.1.4-4.1.6](https://www.rfc-editor.org/rfc/rfc7519.html),
not currently included in the local `rfcs/` collection.
