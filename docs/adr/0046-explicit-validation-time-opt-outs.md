# ADR 0046 — Time checks can be disabled explicitly without changing defaults

- Date: 2026-11-17
- Status: Accepted
- Release: 0.12.0

## Context

Consumers sometimes need to distinguish a bad signature from an expired token.
Validation is non-exhaustive, so external struct-update syntax cannot express this
configuration. Mutable field assignment works but obscures intent.

## Decision

Add `Validation::signature_only()` as an explicit opt-in that disables expiration,
not-before and future-issued-at checks. Add composable `without_exp()`,
`without_nbf()` and `without_iat_future_check()` builders. Existing `new()` and
Default keep every time check enabled and the 60-second leeway. Document
`with_leeway(0)` for consumers requiring strict boundaries.

## Security boundaries

Opting out accepts expired and/or not-yet-valid statements. Signature verification,
key operation/pin checks, limits and exact algorithm allowlists still apply.
Configured required-claim, issuer, subject, audience, typ and maximum-age policies
remain active. `signature_only()` starts with otherwise default validation; adding
policies afterwards adds restrictions. It never permits unsigned tokens.

## Consequences

The builders are additive and need no dependencies. Applications deliberately
opting out of temporal validity must apply any intended time policy separately.
Regression tests verify unchanged defaults, each opt-out, and retained issuer
and required-claim enforcement.
