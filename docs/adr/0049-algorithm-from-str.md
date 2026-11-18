# ADR 0049 — Parse algorithm identifiers through FromStr

- Date: 2026-11-18
- Status: Accepted
- Release: 0.12.1

## Context

The three algorithm enums expose inherent `from_str` methods. Generic Rust
configuration and command-line parsers require the standard `FromStr` trait.

## Decision

Implement `FromStr<Err = JoseError>` for `JwsAlgorithm`, `JweAlgorithm` and
`JweEncryption`. Each implementation delegates to its existing inherent parser.

## Security boundaries

Both entry points compare exact, case-sensitive JOSE wire names and apply the
same compile-time feature gates. Callers still enforce their algorithm
allowlists and key restrictions at verification or decryption.

## Consequences

Applications can use `str::parse` and generic parsers. Existing direct calls
still compile without a trait import. Each enum has one table of wire names
to maintain for parsing.
