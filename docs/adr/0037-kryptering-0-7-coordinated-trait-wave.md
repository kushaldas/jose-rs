# ADR 0037 — Kryptering 0.7 closes the split trait-family window

## Date

2026-10-16

## Status

Accepted; supersedes ADR 0036's decision to retain duplicate RustCrypto families.

## Context

ADR 0036 documented a necessary temporary split: Kryptering 0.6 and jose-rs could not
move their shared RustCrypto traits independently. Kryptering 0.7 is the coordinated
release that ADR required. It moves the backend to `digest` 0.11, `signature` 3,
`elliptic-curve` 0.14, `pkcs8` 0.11, `rsa` 0.10.0-rc.19, and the matching cipher,
hash, signature, and RNG families. Leaving jose-rs on the old direct family would invert
the split and preserve incompatible duplicate types at the backend boundary.

The release also removes `rand` 0.8 and `num-bigint-dig`, adds RSA blinding, and adds
new curve primitives. Its `aes` range can select 0.9.3, whose MSRV is Rust 1.89, while
jose-rs declares Rust 1.88.

## Decision

Upgrade Kryptering and every direct dependency that participates in its public trait
boundary as one change. Replace `rand` with `getrandom` 0.4 and use the `crypto-bigint`
RSA integer type exposed by `rsa`. Use one `pkcs8` 0.11 dependency for classical and
post-quantum encoding instead of a renamed second major.

Set Cargo resolver 3 while retaining `rust-version = "1.88"`. This makes dependency
selection respect the declared compiler floor and selects `aes` 0.9.2 on Rust 1.88.
Verify the result directly with an all-features/all-targets Rust 1.88 build.

Do not expose Kryptering's new Ed448, X448, secp256k1, or Brainpool variants merely
because the backend gained them. Their JOSE identifiers, JWK forms, key-operation rules,
interop evidence, and negative tests remain separate decisions. Existing wildcard
conversion refusals continue to make them unreachable.

Keep RUSTSEC-2023-0071 tracked because the upstream advisory remains open. Kryptering's
OS-RNG RSA blinding materially mitigates it, but does not turn an upstream open advisory
into a claim of formal closure.

## Consequences

- Cryptographic trait families resolve once, avoiding incompatible type boundaries and
  shrinking the lockfile.
- `rand` 0.8 and `num-bigint-dig` leave the dependency graph.
- Dependency API changes are source-internal; jose-rs wire formats and algorithm
  allow-lists do not widen.
- The exact RSA release remains pinned until the coordinated ecosystem leaves its
  release-candidate line.
- Future backend additions still require a jose-rs ADR and complete policy/interop work.
