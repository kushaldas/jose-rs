# ADR 0041 — Refresh dependencies and raise the compiler floor to Rust 1.89

## Date

2026-11-09

## Status

Accepted; updates the compiler-floor decision in ADR 0037.

## Context

Kryptering 0.7.1 and stable RSA 0.10 are available. The locked crypto-bigint 0.7.5 and ctutils 0.4.3 have RustSec advisories with patched compatible releases. AES 0.9.4 requires Rust 1.89; the maintainer authorized raising the MSRV.

## Decision

Require Rust 1.89, resolve AES 0.9.4, Kryptering 0.7.1, stable RSA 0.10, base64 0.23, and compatible lockfile updates. Preserve the coordinated RustCrypto trait family and JOSE algorithm policy. Keep the existing RSA advisory exception until upstream closes it; a dependency refresh does not establish that the timing issue is fixed.

## Consequences

Rust 1.88 users must remain on the previous jose-rs release. The MSRV increase requires a deliberate release version. The dependency policy record and lockfiles must reflect the new floor, and the full feature gate and audit must pass.
