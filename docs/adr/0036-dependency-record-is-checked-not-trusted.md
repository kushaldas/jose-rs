# ADR 0036 — Two majors in one lock, documented, beat one major forced forward

## Date

2026-07-28

## Status

Accepted

## Context

`future_plan.md` Q2 asks for dependency, MSRV and platform checks: check the locked
published backend before selecting a feature, "keep RustCrypto trait-version families
coherent and document blockers rather than forcing isolated major upgrades", respect the
declared MSRV, and extend platform/provider checks where a new API needs them.

The measured state of this crate's lock is uncomfortable and worth stating precisely.
Thirty-three package names resolve to two majors. The ones that matter are the
trait families this crate passes across the backend boundary: `digest` 0.10 + 0.11,
`signature` 2 + 3, `elliptic-curve` 0.13 + 0.14, `der` 0.7 + 0.8, `spki` 0.7 + 0.8,
`sec1` 0.7 + 0.8, `pkcs8` 0.10 + 0.11, plus `hmac`, `sha2`, `aes-gcm`, `aead`, `aes`,
`cbc`, `rand_core`.

Two facts make this more than a housekeeping problem.

First, the newer majors arrive **transitively through the backend even in a default
build with no features enabled** — measured: `kryptering` → `ed448-goldilocks` →
`hash2curve` → `digest` 0.11. The split is not caused by our feature flags and cannot be
turned off.

Second, trait types across majors are different types. This crate hands
`digest`/`signature`/`elliptic-curve`-derived values to and receives them from
`kryptering`. Jumping our own direct dependencies (`ecdsa`, `rsa`,
`p256`/`p384`/`p521`, `hmac`/`sha2`/`digest`, `aes-gcm`) to the newer families in
isolation would not compile against the backend we are required to use — and if it did,
it would still leave two families, only inverted. That is precisely the "isolated major
upgrade" Q2 warns against.

There is also a documentation problem sitting on top of it. A page that says "we depend
on kryptering 0.6" after the lock moved is worse than no page, because a reviewer
consults it instead of the lock.

## Decision

### Keep the split, document it, and make the document checked rather than trusted

`docs/dependencies.md` records: the declared MSRV and the rule that raising it is a
breaking change requiring release notes; the backend as the ceiling on feature work,
with each blocked plan item (A0–A3) naming the primitive `kryptering` 0.6.0 does not
expose; the feature → dependency mapping; every direct dependency with its **locked**
version; the duplicated families and which consumer forces each; the coordinated-upgrade
sequence that would remove the split; the compile-time refusals that make certain
schemes unreachable rather than merely declined (`pkcs8` required with `encryption` only,
so SHA-1 PRF / DES / 3DES paths are behind `-insecure` features we do not enable); the
single advisory ignore with its mitigation; and the platform/provider claims (no `unsafe`,
no async, no network, no filesystem in the library; PKCS#11 handle and session ownership
left to the backend; `/proc` read only by a Linux-only perf test).

`tests/dependency_policy.rs` (8 tests) asserts every one of those claims against
`Cargo.toml`, `Cargo.lock` and `.cargo/audit.toml`: each direct dependency is named with
the version our requirement resolves; each feature appears in the feature table; each
ignore in `.cargo/audit.toml` is explained in the document; each direct dependency that
resolves to two majors is listed in the duplicated-families **table** (mentions in the
upgrade prose do not count — a deliberately broken document proved that distinction was
load-bearing); the backend resolves to exactly one version and the document states it;
the "`dev-dependencies` is empty" claim matches the manifest; and no file under `src/`
contains `unsafe`, `std::process::`, `std::net::` or `std::fs::`.

`scripts/dependency-report.sh` regenerates the inputs (`--duplicates` lists the split) so
"update the doc" is a command, not a transcription.

### Refuse the tidy-up

No isolated major bumps, no `#[allow]`-style workaround, and no attempt to unify
`pkcs8` by moving the password-key-file allow-list (ADR 0025) onto 0.11, where its
scheme feature names and defaults are not the ones the allow-list was audited against.
`post-quantum` needs `pkcs8` 0.11 and is renamed (`pkcs8-pq`) precisely so both can exist
without either lying about which one it is.

## Consequences

* The dependency story is reviewable in one page and the page cannot silently rot: the
  same CI matrix that checks behaviour checks the claims about what it depends on.
* Duplicated majors remain in the lock, so builds pull more packages than ideal. This is
  accepted, named, and paired with the upgrade sequence that would end it — the first
  step of which is not ours to take.
* Adding a test-only dependency is now a visible decision: `dev-dependencies` is empty
  and a test asserts it stays that way unless the document is updated to say why. That
  is what makes "no benchmarking harness dependency" (ADR 0035) and "fuzzing lives in its
  own package" (ADR 0034) enforceable rather than incidental.
* The MSRV floor is a claim with a policy attached; raising it must arrive as a release
  note, not as a side effect of a dependency update.
* The platform assertions are deliberately blunt (`unsafe {`, `std::fs::`). A legitimate
  future need — say, reading a key file — has to update both the code and the document's
  promise, which is the friction intended.
