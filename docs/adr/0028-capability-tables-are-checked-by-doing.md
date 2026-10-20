# ADR 0028 — A capability table nobody runs is a rumour

## Date

2026-07-28

## Status

Accepted

## Context

Callers ask, usually in the wrong place: does this build do `P-521`? Can it open an
`ENCRYPTED PRIVATE KEY` file? Is `RSA-OAEP` missing because nobody wrote it, or because a feature
is off, or because we will never do it? Those are four different answers and the crate had been
answering all four with "read the source".

The obvious cures are the wrong ones. A markdown table drifts the day it is written. A
runtime registration mechanism answers the question correctly and destroys the guarantee: after
anything can `register()` an algorithm, the table describes whatever the process has loaded —
including what a dependency loaded — rather than what this crate implements.

## Decision

### Read-only data, checked by doing

`src::capability` exposes `const`-shaped rows (`identifier`, `availability`, `operations`, `note`)
built from the same enums the operations take. No registry, no `register()`, no global state:
[`capability::all()`](crate::capability::all) returns the same rows in this process forever.

Then `tests/capability_report.rs` treats the table as a set of **claims and falsifies them**:

* every row that advertises `sign`/`verify`/`encrypt`/`decrypt` performs it, and also confirms that
  a tampered message still fails (so "verify" is not vacuous);
* every row that says *not available* is attempted and must refuse — a feature-gated identifier
  must fail to parse with the feature off, a recognized-but-unsupported one must parse and refuse
  at the operation, and a policy refusal must not be accepted anywhere;
* the identifier lists are enumerated from the enums with an **exhaustive `match` in the test**, so
  adding a variant without a table row is a compile error rather than an incomplete table;
* `docs/capabilities.md` is the module's own rendered output, compared against the committed file.

Two wrong rows were caught while building this, which is the evidence that the arrangement works:

* `HS1` had been listed as "gated behind `deprecated`". There is no such identifier in the crate at
  all — it was a plausible-sounding invention, and it survived until the invariant "a row gated on
  a feature this build **has** must advertise an operation" rejected it.
* `ML-DSA-87-Ed448` had been marked recognized-but-unsupported on the sound-sounding theory that
  the backend exposes no standalone Ed448. The test signed and verified with it successfully: the
  composite carries Ed448 internally; only the standalone key type is missing, and that is its own
  row now. The hand-written guess was wrong in the *pessimistic* direction, which a doc-only table
  would have shipped forever.

### Four statuses, because "unsupported" is four answers

`Supported`, `RequiresFeature(feature)`, `RecognizedNotSupported`, and `RefusedByPolicy(reason)`.
Conflating the last two is how "we don't support RSA1_5 *yet*" gets said by accident — it is a
chosen-ciphertext oracle and RFC 8725 §4.1 forbids it, and that belongs in the report as a refusal
with the reason. `RecognizedNotSupported` matters differently: `ES256K` parses into the public enum,
so an implementation that reported "recognized" as "supported" would claim secp256k1 support it does
not have.

`Availability::is_available()` resolves `RequiresFeature` against the features **this build** was
compiled with, so the report describes the library in front of the caller rather than an ideal one.

### Feature combinations are the test matrix, not an afterthought

The table renders its own build's feature state, so the docs-drift check runs in the default
configuration and a companion test runs under `deprecated`/`post-quantum`, asserting that a row
gated on an enabled feature is not empty and that every available identifier is rendered. Running
the whole file under all five CI configurations is what makes "recognized identifiers stay visibly
unsupported across feature combinations" a checked property: the same table that passes with
`post-quantum` off must, with it on, list nine more usable rows.

### What is deliberately not here

No per-key-size matrix (`RSA` says "≥ 2048 bits" as a note, not a machine-readable bound — the
enforcement lives in code, and a second machine-readable copy would be a second thing to keep
true), no runtime capability negotiation, and no claim about the *backend's* internals beyond what
this crate's own entry points do.

## Consequences

* Capability questions have an answer in the library, and documentation that cannot drift: the
  tables in `docs/capabilities.md` are generated, and the test fails if they are stale.
* The table is ~50 rows of metadata and one test file; keeping it honest costs nothing at runtime.
* Cost is paid in CI seconds: the operation test generates real keys (RSA-2048 and P-521 dominate),
  about a minute per configuration. That is the price of "advertised" meaning "verified", and it is
  the same money the existing matrix already pays.
