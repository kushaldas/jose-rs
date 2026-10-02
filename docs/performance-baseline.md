# Performance baselines

Q1 of the roadmap asks for reproducible baselines for latency, allocation and peak
memory "on representative key/token sizes", with attention to recipient counts,
repeated key conversion, KDF cost and large post-quantum encodings — and for numeric
targets to come from measurement rather than invention.

This repository therefore keeps two things: a harness that produces the numbers, and
invariants that hold without knowing the machine.

```sh
cargo run --release --example perf_baseline              # markdown table
cargo run --release --example perf_baseline -- --json    # machine-readable
cargo run --release --example perf_baseline -- --slow    # + 600 000-iteration PBES2
cargo test --release --test perf_baselines               # shape invariants
```

## Why the numbers are not committed

A committed baseline table is a table about one CPU. It goes stale on the next
machine and reads like a contract while describing a laptop. So the *procedure* is
versioned and the numbers go in the pull request that changes them, with the command
line and the machine class alongside. The one exception is a number that is a policy
rather than a measurement — iteration budgets, size caps, recipient caps — and those
live in the code that enforces them, with their own ADR.

Compare rows *within* one run. Diffing this table across machines is the mistake the
harness is built to avoid.

## What to measure

`examples/perf_baseline.rs` covers, per repeat (median of 9 after a warm-up, single
thread, release profile):

| Group | Rows | Why it is on the list |
|---|---|---|
| sign / verify | HS256, ES256, Ed25519, 1 KiB payload | the common paths, and the cheapest baseline for everything else |
| post-quantum | ML-DSA-65 sign/verify (`--features post-quantum`) | "large PQ encodings": signature size dominates |
| JWE compact | `dir` with A128GCM / A256GCM / A256CBC-HS512, 4 KiB | content protection per `enc`, CEK size follows `enc` |
| general JWE | encrypt for 1 / 8 / 32 recipients; decrypt one of N | the recipient-count axis, both directions |
| key conversion | JWK → `SoftwareKey` (EC P-256) | the "repeated key conversion" axis |
| JWK Set | diagnostics over 64 entries, `select` by kid, parse + limit check over 512 | attacker-shaped input |
| parse | certificate PEM → JWK, PKCS#8 PEM → JWK, claims with the duplicate-member walk | new parsers, measured individually |
| PBES2 | 2 048 and 65 536 iterations; 600 000 with `--slow` | the KDF-cost axis, where the cost *is* the feature |

`per unit` divides the median by the row's `n`, which is the column worth comparing
across a change — it is what shows whether a fix scaled with the work or around it.

## What CI enforces, and why it is shape rather than speed

`tests/perf_baselines.rs` asserts four shapes, each with a slack factor far larger
than the effect it guards against. They are alarms for order-of-magnitude regressions,
not gates on drift:

- **Decrypting one named recipient does not scale with the recipient count** (alarm at
  10×; measured ≈1×). Encryption is allowed to grow — that is the work — but not
  super-linearly (alarm at 40× for 32× the recipients).
- **Repeated key conversion is not super-linear** (alarm at 500× for 50 conversions;
  measured ≈50×).
- **Password derivation follows the caller's budget**: 4× the iterations is measurably
  slower (a silent no-op parameter would not be), and an input the budget rejects costs
  far less than one it accepts.
- **Oversized documents are refused before they are parsed**, self-calibrated against
  the cost of actually parsing a document the same budget admits.

A wall-clock threshold ("ES256 verify under 5 ms") is not in that list on purpose: it
passes on a build machine, fails on a loaded runner, and teaches people to rerun the
job instead of reading the failure. Ratios measured back-to-back in one process are the
version of a performance test that can be trusted.

Writing these tests corrected one assumption worth recording: the JWK Set budget is
*two* checks with different powers. `max_bytes` can fire before parsing and is the
pre-parse line of defence; `max_entries` cannot, because an entry count is not knowable
until the entries are parsed — so its contract is to refuse completely, never to hand
back a truncated set. A test that blurred the two would have passed for the wrong
reason.

## Interpreting a regression

1. Run the harness on the branch and on `main`, back to back, same machine.
2. Look at `per unit`, not the total.
3. Check which axis moved: recipient count, key conversion, KDF iterations, document
   size.
4. Keep optimization changes separate from algorithm or format changes, so the
   comparison has one variable.

Streaming is deliberately out of scope: any later streaming design has to say where
authenticated plaintext is held before release, and must not expose unauthenticated
chunks to save memory.
