# ADR 0035 — Baselines are a harness plus shapes; committed numbers are not baselines

## Date

2026-07-28

## Status

Accepted

## Context

`future_plan.md` Q1 asks for reproducible baselines for allocation count, peak memory
and latency on representative key/token sizes — recipient counts, repeated key
conversion, KDF cost, large post-quantum encodings — and for numeric targets in
performance work to come "from measured baselines, not invented estimates".

Two ways to satisfy that fail. Committing a benchmark table writes down one machine's
numbers and lets them read as a contract; a year later nobody can tell whether a
regression is real or whether the laptop changed. Putting thresholds in tests
("ES256 verify under 5 ms") produces a suite that passes on a build machine, fails on a
loaded runner, and trains people to rerun the job rather than read the failure.

This crate also has a class of performance claim that *is* a security property: work
must follow the caller's budget, not the input's ambition. An iteration count, a
document size or a recipient count that translates into unbounded work is a
denial-of-service lever held by whoever wrote the bytes. That has to be enforced in
CI, not measured once in a PR.

## Decision

### The harness lives in the repository; the numbers live in the pull request

`examples/perf_baseline.rs` measures the axes the plan names — per-algorithm sign and
verify, `dir` JWE per `enc`, general JWE for 1/8/32 recipients and decrypt of one of N,
JWK → backend key conversion, JWK Set diagnostics/selection/parse, the new parsers
(certificate walk, PEM import, claims duplicate-member scan), and PBES2 at two
iteration counts by default with the expensive ones behind `--slow`. Output is markdown
or `--json`, each row carrying `n` and a `per unit` column, because the useful question
across a change is "what did it cost per recipient / per key / per iteration", not
"what did the total take".

`docs/performance-baseline.md` records the procedure, which axes exist and why, and how
to read a regression. No machine-specific numbers are committed.

### CI enforces shapes, self-calibrated against their own baseline

`tests/perf_baselines.rs` asserts four properties, each with a slack factor an order of
magnitude above the measured effect, and each calibrated on the machine running it
rather than against an absolute threshold:

- decrypting one addressed recipient does not scale with the number of recipients in
  the document (alarm at 10×, measured ≈1×); encryption may grow but not super-linearly
  (alarm at 40× for 32× the recipients);
- repeated key conversion is not super-linear (alarm at 500× for 50 conversions,
  measured ≈50×);
- password derivation follows the caller's budget — more iterations is measurably more
  work, and an input the budget refuses costs far less than one it admits;
- an oversized document is refused *before* being parsed, measured as RSS growth
  relative to parsing a document the same budget admits (Linux; elsewhere the test says
  so and passes rather than substituting a weaker claim silently).

### Writing the memory test corrected the claim it was making

`SetLimits` has two checks with different powers, and the first draft of the test
asserted the stronger-sounding version of both. `max_bytes` can and must fire before
parsing. `max_entries` cannot: an entry count is not knowable until the entries exist,
so a 3 MB set with 20 000 valid entries is parsed and *then* refused — measured, ~21 MB
of RSS. The test now states each contract separately: the byte budget is the pre-parse
defence (refusal grows RSS by ≈0 against a parse that grows tens of megabytes); the
entry budget's job is to refuse completely, never to hand back a truncated set that
looks like a caller's keys went missing.

### Not done

No committed numeric targets ("verify must be under X µs"), no criterion/iodine
dependency, and no CI job that fails on latency drift. Adding a benchmark harness as a
dev-dependency is a lockfile change with its own review, and none of the four
invariants needed one: `Instant` plus a median is enough for a shape assertion. If a
future change needs statistical rigor beyond that, the harness is the place it grows.

## Consequences

* Performance claims in this repository come with a command line and a machine class,
  in the PR that changes them; `docs/performance-baseline.md` says what to run.
* The security-relevant half of performance — bounded work under hostile input — is
  enforced on every commit, in the same configuration matrix as everything else.
* Timing tests exist, which is a flakiness risk accepted deliberately and bounded
  three ways: ratios instead of absolutes, an order-of-magnitude of slack, and a
  measured self-calibration for the memory case. Each test names its alarm threshold in
  prose so a failure says what shape broke.
* The `perf_baseline` example must be kept in step with new algorithms and parsers;
  nothing checks that mechanically, and the doc's "what to measure" table is the
  checklist. A forgotten row is a blind spot, not a failure — stated so that the gap is
  visible rather than implied.
