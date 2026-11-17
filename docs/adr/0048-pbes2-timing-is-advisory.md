# ADR 0048 - PBES2 timing ratios are advisory

- Date: 2026-11-17
- Status: Accepted; supersedes ADR 0035's blocking PBES2 timing-ratio decision.
- Release: 0.12.0

## Context

The PR passed, but the identical merged code failed the PBES2 performance test:
8 192 iterations measured about 75.6 ms versus 46.5 ms for 2 048 iterations.
The assertion required a ratio greater than two. Whole-operation measurements
include randomness, allocation, encryption and scheduling; five-sample medians
cannot remove sustained contention or fixed overhead. Ratios are not portable
proof that the iteration parameter reaches the KDF.

The malformed-DER refusal check was also misleading: it started its timer after
calling the parser, and the input contained no iteration count to test a budget.

## Decision

Keep the PBES2 timing measurement, but print an advisory when the ratio misses
its threshold and let the test pass. Encryption failures still fail normally.
Remove the unrelated malformed-DER timing check rather than present it as proof
of early budget enforcement. Other performance checks retain their existing rules.

## Security boundaries

No library validation, cryptographic operation or work budget changes. Functional
PBES2 and encrypted-PKCS#8 tests still enforce parameter propagation and budget
refusals. A timing warning does not establish a security or correctness failure.

## Consequences

Timing noise no longer blocks CI through this PBES2 ratio. A genuine performance
regression on this axis will also be advisory, so investigate measurements using
the release-mode baseline harness. Cargo captures successful-test output by default;
run with `--show-output` to display advisories. No dependencies or public APIs change.
