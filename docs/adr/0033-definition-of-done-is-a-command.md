# ADR 0033 — The definition of done is a command, and the rest is judgement

## Date

2026-07-28

## Status

Accepted

## Context

`future_plan.md` Q3 specifies a per-PR definition of done as a checklist plus a baseline
command list. Checklists in prose are not enforced by anything, and every real failure this
project has had was in the "did not run it" category rather than the "did not know better"
category:

* clippy run with `-D warnings` as a *cargo-clippy argument* — a clean, meaningless pass;
* a green `cargo test --lib` that had skipped every file in `tests/`;
* a stale `interop/rust-harness` binary producing confident false failures after a library
  change;
* an edit anchored on a remembered file layout, which matched nothing and "succeeded" by
  changing nothing;
* a capability table nobody regenerated, advertising support the code does not have.

Some of those became tests. The rest are ordering and completeness problems that a reviewer
cannot reliably catch by reading a diff either, because the diff is exactly where the missing
step is invisible.

## Decision

### Split the checklist into what a script can check and what it cannot

`scripts/gate.sh` runs the mechanical half as one command, and prints the totals (tests per
feature configuration, interop check counts) so "I ran the gate" becomes a pasteable claim
rather than an assertion. `just gate` / `just gate-quick` / `just gate-interop` are aliases to
the same script; CI keeps calling `cargo` directly, so nothing depends on `just` existing.

`docs/definition-of-done.md` holds both halves, with the human half explicitly labelled as
judgement: RFC-and-errata reading, an ADR that states a consequence, negative tests that fail
for the reason they claim, peer evidence that also pins what the peer *accepts*, migration
notes, staged-file review, and human merge. The script's own closing output prints that
remaining list rather than implying green means done.

### The script encodes the lessons, not just the commands

The invocations are the ones CI uses and are commented with the reason each one is written
that way — five feature configurations (`pem` is not a feature), `RUSTFLAGS='-D warnings'`
rather than a clippy argument, no `--lib`, `--locked` everywhere so a lockfile change is loud.
A comment that says *"this flag is not a cargo-clippy argument; passing it there does nothing"*
is cheaper than the next occurrence of the mistake.

### Regenerating the capability tables is part of the gate

A generated document with no check on it drifts silently and reads as authoritative. The gate
diffs `docs/capabilities.md` against `examples/capabilities.rs` in about a second, and
`tests/capability_report.rs` also fails when they disagree — belt and braces, since the table
is the documentation a caller is most likely to trust without testing.

### The gate is verified by being wrong first

The first version of the script reported two *passing* peer suites as failures, because it
decided pass/fail by substring-matching their human-readable summaries and one suite printed
`0 failed` while another printed `0 failures`. That is the same class of mistake as the ones the
script exists to prevent — an infrastructure check that reports a verdict it did not actually
earn — so it is now fixed at the right layer: peer suites are judged by exit code (every suite
`sys.exit(1)`s on failure), and the interop matrix by counting non-`pass` cells in
`interop-results.json`, since `run-interop.sh` deliberately always exits 0 and the per-cell
results are its contract.

A gate that cannot fail correctly is worse than no gate, because it converts an absent check
into a green one.

### Not done

No git hook that auto-runs the gate. The full gate takes minutes; a pre-commit hook that
people learn to bypass with `-n` teaches the wrong lesson about what the gate is for, and this
repo's commits go through human review anyway. No CI matrix change either: CI already runs the
same configurations, and duplicating them in a script that humans run locally is the point.

## Consequences

* "Ran the gate" is one command with evidence in its output, so the claim is checkable after
  the fact.
* The human half is shorter and therefore more likely to be read, and it is where the actual
  risk lives — a script cannot tell whether an ADR states a consequence or whether a negative
  test fails for its stated reason.
* The gate has to be maintained as the CI configuration changes. That is a real coupling, and
  it is documented in the script header; the alternative (two independent lists that drift) is
  how projects end up with a green local build and a red pipeline.
* The script's own correctness is exercised by hand, not by a test — running it from a test
  would take minutes and recurse. Its two known-tricky spots (exit-code judgement, always-zero
  matrix wrapper) are commented where they are.
