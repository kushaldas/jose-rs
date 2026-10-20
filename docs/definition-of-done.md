# Definition of done (per change)

The mechanical half of this list is a command:

```sh
./scripts/gate.sh                 # fmt + tests×5 + clippy×5 + strict rustdoc + capability drift
./scripts/gate.sh --quick         # default configuration only, while iterating
./scripts/gate.sh --with-interop  # the above plus the matrix and every peer suite
just gate                         # same thing, if you have `just`
```

`scripts/gate.sh` is the implementation; the `just` recipes are aliases, and CI calls the same
commands directly. Green means the build is clean. It does **not** mean the change is done —
the second half below is judgement, which is exactly why it is not in the script.

## Checked by the script

- [ ] `cargo fmt --all -- --check`.
- [ ] Tests pass in all five CI feature configurations, printed with per-run totals:
  `""`, `--no-default-features`, `--features deprecated`, `--features post-quantum`,
  `--all-features`.
- [ ] Clippy is clean in all five, with warnings denied via `RUSTFLAGS='-D warnings'`
  (that flag is not a `cargo clippy` argument; passing it as one silently does nothing).
- [ ] `RUSTDOCFLAGS='-D warnings' cargo doc --locked --all-features --no-deps` — broken
  intra-doc links and missing rustdoc on public items fail the build here, not in review.
- [ ] `docs/capabilities.md` matches `src/capability.rs` (`just capabilities` regenerates).
- [ ] `Cargo.lock` untouched unless the change *is* a dependency change, in which case it
  gets its own commit and its own review note (`--locked` is what makes an accidental change
  loud rather than silent).

## Checked by a human reading the diff

- [ ] The relevant RFC sections (and current errata) were read for the specific protocol
  question at hand, not recalled. Local copies live in `rfcs/`.
- [ ] An ADR exists for any decision a future maintainer would otherwise have to reverse-engineer,
  and it states a **consequence** — what this makes harder or impossible — not only the choice.
  Numbered sequentially in `docs/adr/`, indexed in `docs/adr/README.md`.
- [ ] Public rustdoc explains *why* an API refuses what it refuses; every `# Errors` section
  names the variants actually returned.
- [ ] New behaviour has tests in `tests/`, not only `#[cfg(test)] mod tests`. A lib-only green
  run proves nothing about the integration surface (`--lib` is how this was missed once).
- [ ] Negative and resource-bound cases exist, and each would fail for its stated reason —
  a refusal test that passes because the code refuses *something else* is worse than no test.
- [ ] Peer evidence exists for anything on the wire: the interop matrix cell, or a peer suite
  (`interop/tests/…`) that also asserts what the peer *accepts*, so our stricter refusal is
  shown to be a choice about a real ambiguity rather than a hypothetical.
- [ ] `CHANGELOG.md`, `README.md`, `docs/capabilities.md`, `interop/README.md` and
  `pi_plan.md` describe what the code now does, including limits and refusals — not what was
  intended.
- [ ] Migration notes for anything a caller could notice, including messages and error
  classifications. "No public signature changed" is worth writing when it is true.
- [ ] Staged files are deliberate: `git status` reviewed before `git add`; no generated
  artifacts, no scratch files, no fixtures containing real or reusable secrets. Working notes
  stay untracked (see the repo's policy in `AGENTS.md`).
- [ ] One commit per feature, with the evidence counts in the message (test totals per
  configuration, interop check counts) so a reader can tell what was run without rerunning it.
- [ ] Human review and merge, before any dependent task starts.

## Why the gate is a script

A checklist that has to be remembered is a checklist that gets half-run, and the failures this
project actually hit were all in the "forgot to run it" category:

- editing against a remembered file layout, so the edit silently matches nothing (ground-truth
  the file with `grep`/`sed -n` before anchoring, and re-read after `cargo fmt`);
- trusting a stale `interop/rust-harness` binary, which produces confident false failures;
- running clippy with `-D warnings` as a cargo-clippy argument and getting a clean, meaningless
  run;
- a green `--lib` run that skipped every integration test;
- a capability table that nobody regenerated, quietly advertising support that does not exist
  (the executable version of this test caught two wrong rows on the day it was written — see
  ADR 0032's sibling, ADR 0028).

Each of those is now either a script step or a test, because prose did not prevent any of them.
