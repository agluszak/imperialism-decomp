# Imperialism repository guide

This repository has two implementations of **Imperialism (1997)**:

- `decomp/`: the retail-faithful C++ reconstruction and executable oracle.
- `rust/`: the new Rust implementation.

Retail `Imperialism.exe`, its behavior, and its real data/file/network formats are the ground truth.
Follow the nearest scoped `AGENTS.md` and run tools from that subproject.

## Simplicity is a requirement

Write the smallest clear solution that satisfies the current task and retail behavior. This project
has no external users to preserve compatibility for and no reason to design for hypothetical ones.

- Prefer changing an existing path over adding a parallel path.
- Prefer concrete code over abstraction. Do not add a trait/interface/base class, factory, builder,
  registry, plugin system, protocol layer, wrapper, feature flag, configuration mode, generator, or
  generic framework unless a concrete current need makes the direct solution inadequate.
- One implementation or one caller is not evidence that a general abstraction is needed. A little
  duplication is often cheaper than the wrong abstraction; refactor when a real repeated shape exists.
- Do not turn a one-off command, script, conversion, or investigation into permanent tooling unless it
  is genuinely recurring.
- Do not implement adjacent improvements merely because they are possible. Finish the requested
  behavior; record genuinely useful follow-up work in Beads.
- Delete obsolete code, tests, docs, formats, and tooling when replacing them. Fewer moving parts are
  better.
- Reuse the mechanisms already present before inventing another layer.

When choosing between a direct special-purpose implementation and a more flexible design for imagined
future requirements, choose the direct implementation.

## Port primary behavior first

The purpose of this repository is to recover and run Imperialism, not to maximize test count or build
support infrastructure. Spend feature work on production code that extends an executable gameplay,
format, or UI path.

- Port the retail operation and connect it to its real caller before expanding adjacent helpers.
- Keep rules in production code. Do not leave faithful implementations reachable only from tests.
- Test the smallest meaningful behavior boundary, preferably through the existing retail differential
  and complete semantic state comparison. A focused success case and a materially different edge or
  reversal are usually enough.
- Do not add Rust unit tests for obvious constructors, getters, constant tables, serde spelling, simple
  matches, or private plumbing unless they protect a demonstrated bug or ambiguous retail behavior.
- Do not build test frameworks, generators, fixtures, adapters, or diagnostic commands merely to make
  testing more convenient. Extend existing tooling only when the current vertical slice cannot be
  verified without it.
- Do not delay primary logic to pursue exhaustive test matrices, coverage targets, warning cleanup, or
  speculative malformed-input cases. Validate risks in proportion to their retail relevance.
- In internal Rust crates, use wildcard imports where they keep rule code direct. If a Clippy lint
  consistently demands boilerplate or a less faithful shape without finding a concrete defect, allow
  it at the narrowest useful scope instead of churning the implementation.
- A passing helper test does not make disconnected code complete. Completion means the recovered logic
  is authoritative state and is invoked by the intended production path.

When time or scope forces a choice, implement more of the real retail path and keep only the tests
needed to prove that path.

## Compatibility

The only compatibility target is retail Imperialism. Repository-owned APIs and formats may be broken
freely: update all current producers, consumers, fixtures, and tests together and delete the old form.

Do **not** add compatibility shims, deprecated aliases, legacy modes, dual readers/writers, V1/V2
protocol forks, version negotiation, migrations, or fallback paths for our own previous designs.
Version something only when retail itself has distinct versions or two forms must actually coexist now.

The Rust implementation may use the C++ reconstruction as an external process oracle, but must not
link to it or reproduce accidental C++/MFC/ABI structure. `fixtures/retail/` is retail evidence, not a
generic shared-code namespace.

## Work hygiene

- Use Beads for durable task state and follow-ups; run `bd prime` when context is missing.
- Preserve unrelated working-tree changes. Never use blanket stash/reset/restore/clean operations to
  escape a failure.
- Keep commits and diffs scoped. Push or open a PR only when requested.
- Do not weaken checks or rewrite policy baselines merely to make them green.
- Put standing invariants in the nearest `AGENTS.md`, repeatable procedures in skills, and durable
  evidence in focused docs. Do not add worklogs or checked-in agent plans.
