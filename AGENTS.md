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
