# Imperialism repository

This repository contains two implementations of **Imperialism (1997)**:

- `decomp/` reconstructs the Windows retail executable.
- `rust/` is an independent Rust implementation.

Retail `Imperialism.exe`, its behavior, and its real data, file, and network formats are ground
truth. Follow the nearest scoped `AGENTS.md` and run commands from that subproject.

## Principles

- Implement the smallest clear solution required by current retail behavior.
- Prefer modifying an existing path over creating a parallel one.
- Use concrete code. Do not add abstractions, generators, protocols, configuration modes, or tooling
  for hypothetical future needs.
- Repository-owned APIs and formats have no compatibility contract. Update every current producer,
  consumer, fixture, and test together; do not add shims, migrations, or old/new modes.
- Delete replaced code and obsolete infrastructure.
- Connect recovered behavior to its production caller. Production completeness matters more than
  test, coverage, or tooling completeness.
- Reuse existing mechanisms and validate risk in proportion to its retail relevance.
- Preserve unrelated working-tree changes. Keep commits and diffs scoped, and publish only when
  requested.
- Do not weaken checks or rewrite policy baselines merely to make them green.

## Project knowledge

- Standing architectural invariant -> nearest `AGENTS.md`
- Repeatable task procedure -> skill
- Recovered evidence or explanation -> focused docs or Ghidra
- Durable unfinished work -> Beads
- History -> Git

Do not add worklogs, checked-in agent plans, or review-specific prohibitions to `AGENTS.md`. Prefer
enforcing a rule in source structure, types, tests, or lints when practical.
