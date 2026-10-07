# Imperialism repository

This repository contains two implementations of **Imperialism (1997)**:

- `decomp/` reconstructs the Windows retail executable.
- `rust/` is an independent Rust implementation.

Retail `Imperialism.exe`, its observable behavior, and its real data, file, and network formats are
ground truth. Follow the nearest scoped `AGENTS.md`.

## Rules

- Implement the smallest clear solution required by current retail behavior.
- Keep one path and one authoritative representation for each thing. Prefer changing an existing path
  over adding a parallel one.
- Do not add abstractions, generators, protocols, configuration modes, compatibility shims, migrations,
  or infrastructure for hypothetical future needs.
- Repository-owned APIs and formats have no compatibility contract. Update current users together.
- Delete superseded code, tests, documentation, and tooling instead of preserving old pathways.
- Production correctness and completeness matter more than coverage, tooling, or metric completeness.
- Do not weaken checks or rewrite baselines merely to make them green.
- Preserve unrelated working-tree changes and keep diffs scoped.

## Knowledge placement

Keep durable architectural invariants in `AGENTS.md`, repeatable procedures in skills, recovered evidence
in focused docs or Ghidra, and history in Git. Do not check in agent worklogs, plans, or review-specific
rules.
