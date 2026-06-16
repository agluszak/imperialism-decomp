---
name: repo-layout-skills-and-vendor
description: post-consolidation layout — AGENTS.md contract + .claude/skills/ workflows + vendored Ghidra/Mac assets; imperialism_knowledge no longer a dependency
metadata:
  type: project
---

Doc/workflow consolidation done 2026-06-03. The scattered docs (INSTRUCTIONS.md,
control_plane.md, class_recovery.md, vtable_strategy.md, vtable_migration_plan.md,
reccmp_fork.md) were collapsed into:

- **`AGENTS.md`** (real file; `CLAUDE.md` → symlink): the contract — Hard Rules,
  command policy, MSVC500 guardrail, commit-message policy, and a map to skills/docs.
- **`.claude/skills/`** (4 skills, each `SKILL.md` + supporting files):
  - `decomp-loop` — porting loop; `heuristics.md` = the 85 Similarity Improvement
    Notes (the former INSTRUCTIONS.md playbook; append new lessons here, not INSTRUCTIONS).
  - `ghidra` — pyghidra read tools; `function-doc-workflow.md` = the interactive
    Ghidra documentation methodology (migrated from imperialism_knowledge/instructions.md).
  - `quality-control` — build/compare/gates + reccmp failure modes.
  - `class-recovery` — slice/mac-evidence + vcall facade registry + vtable migration.
- **`docs/`**: kept historical `worklog.md` plus `toolchain.md`; new
  `docs/reference/` holds layout contracts +
  game-domain docs (migrated from imperialism_knowledge).

**Vendoring (the external sibling is no longer required):** Ghidra program is at
`vendor/ghidra/` (portable `.gzf` via Git LFS; live `.rep` gitignored, recreated by
`just restore-project`). Mac CodeWarrior evidence at `vendor/macos_codewarrior/evidence/`.
All tool path defaults (tools/ghidra/*.py, tools/workflow/{macos_evidence,slice_discovery,
class_discovery}.py, justfile) now resolve `vendor/...` from the repo root; `GHIDRA_PROJECT_DIR`
env still overrides. See [[knowledge-db-impk-external]].

**Why:** info was duplicated 3–4× across files; the sibling `imperialism_knowledge`
repo was an undeclared hard dependency. **How to apply:** put workflow guidance in the
right skill, record matching lessons in `decomp-loop/heuristics.md`, put change-specific
commands and score deltas in clear commit messages, and never reintroduce a path to
`../imperialism_knowledge`.
Supersedes [[next-ui-widget-split-steps]] location refs that pointed at old docs.
