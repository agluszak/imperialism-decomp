---
name: verify
description: Build, compare, triage, and verify Imperialism decomp changes under decomp/.
---

# Verify decomp changes

Run from `decomp/`.

1. While iterating, use the narrowest real check: `just build`, `just triage 0xADDR`, `just vtable`,
   `just datacmp`, `just stackcmp`, or `just serde-audit`.
2. Format manually edited files with `just format-check <paths>`.
3. Run `just precommit` before committing. It covers the build, hard source gates, tooling tests,
   generated-input integrity, and the runtime suite.

Use reccmp's structured result: `mismatch` is actionable; `effective` is already proved safe;
`inconclusive` needs comparator, metadata, pairing, or evidence work. Do not decide safety from a
rendered assembly diff and do not regress a real C++ model merely to clear a check.
