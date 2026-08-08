---
name: verify
description: Build, compare, triage, format, gate, test, and diagnose Imperialism decomp changes with the repository's just and reccmp workflows. Use for any verification request, score or pairing failure, vtable/data/stack comparison, precommit run, regression assessment, gate failure, baseline review, or fix-forward decision under decomp/.
---

# Verify decomp changes

Run from `decomp/`. Read [quality-control.md](references/quality-control.md) before diagnosing a
failure or interpreting a comparison.

## Ladder

1. Use focused `just build`, `just triage`, `just vtable`, `just datacmp`, `just stackcmp`, or
   `just serde-audit` checks while iterating.
2. Format manually edited paths with `just format-check <paths>`.
3. Run `just agent-check` for receipt-backed function work.
4. Run `just precommit` before every commit, review stats and structured semantic results, then
   refresh the stats baseline only when the verified delta is accepted.

Only `mismatch` is actionable source-recovery evidence. `effective` is already proved harmless;
`inconclusive` requires verifier, metadata, alignment, or pairing analysis. Do not parse rendered
assembly by eye to declare safety, and do not revert real C++ architecture to make a gate green.
Policy-baseline updates require explicit human approval.
