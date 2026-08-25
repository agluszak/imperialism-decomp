---
name: verify
description: Select and run the repository checks for C++ reconstruction and decomp tooling changes.
---

# Verify decomp changes

Run from `decomp/`.

1. Build with `just build`.
2. Compare every touched retail function with `just triage 0xADDR` or `just triage --file path`.
   `mismatch` is actionable; `effective` is proved harmless; `inconclusive` requires evidence,
   metadata, pairing, or comparator diagnosis.
3. Run the relevant specialized check when the change affects its domain:
   `just vtable ClassName`, `just datacmp`, `just stackcmp`, or `just serde-audit`.
4. Format manual files with `just format <paths>` and verify them with
   `just format-check <paths>`.
5. Run `just gates` for source-policy work and `just precommit` for a completed change. `precommit`
   covers builds, gates, tooling tests, generated integrity, and the PR runtime suite.

Report any residual mismatch or inconclusive result explicitly; do not convert it into a passing
claim.
