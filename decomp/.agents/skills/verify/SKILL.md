---
name: verify
description: Select and run the repository checks for C++ reconstruction and decomp tooling changes.
---

# Verify decomp changes

Run from `decomp/`.

1. Start from saved comparison evidence. During recovery, finish a coherent batch (roughly 50–100
   affected functions when feasible) before rebuilding with `just build`.
2. Run `just compare --changed` for the batch, or `just compare --all` after build/toolchain changes.
   Inspect its saved Ghidriff report. `differences` are evidence, not percentage failures;
   `unpaired` and `analysis-failed` require pairing or analysis investigation.
3. Run the relevant specialized check when the change affects its domain:
   `just vtable ClassName`, `just datacmp`, or `just serde-audit`. Run runtime differential fixtures
   only when the batch plausibly changes observable behavior.
4. Format manual files with `just format <paths>` and verify them with
   `just format-check <paths>`.
5. Run `just gates` for source-policy work and `just precommit` near the end of a source batch.
   Tooling-only work uses focused tests/lint for the changed owner; documentation uses diff review.

Report observed outcomes and unresolved evidence. Do not infer behavior or source spelling solely
from a clean or differing decompilation.
