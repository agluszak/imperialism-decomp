---
name: sync-evidence
description: Synchronize Imperialism binary inventories, function ownership, generated build inputs, Ghidra source metadata, and derived evidence without hand-editing generated artifacts. Use for refresh-inventory, source ownership or marker moves, stub/index generation, Ghidra apply-source, export/resync failures, entity type flips, junk thunk rows, size clamps, or generated-integrity failures under decomp/.
---

# Synchronize evidence

Run from `decomp/` and read [sync-pipeline.md](references/sync-pipeline.md) before mutating inventory,
ownership, Ghidra metadata, or generated inputs.

Use the documented `just` pipeline. Manual C++ source remains manually owned; build-directory stubs,
indexes, and evidence exports are derived. Never hand-edit a generated file to clear a failure.
Classify resync failures by their evidence cause—junk thunk row, wrong ownership, type flip, truncated
extent, size clamp, or stale DB label—and fix the owning source or database forward.
