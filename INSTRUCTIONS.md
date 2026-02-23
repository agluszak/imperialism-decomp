# Imperialism Decomp Working Instructions

## Naming and Identifier Policy

1. Do not rename variables, parameters, or helper identifiers for style-only reasons.
2. Do not convert exported code to snake_case/camelCase just to match personal preference.
3. Keep naming aligned with Ghidra export unless there is a meaningful semantic reason to change.
4. Acceptable renames are limited to:
   - fixing clearly wrong names (e.g. bad auto-name collisions),
   - applying domain meaning discovered during reverse engineering,
   - unifying wrappers/library prefixes (`Afx_`, `Mfc_`, `Crt_`, `Dx_`) for scope classification.
5. If a rename is meaningful, capture it in Ghidra and re-export so snapshots and source stay in sync.

## Source of Truth

1. Ghidra is the canonical source for recovered names, prototypes, comments, and type information.
2. `src/ghidra_autogen/` and `include/ghidra_autogen/` are regenerated snapshots from Ghidra.
3. Manual files in `src/game/` should preserve exported naming unless there is an explicit RE-driven reason not to.

## Code Shape Policy

1. Do not use inline assembly (`__asm`, `_asm`, `asm(...)`) in project source files.
2. Express reconstructed behavior in normal C/C++ code (typed structs/classes, virtual calls, helpers) so code remains maintainable and portable across toolchain experiments.

## Sync Rule

After meaningful renames in Ghidra, run export sync and then continue implementation:

```bash
uv run python tools/ghidra/sync_exports.py \
  --ghidra-install-dir <GHIDRA_DIR> \
  --ghidra-project-dir <GHIDRA_PROJECT_DIR> \
  --ghidra-project-name <GHIDRA_PROJECT_NAME> \
  --ghidra-program-name Imperialism.exe
```

## Promotion Workflow

1. Promote function bodies from `src/ghidra_autogen/` into manual files with:
```bash
uv run python tools/workflow/promote_from_autogen.py \
  --target-cpp src/game/<file>.cpp \
  --address 0x<ADDR> [--address 0x<ADDR> ...]
```
2. Immediately convert promoted raw offset access into typed field access:
   - replace `*(type *)((int)obj + off)` with struct fields.
   - introduce/adjust local structs for stable offsets instead of repeating `reinterpret_cast` math.
3. After promotion, mark corresponding autogen stubs as manual overrides:
   - change `// FUNCTION: IMPERIALISM 0x...` to `// MANUAL_OVERRIDE_ADDR: IMPERIALISM 0x...` in `src/autogen/stubs/stubs_part*.cpp`.

## Similarity Improvement Notes

Keep this section updated while working. Add short, concrete notes after each reccmp iteration.

Current reminders for improving `% similarity`:

1. Prefer virtual-slot wrappers over ad-hoc function-pointer typedef calls.
2. Preserve original control-flow shape first (early-return vs fail-and-continue) before micro-tuning names.
3. Match argument count at each vtable slot (`+0xA4`, `+0xA8`, etc.); wrong arity tanks similarity quickly.
4. Reuse exact tag/bitmap constants and stack-local layout arrays from Ghidra comments.
5. Track one function at a time with `reccmp --verbose`, then commit only when no regression on neighboring functions.
6. For UI-control initializers, missing style/bounds slots (`+0x1B4`, `+0x1C4`, `+0x12C`, `+0x168`) can cost >20% by themselves.
7. If Ghidra shows assertion paths, keep their line IDs (`USmallViews.cpp` style) and preserve fail-and-continue shape unless proven otherwise.
8. After emitting MessageBox + USmallViews assert for nil controls, avoid adding extra post-assert guards unless original code clearly branches; those guards often hurt shape matching.
9. Use match flags as CSV (`/Oy-,/Ob1`) in CMake args; malformed slash concatenation (`/Oy-/Ob1`) can degrade codegen via invalid `/O/` parsing.
10. Tiny wrapper/orphan functions are prone to folding/aliasing; lock calling-convention shape first (`ret 4`/`ret 8`) before spending time on body micro-tuning.
11. For tiny `ret 4` orphan wrappers (`0x588c30`/`0x5899c0` style), avoid extra frame/prologue shape; argument access through stack offsets strongly affects similarity.
12. `UpdateTradeBarFromSelectedMetricRatio_*` functions include `USmallViews.cpp` assert side path after `MessageBoxA`; omitting that path materially lowers similarity.
13. `ClampAndApplyTradeMoveValue` relies on x87 float path and signed compare ordering; replacing with simplified integer math causes large diffs.
14. Prefer promoting contiguous address ranges (same subsystem) in one run of `promote_from_autogen.py` to preserve natural function ordering and reduce merge churn.
15. After promotion, first clean compile breakages by normalizing class-style decompiler output into existing project free-function style before similarity tuning.
16. For control lookups on owner panels, use a single typed helper (`ResolveOwnerControl`) instead of repeating inline `reinterpret_cast` at each callsite.
