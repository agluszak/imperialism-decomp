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

## File Organization Policy

1. Use class-named source files for class-owned implementations:
   - `src/game/<ClassName>.cpp` (for example: `src/game/TCivReport.cpp`, `src/game/TTransportPicture.cpp`).
2. Do not add new class implementations to mixed bucket files.
3. Keep mixed files only for true globals/wrappers that have no class ownership.

## Code Shape Policy

1. Do not use inline assembly (`__asm`, `_asm`, `asm(...)`) in project source files.
2. Express reconstructed behavior in normal C/C++ code (typed structs/classes, virtual calls, helpers) so code remains maintainable and portable across toolchain experiments.
3. If a function was originally `__thiscall` but is represented as a free wrapper (`__fastcall` bridge), keep a reminder comment directly inside the function body:
   - `// ORIG_CALLCONV: __thiscall`
   - Do not place this between `// FUNCTION: ...` and the signature (reccmp parser sensitivity).

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
Or for contiguous windows:
```bash
just promote-range src/game/<file>.cpp 0x<START> 0x<END>
```
2. For trade-screen:
   - keep global/non-class trade functions in `src/game/trade_screen.cpp`.
   - keep class-owned trade functions in class files under `src/game/` (`TAmtBar.cpp`, `TIndustryCluster.cpp`, etc.), included by `trade_screen.cpp`.
   - class wrapper implementations outside trade-screen must go to `src/game/<ClassName>.cpp`.
3. Immediately convert promoted raw offset access into typed field access:
   - replace `*(type *)((int)obj + off)` with struct fields.
   - introduce/adjust local structs for stable offsets instead of repeating `reinterpret_cast` math.
4. After promotion, mark corresponding autogen stubs as manual overrides:
   - change `// FUNCTION: IMPERIALISM 0x...` to `// MANUAL_OVERRIDE_ADDR IMPERIALISM 0x...` in `src/autogen/stubs/stubs_part*.cpp`.
5. For splitting mixed files into class files, use:
```bash
uv run python tools/workflow/split_classes_in_file.py \
  --source-cpp src/game/<mixed_file>.cpp
```

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
17. Pull vtable/class-descriptor addresses from `config/symbols.csv` / `config/symbols.ghidra.txt` (not guesses); wrong constants can keep whole constructor/destructor blocks at `0%`.
18. Treat newly promoted blocks as two phases: first `compiles and links`, then `shape/data parity`; first-pass ports can still report `0%` despite clean builds.
19. `reccmp_latest.json` stores `matching` as ratio (`0.2987`), not percent; always multiply by `100` when recording stats in docs.
20. Keep helper usage patterns consistent inside one subsystem (same constructor/destructor style for `*AmtBar` families) before micro-tuning single functions.
21. For constructor/destructor wrappers that Ghidra shows as unusual `__cdecl` + implicit `ECX`, verify calling-convention/prologue shape before data-layout tuning; wrong wrapper shape can stay pinned at `0%`.
22. Bridge calls to Ghidra-exported ctor/dtor thunks should usually use `__fastcall` wrappers (ECX-based) in this codebase; plain cdecl wrappers (`push/call/add esp`) often lose >15% similarity on small wrappers.
23. Validate suspicious `0.00%` entries with `reccmp --verbose 0xADDR`; JSON summaries can underreport some wrapper matches, while verbose diffs show actionable percentages.
24. If promoted class-scoped raws (`ClassName::Func`) fail to compile because the class type is not declared in manual files, immediately convert them to free typed wrappers (`StateStruct *`) and continue; do not stall on class reconstruction.
25. High-throughput loop works best with class “quads” (create/get/construct/destroy) imported together via `promote_from_autogen.py`, then normalized to shared runtime bridges.
26. Keep `#pragma auto_inline(off)` around tiny wrapper batches to avoid temporary pair-count regressions from inlining/folding; re-enable after the batch.
27. For `0x58C330/0x58C360/0x58C7C0`-style numbered-arrow wrappers, explicit field mapping (`width38`, `hoverTag4e`, `value84`, `value86`) plus virtual helper calls (`InvokeSlotE4`, `QueryBounds`) gives immediate ~60-70% range without deep tuning.
28. For promoted class-wrapper quads, convert class-scoped decompiler output into local `*State` structs plus shared bridge helpers immediately; this keeps compile stability and typically yields 34-86% first-pass similarity.
29. `MANUAL_OVERRIDE_ADDR` entries in stub parts must not keep a `FUNCTION` annotation for the same address, or reccmp sees duplicate mappings and may diff against the stub.
30. After any annotation-only edit in source/stub files, do a rebuild before trusting stats; stale PDB line mappings can create false pairing regressions.
31. For view/toolbar wrapper quads with this current shape, first-pass pattern is consistently around `34.78/50.00/85.71/66.67` (`create/get/construct/destruct`); treat this as a quick baseline before deeper prologue/calling-convention tuning.
32. Keep `src/game/trade_screen.cpp` as the single global trade-screen implementation file; keep class-owned code in separate `src/game/T*.cpp` files.
33. If a function is clearly class-owned, move it into `src/game/<ClassName>.cpp` instead of any mixed bucket file.
34. Keep `src/game/ui_widget_wrappers.cpp` for global/non-class wrappers only; class-owned UI wrappers belong in class files.
35. Keep trade-screen class functions in flat class files under `src/game/<ClassName>.cpp`, included from `src/game/trade_screen.cpp`.
36. In manual files, keep `// FUNCTION: ...` immediately above the function signature; do not insert `GHIDRA_*` comment lines between them, or reccmp may fail to match the address.
37. For this MSVC500 setup, avoid `__thiscall` in free-function pointer casts; normalize these wrappers with `__fastcall` shape to keep builds stable.
38. Use mixed address-cluster promotion when needed (not strictly class-by-class): promote contiguous subsystem addresses first, then normalize class-scoped raw output into compile-safe wrappers.
39. For ctor chains, keep `thiscall` as real member methods (`Class::thunk_*` calling `Class::Construct*`), and reserve free-function thunk casts only for unresolved external bridges.
40. If `reccmp --verbose 0xADDR` reports “Failed to find a match”, verify the function is not being dropped as unreferenced by linker optimization (`/OPT:REF`) before spending time on body tuning.
41. For `UpdateTradeMoveControlsFromDrag`/`UpdateTradeMoveControlsFromScaledDrag`, use the selected control’s raw value field (`+0x4`) for move/bar updates; replacing it with virtual `QueryStepValue()` calls hurts similarity.
42. Keep the move-control invalidation shape in drag handlers: `QueryBounds` -> `OffsetRect` -> `CopyRect` -> `thunk_InvalidateCityDialogRectRegion`; skipping this block costs double-digit similarity.
43. In `InitializeTradeSellControlState`, the `gree` branch must use the `USmallViews.cpp` assert path (`0x7b8`) and not a message-only helper.
44. For this trade-screen cluster, defining `0x588c60` as a member `thiscall` method and keeping the same address-local shape as `0x5899f0` is materially better than the older free-function fastcall wrapper shape.
45. For missing trade-screen functions, promote contiguous TAmtBarCluster ranges directly into `src/game/trade_screen.cpp`, then immediately normalize class-scoped autogen output into typed free wrappers.
46. Prefer direct typed handler calls (`InitializeTradeMoveAndBarControls` / `HandleTradeMoveControlAdjustment`) in manual code paths instead of routing through unresolved thunk stubs.
47. For `0x586D60`/`0x586E70` first-pass shape, preserve explicit control-tag lookups (`"move"`, `"avai"`, `"bar"`) and keep the dispatch tail path present even when command-specific handling is incomplete.
48. In throughput mode, “done for this pass” is: address mapped in source, compiles, stub flipped to `MANUAL_OVERRIDE_ADDR`, and no build regressions; similarity tuning comes in later loops.
49. Tiny orphan setters (`0x586A60`/`0x586A80`/`0x586AB0`) are good throughput targets; map them with typed field writes to remove stub ownership quickly.
50. For tiny orphan wrappers, calling-convention/stack-pop mismatches (`ret 4` vs `ret 8`) can force `0%` despite correct semantics; defer micro-tuning until broader coverage is mapped.
51. Use `just promote` in bigger contiguous batches, then immediately normalize to compile-safe typed wrappers in `trade_screen.cpp` instead of polishing one function at a time.
52. For heavy render paths, first-pass typed wrappers with existing virtual methods (`IsActionable`, `QueryBounds`, `CaptureLayout`, `Refresh`) are acceptable to secure ownership and keep momentum.
53. After each big batch, verify the local stub shard has zero remaining `FUNCTION` entries for the active address window before moving to the next window.
54. For panel-control wrappers like `0x586090`, keep the post-`MessageBoxA` assert path (`USmallViews.cpp` + line literal) when present in Ghidra; dropping it usually costs a large chunk of wrapper similarity.
55. Prefer `just promote-range <file> <start> <end>` for throughput, then immediately normalize to compile-safe wrappers and flip stub ownership to `MANUAL_OVERRIDE_ADDR`.
56. In command handlers (`0x589DA0`/`0x58A940` style), compare explicit command IDs (`100`, `0x65`, `10`) directly; arithmetic-normalized branching (`cmd - 100`) changes prologue/branch layout and often lowers similarity.
57. For fail-and-continue paths, keep `MessageBoxA` without adding extra early-return guards after null checks unless original flow proves a return; added guards frequently diverge branch shape.
58. Raw `ghidra_autogen` class bodies for heavy UI/render functions can break MSVC500 compilation; if class/type surface is incomplete, keep heavy bodies in stubs and only promote compile-safe wrappers/thunks first.
59. If verbose diff shows stack-pop mismatch (`ret 4` vs `ret 0xc`) on command handlers, align method signatures to include payload args (`commandId`, `eventArg`, `eventExtra`) even when only `commandId` is semantically used.
60. For `0x586D60`-style initializers, preserve the stack-argument call shape (`ret 4`) by using a signature with an explicit stack seed parameter; one-arg fastcall variants drift quickly.
61. When emitting `USmallViews` assert paths, avoid helper wrappers that emit a second `MessageBoxA`; duplicate message-box calls create large branch/prologue divergence.
62. For scenario-tag lookup handlers (`0x58AF80`), keep the literal 4-byte tag table loop shape (`0x72733020` etc.) before optimizing type names; matching loop shape is higher impact than naming cleanup.
63. For standalone class files (compiled outside `trade_screen.cpp`), do not introduce new unresolved QuickDraw/string helper externs in first pass; map ownership with compile-safe bodies first, then wire real helper symbols once they are link-proven.
64. If `reccmp` reports dropped duplicate addresses, check for stale `// FUNCTION:` tags still present in `src/autogen/stubs/stubs_part*.cpp` after promotion; demote them to non-reccmp comments immediately.
65. For this MSVC500 build, do not use `__thiscall` in free-function pointer casts; use `__fastcall` wrappers for ECX-style thunk bridges to avoid compile breaks and keep calling-shape stable.
66. For `NumberedArrowButton` wrappers (`0x58B460/0x58B750/0x58B8D0`), preserving raw field offsets (`+0x90/+0x92/+0x94/+0x96/+0x98/+0x9c`) is high impact; mapping them to `value84/value86` directly loses major similarity.
67. For render wrappers that were `0.00%` due pure JMP forwarding, first-pass inlining of Ghidra body shape (quickdraw acquire/clip/release sequence) can quickly lift them into ~`16-30%` before fine-tuning.
68. Use global addresses from `config/symbols.ghidra.txt`/`config/symbols.csv` for runtime pointers (`g_pGlobalMapState`, `g_pStrategicMapViewSystem`, `g_pActiveQuickDrawSurfaceContext`, overlay cache globals) instead of inventing surrogate globals.
69. Tiny orphan leaves with `ret 8` shape should be modeled as stack-arg popping wrappers (`__stdcall` + explicit unused arg) before any body tweaks; otherwise they stay near `0%` due calling-shape mismatch.
70. For quickdraw overlay wrappers (`0x589540`/`0x58A3B0` style), prefer overlay-cache globals (`g_nOverlayClipCacheParamX/Y`) + rect invalidation flow over generic `QueryBounds`/`ApplyBounds` patterns; that improves branch/data shape consistency.
71. For gameplay handlers like `InputState::HandleKeyDown (0x55FC40)`, avoid hardcoded function-address typedef calls when the thunk symbol exists; direct thunk calls + minimal casted bridge only where needed can materially improve call-shape matching.
72. Do not run `just compare` and `just stats` in parallel; Wine `cvdump`/`winedbg` contention can create false pairing regressions and stale debug-data errors.
73. `0x5873E0` (`HandleTradeSellControlCommand`) benefits from adding the missing `0x67/0x68` UI-mode propagation loops (17 tag fan-out), keeping fail-and-continue behavior, and preserving `ret 0xc` via an explicit unused stack arg in the wrapper signature.
74. `0x5897B0` (`SelectTradeCommodityPresetBySummaryTagAndInitControls`) needs a stack-arg signature shape (`ret 4` path), thunk-init call via casted bridge to `thunk_InitializeTradeMoveAndBarControls`, and post-init slot `+0x1D4` dispatch on `this` (not owner fallback).
75. `0x58A690` (`RefreshTradeMoveBarAndTurnControl`) currently matches better with message-only nil paths; avoid injecting extra `USmallViews` assert helper calls there.
76. `0x5866B0` (`UpdateTradeSummaryMetricControlsFromRecord`) matches much better as explicit per-tag straight-line code (no tag loop arrays): first `aert` path uses dword from `[record+0xac]+0x10`, `rtnu/iart/forp` use short offsets `+4/+6/+8`, with assert lines `0x67d/0x682/0x687`, and function signature kept in `thiscall` shape via `__fastcall(this, unusedEdx, stackArg)` (`ret 4`).
77. For `0x586E70` (`HandleTradeMoveControlAdjustment`), original branch shape uses `normalized = commandId - 100` with `0/1` cases; in this function, preserving this normalized branch form and keeping fail-and-continue (no extra early return after nil asserts) improves similarity versus the prior guarded/goto-heavy variant.
78. For `0x5882F0` (`UpdateTradeSellControlAndBarFromNationMetric`), an aggressive fail-and-continue rewrite (removing nil guards and forcing short-only clamp/data flow) regressed (`22.41% -> 17.57%`); keep the guarded version for now and revisit with smaller shape-only changes.
79. For tiny sell-quantity predicates (`0x587900`/`0x587950`), keep signatures/call-shape minimal and avoid defensive nil checks: using global `g_pUiRuntimeContext` in `0x587900`, returning bool/int directly, and forwarding `0x587950` straight to slot `+0x1e8` can jump these wrappers from low-double-digits into high similarity quickly.
80. For `0x5873E0`, keep it on a dedicated TAmtBarCluster-shaped context (`field +0x88` metric slot) rather than `TradeMovePanelContext`; this fixes offset drift in emitted code and keeps subsequent shape passes focused on branch/prologue differences instead of layout artifacts.
81. For trade-selection handlers (`0x588B70`, `0x5897B0`), keep the extra stack arg in the signature (`ret 4` shape) and forward it into `thunk_InitializeTradeMoveAndBarControls`; dropping that arg usually costs double-digit similarity.
82. `just promote` is high-throughput for compile-safe wrappers, but raw heavy UI/render exports can introduce non-C++ decompiler artifacts (`undefined1`, `stack0x...`, class-scoped raw symbols) that break MSVC500; when this happens, rollback the promoted block immediately and continue with manual/typed promotion.
83. `0x587130` (`InitializeTradeSellControlState`) benefits from an explicit stack `styleSeed` parameter that is forwarded into `InitializeTradeMoveAndBarControls`; this preserves the `ret 4` tail shape and improves matching.
84. For class-owned render methods like `0x58BC60`, promote with `just promote --overwrite-existing` first, then normalize raw class/type artifacts into local state structs while preserving the original two-pass text draw + theme-color flow; placeholder/no-op ports stay near `0%`.
85. Resolver-slot caching (`vtable + 0x94`) is function-sensitive: it improved `0x587DD0` materially but regressed `0x588030`; apply it per function after a targeted compare, not as a blanket refactor.
86. In `SetTradeOfferSecondaryBitmapState` (`0x588030`), keep the secondary layout capture buffer as `{0xA3, 0}`; using `{0xA3, 1}` regresses similarity.
87. For newly promoted class handlers (`0x58E1C0` / `0x58EED0`), first-pass compile-safe wrappers with explicit payload structs and tag constants give usable ownership quickly (`~25-45%`) before deeper shape/data tuning.
88. In this MSVC500 toolchain, `__thiscall` inside free-function pointer casts fails to compile (`C4234`); convert these bridges to `__fastcall` with explicit dummy `edx` arguments.
89. For constructor wrappers like `0x58F050`, keep first pass focused on alloc + base-ctor + vtable/field init; defer Ghidra's synthetic SEH prologue/epilogue recreation until later shape pass.
90. In `0x58F110`-style civilian-class cache handlers, model class-id cache and order class-id as `short` at `+0x60/+0x04`; using 32-bit fields regresses call/compare shape.
91. Tiny `ret 4` setters (`0x58E440` pattern) are sensitive to prologue shape; first-pass wrapper ownership is fine, and EBP/prologue micro-tuning should be deferred to dedicated tiny-wrapper pass.
92. For `0x58F3C0`-style province/tile counters, replacing helper wrappers with direct fixed-address globals plus direct collection vtable slot calls (`+0x24/+0x28`) produced a clear first-pass gain (`16.67% -> 24.88%`).
93. For Win32 `PtInRect` bridges in promoted UI hit-test functions, keep ABI exact (`RECT*`, `POINT` by value); pointer-form signatures distort call shape and break semantics.
94. When `just promote` injects class-scoped methods into manual files with incomplete class surfaces, immediately normalize them into compile-safe free wrappers (`// ORIG_CALLCONV: __thiscall`) and flip stubs to `MANUAL_OVERRIDE_ADDR` in the same pass.
95. In `0x58F1A0` click-hit-test flow, a pointer-driven legend-slot loop (`currentSelectionCount`-style) regressed hard (`17.14% -> 4.92%`); keep the slot-index loop shape for now.
96. Promoted `// GHIDRA_FUNCTION ...` blocks are not reccmp markers; convert to `// FUNCTION: IMPERIALISM 0x...` in manual files before compare runs.
97. For compile-only ownership passes, bridged thunk wrappers are acceptable first step (`reinterpret_cast<...>(thunk_...)(...)`), but keep the original-callconv reminder and do not tune body shape in the same iteration.
98. In `0x58F550`, replacing a pure thunk-forwarder with real shape/data body plus style-init call (`InitializeUiTextStyleDescriptorAndApplyQuickDraw(0,0xc,0x2b68)`) improved `0.00% -> 16.11%`.
99. For `0x58F550`, forcing explicit stack args on virtual calls (`slot + 0x1A0/0x1A4/0x1A8`) regressed (`16.11% -> 15.53%`); keep the simpler one-arg `__fastcall(this)` call shape.
