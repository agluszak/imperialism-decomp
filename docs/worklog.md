# Worklog

## 2026-02-23

### Mixed promotion batch (non-class + trade-cluster wrappers)
1. Switched from strict class-by-class promotion to mixed address-cluster promotion for trade-screen.
2. Promoted non-class/global trade functions into `src/game/trade_screen.cpp` via `just promote`:
   1. `0x00586170` `UpdateTradeResourceSelectionByIndex`
   2. `0x005866B0` `UpdateTradeSummaryMetricControlsFromRecord`
   3. `0x005870B0` `ConstructTradeSellControlPanel`
3. Promoted adjacent trade-cluster wrappers into `src/game/trade_screen.cpp` and normalized to compile-safe wrappers:
   1. `0x00587010` `CreateTradeSellControlPanel`
   2. `0x00587090` `GetTTradeClusterClassNamePointer`
   3. `0x005870E0` `DestroyTradeSellControlPanel`
4. Converted all six promoted blocks from raw Ghidra class output into maintainable wrapper shape:
   1. removed raw class-scoped forms that failed MSVC500 parsing.
   2. replaced with explicit free-function wrappers and typed pointer access.
   3. removed `GHIDRA_*` lines between `// FUNCTION` and function signatures to keep reccmp matching stable.
5. Updated stub ownership to avoid duplicate mappings:
   1. `src/autogen/stubs/stubs_part017.cpp`: `0x00586170` -> `MANUAL_OVERRIDE_ADDR`
   2. `src/autogen/stubs/stubs_part018.cpp`: `0x005866B0`, `0x00587010`, `0x00587090`, `0x005870B0`, `0x005870E0` -> `MANUAL_OVERRIDE_ADDR`
6. Verification sequence:
   1. `just build`
   2. `just detect`
   3. `just stats`
7. Latest snapshot (`2026-02-23T19:59:43Z`):
   1. paired: `12229/12229` (`100%`)
   2. aligned: `43`
   3. average similarity: `2.13%` (`+0.02 pp` from previous run)
   4. no failed-to-match lines (`0`)

### Flatten trade-screen layout into `src/game/`
1. Removed nested trade-screen directories from active layout:
   1. `src/game/trade_screen_parts/`
   2. `src/game/trade_screen_classes/`
2. Moved files to flat `src/game/`:
   1. `TAmtBar.cpp`, `TIndustryCluster.cpp`, `TIndustryAmtBar.cpp`, `TRailCluster.cpp`, `TRailAmtBar.cpp`, `TShipyardCluster.cpp`, `TShipAmtBar.cpp`, `TTraderAmtBar.cpp` moved to `src/game/`.
3. Inlined `trade_screen_part_1.cpp` and `trade_screen_part_2.cpp` directly into `src/game/trade_screen.cpp`, then deleted both part files.
4. Updated `INSTRUCTIONS.md` and `docs/control_plane.md` to reflect flat `src/game/` policy.
5. Verification:
   1. Docker MSVC500 build: success.
   2. `reccmp-project detect`: success.
   3. `progress_stats.py` snapshot (`2026-02-23T19:05:52Z`): paired `12229/12229`, aligned `43`, average similarity `2.06%`.

### Trade-screen class-file split (part files -> class files)
1. Split class-owned functions out of:
   1. `src/game/trade_screen_parts/part_1.cpp`
   2. `src/game/trade_screen_parts/part_2.cpp`
2. Added class include files under `src/game/trade_screen_classes/`:
   1. `TAmtBar.cpp`
   2. `TIndustryCluster.cpp`
   3. `TIndustryAmtBar.cpp`
   4. `TRailCluster.cpp`
   5. `TRailAmtBar.cpp`
   6. `TShipyardCluster.cpp`
   7. `TShipAmtBar.cpp`
   8. `TTraderAmtBar.cpp`
3. Updated `src/game/trade_screen.cpp` include list to include new class files.
4. Resulting structure:
   1. `part_1.cpp`: global/non-class only (23 functions).
   2. `part_2.cpp`: global/non-class only (1 function).
5. Verification:
   1. Docker MSVC500 build: success.
   2. `reccmp-project detect`: success.
   3. `progress_stats.py` snapshot (`2026-02-23T18:59:01Z`):
      1. paired `12229/12229` (`100%`)
      2. aligned `43`
      3. average similarity `2.06%` (no regression)

### Class-file split refactor (active)
1. Enforced class-per-file layout for extracted wrappers.
2. Added dedicated class files:
   1. `src/game/TCivReport.cpp`
   2. `src/game/TTransportPicture.cpp`
   3. `src/game/TArmyToolbar.cpp`
   4. `src/game/TStratReportView.cpp`
   5. `src/game/TCivToolbar.cpp`
   6. `src/game/TArmyInfoView.cpp`
3. Added reusable splitter script:
   1. `tools/workflow/split_classes_in_file.py`
4. Applied splitter to `src/game/ui_widget_wrappers.cpp`, generating:
   1. `src/game/TCivilianButton.cpp`
   2. `src/game/THQButton.cpp`
   3. `src/game/TPlacard.cpp`
   4. `src/game/TArmyPlacard.cpp`
   5. `src/game/TNumberedArrowButton.cpp`
   6. `src/game/TCombatReportView.cpp`
5. `src/game/ui_widget_wrappers.cpp` now keeps only global/non-class wrappers.
6. Build-system updates:
   1. `CMakeLists.txt` now includes the new class files.
   2. Removed mixed `src/game/toolbars_and_views.cpp`.
7. Stub ownership updates:
   1. Flipped `TTransportPicture` quad (`0x00591D90`, `0x00591E50`, `0x00591E70`, `0x00591EC0`) to `MANUAL_OVERRIDE_ADDR`.
8. Verification:
   1. Docker MSVC500 build: success.
   2. `reccmp-project detect`: success.
   3. `progress_stats.py` snapshot (`2026-02-23T18:54:09Z`):
      1. paired `12229/12229` (`100%`)
      2. aligned `43`
      3. average similarity `2.06%` (no regression from split)

### Trade-screen scope cleanup (move widget wrappers out)
1. Moved non-trade widget wrapper quads from `trade_screen_parts/part_2.cpp` into:
   1. `src/game/ui_widget_wrappers.cpp`
2. Moved addresses:
   1. `0x0058B340..0x0058C900` (`TCivilianButton`, `THQButton`, `TPlacard`, `TArmyPlacard`, `TNumberedArrowButton`, `TCombatReportView` wrappers)
3. Trade-screen parts now:
   1. `part_1`: `0x00587130..0x0058A940`
   2. `part_2`: `0x0058AAA0..0x0058AF30`
4. Build-system update:
   1. added `src/game/ui_widget_wrappers.cpp` to `CMakeLists.txt`.
5. Validation:
   1. Docker MSVC500 build: success.
   2. `progress_stats.py` (`2026-02-23T18:36:08Z`) unchanged:
      1. paired `12229/12229` (`100%`)
      2. aligned `43`
      3. average similarity `2.01%`

### Trade-screen scope cleanup (move non-trade wrappers out)
1. Moved clearly non-trade class wrapper quads out of trade-screen into:
   1. `src/game/toolbars_and_views.cpp`
2. Moved addresses:
   1. `0x0058DE40..0x0058DF10` (`TArmyToolbar` wrappers)
   2. `0x0058E330..0x0058E3F0` (`TStratReportView` wrappers)
   3. `0x0058EA00..0x0058EAD0` (`TCivToolbar` wrappers)
   4. `0x00591500..0x005915D0` (`TArmyInfoView` wrappers)
3. Trade-screen layout now:
   1. `src/game/trade_screen.cpp` (shared scaffolding)
   2. `src/game/trade_screen_parts/part_1.cpp` and `part_2.cpp` only
4. Build-system update:
   1. added `src/game/toolbars_and_views.cpp` to `CMakeLists.txt`.

### Trade-screen file split (maintainability refactor)
1. Split `src/game/trade_screen.cpp` into shared scaffolding + address-ordered part files:
   1. `src/game/trade_screen.cpp` (shared declarations/helpers + include hub)
   2. `src/game/trade_screen_parts/part_1.cpp` (`0x00587130..0x0058A940`)
   3. `src/game/trade_screen_parts/part_2.cpp` (`0x0058AAA0..0x0058C900`)
   4. `src/game/trade_screen_parts/part_3.cpp` (`0x0058DE40..0x005915D0`)
2. Validation:
   1. Docker MSVC500 build succeeded.
   2. `reccmp-project detect` succeeded.
   3. `progress_stats.py` (`2026-02-23T18:25:19Z`) stayed stable:
      1. paired `12229/12229` (`100%`)
      2. aligned `43`
      3. average similarity `2.01%` (no regression).
3. Workflow update:
   1. new trade-screen promotions should target `src/game/trade_screen_parts/part_*.cpp` directly.

### Batch loop progress (TArmyInfoView wrapper quad)
1. Promoted with `promote_from_autogen.py`:
   1. `0x00591500`, `0x00591580`, `0x005915A0`, `0x005915D0`
2. Converted promoted code to typed/manual wrappers in `src/game/trade_screen.cpp`:
   1. added `ArmyInfoViewState`.
   2. added vtable/classdesc placeholders for `TArmyInfoView`.
   3. normalized ctor/dtor path to existing `TradeScreenRuntimeBridge` helpers.
3. Stub sync:
   1. switched all 4 addresses to `MANUAL_OVERRIDE_ADDR` in `src/autogen/stubs/stubs_part018.cpp`.
4. Verification (`progress_stats.py`, `2026-02-23T17:31:55Z`):
   1. paired coverage: `12229/12229` (`100%`).
   2. aligned: `43`.
   3. average similarity: `2.01%` (`+0.03 pp` from prior `1.98%`).
5. Targeted `reccmp --verbose` checkpoints:
   1. `0x00591500`: `34.78%`
   2. `0x00591580`: `50.00%`
   3. `0x005915A0`: `85.71%`
   4. `0x005915D0`: `66.67%`

### Batch loop progress (TStratReportView + TCivToolbar wrapper quads)
1. Promoted with `promote_from_autogen.py`:
   1. `0x0058E330`, `0x0058E3A0`, `0x0058E3C0`, `0x0058E3F0`
   2. `0x0058EA00`, `0x0058EA80`, `0x0058EAA0`, `0x0058EAD0`
2. Converted promoted code to typed/manual wrappers in `src/game/trade_screen.cpp`:
   1. Added `StratReportViewState` and `CivToolbarState`.
   2. Added bridge helper for `thunk_ConstructUiResourceEntryType4B0C0`.
   3. Added vtable/classdesc placeholders for `TStratReportView` and `TCivToolbar`.
3. Stub sync:
   1. flipped all 8 addresses to `MANUAL_OVERRIDE_ADDR` in `src/autogen/stubs/stubs_part018.cpp` and removed `FUNCTION` tags for those addresses.
4. Verification (`progress_stats.py`, `2026-02-23T17:28:06Z`):
   1. paired coverage: `12229/12229` (`100%`).
   2. aligned: `43`.
   3. average similarity: `1.98%` (`+0.05 pp` from prior `1.93%`).
5. Targeted `reccmp --verbose` checkpoints:
   1. `0x0058E330`: `34.78%`
   2. `0x0058E3A0`: `50.00%`
   3. `0x0058E3C0`: `85.71%`
   4. `0x0058E3F0`: `66.67%`
   5. `0x0058EA00`: `34.78%`
   6. `0x0058EA80`: `50.00%`
   7. `0x0058EAA0`: `85.71%`
   8. `0x0058EAD0`: `66.67%`

### Batch loop progress (TArmyToolbar wrapper quad)
1. Normalized promoted raw class-scoped decompiler output for:
   1. `0x0058DE40`
   2. `0x0058DEC0`
   3. `0x0058DEE0`
   4. `0x0058DF10`
2. Converted to typed/manual wrappers in `src/game/trade_screen.cpp`:
   1. added `ArmyToolbarState`.
   2. added vtable/classdesc placeholders for `TArmyToolbar`.
   3. reused bridge ctor + shared dtor pattern used by neighboring toolbar wrappers.
3. Stub sync:
   1. switched all four addresses to `MANUAL_OVERRIDE_ADDR` in `src/autogen/stubs/stubs_part018.cpp`.
4. Verification (`reccmp --verbose`):
   1. `0x0058DE40`: `34.78%`
   2. `0x0058DEC0`: `50.00%`
   3. `0x0058DEE0`: `71.43%`
   4. `0x0058DF10`: `66.67%`
5. Process note:
   1. annotation-only changes in stubs require rebuild before metrics; stale line mapping caused a temporary false coverage drop that disappeared after rebuild.

### Batch loop progress (numbered-arrow wrapper trio)
1. Promoted with `promote_from_autogen.py`:
   1. `0x0058C330` `OrphanCallChain_C1_I08_0058c330`
   2. `0x0058C360` `OrphanCallChain_C2_I23_0058c360`
   3. `0x0058C7C0` `WrapperFor_thunk_HandleCursorHoverSelectionByChildHitTestAndFallback_At0058c7c0`
2. Converted to typed/manual wrappers in `src/game/trade_screen.cpp`:
   1. extended `NumberedArrowButtonState` with explicit fields (`width38`, `hoverTag4e`, `value84`, `value86`).
   2. added extern thunk declaration for `thunk_HandleCursorHoverSelectionByChildHitTestAndFallback`.
   3. used existing virtual helpers (`InvokeSlotE4`, `QueryBounds`, `IsActionable`) instead of raw offset calls.
3. Stub sync:
   1. switched all three addresses to `MANUAL_OVERRIDE_ADDR` in `src/autogen/stubs/stubs_part018.cpp`.
4. Verification (`progress_stats.py`, `2026-02-23T17:19:42Z`):
   1. paired coverage: `12229/12229` (`100%`).
   2. aligned: `43`.
   3. average similarity: `1.91%` (`+0.02 pp`).
5. Targeted `reccmp --verbose` checkpoints:
   1. `0x0058C330`: `60.00%`
   2. `0x0058C360`: `69.39%`
   3. `0x0058C7C0`: `68.75%`

### Batch loop progress (THQ/Army wrapper pass)
1. Promoted batch with existing workflow script:
   1. `0x0058B6E0`
   2. `0x0058B7F0`
   3. `0x0058BF50`
   4. `0x0058C140`
2. Reworked promoted code into manual/typed wrappers in `src/game/trade_screen.cpp`:
   1. added virtual slot helper for `+0x1CC` (`TradeControl::InvokeSlot1CC`).
   2. extended `HQButtonState` layout with explicit fields used by wrappers.
   3. converted problematic `TArmyPlacard::*` class-scoped raws to free typed wrappers after compile breakage.
3. Stub sync:
   1. flipped all four addresses to `MANUAL_OVERRIDE_ADDR` in `src/autogen/stubs/stubs_part018.cpp`.
4. Results (`progress_stats.py`, `2026-02-23T10:54:06Z`):
   1. paired coverage restored near full: `12228/12229`.
   2. average similarity: `1.84%` (`+0.36 pp` vs failed build snapshot).

### Batch loop progress (TNumberedArrowButton + TCombatReportView quads)
1. Promoted and normalized 8 low-risk class quad functions:
   1. `0x0058C1E0`, `0x0058C280`, `0x0058C2A0`, `0x0058C2E0`
   2. `0x0058C830`, `0x0058C8B0`, `0x0058C8D0`, `0x0058C900`
2. Added reusable scaffolding:
   1. `NumberedArrowButtonState`, `CombatReportViewState` layouts.
   2. bridge helper for `thunk_ConstructUiCommandTagResourceEntryBase`.
   3. symbol placeholders for vtable/classdesc pairs.
3. Stub sync:
   1. flipped all eight addresses to `MANUAL_OVERRIDE_ADDR` in `src/autogen/stubs/stubs_part018.cpp`.
4. Results (`progress_stats.py`, `2026-02-23T10:56:41Z`):
   1. paired: `12228/12229` (coverage `99.99%`).
   2. aligned: `43`.
   3. average similarity: `1.89%` (`+0.05 pp` from previous loop).

### Similarity push (wrapper shape + class wrapper extraction)
1. Improved call-shape parity in `src/game/trade_screen.cpp`:
   1. switched bridge wrapper calls for ctor/dtor helper thunks from cdecl-style to `__fastcall` bridge usage.
   2. tightened `0x0058ABF0` (`SelectTradeSpecialCommodityAndRecomputeBarLimits`) toward original branch/divide shape.
2. Promoted and converted 16 additional class wrapper functions from autogen into typed manual code:
   1. `0x0058B340`, `0x0058B3C0`, `0x0058B3E0`, `0x0058B410`
   2. `0x0058B5C0`, `0x0058B640`, `0x0058B660`, `0x0058B690`
   3. `0x0058B960`, `0x0058B9F0`, `0x0058BA10`, `0x0058BA40`
   4. `0x0058BE30`, `0x0058BEB0`, `0x0058BED0`, `0x0058BF00`
3. Marked all corresponding stubs in `src/autogen/stubs/stubs_part018.cpp` as `MANUAL_OVERRIDE_ADDR`.
4. Added anti-folding guard for tiny wrappers:
   1. `#pragma auto_inline(off)` around the newly added small wrapper block.
   2. restored pairing coverage after temporary `paired -1` regression.
5. Verification (`progress_stats.py`, `2026-02-23T10:47:59Z`):
   1. paired coverage: `12229/12229` (`100%`).
   2. aligned: `43`.
   3. average similarity: `1.83%` (up from `1.73%` before this pass, `+0.10 pp`).
6. Targeted verbose checkpoints from this pass:
   1. `0x0058AB60`: `91.67%`
   2. `0x0058ABF0`: `81.36%`
   3. `0x0058AEF0`: `91.67%`
   4. `0x0058AAA0`: `42.11%`

### Trade-screen extraction batch (`0x0058AAA0`..`0x0058ABF0`)
1. Promoted and converted 5 contiguous `TShipAmtBar` functions into typed C++ in `src/game/trade_screen.cpp`:
   1. `0x0058AAA0` `CreateTShipAmtBarInstance`
   2. `0x0058AB40` `GetTShipAmtBarClassNamePointer`
   3. `0x0058AB60` `ConstructTShipAmtBarBaseState`
   4. `0x0058ABA0` `DestructTShipAmtBarAndMaybeFree`
   5. `0x0058ABF0` `SelectTradeSpecialCommodityAndRecomputeBarLimits`
2. Added missing constants from exported symbols:
   1. `kVtableTShipAmtBar = 0x00666998`
   2. `kAddrClassDescTShipAmtBar = 0x00663010`
3. Marked corresponding autogen stubs as manual overrides in `src/autogen/stubs/stubs_part018.cpp`.
4. Verification:
   1. Docker MSVC500 build: success.
   2. `reccmp-project detect`: success.
   3. `progress_stats.py` snapshot (`2026-02-23T10:35:21Z`):
      1. Recompiled functions: `12354` (`+5`).
      2. Paired coverage: `12229/12229` (`100%`).
      3. 100% aligned: `43` (unchanged).
      4. Average similarity: `1.69%` (`+0.03 pp`).
5. Focused similarities for this batch:
   1. `0x0058AAA0`: `0.00%`
   2. `0x0058AB40`: `0.00%`
   3. `0x0058AB60`: `0.00%`
   4. `0x0058ABA0`: `0.00%`
   5. `0x0058ABF0`: `0.00%`
6. Observations (works vs does not):
   1. Works: contiguous promotion + immediate typed rewrite keeps compile/link stable and keeps momentum.
   2. Works: using exported vtable/class descriptor addresses directly avoids symbol drift.
   3. Does not yet work: first-pass shape parity on this block; all 5 remain at `0%` and need branch/order/data-layout tuning.
   4. Does not yet work: relying on inferred field semantics without validating exact offset semantics in hot code paths.

### Trade-screen extraction batch (`0x0058AE30`..`0x0058AF30`)
1. Promoted and converted 4 additional contiguous amount-bar functions:
   1. `0x0058AE30` `CreateTTraderAmtBarInstance`
   2. `0x0058AED0` `GetTTraderAmtBarClassNamePointer`
   3. `0x0058AEF0` `ConstructTTraderAmtBar_Vtbl00666ba0`
   4. `0x0058AF30` `DestructTTraderAmtBarMaybeFree`
2. Added constants:
   1. `kVtableTTraderAmtBar = 0x00666ba0`
   2. `kAddrClassDescTTraderAmtBar = 0x00663028`
3. Marked corresponding autogen stubs as manual overrides in `src/autogen/stubs/stubs_part018.cpp`.
4. Verification:
   1. Docker MSVC500 build: success.
   2. `reccmp-project detect`: success.
   3. `progress_stats.py` snapshot (`2026-02-23T10:37:58Z`):
      1. Recompiled functions: `12332`.
      2. Paired coverage: `12229/12229` (`100%`).
      3. 100% aligned: `43` (unchanged).
      4. Average similarity: `1.71%` (`+0.02 pp`).
5. Focused similarities for this batch:
   1. `0x0058AE30`: `0.00%`
   2. `0x0058AED0`: `0.00%`
   3. `0x0058AEF0`: `0.00%`
   4. `0x0058AF30`: `0.00%`
6. Observations:
   1. Works: contiguous extraction still raises global average despite low first-pass local scores.
   2. Does not yet work: constructor/destructor wrappers in this block likely still have signature/prologue mismatch relative to original code shape.

### Process and documentation updates
1. Updated `AGENTS.md` with a mandatory continuous matching loop:
   1. shape pass -> data pass -> targeted reccmp -> neighbor regression check.
   2. explicit requirement to update `INSTRUCTIONS.md` similarity notes each iteration.
2. Wired docs into `AGENTS.md` as required sync targets:
   1. `docs/control_plane.md`
   2. `docs/worklog.md`
   3. `docs/toolchain.md`
   4. `docs/reccmp_fork.md`
3. Extended `INSTRUCTIONS.md` similarity notes with concrete reminders from current trade-screen tuning.

### Trade-screen implementation progress
1. Continued manual extraction in `src/game/trade_screen.cpp` (no inline asm):
   1. `InitializeTradeSellControlState` (`0x00587130`)
   2. `SetTradeOfferSecondaryBitmapState` (`0x00588030`)
   3. `UpdateTradeSellControlAndBarFromNationMetric` (`0x005882F0`)
2. Added/expanded virtual wrappers for control slots and nation metric queries.
3. Kept corresponding autogen stubs as manual overrides in `src/autogen/stubs/stubs_part018.cpp`.

### Current targeted similarity checkpoint
1. `0x00587AA0`: `77.86%`
2. `0x00587BB0`: `61.89%`
3. `0x00587DD0`: `55.15%`
4. `0x00587130`: `43.79%`
5. `0x00588030`: `43.73%`
6. `0x005882F0`: `30.17%` (up from `17.39%` earlier in this session)

### Next immediate loop target
1. Raise `0x005882F0` by tightening bar-scaling/control-update flow to original asm shape.

### Iteration update (flags + new trade functions)
1. Fixed MSVC match-flag parsing in `CMakeLists.txt`:
   1. Accepts legacy slash style (`/Oy-/Ob1`) and CSV style (`/Oy-,/Ob1`).
   2. Removed compiler warnings from malformed options (`/O/`, `/OO`).
2. Updated `trade_screen.cpp` shape pass for:
   1. `0x00588030` with line-specific USmallViews assert IDs (`0x98f`, `0x9ad`, `0x9af`, `0x9b1`).
   2. `0x005882F0` fail-and-continue/guard balance (restored best local variant).
3. Ported additional small functions from the same neighborhood (real C++ with virtual-slot calls):
   1. `0x00588610` `WrapperFor_thunk_NoOpUiLifecycleHook_At00588610`
   2. `0x00588630` `OrphanCallChain_C2_I15_00588630`
   3. `0x00588670` `OrphanCallChain_C1_I03_00588670`
4. Marked corresponding stubs as manual overrides in `src/autogen/stubs/stubs_part018.cpp`.
5. Added `docs/reccmp_fork.md` and kept AGENTS docs references aligned.

### Current targeted checkpoint after this iteration
1. `0x00587130`: `43.79%`
2. `0x00588030`: `42.07%`
3. `0x005882F0`: `33.47%`
4. `0x00588610`: `40.00%`
5. `0x00588630`: `62.86%` (best observed during tuning: `74.29%`)
6. `0x00588670`: `46.15%`

### Aggregate snapshot (`progress_stats.py`)
1. Timestamp: `2026-02-23T06:21:53Z`.
2. Paired coverage: `12229 / 12229` (`100%`).
3. Aligned functions: `43`.
4. Average similarity: `1.49%` (`+0.04 pp` vs previous snapshot).

### Bulk extraction pass in `trade_screen.cpp`
1. Added real C++ implementations (with GHIDRA comments preserved) for:
   1. `0x00588950` `ClampAndApplyTradeMoveValue`
   2. `0x00588C30` `OrphanCallChain_C1_I06_00588c30`
   3. `0x00588F60` `UpdateTradeBarFromSelectedMetricRatio_B`
   4. `0x00588FF0` `HandleTradeMoveStepCommand`
   5. `0x005899C0` `OrphanCallChain_C1_I06_005899c0`
   6. `0x00589D10` `UpdateTradeBarFromSelectedMetricRatio_A`
2. Extended local virtual-shape model for trade controls/owners:
   1. added slot wrappers for `+0x30`, `+0x1A0`, `+0x1AC`, `+0x1D0`, `+0x1D4`, `+0x1D8`.
   2. added typed local structs (`TradeMoveControlState`, `TradeMovePanelContext`).
   3. refactored the newly extracted trade handlers to class members (`TradeMovePanelContext::*`, `TradeMoveControlState::*`) to keep object shape coherent.
3. Marked matching autogen stubs as `MANUAL_OVERRIDE_ADDR` in `src/autogen/stubs/stubs_part018.cpp`.
4. Build and compare status:
   1. Docker MSVC500 build succeeded.
   2. `reccmp-project detect` succeeded.
   3. Targeted verbose checks produced fresh diffs for all six addresses.
5. Current similarities for newly extracted functions:
   1. `0x00588950`: `36.36%`
   2. `0x00588C30`: `55.56%`
   3. `0x00588F60`: `69.44%`
   4. `0x00588FF0`: `39.02%`
   5. `0x005899C0`: `55.56%`
   6. `0x00589D10`: `69.44%`
6. Current snapshot after this batch:
   1. Timestamp: `2026-02-23T09:07:55Z`.
   2. Recompiled functions: `12320` (`+6`).
   3. Paired functions: `12229` (coverage `100%`).
   4. Aligned functions: `43` (unchanged).
   5. Average similarity: `1.52%` (`+0.01 pp` in latest run after this shape pass).

### Promotion-script batch (`0x00589260`, `0x00589660`)
1. Added explicit workflow guidance to `INSTRUCTIONS.md`:
   1. Use `tools/workflow/promote_from_autogen.py` for body promotion.
   2. Convert cast/offset field access to typed struct fields immediately after promotion.
   3. Flip corresponding stubs to `MANUAL_OVERRIDE_ADDR`.
2. Promoted two new functions into `src/game/trade_screen.cpp`:
   1. `0x00589260` `InitializeTradeBarsFromSelectedCommodityControl`
   2. `0x00589660` `CreateTradeMoveScaledControlPanel`
3. Converted promoted bodies to project-style C++:
   1. Added typed `IndustryAmtBarState` layout.
   2. Replaced raw pointer arithmetic with field access in the new implementations.
4. Updated stub overrides in `src/autogen/stubs/stubs_part018.cpp`:
   1. `0x00589260`
   2. `0x00589660`
5. Resolved temporary pairing regression:
   1. Small wrappers in the same block were being inlined out of PDB mapping.
   2. Added `#pragma auto_inline(off)` / `on` guard around the tiny-wrapper block.
6. Verification:
   1. Docker MSVC500 build: success.
   2. `progress_stats.py` snapshot (`2026-02-23T09:54:52Z`):
      1. Paired coverage restored to `12229/12229` (`100%`).
      2. Average similarity: `1.60%` (`+0.03 pp` vs prior snapshot).
   3. Targeted reccmp:
      1. `0x00589260`: `37.25%`
      2. `0x00589660`: `37.50%`

### Trade-screen extraction batch (`0x00589DA0`..`0x0058A020`)
1. Promoted 6 contiguous functions from `src/ghidra_autogen/` into `src/game/trade_screen.cpp` using:
   1. `uv run python tools/workflow/promote_from_autogen.py --target-cpp src/game/trade_screen.cpp --address 0x00589DA0 --address 0x00589ED0 --address 0x00589F70 --address 0x00589F90 --address 0x00589FD0 --address 0x0058A020`
2. Replaced raw decompiler output with typed C++ implementations:
   1. `0x00589DA0` `TradeMovePanelContext::HandleTradeMovePageStepCommand`
   2. `0x00589ED0` `CreateTRailAmtBarInstance`
   3. `0x00589F70` `GetTRailAmtBarClassNamePointer`
   4. `0x00589F90` `ConstructTRailAmtBarBaseState`
   5. `0x00589FD0` `DestructTRailAmtBarAndMaybeFree`
   6. `0x0058A020` `SelectTradeSummaryMetricByTagAndUpdateBarValues`
3. Removed unnecessary cast repetition:
   1. added typed lookup helper `ResolveOwnerControl(...)`.
   2. switched multiple owner-control lookups to helper use.
   3. replaced redundant screen cast sites with existing typed wrappers.
4. Marked all 6 corresponding stubs as `MANUAL_OVERRIDE_ADDR` in `src/autogen/stubs/stubs_part018.cpp`.
5. Verification:
   1. Docker MSVC500 build: success.
   2. `reccmp-project detect`: success.
   3. `progress_stats.py` snapshot (`2026-02-23T10:09:13Z`):
      1. Recompiled functions: `12343` (`+8`).
      2. Paired coverage: `12229/12229` (`100%`).
      3. 100% aligned: `43` (unchanged).
      4. Average similarity: `1.63%` (`+0.03 pp`).
6. Current similarities for newly extracted functions:
   1. `0x00589DA0`: `0.27%`
   2. `0x00589ED0`: `0.36%`
   3. `0x00589F70`: `0.50%`
   4. `0x00589F90`: `0.74%`
   5. `0x00589FD0`: `0.67%`
   6. `0x0058A020`: `0.11%`
7. Interpretation:
   1. extraction/build pipeline is healthy for this range.
   2. similarity is now in early “raw shape” stage for the newly promoted block and needs dedicated shape passes.

## 2026-02-22

### Infrastructure and pipeline
1. Fixed rootless Docker runtime path for this host:
   1. `storage-driver=fuse-overlayfs`
   2. `features.containerd-snapshotter=false`
2. Standardized Docker invocation for this project:
   1. `docker build --network host ...`
   2. `docker run --network none ...`
3. Confirmed containerized MSVC build works end-to-end on current machine.

### Build-system and autogen changes
1. Replaced single-file stub generation with chunked stubs:
   1. `tools/stubgen.py` now writes `src/autogen/stubs/stubs_part*.cpp`.
   2. Writes `src/autogen/stubs/_manifest.json`.
2. Updated `CMakeLists.txt` to compile all `src/autogen/stubs/*.cpp`.
3. Removed legacy dependency on `src/autogen/stubs.cpp`.
4. Added temporary local placeholders in `src/game/thunks.cpp` for two unresolved callee symbols.

### Ghidra resync
1. Ran clean full sync from Ghidra 12.0.2 project:
   1. `12230` user-defined functions exported.
   2. `4935` globals exported.
   3. `455` decompiled body files.
   4. `17` type header files (`595` types).

### Similarity and scope control
1. Added `tools/reccmp/symbol_buckets.py` (shared bucket classifier).
2. Added `tools/reccmp/library_inventory.py` (bucket + similarity summary).
3. Added `tools/reccmp/generate_ignore_functions.py`:
   1. Generates candidate ignore lists from symbol buckets.
   2. Writes patch block and JSON artifacts.
   3. Can apply directly to `reccmp-project.yml`.
4. Applied ignore set to `reccmp-project.yml`:
   1. `report.ignore_functions`: `2606` names.
   2. Buckets: `crt_likely`, `mfc_likely`, `directx_audio_net_likely`.

### Baseline numbers recorded
1. Full compare:
   1. `12229` paired / `12229` original.
   2. `42` aligned.
   3. `1.13%` average similarity.
2. Focused compare (with ignores):
   1. `10311` functions compared.
   2. `42` aligned.
   3. `1.32%` average similarity.

### Next actions
1. Split “focused” and “full” metrics in reporting to avoid confusion.
2. Lock ignore-generation policy (which buckets are permanent vs temporary).
3. Start targeted implementation batches from high-impact game functions.

## 2026-02-23 21:07:41 UTC - TView/TControl ctor hierarchy pass

### Commands
1. `just promote src/game/TControl.cpp --address 0x004087FB --address 0x0048E520`
2. `just promote src/game/TView.cpp --address 0x004064E2`
3. `just build`
4. `just detect`
5. `just compare 0x004064E2`
6. `just compare 0x0048A8E0`
7. `just compare 0x004087FB`
8. `just compare 0x0048E520`

### Changes
1. Added class files:
   1. `src/game/TView.cpp`
   2. `src/game/TControl.cpp`
2. Added shared class layout header:
   1. `include/game/TControl.h`
3. Updated runtime bridges to call class members:
   1. `include/game/ui_widget_shared.h`
   2. `src/game/trade_screen.cpp`
4. Added new compile units:
   1. `src/game/TView.cpp`
   2. `src/game/TControl.cpp`
5. Marked overridden stub addresses as manual:
   1. `0x004064E2`
   2. `0x004087FB`
   3. `0x0048A8E0`
   4. `0x0048E520`

### Results
1. `0x004064E2` `TView::thunk_ConstructUiResourceEntryBase`: `100.00%`
2. `0x004087FB` `TControl::thunk_ConstructUiCommandTagResourceEntryBase`: `100.00%`
3. `0x0048A8E0` `TView::ConstructUiResourceEntryBase`: `38.60%`
4. `0x0048E520` `TControl::ConstructUiCommandTagResourceEntryBase`: `54.05%`

## 2026-02-23 - trade_screen promotion batch

### Commands
1. `just promote src/game/trade_screen.cpp --address 0x00583BD0 --address 0x0058AEF0 --address 0x0059A180`
2. `just format src/game/trade_screen.cpp src/autogen/stubs/stubs_part017.cpp src/autogen/stubs/stubs_part018.cpp`
3. `just build`
4. `just detect`
5. `just compare 0x00583BD0`
6. `just compare 0x0059A180`

### Changes
1. Promoted and normalized `0x00583BD0` as compile-safe C++ in `src/game/trade_screen.cpp`.
2. Promoted and normalized `0x0059A180` as compile-safe C++ in `src/game/trade_screen.cpp`.
3. Dropped duplicate promoted `0x0058AEF0` block from `src/game/trade_screen.cpp` because `TTraderAmtBar.cpp` already owns that function (`// FUNCTION: IMPERIALISM 0x0058AEF0`).
4. Marked stubs as manual overrides:
   1. `src/autogen/stubs/stubs_part017.cpp` (`0x00583BD0`)
   2. `src/autogen/stubs/stubs_part018.cpp` (`0x0059A180`)

### Results
1. Build passes.
2. `reccmp --verbose` currently reports “Failed to find a match” for `0x00583BD0` and `0x0059A180` (likely unreferenced function elimination path to investigate).

## 2026-02-23 21:34:00 UTC - trade_screen class split scaffolding

### Commands
1. `just build`
2. `just detect`
3. `just compare 0x00587130`
4. `just compare 0x00588950`
5. `just compare 0x005899F0`

### Changes
1. Split class-owned trade screen implementations into class files included by `src/game/trade_screen.cpp`:
   1. `src/game/TradeScreenContext.cpp`
   2. `src/game/TradeMoveControlState.cpp`
   3. `src/game/TradeMovePanelContext.cpp`
2. Kept struct declarations in `src/game/trade_screen.cpp` as codegen source-of-truth for now to avoid mangling/codegen churn.
