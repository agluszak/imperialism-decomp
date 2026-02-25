# Imperialism Decomp Control Plane

Last updated: 2026-02-25

## Purpose
This file is the single source of truth for:
1. Current matching strategy.
2. Current baseline metrics.
3. Exact commands that define the pipeline.
4. Active scope filters (what we are intentionally ignoring).

## Current Strategy
1. Keep Ghidra as source of truth for symbols/types/comments.
2. Export full snapshots to repo (`symbols`, decomp bodies, type headers).
3. Build with old MSVC toolchain in Docker/Wine.
4. Track two metric views:
   1. Full compare (all functions).
   2. Focused compare (runtime/library-heavy symbols ignored in `report.ignore_functions`).

## Current Baseline
From latest fresh import + rebuild + reccmp run:

1. Inventory:
   1. Functions in `config/symbols.csv`: `12230`.
   2. Globals in `config/symbols.csv`: `4935`.
   3. Decompiled bodies: `12230` functions in `455` files.
   4. Exported type headers: `17` headers, `595` types.
2. Build:
   1. Recompiled functions discovered: `12288`.
   2. Paired with original: `12229` (100% coverage).
3. Similarity:
   1. Full compare avg similarity: `1.13%`.
   2. Focused compare avg similarity (with ignores): `1.32%`.
   3. 100% aligned functions: `42`.

Latest `progress_stats` snapshot (`2026-02-24T15:08:48Z`):
1. Paired functions: `12228` (coverage `100%`).
2. Recompiled functions discovered: `12511`.
3. 100% aligned functions: `60`.
4. Average similarity (current compare set): `2.56%`.
5. Paired globals (`dat/lab/str/flo/wid`): `272 / 5065` (coverage `5.37%`).
6. Non-function coverage including imports: `5.77%`.

Latest `progress_stats` snapshot (`2026-02-24T20:41:48Z`):
1. Paired functions: `12228` (coverage `100%`).
2. Recompiled functions discovered: `12514`.
3. 100% aligned functions: `60`.
4. Average similarity (current compare set): `2.56%`.
5. Paired globals (`dat/lab/str/flo/wid`): `272 / 5065` (coverage `5.37%`).
6. Non-function coverage including imports: `5.78%`.

Latest `progress_stats` snapshot (`2026-02-24T20:58:45Z`):
1. Paired functions: `12228` (coverage `100%`).
2. Recompiled functions discovered: `12520`.
3. 100% aligned functions: `60`.
4. Average similarity (current compare set): `2.57%`.
5. Paired globals (`dat/lab/str/flo/wid`): `272 / 5065` (coverage `5.37%`).
6. Non-function coverage including imports: `5.78%`.

Latest `progress_stats` snapshot (`2026-02-25T00:14:43Z`):
1. Paired functions: `12228` (coverage `100%`).
2. Recompiled functions discovered: `12520`.
3. 100% aligned functions: `60`.
4. Average similarity (current compare set): `2.58%`.
5. Paired globals (`dat/lab/str/flo/wid`): `272 / 5067` (coverage `5.37%`).
6. Non-function coverage including imports: `5.78%`.

Latest incremental checkpoint (`2026-02-24 21:25 UTC`):
1. `0x0058F3C0` `UpdateCivilianOrderTargetTileCountsForOwnerNation`: `24.88% -> 30.77%`.
2. Retained shape change:
   1. inner 5-slot loop switched to decrement-counter form (`remainingSlots`), which matched original `dec/jne` loop shape better.
3. Reverted probes in same pass:
   1. `/Oy`-style build probe (`/Oy,/Ob1`) regressed this function.
   2. local-pressure rewrite removing `mapState`/`tableBase` regressed this function.

Latest incremental checkpoint (`2026-02-24 21:45 UTC`):
1. `0x0058F3C0` `UpdateCivilianOrderTargetTileCountsForOwnerNation`: improved to `97.98%`.
2. High-impact retained changes:
   1. function-local `#pragma optimize("y", on)` around this function.
   2. province gate shape `if (provinceCount < provinceOrdinal) return;` with `provinceOrdinal = 1`.
   3. cast/sign-extension alignment for tile index/profile (`(short)` -> `(int)(short)` chain, signed-byte profile to `short`).
3. Notes:
   1. a C-linkage symbol probe for table globals regressed this function (`97.98% -> 96.97%`) and was reverted.

Latest incremental checkpoint (`2026-02-25 00:09 UTC`):
1. `0x0058F550` `RefreshCivilianTargetLegendBySelectedClass`: `16.11% -> 18.34%`.
   1. retained forwarded payload shape into slots `+0x1A0/+0x1A4/+0x1A8`,
   2. retained early shared-string init and pointer-driven legend reset loop.
2. `0x0058F1A0` `DestructTCivDescriptionAndMaybeFree`: `17.14% -> 18.50%`.
   1. retained virtual `GetCount/GetByOrdinal` province collection calls,
   2. retained pointer-driven outer legend-counter walk.
3. Stability checks:
   1. `0x0058F3C0`: still `97.98%`.
   2. `0x0058F110`: still `69.39%`.
   3. direct-access rewrite probe on `0x0058F110` regressed to `53.06%` and was reverted.
4. Remaining low-score owned functions in this cluster:
   1. `0x0058F7B0`: `0.00%`.
   2. `0x0058FEC0`: `0.00%`.

Latest incremental checkpoint (`2026-02-25 00:14 UTC`):
1. `0x0058F7B0` `RenderCivilianTargetLegendVariantA`: `0.00% -> 25.25%`.
2. `0x0058FEC0` `RenderCivilianTargetLegendVariantB`: `0.00% -> 16.81%`.
3. Stability checks:
   1. `0x0058F3C0`: still `97.98%`.
   2. `0x0058F550`: still `18.34%`.
4. Current owned legend-cluster stack:
   1. `0x0058F3C0`: `97.98%`
   2. `0x0058F110`: `69.39%`
   3. `0x0058F7B0`: `25.25%`
   4. `0x0058F550`: `18.34%`
   5. `0x0058F1A0`: `18.50%`
   6. `0x0058FEC0`: `16.81%`

Latest incremental checkpoint (`2026-02-25 01:53 UTC`):
1. `0x0058F1A0` `DestructTCivDescriptionAndMaybeFree`: `20.87% -> 22.22%`.
   1. retained virtual province collection call shape and pointer-based legend-counter walk.
   2. removed outer-loop `candidateOrdinal++` on slot-advance path.
2. `0x0058F3C0`: retained `97.98%`.
   1. restored `CivilianClassCacheContext` typed target-count slots and `#pragma optimize("y", on)` around this function.
3. `0x0058F550`: currently `16.11%` in this branch state.

Latest incremental checkpoint (`2026-02-24 20:56 UTC`):
1. Promoted and owned `TCivDescription` legend block addresses:
   1. `0x0058F550` `RefreshCivilianTargetLegendBySelectedClass` (`0.00%`, first-pass thunk bridge).
   2. `0x0058F7B0` `RenderCivilianTargetLegendVariantA` (`0.00%`, first-pass thunk bridge).
   3. `0x0058FEC0` `RenderCivilianTargetLegendVariantB` (`0.00%`, first-pass thunk bridge).
2. Kept compile stability by converting raw class-scoped promoted bodies to compile-safe wrapper form and flipping stub markers to `MANUAL_OVERRIDE_ADDR`.

Latest incremental checkpoint (`2026-02-24 20:58 UTC`):
1. Promoted and owned `0x00590CB0` `BuildCivReportNationEntryDetailTextBlock` in `src/game/TCivReport.cpp`.
2. First-pass compile-safe bridge result: `16.67%` (`just compare 0x00590cb0`).
3. Stub marker at `src/autogen/stubs/stubs_part018.cpp` flipped to `MANUAL_OVERRIDE_ADDR`.

Latest incremental checkpoint (`2026-02-24 21:07 UTC`):
1. `0x0058F550` `RefreshCivilianTargetLegendBySelectedClass`: `0.00% -> 16.11%` after replacing thunk-forward body with real legend reset + class dispatch + localized text draw path.
2. Adjacent `TCivDescription` checks stayed stable in the same pass:
   1. `0x0058F1A0`: `17.14%`
   2. `0x0058F3C0`: `24.88%`
3. Reverted one regressing variant on `0x58F550` (`16.11% -> 15.53%`) and kept the higher-scoring shape.

Latest incremental checkpoint (`2026-02-24 20:38 UTC`):
1. `0x0058F3C0` `UpdateCivilianOrderTargetTileCountsForOwnerNation`: `24.88%` after direct fixed-address global/vtable-slot shape pass in `src/game/TCivDescription.cpp`.
2. `0x0058F1A0` `DestructTCivDescriptionAndMaybeFree`: `17.14%` first-pass ownership in `src/game/TCivDescription.cpp`.
3. `0x0058F110` `UpdateCivilianOrderClassAndRefreshTargetCounts`: retained `69.39%` (short-width class-id shape restored).

Latest incremental checkpoint (`2026-02-24 15:08 UTC`):
1. `0x0058E1C0` `HandleMapContextActionArmyRatioAndModeCommands`: `24.60%` first-pass ownership in `src/game/TArmyToolbar.cpp`.
2. `0x0058EED0` `HandleCivilianMapCommandPanelAction`: `44.98%` first-pass ownership in `src/game/TCivToolbar.cpp`.
3. `0x0058F050` `CreateTCivDescriptionInstance`: `42.86%` first-pass ownership in new `src/game/TCivDescription.cpp`.
4. `0x0058F0F0` `GetTCivDescriptionClassNamePointer`: `50.00%` first-pass ownership in new `src/game/TCivDescription.cpp`.
5. `0x0058F110` `UpdateCivilianOrderClassAndRefreshTargetCounts`: `69.39%` after short-width class-id shape pass in `src/game/TCivDescription.cpp`.
6. `0x0058E440` `OrphanTiny_SetDwordEcxOffset_60_0058e440`: `33.33%` first-pass ownership in `src/game/ui_widget_wrappers.cpp` (prologue-shape tuning deferred).

Latest incremental checkpoint (`2026-02-24 14:09 UTC`):
1. `0x00587130` `InitializeTradeSellControlState`: `41.52%` after restoring explicit stack-seed forwarding (`ret 4` shape).
2. `0x0058BC60` `PlacardState::RenderPlacardValueTextWithShadow`: `55.62%` after replacing placeholder body with full shared-string + themed two-pass text draw flow.
3. `0x00588B70` `SyncTradeCommoditySelectionWithActiveNationAndInitControls`: `42.50%` current retained shape.

Latest incremental checkpoint (`2026-02-24 14:35 UTC`):
1. `0x005873E0` `HandleTradeSellControlCommand`: restored to `23.68%` baseline shape after reverting a regressing gate/default experiment.
2. `0x00587DD0` `SetTradeOfferControlBitmapState`: improved to `52.21%` by caching resolver slot `+0x94` and preserving call-order/layout capture shape.
3. `0x00588030` `SetTradeOfferSecondaryBitmapState`: improved to `42.31%` with `{0xA3,0}` layout capture and enabled/state ordering, while keeping direct `ResolveControlByTag` lookups.

## Active Ignore Scope
Generated by `python -m tools.reccmp.generate_ignore_functions` and applied to `reccmp-project.yml`:

1. `report.ignore_functions`: `2606` function names.
2. Source buckets used:
   1. `crt_likely`
   2. `mfc_likely`
   3. `directx_audio_net_likely`

Notes:
1. `report.ignore_functions` is name-based.
2. `ghidra.ignore_functions` is address-based and is currently not auto-applied in project config.

## Canonical Commands
### 1) Full Ghidra sync
```bash
just sync-ghidra
```

### 2) Sync function ownership map
```bash
just sync-ownership
```

### 3) Regenerate stubs
```bash
just regen-stubs
```

### 4) Annotate globals from symbols
```bash
just annotate-globals
```

### 5) Annotate vtables from symbols
```bash
just annotate-vtables
```

### 6) Normalize marker formatting
```bash
just normalize-markers
```

### 7) Rebuild (Docker rootless-safe mode)
```bash
just build
```

### 8) Detect + compare
```bash
just detect
just compare
```

### 9) Progress summary
```bash
just stats
```
This summary tracks both function metrics and non-function roadmap coverage (globals/data/labels/strings/floats/wide strings/imports).

### 10) Inventory and ignore generation
```bash
uv run python -m tools.reccmp.library_inventory --json-out build-msvc500/library_inventory.json
uv run python -m tools.reccmp.generate_ignore_functions --target IMPERIALISM --apply
```

### 10) Session queue generation
```bash
uv run python -m tools.reccmp.session_loop --target IMPERIALISM --pick 8 --top 50 --min-size 1
```

### 11) Range-based promotion
```bash
just promote-range src/game/trade_screen.cpp 0x00585f70 0x00586150
```

## Known Pitfalls
1. Ghidra decompiler output is generated on-demand; full sync re-decompiles functions.
2. Single huge `stubs.cpp` breaks old MSVC linker/debug limits; use chunked stubs in `src/autogen/stubs/`.
3. Rootless Docker networking may fail with bridge mode; use `--network none` for `docker run`.
4. Two unresolved thunk callees are currently handled by local placeholders in `src/game/thunks.cpp`.
5. Match-flag plumbing accepts both old slash format (`/Oy-/Ob1`) and CSV format (`/Oy-,/Ob1`); use CSV in commands for clarity.
6. Keep reccmp marker syntax exact (`// TYPE: MODULE 0x...` lowercase hex) and keep pseudo markers non-reccmp (`// MANUAL_OVERRIDE_ADDR ...`, `// PROMOTED_FUNCTION ...`) to avoid parser noise.
7. Run `just compare` and `just stats` sequentially; parallel runs can trigger Wine `winedbg`/`cvdump` contention and produce false temporary regressions.

## Current Priorities
1. Keep focused ignore list stable and review weekly.
2. Move from wrapper/thunk/no-op wins into medium-sized game functions.
3. Improve type/prototype fidelity in hotspots before deep body work.
4. Continue `TCivDescription` shape/data passes around `0x0058F7B0` and `0x0058FEC0` (now de-thunked), then return to `0x0058F550`/`0x0058F1A0` for control-flow and call-shape tuning.

## Latest Non-Trade Checkpoint
1. `0x0055FC40` `InputState::HandleKeyDown`: `25.69%` (from `20.42%` after direct-thunk-call shape pass in `src/game/input_state.cpp`).

## Active Class Focus: `trade_screen.cpp`

Current loop policy for this class:
1. `shape pass` first (branch/call order/assert paths).
2. `data pass` second (type widths, clamp order, float/int math).
3. Rebuild + targeted `reccmp --verbose` per touched address.
4. No regressions allowed on adjacent trade-screen functions.
5. Promotion can be mixed by contiguous trade-screen address clusters (not only class-by-class); normalize promoted raw class output immediately after import.

File layout note:
1. `src/game/trade_screen.cpp` contains shared scaffolding/helpers and global/non-class trade-screen functions.
2. Class-owned wrappers now live in class files (`src/game/<ClassName>.cpp`), including:
   1. `TCivilianButton`, `THQButton`, `TPlacard`, `TArmyPlacard`, `TNumberedArrowButton`, `TCombatReportView`
   2. `TArmyToolbar`, `TStratReportView`, `TCivToolbar`, `TCivDescription`, `TArmyInfoView`
   3. `TCivReport`, `TTransportPicture`
3. `src/game/ui_widget_wrappers.cpp` is reserved for global/non-class wrappers.
4. Trade-screen class methods are in flat class files under `src/game/` and included by `src/game/trade_screen.cpp`:
   1. `TAmtBar.cpp`
   2. `TIndustryCluster.cpp`
   3. `TIndustryAmtBar.cpp`
   4. `TRailCluster.cpp`
   5. `TRailAmtBar.cpp`
   6. `TShipyardCluster.cpp`
   7. `TShipAmtBar.cpp`
   8. `TTraderAmtBar.cpp`
5. New extractions should be promoted into class files when symbol ownership is class-scoped.

### Trade Screen Checkpoint (latest)

Targeted similarities from current `build-msvc500`:
1. `0x00587AA0` `SetTradeBidSecondaryBitmapState`: `77.86%`
2. `0x00587BB0` `SetTradeBidControlBitmapState`: `61.89%`
3. `0x00587DD0` `SetTradeOfferControlBitmapState`: `52.21%`
4. `0x00587130` `InitializeTradeSellControlState`: `41.52%`
5. `0x00588030` `SetTradeOfferSecondaryBitmapState`: `42.31%`
6. `0x005882F0` `UpdateTradeSellControlAndBarFromNationMetric`: `22.41%`
7. `0x00588630` `OrphanCallChain_C2_I15_00588630`: `62.86%`
8. `0x00588670` `OrphanCallChain_C1_I03_00588670`: `46.15%`
9. `0x00588610` `WrapperFor_thunk_NoOpUiLifecycleHook_At00588610`: `40.00%`
10. `0x00588950` `ClampAndApplyTradeMoveValue`: `33.03%`
11. `0x00588C30` `OrphanCallChain_C1_I06_00588c30`: `55.56%`
12. `0x00588F60` `UpdateTradeBarFromSelectedMetricRatio_B`: `53.73%`
13. `0x00588FF0` `HandleTradeMoveStepCommand`: `28.57%`
14. `0x005899C0` `OrphanCallChain_C1_I06_005899c0`: `55.56%`
15. `0x00589D10` `UpdateTradeBarFromSelectedMetricRatio_A`: `53.73%`
16. `0x00589260` `InitializeTradeBarsFromSelectedCommodityControl`: `37.25%`
17. `0x00589660` `CreateTradeMoveScaledControlPanel`: `37.50%`
18. `0x00588C60` `UpdateTradeMoveControlsFromDrag`: `25.53%`
19. `0x005899F0` `UpdateTradeMoveControlsFromScaledDrag`: `31.62%`
20. `0x00586C40` `CreateTradeMoveControlPanelBasic`: `34.78%`
21. `0x00586CC0` `GetTAmtBarClusterClassNamePointer`: `50.00%`
22. `0x00586CE0` `ConstructTradeMoveControlPanelBasic`: `71.43%`
23. `0x00586D10` `DestructTAmtBarClusterMaybeFree`: `66.67%`
24. `0x00586D60` `InitializeTradeMoveAndBarControls`: `53.12%`
25. `0x00586E70` `HandleTradeMoveControlAdjustment`: `26.23%`
26. `0x005873E0` `HandleTradeSellControlCommand`: `23.68%`
27. `0x00586A60` `OrphanTiny_SetWordEcxOffset_8c_00586a60`: `40.00%`
28. `0x00586A80` `OrphanLeaf_NoCall_Ins05_00586a80`: `40.00%`
29. `0x00586AB0` `OrphanTiny_SetWordEcxOffset_8e_00586ab0`: `40.00%`
30. `0x00586E50` `OrphanLeaf_NoCall_Ins02_00586e50`: `0.00%`
31. `0x00586FF0` `OrphanRetStub_00586ff0`: `0.00%`
32. `0x00586660` `DestructTCityBarClusterAndMaybeFree`: `66.67%`
33. `0x00586840` `CreateTProductionClusterInstance`: `42.86%`
34. `0x00586900` `GetTProductionClusterClassNamePointer`: `50.00%`
35. `0x00586920` `ConstructTProductionClusterBaseState`: `84.62%`
36. `0x00586970` `DestructTProductionClusterAndMaybeFree`: `66.67%`
37. `0x005869C0` `HandleProductionClusterValuePanelSplitArrowCommand64or65AndForward`: `35.56%`
38. `0x00586AD0` `CreateTClosePictureInstance`: `34.78%`
39. `0x00586B50` `GetTClosePictureClassNamePointer`: `50.00%`
40. `0x00586B70` `ConstructTClosePictureBaseState`: `85.71%`
41. `0x00586BA0` `DestructTClosePictureAndMaybeFree`: `66.67%`
42. `0x00586BF0` `WrapperFor_DispatchUiMouseEventToChildrenOrSelf_At00586bf0`: `65.31%`
43. `0x00588690` `RenderPrimarySurfaceOverlayPanelWithClipCache`: `20.69%`
44. `0x00589340` `RenderQuickDrawControlWithHitRegionClip_A`: `18.87%`
45. `0x00589540` `RenderQuickDrawOverlayWithHitRegion_00589540`: `17.24%`
46. `0x00589DA0` `TradeMoveStepCluster::HandleTradeMovePageStepCommand`: `25.37%`
47. `0x0058A610` `TradeMoveStepCluster::SelectTradeSpecialCommodityAndInitializeControls`: `48.89%`
48. `0x0058A940` `TradeMoveStepCluster::HandleTradeMoveArrowControlEvent`: `29.87%`
49. `0x0058A690` `TradeMoveStepCluster::RefreshTradeMoveBarAndTurnControl`: `15.45%`
50. `0x0058AF80` `TradeAmountBarLayout::UpdateNationStateGaugeValuesFromScenarioRecordCode`: `20.14%`
51. `0x0058B070` `WrapperFor_GetActiveNationId_At0058b070`: `49.18%`
52. `0x0058BC60` `PlacardState::RenderPlacardValueTextWithShadow`: `55.62%`
53. `0x0058BAB0` `PlacardState::WrapperFor_thunk_NoOpUiLifecycleHook_At0058bab0`: `43.48%`
54. `0x0058BB50` `PlacardState::WrapperFor_thunk_InvalidateCityDialogRectRegion_At0058bb50`: `44.04%`
55. `0x005866B0` `UpdateTradeSummaryMetricControlsFromRecord`: `34.91%`
56. `0x00588B70` `SyncTradeCommoditySelectionWithActiveNationAndInitControls`: `42.50%`
57. `0x005897B0` `SelectTradeCommodityPresetBySummaryTagAndInitControls`: `34.39%`

Immediate objective:
1. Trade-screen batch mapping for `0x586000-0x58A000` is now fully owned (`stubs_part018.cpp` has zero remaining `FUNCTION` entries in that window).
2. Run targeted shape pass on lowest trade-screen cluster scores first: `0x005873E0`, `0x00586E70`, `0x00588690`, `0x00589340`, `0x00589540`.
3. Fix tiny-signature calling-convention mismatches (`0x00586E50`, `0x00586FF0`) after current batch-stabilization.
4. Remaining unmapped (`FUNCTION`) in `0x586000-0x58C000`: `10` addresses.

Latest focused shape-pass checkpoints:
1. `0x00589DA0`: `25.37%`
2. `0x0058A610`: `54.55%`
3. `0x0058A940`: `41.03%`
4. `0x00588FF0`: `28.57%`
5. `0x005866B0`: `34.91%`
6. `0x00586E70`: `26.23%`

Latest wrapper batch checkpoints:
1. `0x00585F70` `CreateTUnitToolbarClusterInstance`: `34.78%`
2. `0x00585FF0` `GetTUnitToolbarClusterClassNamePointer`: `50.00%`
3. `0x00586010` `ConstructTUnitToolbarClusterBaseState`: `71.43%`
4. `0x00586040` `DestructTUnitToolbarClusterAndMaybeFree`: `66.67%`
5. `0x00586090` `WrapperFor_thunk_DispatchPanelControlEvent_At00586090`: `35.96%`
6. `0x00586150` `OrphanVtableAssignStub_00586150`: `100.00%`
7. `0x0058DE40` `CreateTArmyToolbarInstance`: `34.78%`
8. `0x0058DEC0` `GetTArmyToolbarClassNamePointer`: `50.00%`
9. `0x0058DEE0` `ConstructTArmyToolbarBaseState`: `71.43%`
10. `0x0058DF10` `DestructTArmyToolbarAndMaybeFree`: `66.67%`
11. `0x0058E330` `CreateTStratReportViewInstance`: `34.78%`
12. `0x0058E3A0` `GetTStratReportViewClassNamePointer`: `50.00%`
13. `0x0058E3C0` `ConstructTStratReportViewBaseState`: `85.71%`
14. `0x0058E3F0` `DestructTStratReportViewAndMaybeFree`: `66.67%`
15. `0x0058EA00` `CreateTCivToolbarInstance`: `34.78%`
16. `0x0058EA80` `GetTCivToolbarClassNamePointer`: `50.00%`
17. `0x0058EAA0` `ConstructTCivToolbarBaseState`: `85.71%`
18. `0x0058EAD0` `DestructTCivToolbarAndMaybeFree`: `66.67%`
19. `0x00591500` `CreateTArmyInfoViewInstance`: `34.78%`
20. `0x00591580` `GetTArmyInfoViewClassNamePointer`: `50.00%`
21. `0x005915A0` `ConstructTArmyInfoViewBaseState`: `85.71%`
22. `0x005915D0` `DestructTArmyInfoViewAndMaybeFree`: `66.67%`

## 2026-02-24 09:59 UTC checkpoint - trade-screen wrapper deepening

Focused addresses in `0x58A1B0-0x58BFE0` after latest shape/data pass:
1. `0x0058A1B0` `RenderQuickDrawControlWithHitRegionClip_B`: `30.06%` (from `0.00%`)
2. `0x0058A3B0` `RenderQuickDrawOverlayWithHitRegion_0058a3b0`: `23.76%` (from `16.67%`)
3. `0x0058AC80` `RenderQuickDrawControlWithHitRegionClip_C`: `27.03%` (from `0.00%`)
4. `0x0058B0F0` `RenderControlWithTemporaryRectClipRegionAndChildren`: `16.44%` (from `0.00%`)
5. `0x0058B460` `OrphanCallChain_C4_I34_0058b460`: `64.37%` (from `59.38%`)
6. `0x0058B4F0` `BlitHintOverlayRectWithCtrlModifierPalette`: `20.93%` (from `0.00%`)
7. `0x0058B750` `OrphanCallChain_C3_I43_0058b750`: `33.33%` (from `15.69%`)
8. `0x0058B890` `OrphanCallChain_C2_I16_0058b890`: `50.00%` (unchanged)
9. `0x0058B8D0` `OrphanCallChain_C2_I37_0058b8d0`: `47.22%` (from `24.49%`)
10. `0x0058BFE0` `RenderRightAlignedNumericOverlayWithShadow`: `19.61%` (from `0.00%`)

Global metric delta:
1. average similarity: `2.46%` (was `2.42%` at this checkpoint window start)
2. aligned functions: `49` (unchanged)
3. paired coverage: `100.00%` (unchanged)

Tiny-orphan call-shape update (`2026-02-24 10:03 UTC`):
1. `0x00586E50` lifted to `20.00%` by matching `ret 8` stack-pop signature shape (`__stdcall` + explicit unused arg).
2. `0x00586FF0` remains `0.00%` (original appears as zero-byte/no-body mapping; current emitted `ret` still mismatches).

Quickdraw base-pair update (`2026-02-24 10:06 UTC`):
1. `0x00589340` `RenderQuickDrawControlWithHitRegionClip_A`: `30.06%` (was `18.87%`).
2. `0x00589540` `RenderQuickDrawOverlayWithHitRegion_00589540`: `22.45%` (was `17.24%`).

## 2026-02-24 11:45 UTC checkpoint - trade command/preset shape pass

1. `0x005873E0` `HandleTradeSellControlCommand`: `15.50%` (from `11.94%` in this track).
2. `0x005897B0` `SelectTradeCommodityPresetBySummaryTagAndInitControls`: `19.13%` (from `16.95%` session baseline).

Applied shape changes:
1. Added missing `0x67/0x68` propagation branches with 17-tag row fan-out loop (`0sr..6sr`, `0am..5am`, `0dg..3dg`) in `0x005873E0`.
2. Preserved `0x005873E0` as free fastcall wrapper after testing; member-method conversion regressed this function in current type/layout state, then restored `ret 0xc` stack-pop shape with an explicit unused stack argument.
3. For `0x005897B0`, aligned call-shape toward original by:
   1. explicit stack-arg signature (`ret 4` behavior),
   2. casted thunk bridge call to `thunk_InitializeTradeMoveAndBarControls`,
   3. post-init slot `+0x1D4` dispatch on `this` instead of owner fallback.

Global metrics remained stable:
1. aligned functions: `60`
2. average similarity: `2.50%`
3. paired coverage: `100.00%`.

## 2026-02-24 11:55 UTC checkpoint - trade summary/move-adjust shape pass

1. `0x005866B0` `UpdateTradeSummaryMetricControlsFromRecord`: `34.91%` (from `8.62%` in this track).
2. `0x00586E70` `HandleTradeMoveControlAdjustment`: `26.23%` (from `17.39%`).
3. `0x005873E0` `HandleTradeSellControlCommand`: `15.50%` (unchanged guard check).
4. `0x005882F0` `UpdateTradeSellControlAndBarFromNationMetric`: `22.41%` (attempted rewrite regressed to `17.57%`, reverted).

Applied shape changes:
1. `0x005866B0`:
   1. switched to `thiscall` wrapper shape (`__fastcall(this, unusedEdx, stackArg)`),
   2. replaced loop/arrays with explicit per-tag sequence (`aert`, `rtnu`, `iart`, `forp`),
   3. matched `USmallViews` assert line ids on nil paths (`0x67d`, `0x682`, `0x687`),
   4. aligned first setter arg to dword path (`[record+0xac]+0x10`) and remaining to short offsets (`+4/+6/+8`).
2. `0x00586E70`:
   1. moved to normalized command branch shape (`commandId - 100` => `0/1`),
   2. preserved fail-and-continue behavior after nil asserts (no extra early returns).

Global snapshot (`2026-02-24T11:55:01Z`):
1. aligned functions: `60`
2. average similarity: `2.51%`
3. paired coverage: `100.00%`
4. failed-to-match lines: `0`.

## 2026-02-24 12:13 UTC checkpoint - trade sell-command layout pass

1. `0x005873E0` `HandleTradeSellControlCommand`: `23.68%` (from `15.50%` in prior checkpoint).
2. `0x005897B0` `SelectTradeCommodityPresetBySummaryTagAndInitControls`: `27.87%` (unchanged this pass).
3. `0x0055FC40` `InputState::HandleKeyDown`: `25.69%` (probe changes reverted; no net delta).

Applied shape changes:
1. Converted `0x005873E0` to a real member implementation (`__thiscall` shape, `ret 0xc`), with command switch layout and explicit cases `100/0x65/0x67/0x68/0x69/0x6A`.
2. Restored case-`100` gating/flow pieces (`slot +0x1dc` check, `Sell` + `mCap` lookups, `0x816`/`0x81d` assert paths) and preserved fan-out loops for `0x67/0x68`.
3. Split `0x005873E0` onto a dedicated TAmtBarCluster-shaped context (`field +0x88` metric slot) instead of `TradeMovePanelContext`; this removed offset drift in emitted code but did not move similarity beyond `23.68%`.
4. Validated build stability after the `InputState` call-shape probe and restored baseline when no improvement held.

Current constraint to resolve next:
1. `0x005873E0` still diverges on prologue/register allocation and nil-path assert sequence (`0x82f/0x85a/0x874/0x896` pathing), even after layout split.

Global snapshot (`2026-02-24T12:13:54Z`):
1. aligned functions: `60`
2. average similarity: `2.52%`
3. paired coverage: `100.00%`
4. failed-to-match lines: `0`.
