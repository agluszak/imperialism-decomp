# Worklog

## 2026-02-24

### TCivDescription deep shape pass (`0x0058F3C0`) - 97.98%
1. Continued iterative tuning of `src/game/TCivDescription.cpp` `0x0058F3C0` (`UpdateCivilianOrderTargetTileCountsForOwnerNation`).
2. Retained high-impact changes:
   1. enabled function-local frame-pointer omission around this function:
      1. `#pragma optimize("y", on)` before function.
      2. `#pragma optimize("", on)` after function.
   2. switched province-count gate to `provinceCount < provinceOrdinal` with `provinceOrdinal = 1`.
   3. kept direct global-map reload points in the same spots as original.
   4. aligned sign-extension shape:
      1. `provinceTileIndex` as cast chain `(short)` -> `(int)(short)`.
      2. `tileProfileId` stored as `short` loaded from signed byte.
3. Probes tested and reverted:
   1. C-linkage global-symbol variant for table operands (`extern "C"` forms) regressed (`97.98% -> 96.97%`), so reverted.
4. Verification sequence:
   1. `just build`
   2. `just detect`
   3. `just compare 0x0058f3c0`
5. Targeted deltas during this pass:
   1. `30.77% -> 41.58%` after `#pragma optimize("y", on)`.
   2. `41.58% -> 90.36%` after gate/control-flow + data-reload shape alignment.
   3. `90.36% -> 92.86%` after sign-extension alignment for profile/tile index.
   4. `92.86% -> 97.98%` after final cast-chain refinement.

### TCivDescription focused pass (`0x0058F3C0`) - loop-shape improvement
1. Targeted function:
   1. `src/game/TCivDescription.cpp`
   2. `0x0058F3C0` `UpdateCivilianOrderTargetTileCountsForOwnerNation`
2. Shape/data work retained:
   1. kept free-wrapper ownership (`__fastcall` + `// ORIG_CALLCONV: __thiscall`) with direct fixed-address globals and direct province-collection slot calls.
   2. changed inner 5-slot match loop to decrement-counter form (`remainingSlots = 5; ...; remainingSlots--; while (remainingSlots != 0)`).
3. Probes tested and reverted:
   1. function-level/global `/Oy` probe (`/Oy,/Ob1`) regressed this function.
   2. local-pressure rewrite removing `mapState` / `tableBase` also regressed.
4. Verification sequence:
   1. `just build`
   2. `just detect`
   3. `just compare 0x0058f3c0`
5. Targeted delta:
   1. `0x0058F3C0`: `24.88% -> 30.77%` (retained best in this pass).

### TCivDescription loop pass (`0x0058F3C0`, `0x0058F1A0`)
1. Reworked `src/game/TCivDescription.cpp` `0x0058F3C0` (`UpdateCivilianOrderTargetTileCountsForOwnerNation`) to follow exported Ghidra shape more literally:
   1. removed helper indirection and null-guard wrappers.
   2. switched to direct fixed-address globals (`0x6A43D4`, `0x6A4310`, `0x698F58`) and direct province-collection vtable slot calls (`+0x24`, `+0x28`).
2. Kept `0x0058F110` on the short-width class-id shape (restored after a temporary 32-bit regression probe):
   1. `cachedCivilianClassId` and input class-id stay `short`.
3. Promoted `0x0058F1A0` with `just promote` and normalized to compile-safe manual wrapper in `src/game/TCivDescription.cpp`:
   1. replaced raw class-scoped Ghidra output with typed free-wrapper form (`// ORIG_CALLCONV: __thiscall`).
   2. preserved click-hit-test + province/tile scan flow in first-pass form.
   3. declared `PtInRect` with Win32-compatible shape (`RECT*`, `POINT` by value) to avoid ABI drift.
4. Updated stub ownership:
   1. `src/autogen/stubs/stubs_part018.cpp`: `0x0058F1A0` -> `MANUAL_OVERRIDE_ADDR`.
5. Verification sequence:
   1. `just promote src/game/TCivDescription.cpp --address 0x0058f1a0`
   2. `just format src/game/TCivDescription.cpp src/autogen/stubs/stubs_part018.cpp`
   3. `just build`
   4. `just detect`
   5. `just compare 0x0058f110`
   6. `just compare 0x0058f1a0`
   7. `just compare 0x0058f3c0`
   8. `just stats`
6. Targeted similarities:
   1. `0x0058F110`: `69.39%` (unchanged, regression probe reverted).
   2. `0x0058F3C0`: `16.67% -> 24.88%`.
   3. `0x0058F1A0`: `17.14%` first-pass ownership.
7. Global snapshot (`2026-02-24T20:41:48Z`):
   1. paired functions: `12228/12228`
   2. aligned functions: `60`
   3. recompiled functions: `12514`
   4. average similarity: `2.56%`
   5. non-function coverage (with imports): `5.78%`
8. `0x0058F1A0` loop-shape probe:
   1. tested pointer-driven legend-slot loop (`currentSelectionCount`/end-pointer form).
   2. regression observed: `17.14% -> 4.92%`.
   3. reverted to slot-index loop; `0x0058F1A0` restored to `17.14%`.

### New function batch promotion (`0x0058E1C0`, `0x0058EED0`, `0x0058F050`, `0x0058F0F0`, `0x0058F110`, `0x0058E440`)
1. Promoted new functions with `just promote`:
   1. `just promote src/game/TArmyToolbar.cpp --address 0x0058E1C0`
   2. `just promote src/game/TCivToolbar.cpp --address 0x0058EED0`
   3. `just promote src/game/TCivDescription.cpp --address 0x0058F050 --address 0x0058F0F0`
   4. `just promote src/game/TCivDescription.cpp --address 0x0058F110`
   5. `just promote src/game/ui_widget_wrappers.cpp --address 0x0058E440`
2. Normalized promoted code into compile-safe manual wrappers:
   1. rewrote promoted class-scoped raws into typed free-wrapper forms in:
      1. `src/game/TArmyToolbar.cpp`
      2. `src/game/TCivToolbar.cpp`
      3. `src/game/TCivDescription.cpp` (new file)
   2. added `src/game/TCivDescription.cpp` to build in `CMakeLists.txt`.
3. Synced stub ownership to avoid duplicate function mapping:
   1. changed addresses to `MANUAL_OVERRIDE_ADDR` in `src/autogen/stubs/stubs_part018.cpp`:
      1. `0x0058E1C0`
      2. `0x0058EED0`
      3. `0x0058F050`
      4. `0x0058F0F0`
      5. `0x0058F110`
      6. `0x0058E440`
4. Build issue encountered and fixed:
   1. `just build` initially failed (`C4234`) due `__thiscall` in free-function pointer casts in `TArmyToolbar`.
   2. replaced those bridge casts with `__fastcall` wrappers + explicit dummy `edx`.
5. Verification sequence:
   1. `just format src/game/TArmyToolbar.cpp src/game/TCivToolbar.cpp src/game/TCivDescription.cpp CMakeLists.txt src/autogen/stubs/stubs_part018.cpp`
   2. `just build`
   3. `just detect`
   4. `just compare 0x0058e1c0`
   5. `just compare 0x0058eed0`
   6. `just compare 0x0058f050`
   7. `just compare 0x0058f0f0`
   8. `just compare 0x0058f110`
   9. `just compare 0x0058e440`
   10. `just stats`
6. Targeted similarities:
   1. `0x0058E1C0`: `24.60%`
   2. `0x0058EED0`: `44.98%`
   3. `0x0058F050`: `42.86%`
   4. `0x0058F0F0`: `50.00%`
   5. `0x0058F110`: `69.39%` (after short-width class-id shape adjustment)
   6. `0x0058E440`: `33.33%` (first-pass tiny-wrapper ownership in `src/game/ui_widget_wrappers.cpp`)
7. Global snapshot (`2026-02-24T15:08:48Z`):
   1. paired functions: `12228/12228`
   2. aligned functions: `60`
   3. recompiled functions: `12511`
   4. average similarity: `2.56%`
   5. non-function coverage (with imports): `5.77%`

### Trade selection shape pass + promotion rollback (`0x00588B70`, `0x005897B0`)
1. Reworked both trade selection handlers in `src/game/trade_screen.cpp` to match locked stack/call shape:
   1. `0x00588B70` `SyncTradeCommoditySelectionWithActiveNationAndInitControls`
   2. `0x005897B0` `SelectTradeCommodityPresetBySummaryTagAndInitControls`
2. Key shape changes:
   1. explicit extra stack arg in signatures (`ret 4` shape),
   2. init call routed through `thunk_InitializeTradeMoveAndBarControls` via explicit `__fastcall` cast,
   3. post-init dispatch kept on `this` via slot `+0x1D4` (`CallPostMoveValueSlot1D4(context, ...)`),
   4. summary-tag branch order aligned to the Ghidra `<` split form (`< 0x706f7076`, `< 0x70726f67`, rail/iart tails).
3. Attempted batch promotion with:
   1. `just promote src/game/trade_screen.cpp --address 0x0058C3D0 --address 0x0058C640 --address 0x0058C950 --address 0x0058D2B0 --address 0x0058D950 --address 0x0058DF60`
4. Promotion outcome:
   1. raw bodies introduced non-compilable decompiler artifacts under MSVC500 (`undefined1`, `stack0x...`, class-scoped raw signatures),
   2. build failed (`just build`),
   3. rolled back promoted block (from `0x0058C3D0` up to `0x0059A180`) and restored compiling baseline.
5. Verification sequence (final retained state):
   1. `just format src/game/trade_screen.cpp`
   2. `just build`
   3. `just compare 0x00588b70`
   4. `just compare 0x005897b0`
   5. `just stats`
6. Targeted deltas:
   1. `0x00588B70`: `26.00% -> 30.00%`
   2. `0x005897B0`: `20.34% -> 34.39%`
7. Global snapshot (`2026-02-24T13:45:30Z`):
   1. paired functions: `12228/12228`
   2. aligned functions: `60`
   3. average similarity: `2.52%`
   4. no duplicate-address drops / failed-to-match lines.

### Trade sell-command member-shape pass (`0x005873E0`)
1. Reworked `src/game/trade_screen.cpp` `0x005873E0` (`HandleTradeSellControlCommand`) into a member-form implementation:
   1. switched from free wrapper to member dispatch to enforce `__thiscall`-style command flow (`ret 0xc`).
   2. restored explicit command switch (`100`, `0x65`, `0x67`, `0x68`, `0x69`, `0x6a`) and fan-out propagation loops for `0x67/0x68`.
   3. restored increment-branch guard and nil-assert paths (`USmallViews` lines `0x816`, `0x81d`) for `Sell`/`mCap` lookups.
2. Verification sequence:
   1. `just format src/game/trade_screen.cpp`
   2. `just build`
   3. `just compare 0x005873e0`
   4. `just stats`
3. Targeted delta:
   1. `0x005873E0`: `15.50% -> 23.68%`
4. Follow-up layout split:
   1. introduced dedicated `TAmtBarClusterContext` layout and moved `0x005873E0` onto it to align `+0x88` metric-slot field usage.
   2. verified `just build` + `just compare 0x005873e0`; offset drift was removed but similarity remained `23.68%` (no further delta this pass).

### Input-state probe (`0x0055FC40`) - no retained delta
1. Ran a call-shape probe in `src/game/input_state.cpp` to test lower-byte flag propagation changes.
2. Result did not hold improvement; restored prior baseline body.
3. Final verified state:
   1. `0x0055FC40`: `25.69%` (unchanged vs pre-probe).

### Trade summary/move-adjust shape pass (`0x005866B0`, `0x00586E70`)
1. Updated `src/game/trade_screen.cpp` `0x005866B0` (`UpdateTradeSummaryMetricControlsFromRecord`):
   1. switched signature to `__fastcall(this, unusedEdx, stackArg)` to preserve `ret 4` shape.
   2. replaced looped tag arrays with explicit tag order (`aert`, `rtnu`, `iart`, `forp`).
   3. matched nil assert paths using `USmallViews.cpp` lines `0x67d`, `0x682`, `0x687`.
   4. aligned argument loading shape to original:
      1. first setter uses dword source from `[record+0xac]+0x10`,
      2. remaining setters use short offsets from `[record+0x1d8]+0x10` (`+4/+6/+8`).
2. Updated `src/game/trade_screen.cpp` `0x00586E70` (`HandleTradeMoveControlAdjustment`):
   1. reshaped branch flow to normalized command form (`commandId - 100` => `0/1`).
   2. kept fail-and-continue behavior after nil-assert message paths (removed extra early exits).
3. Verification sequence:
   1. `just format src/game/trade_screen.cpp`
   2. `just build`
   3. `just compare 0x005866b0`
   4. `just compare 0x00586e70`
   5. `just compare 0x005873e0`
   6. `just stats`
4. Targeted deltas:
   1. `0x005866B0`: `8.62% -> 34.91%`
   2. `0x00586E70`: `17.39% -> 26.23%`
   3. `0x005873E0`: `15.50%` (unchanged)
5. Global snapshot (`2026-02-24T11:55:01Z`):
   1. paired functions: `12228/12228`
   2. aligned functions: `60`
   3. average similarity: `2.51%`
   4. no duplicate-address drops / failed-to-match lines.

### Trade metric-bar regression probe (`0x005882F0`)
1. Tested a deeper shape rewrite for `0x005882F0` in `src/game/trade_screen.cpp`:
   1. forced nil fail-and-continue paths (removed extra guards),
   2. switched to short-biased clamp/data flow and direct slot lookups.
2. Verification:
   1. `just format src/game/trade_screen.cpp`
   2. `just build`
   3. `just compare 0x005882f0`
3. Result:
   1. similarity regressed `22.41% -> 17.57%`.
4. Action:
   1. reverted that rewrite and restored the prior guarded implementation.
5. Post-revert checks:
   1. `just compare 0x005882f0` => `22.41%` restored.
   2. `just compare 0x005866b0` => `34.91%` (kept).
   3. `just compare 0x00586e70` => `26.23%` (kept).
   4. `just stats` (`2026-02-24T11:58:02Z`): average similarity `2.51%`, aligned `60`, paired `12228/12228`.

### Trade command/preset shape pass (`0x005873E0`, `0x005897B0`)
1. Updated `src/game/trade_screen.cpp` for `0x005873E0` `HandleTradeSellControlCommand`:
   1. added missing `0x67/0x68` UI-runtime propagation paths.
   2. added 17-tag fan-out loop over row controls (`0sr..6sr`, `0am..5am`, `0dg..3dg`) with slot `+0x1d8`/`+0x1e0` behavior.
   3. kept fail-and-continue behavior for nil controls.
2. Tested member-method (`thiscall`) reshaping for `0x005873E0`, confirmed regression, and reverted to the better free-wrapper shape in current codebase.
3. Added explicit unused stack arg to `0x005873E0` wrapper signature to restore `ret 0xc` stack-pop shape.
4. Updated `0x005897B0` `SelectTradeCommodityPresetBySummaryTagAndInitControls`:
   1. added explicit unused stack arg to preserve `ret 4` shape.
   2. switched init call to casted thunk bridge `thunk_InitializeTradeMoveAndBarControls`.
   3. switched post-init move dispatch to slot `+0x1D4` on `this` (removed owner fallback).
5. Verification sequence:
   1. `just format src/game/trade_screen.cpp`
   2. `just build`
   3. `just detect`
   4. `just compare 0x005873e0`
   5. `just compare 0x005897b0`
   6. `just stats`
6. Targeted deltas:
   1. `0x005873E0`: `11.94% -> 15.50%`
   2. `0x005897B0`: `16.95% -> 19.13%` (session baseline to latest)
7. Global snapshot (`2026-02-24T11:47:29Z`):
   1. paired functions: `12228/12228`
   2. aligned functions: `60`
   3. average similarity: `2.50%`
   4. no duplicate-address drops / failed-to-match lines.

### Input-state call-shape pass (`0x0055FC40`)
1. Updated `src/game/input_state.cpp` to reduce call-shape drift in `InputState::HandleKeyDown`:
   1. removed hardcoded function-address typedef dispatch for:
      1. `thunk_GetActiveNationId`
      2. `thunk_GetNavyPrimaryOrderListHead`
      3. `thunk_SetMapTileStateByteAndNotifyObserver`
   2. switched to direct thunk symbol calls where available.
   3. kept a casted bridge only for `thunk_SetMapTileStateByteAndNotifyObserver` callsite argument shape.
2. Verification sequence:
   1. `just format src/game/input_state.cpp`
   2. `just build`
   3. `just compare 0x0055fc40`
   4. `just detect`
   5. `just stats`
3. Targeted delta:
   1. `0x0055FC40` `InputState::HandleKeyDown`: `20.42% -> 25.69%` (`+5.27 pp`)
4. Tooling note captured:
   1. running `just compare` and `just stats` in parallel caused transient Wine `winedbg`/`cvdump` instability and false pairing regressions; sequential runs recover stable metrics.

### Marker normalization + vtable/string annotation tooling
1. Added reusable workflow scripts:
   1. `tools/workflow/normalize_reccmp_markers.py`
   2. `tools/workflow/annotate_vtables_from_symbols.py`
   3. `tools/workflow/annotate_strings_from_symbols.py`
2. Added duplicate-resolution override files:
   1. `config/global_annotation_overrides.csv`
   2. `config/vtable_annotation_overrides.csv`
   3. `config/string_annotation_overrides.csv`
3. Added `just` entrypoints:
   1. `just normalize-markers`
   2. `just annotate-vtables`
   3. `just annotate-strings`
4. Applied normalization:
   1. standardized reccmp markers to exact format (`// TYPE: MODULE 0x...` with lowercase hex).
   2. converted pseudo markers to non-reccmp form (`// MANUAL_OVERRIDE_ADDR ...`, `// PROMOTED_FUNCTION ...`) to avoid parser noise.
5. Applied vtable annotations:
   1. `include/game/TControl.h`
   2. `include/game/TView.h`
6. Lint impact:
   1. `bad_decomp_marker`: `0`
   2. `bogus_marker`: `0`
   3. remaining lint errors are only existing `function_out_of_order` in:
      1. `src/game/list_utils.cpp`
      2. `src/game/object_pool.cpp`

### Annotate manual globals from symbols.csv
1. Added reusable annotator:
   1. `tools/workflow/annotate_globals_from_symbols.py`
   2. Matches `type=global` names from `config/symbols.csv` and inserts missing `// GLOBAL: IMPERIALISM 0x...` markers.
   3. Resolves duplicate-name globals via override file, name suffix, file-context, then deterministic fallback.
   4. Script is idempotent.
2. Added runner command:
   1. `just annotate-globals`
3. Applied annotations in manual files:
   1. `include/game/ui_widget_shared.h`
   2. `src/game/TArmyInfoView.cpp`
   3. `src/game/TArmyToolbar.cpp`
   4. `src/game/TCivReport.cpp`
   5. `src/game/TCivToolbar.cpp`
   6. `src/game/TSoundPlayer.cpp`
   7. `src/game/TStratReportView.cpp`
   8. `src/game/TTransportPicture.cpp`
   9. `src/game/TWarningView.cpp`
   10. `src/game/trade_screen.cpp`
4. Verification loop:
   1. `uv run python tools/workflow/annotate_globals_from_symbols.py --paths src/game include/game` (dry-run: no pending changes after apply)
   2. `just build`
   3. `just stats`
5. Result snapshot (`2026-02-24T10:55:59Z`):
   1. paired functions recovered to `12228/12228` (post-rebuild)
   2. paired globals (`dat/lab/str/flo/wid`) now `272/5063` (`5.37%`)
   3. paired data rows (`dat`) now `12/1399` (`0.86%`)

### Track globals/non-function roadmap coverage in `just stats`
1. Extended `tools/reccmp/progress_stats.py` to parse and persist non-function row coverage from `reccmp_roadmap.csv`:
   1. Aggregate globals (`dat/lab/str/flo/wid`) counts: original/recompiled/paired/unpaired + coverage.
   2. Per-row-type counts for: `dat`, `lab`, `str`, `flo`, `wid`, `imp`.
   3. Non-function aggregate coverage (including imports).
2. Kept existing function/alignment metrics unchanged so session loop tooling remains compatible.
3. Verification:
   1. `uv run python tools/reccmp/progress_stats.py --target IMPERIALISM --build-dir build-msvc500 --no-run`
   2. `just stats`
4. Current non-function snapshot (`2026-02-24T10:24:28Z`):
   1. globals paired: `260 / 5027` (`5.17%`)
   2. non-function paired total (including imports): `334 / 5981` (`5.58%`)
   3. strings paired: `260 / 1999` (`13.01%`)
   4. data/labels/floats paired: `0 / 3028` (`0.00%`)
   5. imports paired: `74 / 954` (`7.76%`)

### Trade-step/arrow shape pass + callconv annotations
1. Added reusable callconv annotation script:
   1. `tools/workflow/annotate_orig_callconv.py`
   2. Applied `// ORIG_CALLCONV: __thiscall` to thiscall-backed wrappers in:
      1. `src/game/trade_screen.cpp`
      2. `src/game/TAmtBar.cpp`
      3. `src/game/TIndustryAmtBar.cpp`
      4. `src/game/TShipyardCluster.cpp`
2. Reworked handler shape in class files to follow Ghidra branch order:
   1. `0x00589DA0` (`src/game/TIndustryAmtBar.cpp`)
      1. switched to direct `commandId == 100` / `commandId == 0x65` branching.
      2. preserved fail-and-continue `MessageBoxA` path (no extra early returns).
   2. `0x0058A940` (`src/game/TShipyardCluster.cpp`)
      1. switched to explicit `commandId == 10` + left/right tag split shape.
      2. preserved fail-and-continue `MessageBoxA` path.
   3. `0x00588FF0` (`src/game/TAmtBar.cpp`)
      1. removed redundant post-check branch and aligned minus-step path shape.
      2. changed method signature to `(int commandId, void* eventArg, int eventExtra)` to restore `ret 0xc` shape.
3. Verified with loop:
   1. `just build`
   2. `just detect`
   3. `just compare 0x00589DA0`
   4. `just compare 0x0058A610`
   5. `just compare 0x0058A940`
   6. `just compare 0x00588FF0`
   7. `just stats`
4. Targeted similarity checkpoints:
   1. `0x00589DA0`: `25.37%`
   2. `0x0058A610`: `54.55%`
   3. `0x0058A940`: `41.03%`
   4. `0x00588FF0`: `28.57%`
5. Global snapshot (`2026-02-24T00:20:35Z`):
   1. paired `12228/12228` (`100%`)
   2. aligned `49`
   3. average similarity `2.41%`
   4. failed-to-match lines `0`

### Promotion stress test (class files) and rollback policy
1. Promoted extra addresses into class files with `just promote`:
   1. `src/game/TWarningView.cpp` (`0x004013E3`, `0x0040365C`, `0x0040407A`, `0x004092B9`, `0x00592980`, `0x00592A70`)
   2. `src/game/TTransportPicture.cpp` (`0x004014F1`, `0x004024C8`, `0x00402A04`, `0x00405592`, `0x0040712B`, `0x00407DF6`, `0x00591F10`, `0x005921C0`, `0x00592830`)
2. Result:
   1. raw promoted class-scoped output did not compile under current manual type surface (MSVC500 emitted >100 parse/type errors in `TTransportPicture.cpp`).
3. Action:
   1. restored `src/game/TWarningView.cpp` and `src/game/TTransportPicture.cpp` to last stable state.
   2. kept promotion insight as policy: only keep compile-safe wrappers/thunks for these files until class/type reconstruction is ready.

## 2026-02-23

### Range-based promotion workflow (`just promote-range`) + first real batch
1. Added contiguous-window promotion support in `tools/workflow/promote_from_autogen.py`:
   1. new `--range START:END` argument (repeatable).
   2. range selection now resolves against existing autogen function addresses (sparse-safe).
2. Added `just` entrypoint:
   1. `just promote-range <target_cpp> <start> <end>`.
3. Used range workflow in trade-screen:
   1. `just promote-range src/game/trade_screen.cpp 0x00586010 0x00586150`
   2. `just promote-range src/game/trade_screen.cpp 0x00585f70 0x00585ff0`
4. Normalized promoted raw class-scoped output to compile-safe wrappers in `src/game/trade_screen.cpp`:
   1. `0x00585F70` `CreateTUnitToolbarClusterInstance`
   2. `0x00585FF0` `GetTUnitToolbarClusterClassNamePointer`
   3. `0x00586010` `ConstructTUnitToolbarClusterBaseState`
   4. `0x00586040` `DestructTUnitToolbarClusterAndMaybeFree`
   5. `0x00586090` `WrapperFor_thunk_DispatchPanelControlEvent_At00586090`
   6. `0x00586150` `OrphanVtableAssignStub_00586150`
5. Stub ownership sync:
   1. flipped `0x00585F70`, `0x00585FF0`, `0x00586010`, `0x00586040`, `0x00586090`, `0x00586150` to `MANUAL_OVERRIDE_ADDR` in `src/autogen/stubs/stubs_part017.cpp`.
6. Verification commands:
   1. `just format src/game/trade_screen.cpp src/autogen/stubs/stubs_part017.cpp`
   2. `just build`
   3. `just detect`
   4. `just compare 0x00585F70`
   5. `just compare 0x00585FF0`
   6. `just compare 0x00586010`
   7. `just compare 0x00586040`
   8. `just compare 0x00586090`
   9. `just compare 0x00586150`
   10. `just stats`
7. Targeted similarities:
   1. `0x00585F70`: `34.78%`
   2. `0x00585FF0`: `50.00%`
   3. `0x00586010`: `71.43%`
   4. `0x00586040`: `66.67%`
   5. `0x00586090`: `35.96%`
   6. `0x00586150`: `100.00%`
8. Global snapshot (`2026-02-23T23:46:18Z`):
   1. original: `12224`
   2. recompiled: `12474` (`+6`)
   3. paired: `12224`
   4. aligned: `46` (`+1`)
   5. average similarity: `2.31%` (`+0.26 pp`)

### Trade-screen shape pass (drag + init-state trio)
1. Reworked `src/game/trade_screen.cpp` drag handlers to match original shape more closely:
   1. `0x00588C60` converted to member `thiscall` form (`TradeMovePanelContext::UpdateTradeMoveControlsFromDrag`).
   2. Restored move-control dirty-rect invalidation block in both drag handlers:
      1. `QueryBounds` -> `OffsetRect` -> `CopyRect` -> `thunk_InvalidateCityDialogRectRegion`.
   3. Switched drag update math/control writes to raw selected value field (`+0x4`) instead of virtual `QueryStepValue()` in:
      1. move-control `SetControlValue(..., 0)`
      2. selected-vs-target comparison for `auxValueB`
      3. bar `scaledRange` calculation.
   4. Kept explicit `USmallViews.cpp` assert paths (`0xb42/0xb49`, `0xcf2/0xcf9`) in-place with fail-and-continue behavior.
2. Updated `InitializeTradeSellControlState` (`0x00587130`) green-control branch:
   1. replaced message-only `RequireControlByTag` path with assert path line `0x7b8`.
3. Added local RECT interop declarations in `trade_screen.cpp`:
   1. `tagRECT`/`RECT`
   2. `OffsetRect` and `CopyRect` imports
   3. casted call bridge for `thunk_InvalidateCityDialogRectRegion`.
4. Verification commands:
   1. `just format src/game/trade_screen.cpp`
   2. `just build`
   3. `just detect`
   4. `just compare 0x00588C60`
   5. `just compare 0x005899F0`
   6. `just compare 0x00587130`
   7. `just stats`
5. Targeted similarity deltas:
   1. `0x00588C60`: `17.02% -> 25.53%`
   2. `0x005899F0`: `18.94% -> 31.62%`
   3. `0x00587130`: `24.61% -> 30.91%`
6. Global metrics snapshot (`2026-02-23T22:58:07Z`):
   1. paired `12228/12228` (`100%`)
   2. aligned `45`
   3. average similarity `2.16%` (no global delta this iteration)

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

## 2026-02-23 23:13:37 UTC - trade_screen missing-function throughput pass

### Commands
1. `just promote src/game/trade_screen.cpp --address 0x00586C40 --address 0x00586CC0 --address 0x00586CE0 --address 0x00586D10 --address 0x00586D60 --address 0x00586E70`
2. `just build`
3. `just detect`
4. `just compare 0x00586C40`
5. `just compare 0x00586CC0`
6. `just compare 0x00586CE0`
7. `just compare 0x00586D10`
8. `just compare 0x00586D60`
9. `just compare 0x00586E70`
10. `just stats`
11. Implemented and mapped `0x005873E0` in `src/game/trade_screen.cpp`
12. `just build`
13. `just detect`
14. `just compare 0x005873E0`
15. `just stats`

### Changes
1. Promoted missing TAmtBarCluster range directly into `src/game/trade_screen.cpp` and normalized it into compile-safe typed wrappers:
   1. `0x00586C40` `CreateTradeMoveControlPanelBasic`
   2. `0x00586CC0` `GetTAmtBarClusterClassNamePointer`
   3. `0x00586CE0` `ConstructTradeMoveControlPanelBasic`
   4. `0x00586D10` `DestructTAmtBarClusterMaybeFree`
   5. `0x00586D60` `InitializeTradeMoveAndBarControls`
   6. `0x00586E70` `HandleTradeMoveControlAdjustment`
2. Added first-pass implementation for missing `0x005873E0` `HandleTradeSellControlCommand` in `src/game/trade_screen.cpp`.
3. Switched active trade-screen call paths to direct typed handlers:
   1. `include/game/ui_widget_shared.h`
   2. `src/game/TAmtBar.cpp`
   3. `src/game/TIndustryAmtBar.cpp`
   4. `src/game/TShipyardCluster.cpp`
4. Marked promoted addresses as manual overrides in `src/autogen/stubs/stubs_part018.cpp`:
   1. `0x00586C40`
   2. `0x00586CC0`
   3. `0x00586CE0`
   4. `0x00586D10`
   5. `0x00586D60`
   6. `0x00586E70`
   7. `0x005873E0`

### Results
1. Build and detect pass with the promoted trade-screen range.
2. Targeted similarities (first-pass shape):
   1. `0x00586C40`: `34.78%`
   2. `0x00586CC0`: `50.00%`
   3. `0x00586CE0`: `71.43%`
   4. `0x00586D10`: `66.67%`
   5. `0x00586D60`: `37.74%`
   6. `0x00586E70`: `12.60%`
   7. `0x005873E0`: `11.94%`
3. Global stats after this pass:
   1. original functions: `12224`
   2. recompiled functions: `12449`
   3. aligned functions: `45`
   4. average similarity: `2.19%`

## 2026-02-23 23:17:07 UTC - trade_screen tiny orphan mapping pass

### Commands
1. Implemented and mapped in `src/game/trade_screen.cpp`:
   1. `0x00586A60`
   2. `0x00586A80`
   3. `0x00586AB0`
   4. `0x00586E50`
   5. `0x00586FF0`
2. `just build`
3. `just detect`
4. `just compare 0x00586A60`
5. `just compare 0x00586A80`
6. `just compare 0x00586AB0`
7. `just compare 0x00586E50`
8. `just compare 0x00586FF0`
9. `just stats`

### Changes
1. Added first-pass typed implementations for five missing small trade-screen functions.
2. Extended `TradeMoveStepCluster` with `field_90`/`field_94` to remove raw offset writes in the tiny setters.
3. Marked stub ownership as manual in `src/autogen/stubs/stubs_part018.cpp`:
   1. `0x00586A60`
   2. `0x00586A80`
   3. `0x00586AB0`
   4. `0x00586E50`
   5. `0x00586FF0`

### Results
1. Targeted similarities:
   1. `0x00586A60`: `40.00%`
   2. `0x00586A80`: `40.00%`
   3. `0x00586AB0`: `40.00%`
   4. `0x00586E50`: `0.00%` (signature/ret-shape mismatch, likely `ret 8`)
   5. `0x00586FF0`: `0.00%` (tiny return-stub shape still off)
2. Global stats after this pass:
   1. original functions: `12224`
   2. recompiled functions: `12454`
   3. aligned functions: `45`
   4. average similarity: `2.21%`

## 2026-02-24 00:40:00 UTC - trade-screen shape pass + new ownership mapping

### Commands
1. `just build`
2. `just detect`
3. `just stats`
4. `just compare 0x00586D60`
5. `just compare 0x00586E70`
6. `just compare 0x0058A690`
7. `just promote src/game/TShipyardCluster.cpp --address 0x0058A690`
8. `just promote src/game/TTraderAmtBar.cpp --address 0x0058AF80`
9. `just build`
10. `just detect`
11. `just compare 0x0058AF80`

### Changes
1. Promoted and mapped `0x0058A690` into `src/game/TShipyardCluster.cpp` as member `TradeMoveStepCluster::RefreshTradeMoveBarAndTurnControl`.
2. Converted `thunk_RefreshTradeMoveBarAndTurnControl` to a real member dispatch instead of global trampoline cast.
3. Re-shaped `0x00586D60` (`InitializeTradeMoveAndBarControls`) to stack-arg form:
   1. signature now carries style seed stack arg (`ret 4` shape)
   2. explicit `USmallViews` assert call path without double-MessageBox helper.
4. Re-shaped `0x00586E70` (`HandleTradeMoveControlAdjustment`) to remove duplicate MessageBox side effects and use corrected assert lines:
   1. `0x749` move nil
   2. `0x74d` avai nil
   3. `0x759` minus-branch move nil.
5. Promoted and mapped `0x0058AF80` into `src/game/TTraderAmtBar.cpp` as member `TradeAmountBarLayout::UpdateNationStateGaugeValuesFromScenarioRecordCode`.
6. Added helper plumbing in `src/game/trade_screen.cpp`:
   1. `TradeMoveStepCluster::RefreshTradeMoveBarAndTurnControl` declaration
   2. `TradeAmountBarLayout::UpdateNationStateGaugeValuesFromScenarioRecordCode` declaration
   3. `CallQueryNationMetricBySlot7C` helper.
7. Flipped stub ownership in `src/autogen/stubs/stubs_part018.cpp`:
   1. `0x0058A690`
   2. `0x0058AF80`.

### Results
1. Build and detect pass with promoted/mapped addresses.
2. Targeted similarities after this pass:
   1. `0x00586D60`: `53.12%`
   2. `0x00586E70`: `17.39%`
   3. `0x0058A690`: `15.45%`
   4. `0x0058AF80`: `20.14%`.
3. Latest global stats (`2026-02-24T00:39:55Z`):
   1. original functions: `12228`
   2. recompiled functions: `12490`
   3. aligned functions: `49`
   4. average similarity: `2.41%`.

## 2026-02-24 00:44:30 UTC - trader/placard ownership pass

### Commands
1. `just promote src/game/TTraderAmtBar.cpp --address 0x0058B070`
2. `just build`
3. `just detect`
4. `just compare 0x0058B070`
5. `just promote src/game/TPlacard.cpp --address 0x0058BC60`
6. `just build`
7. `just detect`
8. `just compare 0x0058BC60`
9. `just stats`

### Changes
1. Promoted and normalized `0x0058B070` into `src/game/TTraderAmtBar.cpp` as compile-safe fastcall wrapper preserving `ret 4` shape.
2. Added `TradeAmountBarLayout::UpdateNationStateGaugeValuesFromScenarioRecordCode` declaration/slot support and retained first-pass mapped implementation for `0x0058AF80`.
3. Promoted `0x0058BC60` into `src/game/TPlacard.cpp` and kept ownership with a compile-safe placeholder body (avoids unresolved QuickDraw helper link failures in standalone class TU).
4. Updated headers for class method declarations:
   1. `include/game/ui_widget_shared.h` (`PlacardState::RenderPlacardValueTextWithShadow`)
5. Flipped stub ownership in `src/autogen/stubs/stubs_part018.cpp`:
   1. `0x0058B070`
   2. `0x0058BC60`.

### Results
1. Targeted similarities:
   1. `0x0058B070`: `49.18%`
   2. `0x0058AF80`: `20.14%`
   3. `0x0058BC60`: `0.00%` (intentional compile-safe placeholder; real QuickDraw path deferred).
2. Remaining unmapped (`FUNCTION`) in `0x586000-0x58C000`: `12` addresses.
3. Latest global stats (`2026-02-24T00:43:56Z`):
   1. original functions: `12228`
   2. recompiled functions: `12492`
   3. aligned functions: `49`
   4. average similarity: `2.42%`.

## 2026-02-24 00:46:40 UTC - placard wrapper batch (0x58BAB0 / 0x58BB50)

### Commands
1. `just promote src/game/TPlacard.cpp --address 0x0058BAB0 --address 0x0058BB50`
2. `just build`
3. `just detect`
4. `just compare 0x0058BAB0`
5. `just compare 0x0058BB50`
6. `just stats`

### Changes
1. Promoted two class-local wrapper functions into `src/game/TPlacard.cpp` and normalized them into typed member methods:
   1. `0x0058BAB0` `PlacardState::WrapperFor_thunk_NoOpUiLifecycleHook_At0058bab0`
   2. `0x0058BB50` `PlacardState::WrapperFor_thunk_InvalidateCityDialogRectRegion_At0058bb50`
2. Added minimal local rect/layout scaffolding in `src/game/TPlacard.cpp` for compile-safe invalidation path.
3. Added method declarations to `include/game/ui_widget_shared.h` for the two new `PlacardState` members.
4. Flipped stub ownership in `src/autogen/stubs/stubs_part018.cpp`:
   1. `0x0058BAB0`
   2. `0x0058BB50`.

### Results
1. Targeted similarities:
   1. `0x0058BAB0`: `43.48%`
   2. `0x0058BB50`: `44.04%`
2. Remaining unmapped (`FUNCTION`) in `0x586000-0x58C000`: `10` addresses.
3. Latest global stats (`2026-02-24T00:46:13Z`):
   1. original functions: `12228`
   2. recompiled functions: `12494`
   3. aligned functions: `49`
   4. average similarity: `2.42%`.

## 2026-02-24 09:59:00 UTC - trade-screen promoted-window rebuild + shape/data pass

### Commands
1. `just build`
2. `just detect`
3. `just stats`
4. `just compare 0x0058A1B0`
5. `rg -n "^// FUNCTION: IMPERIALISM 0x0*58(a1b0|a3b0|ac80|b0f0|b460|b4f0|b750|b890|b8d0|bfe0)$" src`
6. `just compare 0x0058A1B0`
7. `just build`
8. `just compare 0x0058A1B0 0x0058A3B0 0x0058AC80 0x0058B0F0` (targeted loop)
9. `just detect`
10. `just stats`
11. `just build`
12. `just compare 0x0058B460 0x0058B4F0 0x0058B750 0x0058B890 0x0058B8D0 0x0058BFE0` (targeted loop)
13. `just detect`
14. `just stats`

### Changes
1. Fixed duplicate reccmp mapping for promoted addresses:
   1. demoted stale annotations in `src/autogen/stubs/stubs_part018.cpp` from `// FUNCTION:` to `// PROMOTED_FUNCTION:` for:
      1. `0x0058A1B0`
      2. `0x0058A3B0`
      3. `0x0058AC80`
      4. `0x0058B0F0`
      5. `0x0058B460`
      6. `0x0058B4F0`
      7. `0x0058B750`
      8. `0x0058B890`
      9. `0x0058B8D0`
      10. `0x0058BFE0`.
2. Replaced jump-only wrappers in `src/game/trade_screen.cpp` with real quickdraw shape-pass bodies:
   1. `0x0058A1B0`
   2. `0x0058A3B0`
   3. `0x0058AC80`
   4. `0x0058B0F0`.
3. Added reusable helper bridges in `src/game/trade_screen.cpp`:
   1. quickdraw thunk call helpers (`SetQuickDrawTextOrigin`, style pair, clip apply)
   2. runtime slot dispatch helper for UI runtime vslot `0x34`
   3. absolute-address pointer/int readers for global runtime symbols.
4. Added symbol-backed global address constants from fresh Ghidra exports:
   1. `g_szDecimalFormat` (`0x0069430C`)
   2. `g_pActiveQuickDrawSurfaceContext` (`0x006A1D60`)
   3. `g_pStrategicMapViewSystem` (`0x006A21A8`)
   4. `g_pGlobalMapState` (`0x006A43D4`)
   5. overlay cache params (`0x006A4450`, `0x006A4454`).
5. Ported and data-shaped additional wrappers using offset-accurate field access:
   1. `0x0058B460` (`+0x98/+0x9c` state + global-map vslot usage)
   2. `0x0058B4F0` (hint overlay blit/palette path)
   3. `0x0058B750` (bitmap-select branch using `+0x90/+0x92/+0x94/+0x96/+0x98`)
   4. `0x0058B8D0` (mode + bitmap/state update path)
   5. `0x0058BFE0` (shared-string + text-shadow draw flow).
6. Normalized problematic free-function casts from `__thiscall` to `__fastcall` for MSVC500 compatibility where needed.

### Results
1. Targeted similarity deltas in this window:
   1. `0x0058A1B0`: `0.00%` -> `30.06%`
   2. `0x0058A3B0`: `16.67%` -> `23.76%`
   3. `0x0058AC80`: `0.00%` -> `27.03%`
   4. `0x0058B0F0`: `0.00%` -> `16.44%`
   5. `0x0058B460`: `59.38%` -> `64.37%`
   6. `0x0058B4F0`: `0.00%` -> `20.93%`
   7. `0x0058B750`: `15.69%` -> `33.33%`
   8. `0x0058B890`: `50.00%` -> `50.00%` (no movement)
   9. `0x0058B8D0`: `24.49%` -> `47.22%`
   10. `0x0058BFE0`: `0.00%` -> `19.61%`.
2. Latest global stats (`2026-02-24T09:59:10Z`):
   1. original functions: `12228`
   2. recompiled functions: `12504`
   3. aligned functions: `49`
   4. average similarity: `2.46%` (`+0.04 pp` from `2.42%` baseline for this window).

## 2026-02-24 10:03:00 UTC - tiny orphan call-shape pass (`0x586E50`, `0x586FF0`)

### Commands
1. `just compare 0x00586E50`
2. `just compare 0x00586FF0`
3. `just build`
4. `just compare 0x00586E50`
5. `just compare 0x00586FF0`
6. `just detect`
7. `just stats`

### Changes
1. Updated `0x00586E50` signature in `src/game/trade_screen.cpp` from cdecl leaf to stdcall two-arg wrapper to match observed `ret 8` shape:
   1. `short __stdcall OrphanLeaf_NoCall_Ins02_00586e50(short value, int unusedArg)`.
2. Kept `0x00586FF0` as plain no-op return stub (still zero-length mismatch in original vs emitted `ret`).

### Results
1. Targeted similarities:
   1. `0x00586E50`: `0.00%` -> `20.00%`
   2. `0x00586FF0`: `0.00%` -> `0.00%` (no movement; original appears zero-byte/no-body mapping).
2. Global stats (`2026-02-24T10:03:00Z`) unchanged:
   1. aligned functions: `49`
   2. average similarity: `2.46%`.

## 2026-02-24 10:06:48 UTC - quickdraw base pair shape pass (`0x589340`, `0x589540`)

### Commands
1. `just build`
2. `just compare 0x00589340`
3. `just compare 0x00589540`
4. `just detect`
5. `just stats`

### Changes
1. Replaced placeholder bodies in `src/game/trade_screen.cpp` for:
   1. `0x00589340` `RenderQuickDrawControlWithHitRegionClip_A`
   2. `0x00589540` `RenderQuickDrawOverlayWithHitRegion_00589540`.
2. Ported shape to match Ghidra-exported quickdraw flow:
   1. acquire/release surface sequence
   2. hit-region clip application
   3. `IsActionable`-gated draw path
   4. overlay rect invalidation using cached overlay globals (`0x6A4450/0x6A4454`).

### Results
1. Targeted similarities:
   1. `0x00589340`: `18.87%` -> `30.06%`
   2. `0x00589540`: `17.24%` -> `22.45%`.
2. Global stats at `2026-02-24T10:06:48Z` remained:
   1. aligned functions: `49`
   2. average similarity: `2.46%`.

## 2026-02-24 14:09:38 UTC - `ret 4` seed-shape + placard render body pass (`0x587130`, `0x58BC60`)

### Commands
1. `just compare 0x00588B70`
2. `just compare 0x005897B0`
3. `just stats`
4. `just session-loop 12 120 10`
5. `just compare 0x005873E0`
6. `just compare 0x005899F0`
7. `just compare 0x00587130`
8. `just format src/game/trade_screen.cpp`
9. `just build`
10. `just compare 0x00587130`
11. `just compare 0x0058BC60`
12. `just promote src/game/TPlacard.cpp --overwrite-existing --address 0x0058bc60`
13. `just format src/game/TPlacard.cpp`
14. `just build` (fix compile errors introduced by raw promotion)
15. `just compare 0x0058BC60`
16. `just stats`

### Changes
1. Updated `0x00587130` signature and tail call shape in `src/game/trade_screen.cpp`:
   1. `InitializeTradeSellControlState` now takes explicit `unsigned int styleSeed`.
   2. Forwarded `styleSeed` into `InitializeTradeMoveAndBarControls(this, 0, styleSeed)`.
2. Re-promoted `0x0058BC60` in `src/game/TPlacard.cpp` using `just promote --overwrite-existing`.
3. Replaced raw promoted artifacts with compile-safe/manual normalized body:
   1. kept shared-string setup and formatted numeric placard text path,
   2. preserved theme color mapping + two-pass shadow/text draw sequence,
   3. preserved quickdraw origin updates and fill-color restore,
   4. added explicit helper declarations and decimal-format address constant (`0x0069430C`).

### Results
1. `0x00587130` `InitializeTradeSellControlState`: `40.95% -> 41.52%`.
2. `0x0058BC60` `PlacardState::RenderPlacardValueTextWithShadow`: `0.00% -> 55.62%`.
3. `0x00588B70` `SyncTradeCommoditySelectionWithActiveNationAndInitControls`: `42.50%` (validated current shape after this pass).
4. Global stats (`2026-02-24T14:09:38Z`):
   1. aligned functions: `60` (unchanged),
   2. average similarity: `2.53%` (`+0.01 pp`).

## 2026-02-24 14:35:35 UTC - offer bitmap shape/data pass (`0x587DD0`, `0x588030`) + sell-handler baseline restore (`0x5873E0`)

### Commands
1. `just format src/game/trade_screen.cpp`
2. `just build`
3. `just compare 0x005873e0`
4. `just compare 0x00588030`
5. `just compare 0x00587dd0`
6. `just build`
7. `just compare 0x00587dd0`
8. `just compare 0x00588030`
9. `just stats`

### Changes
1. Restored `0x005873E0` `TAmtBarClusterContext::HandleTradeSellControlCommand` to prior stable shape:
   1. reverted case-100 gate back to slot `+0x1DC` (`CallBoolSlot1DC(this)`),
   2. restored default dispatch shape (`default -> HandleTradeMoveControlAdjustment(...); return;` plus post-switch tail call).
2. Adjusted `0x00588030` `SetTradeOfferSecondaryBitmapState`:
   1. fixed secondary capture buffer to `{0xA3, 0}` (was `{0xA3, 1}` in the regressing variant),
   2. grouped enabled/state calls as three `SetEnabledPair` then three `SetStatePair`.
3. Tuned `0x00587DD0` `SetTradeOfferControlBitmapState`:
   1. cached control resolver slot `+0x94` in a local function pointer and reused it for `offr/gree/left/rght` lookups.
4. Tested resolver-caching strategy on `0x00588030`; it regressed there, so reverted `0x588030` back to direct `ResolveControlByTag` while keeping the successful ordering/data tweaks.

### Results
1. `0x005873E0` `HandleTradeSellControlCommand`: back to `23.68%` (restored baseline).
2. `0x00587DD0` `SetTradeOfferControlBitmapState`: `40.58% -> 52.21%`.
3. `0x00588030` `SetTradeOfferSecondaryBitmapState`: `41.67% -> 42.31%` (briefly regressed to `41.56%` during resolver-caching experiment, then recovered).
4. Global stats (`2026-02-24T14:35:35Z`):
   1. aligned functions: `60` (unchanged),
   2. average similarity: `2.53%` (no rounded delta).

## 2026-02-24 20:56:17 UTC - civilian description legend ownership batch (`0x58F550`, `0x58F7B0`, `0x58FEC0`)

### Commands
1. `just promote src/game/TCivDescription.cpp --address 0x0058f550 --address 0x0058f7b0 --address 0x0058fec0`
2. `just build` (observed promoted raw class-syntax compile failures)
3. `just format src/game/TCivDescription.cpp src/autogen/stubs/stubs_part018.cpp`
4. `just build`
5. `just detect`
6. `just compare 0x0058f550`
7. `just compare 0x0058f7b0`
8. `just compare 0x0058fec0`
9. `just stats`

### Changes
1. Promoted three remaining `TCivDescription` legend functions.
2. Replaced raw class-scoped promoted bodies with compile-safe wrappers that bridge through thunk symbols.
3. Added proper reccmp markers in manual source:
   1. `// FUNCTION: IMPERIALISM 0x0058f550`
   2. `// FUNCTION: IMPERIALISM 0x0058f7b0`
   3. `// FUNCTION: IMPERIALISM 0x0058fec0`
4. Flipped stub ownership markers in `src/autogen/stubs/stubs_part018.cpp` to `MANUAL_OVERRIDE_ADDR` for all three addresses.

### Results
1. `0x0058F550`: `0.00%` (first-pass thunk bridge).
2. `0x0058F7B0`: `0.00%` (first-pass thunk bridge).
3. `0x0058FEC0`: `0.00%` (first-pass thunk bridge).
4. Global stats (`2026-02-24T20:56:17Z`):
   1. recompiled functions: `12519` (`+5`)
   2. aligned functions: `60` (unchanged)
   3. average similarity: `2.57%` (`+0.01 pp`).

## 2026-02-24 20:58:45 UTC - civ report detail-text ownership (`0x590CB0`)

### Commands
1. `just promote src/game/TCivReport.cpp --address 0x00590cb0`
2. `just build` (observed promoted raw class-syntax compile failures)
3. `just format src/game/TCivReport.cpp src/autogen/stubs/stubs_part018.cpp`
4. `just build`
5. `just detect`
6. `just compare 0x00590cb0`
7. `just stats`

### Changes
1. Promoted `0x00590CB0` into `src/game/TCivReport.cpp`.
2. Normalized promoted raw body to compile-safe wrapper form with thunk bridge:
   1. `BuildCivReportNationEntryDetailTextBlock(CivReportState*, int, void*)`
   2. preserved `// ORIG_CALLCONV: __thiscall`.
3. Flipped `0x00590CB0` stub marker to `MANUAL_OVERRIDE_ADDR` in `src/autogen/stubs/stubs_part018.cpp`.

### Results
1. `0x00590CB0`: `16.67%` first-pass ownership.
2. Global stats (`2026-02-24T20:58:45Z`):
   1. recompiled functions: `12520` (`+1`)
   2. aligned functions: `60` (unchanged)
   3. average similarity: `2.57%` (unchanged rounded value).

## 2026-02-24 21:07:15 UTC - score pass on `TCivDescription::RefreshCivilianTargetLegendBySelectedClass` (`0x58F550`)

### Commands
1. `just build`
2. `just detect`
3. `just compare 0x0058f550`
4. `just compare 0x0058f1a0`
5. `just compare 0x0058f3c0`
6. `just build`
7. `just detect && just compare 0x0058f550`
8. `just build && just detect && just compare 0x0058f550` (regression test and rollback validation)
9. `just stats`

### Changes
1. Replaced `0x58F550` thunk-forwarder in `src/game/TCivDescription.cpp` with a real first-pass implementation:
   1. legend rect/count reset block for first render,
   2. class-dispatch via vtable slots (`+0x1A0/+0x1A4/+0x1A8`),
   3. localized label setup/draw path (style init + `0x2718` text + measured centering + two-pass draw).
2. Updated `CivDescriptionState` field mapping around `+0x6C` (`legendInitialized`) to align with observed behavior in this function cluster.
3. Tried two additional shape tweaks and kept only the one that improved score:
   1. kept style-init call shape (`InitializeUiTextStyleDescriptorAndApplyQuickDraw(0,0xc,0x2b68)`),
   2. reverted explicit stack-arg virtual-call variant because it regressed.

### Results
1. `0x0058F550`: `0.00% -> 11.76% -> 16.11%` (final for this pass).
2. Adjacent checks stayed stable:
   1. `0x0058F1A0`: `17.14%` (no regression)
   2. `0x0058F3C0`: `24.88%` (no regression)
3. One tested variant regressed and was reverted:
   1. `0x0058F550`: `16.11% -> 15.53% -> 16.11%` (restored).
4. Global stats (`2026-02-24T21:07:15Z`):
   1. aligned functions: `60` (unchanged)
   2. average similarity: `2.57%` (unchanged rounded value).

## 2026-02-25 00:09:17 UTC - `TCivDescription` follow-up shape pass (`0x58F1A0`, `0x58F550`)

### Commands
1. `just build`
2. `just detect`
3. `just compare 0x0058f3c0`
4. `just compare 0x0058f550`
5. `just compare 0x0058f7b0`
6. `just compare 0x0058fec0`
7. `just compare 0x0058f1a0`
8. `just compare 0x0058f110`
9. `just build && just detect && just compare 0x0058f550`
10. `just build && just detect && just compare 0x0058f1a0`

### Changes
1. `0x0058F550` `RefreshCivilianTargetLegendBySelectedClass`:
   1. added explicit forwarded stack payload arg in wrapper signature,
   2. moved `InitializeSharedStringRefFromEmpty` to function entry,
   3. changed legend reset loop to pointer-driven shape (`nextLegendSelectionCountsBySlot`),
   4. forwarded payload into dispatch slots `+0x1A0/+0x1A4/+0x1A8` using compile-safe fastcall bridges.
2. `0x0058F1A0` `DestructTCivDescriptionAndMaybeFree`:
   1. switched province collection dispatch to virtual wrappers (`GetCount`, `GetByOrdinal`),
   2. rewired outer loop to pointer-based legend-counter progression (`currentLegendSelectionCounter`),
   3. preserved fail-and-continue click-hit-test behavior.
3. Retained high-score baseline for `0x0058F3C0`; no regression introduced.

### Results
1. `0x0058F3C0`: retained `97.98%`.
2. `0x0058F550`: `16.11% -> 18.34%`.
3. `0x0058F1A0`: `17.14% -> 18.50%`.
4. `0x0058F110`: unchanged `69.39%`.
5. `0x0058F7B0`: `0.00%` (still thunk-forward baseline).
6. `0x0058FEC0`: `0.00%` (still thunk-forward baseline).
7. `0x0058F110` direct-access probe (`orderState->eCivilianClassId` without local cache) regressed to `53.06%`; reverted to the prior local-`short` baseline (`69.39%`).

## 2026-02-25 00:14:43 UTC - legend-variant de-thunk pass (`0x58F7B0`, `0x58FEC0`)

### Commands
1. `just build`
2. `just detect`
3. `just compare 0x0058f7b0`
4. `just compare 0x0058fec0`
5. `just compare 0x0058f3c0`
6. `just compare 0x0058f550`
7. `just stats`

### Changes
1. `0x0058F7B0` `RenderCivilianTargetLegendVariantA`:
   1. replaced thunk-forward body with first-pass real body,
   2. added early active-nation capability reads from `g_pCityOrderCapabilityState`,
   3. added localized header draw scaffold and retained shared-string lifetime handling.
2. `0x0058FEC0` `RenderCivilianTargetLegendVariantB`:
   1. replaced thunk-forward body with first-pass loop scaffold,
   2. added capability-based row-count selection, profile-row icon blit loop, and formatted count draw path,
   3. wired required quickdraw helper declarations and fixed addresses (`g_pStrategicMapViewSystem`, `g_pActiveQuickDrawSurfaceContext`, `g_szDecimalFormat`).
3. Preserved prior high-similarity anchors:
   1. `0x0058F3C0` unchanged.
   2. `0x0058F550` unchanged.

### Results
1. `0x0058F7B0`: `0.00% -> 25.25%`.
2. `0x0058FEC0`: `0.00% -> 16.81%`.
3. `0x0058F550`: retained `18.34%`.
4. `0x0058F3C0`: retained `97.98%`.
5. Global stats (`2026-02-25T00:14:43Z`):
   1. aligned functions: `60` (unchanged)
   2. average similarity: `2.58%` (unchanged rounded value).

## 2026-02-25 01:53:08 UTC - targeted score pass (`0x58F1A0`)

### Commands
1. `just build`
2. `just detect`
3. `just compare 0x0058f1a0`
4. `just compare 0x0058f3c0`
5. `just compare 0x0058f550`

### Changes
1. `src/game/TCivDescription.cpp`:
   1. kept `0x58F1A0` on virtual `ProvinceCollectionVirtualShape` call shape and pointer-based legend-counter walk.
   2. removed outer-loop `candidateOrdinal++` from `DestructTCivDescriptionAndMaybeFree` slot-advance path.
2. restored `0x58F3C0` high-similarity baseline shape:
   1. `CivilianClassCacheContext` typed counters at `+0x64..+0x6C`.
   2. `#pragma optimize("y", on)` around `UpdateCivilianOrderTargetTileCountsForOwnerNation`.
   3. direct fixed-address table references (`0x6A4310`, `0x698F58`) and class-slot decrement loop.

### Results
1. `0x0058F1A0`: `20.87% -> 22.22%`.
2. `0x0058F3C0`: retained `97.98%`.
3. `0x0058F550`: currently `16.11%` on this branch state.

## 2026-02-25 20:09:36 UTC - ownership/config refactor (reccmp-safe)

### Commands
1. `just sync-ownership`
2. `just regen-stubs`
3. `just build`
4. `just detect`
5. `just compare 0x0058f3c0`
6. `just stats`

### Changes
1. Added canonical config plumbing:
   1. `config/function_name_overrides.csv` (rename/prototype overrides).
   2. `config/function_ownership.csv` (address ownership map).
2. Added shared helper module `tools/workflow/function_ownership.py` and ownership sync tool `tools/workflow/sync_function_ownership.py`.
3. Updated active scripts to use canonical override path with legacy fallback:
   1. `tools/ghidra/sync_exports.py`
   2. `tools/stubgen.py`
   3. `tools/workflow/decomp_loop.py`
   4. `tools/workflow/promote_from_autogen.py`
4. Updated `justfile` to pass ownership/override config explicitly and added `just sync-ownership`.
5. Kept marker semantics reccmp-compatible:
   1. only real reccmp markers (`FUNCTION/STUB/...`) are parsed for comparisons,
   2. ownership sync reads manual source markers and excludes `src/autogen/*`.
6. Fixed one surfaced link-shape issue after ownership suppression:
   1. `src/game/TStratReportView.cpp` now calls `TView::thunk_ConstructUiResourceEntryBase()` as a real member call instead of unresolved free-symbol thunk bridge.

### Results
1. `just sync-ownership` scanned `281` manual-owned functions and wrote `config/function_ownership.csv`.
2. `just regen-stubs` completed successfully with ownership suppression:
   1. generated `24` stub chunks (`11949` stubs),
   2. skipped `281` manual-owned addresses from autogen stubs.
3. Reccmp flow remained operational after refactor:
   1. `just build` succeeded (MSVC500 Docker pipeline),
   2. `just detect` resolved recompiled binary + PDB and updated `reccmp-build.yml`,
   3. `just compare 0x0058f3c0` completed and still reported expected targeted diff output (`97.98%` for this function),
   4. `just stats` completed without duplicate-address parser noise (`dropped duplicate addresses: 0`).
4. Snapshot (`2026-02-25T20:14:51Z`):
   1. aligned functions: `60`
   2. average similarity: `2.58%`
   3. paired functions: `12229 / 12229` (`100%` coverage)

## 2026-02-25 20:30 UTC - Python tooling dedup/refactor pass

### Commands
1. `uv run python -m compileall tools`
2. `just sync-ownership`
3. `just regen-stubs`
4. `just stats`
5. `just inventory`
6. `just generate-ignores`
7. `just session-loop 1 1 1`

### Changes
1. Introduced shared tooling modules:
   1. `tools/common/repo.py` (repo-root/path normalization helpers),
   2. `tools/common/file_scan.py` (shared file iteration + generated-path filter),
   3. `tools/common/pipe_csv.py` (pipe-delimited CSV readers),
   4. `tools/common/hexutil.py` (hex address parsing),
   5. `tools/common/name_overrides.py` (shared `address|name|prototype` parser).
2. Package-structured tooling (`tools` + subpackages now have `__init__.py`) and standardized command execution to module mode (`python -m tools...`).
3. Refactored workflow scripts to remove duplicated scanners/parsers:
   1. `annotate_globals_from_symbols.py`,
   2. `annotate_strings_from_symbols.py`,
   3. `annotate_vtables_from_symbols.py`,
   4. `normalize_reccmp_markers.py`,
   5. `split_classes_in_file.py`,
   6. `stubgen.py`,
   7. `sync_exports.py`,
   8. `promote_from_autogen.py`,
   9. `decomp_loop.py`,
   10. `function_ownership.py`.
4. Refactored reccmp utilities to shared repo helpers and module-safe imports:
   1. `compare_toolchains.py`,
   2. `core_impact_ranking.py`,
   3. `flag_sweep.py`,
   4. `generate_ignore_functions.py`,
   5. `library_inventory.py`,
   6. `progress_stats.py`,
   7. `session_loop.py`,
   8. `symbol_buckets.py`,
   9. `function_shape_stats.py`.
5. Updated command docs/examples to `python -m tools...` in:
   1. `README.md`,
   2. `INSTRUCTIONS.md`,
   3. `tools/ghidra/README.md`,
   4. `tools/reccmp/README.md`,
   5. `docs/control_plane.md`,
   6. `docs/toolchain.md`.

### Results
1. All refactored modules compile (`compileall` clean).
2. Primary reccmp loop still works after refactor:
   1. `just sync-ownership` and `just regen-stubs` succeed.
   2. `just stats` unchanged (`aligned=60`, `avg=2.58%`, no duplicate-address noise).
3. Reccmp helper targets with module mode now run cleanly:
   1. `just inventory`,
   2. `just generate-ignores`,
   3. `just session-loop`.
