# Worklog

## 2026-03-02

### TGreatPower zero-cleanup pass (`0x00404A9D`, `0x00405DE4`, `0x00406B2C`, `0x00406C49`, `0x00406C9E`)
1. Goal: eliminate the remaining `0.00%` thunk cluster in `src/game/TGreatPower.cpp`.
2. Root cause discovered:
   1. these entries are tiny thunk/jump wrappers; large/manual bodies or indirect address-jumps (`mov eax,imm; jmp eax`) stayed at `0.00%`.
   2. earlier direct symbol-forward attempt failed due MSVC decorated-name mismatch (`void` declarations vs stub `undefined4` returns).
3. Retained fix:
   1. switched to direct symbol calls with stub-compatible declarations/signatures:
      1. `ReplyToDiplomacyOffers` -> `GetTGreatPowerClassNamePointer`
      2. `TGreatPower_VtblSlot07` -> `ReleaseOwnedGreatPowerObjectsAndDeleteSelf`
      3. `thunk_RemoveRegionIdAndRunTrackedObjectCleanup_At00406b2c` -> `RemoveRegionIdAndRunTrackedObjectCleanup`
      4. `thunk_ClearFieldBlock1c6_At00406c49` -> `ClearFieldBlock1c6`
      5. `thunk_ResetNationDiplomacySlotsAndMarkRelatedNations_At00406c9e` -> `ResetNationDiplomacySlotsAndMarkRelatedNations`
4. Verification sequence:
   1. `just format src/game/TGreatPower.cpp`
   2. `just build`
   3. `just detect`
   4. `just compare 0x00404A9D`
   5. `just compare 0x00405DE4`
   6. `just compare 0x00406B2C`
   7. `just compare 0x00406C49`
   8. `just compare 0x00406C9E`
   9. anchor stability:
      1. `just compare 0x004DDA90`
      2. `just compare 0x004DDBB0`
      3. `just compare 0x004E8540`
      4. `just compare 0x004E8750`
5. Targeted deltas:
   1. `0x00404A9D`: `0.00% -> 100%`
   2. `0x00405DE4`: `0.00% -> 100%`
   3. `0x00406B2C`: `0.00% -> 100%`
   4. `0x00406C49`: `0.00% -> 100%`
   5. `0x00406C9E`: `0.00% -> 100%`
6. Anchor checks (unchanged in this pass):
   1. `0x004DDA90`: `26.67%`
   2. `0x004DDBB0`: `37.89%`
   3. `0x004E8540`: `42.86%`
   4. `0x004E8750`: `34.25%`

### TGreatPower thunk batch pass (`0x00405DE4`..`0x004097FF`)
1. Continued `src/game/TGreatPower.cpp` ownership block work for the promoted thunk window.
2. First attempt:
   1. replaced many no-op wrappers with direct call-through bridges to inferred callee symbols.
   2. build failed at link (`LNK1120`) with 26 unresolved externals (`LNK2001`) for those bridge targets.
3. Retained approach for this pass:
   1. kept build green by removing unresolved call-through targets.
   2. implemented direct typed bodies (field/vtable shape) for:
      1. `0x00405DE4` `TGreatPower_VtblSlot07`
      2. `0x00406B2C` `thunk_RemoveRegionIdAndRunTrackedObjectCleanup_At00406b2c`
      3. `0x00406C49` `thunk_ClearFieldBlock1c6_At00406c49`
      4. `0x00406C9E` `thunk_ResetNationDiplomacySlotsAndMarkRelatedNations_At00406c9e`
   3. kept remaining wrappers in this promoted window compile-safe placeholders for now.
4. Verification sequence:
   1. `just format src/game/TGreatPower.cpp`
   2. `just build`
   3. `just detect`
   4. `just compare 0x00405DE4`
   5. `just compare 0x00406B2C`
   6. `just compare 0x00406C49`
   7. `just compare 0x00406C9E`
   8. stability checks:
      1. `just compare 0x004DDA90`
      2. `just compare 0x004DDBB0`
      3. `just compare 0x004E8540`
      4. `just compare 0x004E8750`
5. Targeted similarities after retained edits:
   1. `0x00405DE4`: `0.00%`
   2. `0x00406B2C`: `0.00%`
   3. `0x00406C49`: `0.00%`
   4. `0x00406C9E`: `0.00%`
6. Anchor checks stayed stable in this pass:
   1. `0x004DDA90`: `26.67%`
   2. `0x004DDBB0`: `37.89%`
   3. `0x004E8540`: `42.86%`
   4. `0x004E8750`: `34.25%`

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

## 2026-02-25 22:37 UTC - trade_screen targeted shape pass

### Commands
1. `just build`
2. `just compare 0x005866b0`
3. `just compare 0x00586e70`
4. `just compare 0x00583bd0`
5. `just compare 0x00586a60`
6. `just compare 0x00586a80`
7. `just compare 0x00586ab0`
8. `just compare`
9. `just stats`

### Changes
1. Rewired nil-assert helper path in `src/game/trade_screen.cpp`:
   1. added `FailNilPointerWithAssert(sourcePath, line)`,
   2. switched helper dispatch target to `thunk_DestructTShipAndFreeIfOwned` cast with `(file,line)`,
   3. replaced repeated direct casts in trade-screen fail paths (`USmallViews` and `USuperMap`) with helper calls.
2. Corrected call-shape for `0x00583BD0` (`HandleTradeArrowAutoRepeatTickAndDispatch`):
   1. restored stack-arg shape by adding explicit dummy `edx` argument in function signature and thunk forwarding,
   2. converted initial dispatch thunk call and slot `+0x40` calls to explicit `thiscall`-emulated fastcall signatures.
3. Converted tiny `0x586A*` wrappers to real `TradeMoveStepCluster` member methods and forced local frame-pointer omission for that micro-cluster:
   1. `0x00586A60`,
   2. `0x00586A80`,
   3. `0x00586AB0`,
   4. added local `#pragma optimize("y", on/off)` bracket around these three functions.

### Results
1. Targeted function deltas:
   1. `0x00583BD0` `HandleTradeArrowAutoRepeatTickAndDispatch`: `58.18% -> 67.77%`.
   2. `0x00586A60` `OrphanTiny_SetWordEcxOffset_8c_00586a60`: `40.00% -> 100.00%`.
   3. `0x00586A80` `OrphanLeaf_NoCall_Ins05_00586a80`: `40.00% -> 100.00%`.
   4. `0x00586AB0` `OrphanTiny_SetWordEcxOffset_8e_00586ab0`: `40.00% -> 100.00%`.
2. Full-project snapshot after full compare (`just stats`):
   1. paired functions: `12229` (`100.00%` coverage),
   2. aligned functions: `63`,
   3. average similarity: `2.60%`,
   4. failed-to-match lines: `0`.

## 2026-02-25 22:58 UTC - trade arrow dispatch typed-slot pass

### Commands
1. `just build`
2. `just compare 0x00583bd0`
3. `just compare 0x00586e70`
4. `just stats`

### Changes
1. Updated virtual slot typing in `include/game/ui_widget_shared.h` for call-shape fidelity:
   1. `CtrlSlot16(int commandId, void* eventArg, int eventExtra)` (`+0x40`),
   2. `CtrlSlot91(void* dispatchArg)` (`+0x16c`).
2. Reworked `0x00583BD0` (`src/game/trade_screen.cpp`) to use typed virtual calls on `TradeControl` instead of raw vtable casts for the slot `+0x16c` readiness gate and slot `+0x40` command dispatch.
3. Kept local `#pragma optimize("y", on/off)` for `0x00583BD0` and adjusted the repeat-deadline compare to a branch form closer to original codegen (`tick < deadline+5`).
4. Attempted deeper tuning for `0x00586E70`; reverted to a compiling baseline after confirming MSVC500 rejects `__thiscall` free-function pointer casts (`C4234`).

### Results
1. `0x00583BD0` improved from `67.77%` to `82.35%`.
2. `just stats` global snapshot remained unchanged for aggregate metrics (`aligned=63`, `avg=2.60%`), consistent with a single-function targeted pass.

## 2026-03-01 20:00 UTC - `TCapacityOrder` moved into class-member form

### Commands
1. `just build`
2. `UV_CACHE_DIR=/tmp/uv-cache just detect`
3. `UV_CACHE_DIR=/tmp/uv-cache just compare 0x00401c0d`
4. `UV_CACHE_DIR=/tmp/uv-cache just compare 0x00404093`
5. `UV_CACHE_DIR=/tmp/uv-cache just compare 0x00405ab5`
6. `UV_CACHE_DIR=/tmp/uv-cache just compare 0x004b8b80`
7. `UV_CACHE_DIR=/tmp/uv-cache just compare 0x004b8cc0`
8. `UV_CACHE_DIR=/tmp/uv-cache just compare 0x004b8d00`
9. `UV_CACHE_DIR=/tmp/uv-cache just compare 0x004b8d30`

### Changes
1. Converted promoted `TCapacityOrder` wrappers in `src/game/TCapacityOrder.cpp` to real class member methods (`TCapacityOrder::...`).
2. Kept thunk entrypoints as member wrappers that dispatch to member implementations.
3. Removed explicit `__thiscall` keywords from member declarations/definitions; this toolchain emits C4234 for explicit keyword usage even though member-call ABI still uses `thiscall`.

### Results
1. Build is green after conversion.
2. Per-function compare status:
   1. `0x00401c0d`: `100.00%`
   2. `0x00404093`: `0.00%`
   3. `0x00405ab5`: `100.00%`
   4. `0x004b8b80`: `30.89%`
   5. `0x004b8cc0`: `100.00%`
   6. `0x004b8d00`: `74.07%`
   7. `0x004b8d30`: `100.00%`
3. Class checkpoint: `4 / 7` at `100%` after moving into class-member form.

## 2026-03-01 20:09 UTC - `TGreatPower` initial promotion batch

### Commands
1. `just promote src/game/TGreatPower.cpp --address 0x00401172 ... --address 0x00405AC9` (23 addresses)
2. `just sync-ownership`
3. `just regen-stubs`
4. `just build`
5. `UV_CACHE_DIR=/tmp/uv-cache just detect`
6. `UV_CACHE_DIR=/tmp/uv-cache just compare 0x00401172`
7. `UV_CACHE_DIR=/tmp/uv-cache just compare 0x004014A6`
8. `UV_CACHE_DIR=/tmp/uv-cache just compare 0x00401AD2`
9. `UV_CACHE_DIR=/tmp/uv-cache just compare 0x00403C15`
10. `UV_CACHE_DIR=/tmp/uv-cache just compare 0x00404CE1`
11. `UV_CACHE_DIR=/tmp/uv-cache just compare 0x00405AC9`
12. `UV_CACHE_DIR=/tmp/uv-cache just stats`

### Changes
1. Added new manual class file: `src/game/TGreatPower.cpp`.
2. Promoted 23 `TGreatPower` addresses from `src/ghidra_autogen/TGreatPower.cpp` with ownership updates.
3. Replaced raw promoted decompiler blocks with compile-safe first-pass wrappers:
   1. member-method wrappers for `__thiscall`-style thunks,
   2. free wrappers for `__cdecl`/`__stdcall`-style thunks,
   3. direct forwarding to existing stub-backed target symbols (no inline asm).
4. Added `src/game/TGreatPower.cpp` to `CMakeLists.txt`.

### Results
1. Full loop is green:
   1. `just build` passed,
   2. `just detect` passed.
2. Targeted compare baseline:
   1. `0x00401172`: `100.00%`
   2. `0x004014A6`: `0.00%`
   3. `0x00401AD2`: `0.00%`
   4. `0x00403C15`: `0.00%`
   5. `0x00404CE1`: `0.00%`
   6. `0x00405AC9`: `0.00%`
3. Global stats snapshot:
   1. aligned functions: `79`
   2. average similarity: `2.57%`
   3. paired coverage: `100.00%`
   4. timestamp: `2026-03-01T20:09:37.204279+00:00`

## 2026-03-01 20:17 UTC - `TGreatPower` thunk-to-member routing pass

### Commands
1. `just build`
2. `UV_CACHE_DIR=/tmp/uv-cache just detect`
3. `UV_CACHE_DIR=/tmp/uv-cache just compare 0x00401172`
4. `UV_CACHE_DIR=/tmp/uv-cache just compare 0x004014A6`
5. `UV_CACHE_DIR=/tmp/uv-cache just compare 0x00401AD2`
6. `UV_CACHE_DIR=/tmp/uv-cache just compare 0x00403C15`
7. `UV_CACHE_DIR=/tmp/uv-cache just compare 0x00404CE1`
8. `UV_CACHE_DIR=/tmp/uv-cache just compare 0x00405AC9`

### Changes
1. Refactored `src/game/TGreatPower.cpp` so selected thunk wrappers call class member methods instead of inline call-through casts in each thunk body.
2. Moved call-through bridge casts into the corresponding class methods:
   1. `QueueMapActionMissionFromCandidateAndMarkState`
   2. `ComputeAdvisoryMapNodeScoreFactorByCaseMetric`
   3. `ExecuteAdvisoryPromptAndApplyActionType1`
   4. `TryDispatchNationActionViaUiContextOrFallback`
   5. `QueueInterNationEventType0FForNationPairContext`

### Results
1. Build and detect remain green.
2. Compare snapshot after refactor:
   1. `0x00401172`: `100.00%` (unchanged)
   2. `0x004014A6`: `0.00%` (unchanged)
   3. `0x00401AD2`: `0.00%` (unchanged)
   4. `0x00403C15`: `0.00%` (regressed from prior `66.67%`)
   5. `0x00404CE1`: `0.00%` (unchanged)
   6. `0x00405AC9`: `0.00%` (unchanged)
3. Interpretation: structural class-routing requirement is now satisfied, but wrapper indirection in this shape hurts at least one thunk; next pass should move these toward direct class-owned body reconstruction (not bridge-only wrappers).

## 2026-03-01 21:50 UTC - `TGreatPower` class-owned first-pass body attempt

### Commands
1. `just build`
2. `UV_CACHE_DIR=/tmp/uv-cache just detect`
3. `UV_CACHE_DIR=/tmp/uv-cache just compare 0x00401172`
4. `UV_CACHE_DIR=/tmp/uv-cache just compare 0x004014A6`
5. `UV_CACHE_DIR=/tmp/uv-cache just compare 0x00401AD2`
6. `UV_CACHE_DIR=/tmp/uv-cache just compare 0x00403C15`
7. `UV_CACHE_DIR=/tmp/uv-cache just compare 0x00404CE1`
8. `UV_CACHE_DIR=/tmp/uv-cache just compare 0x00405AC9`
9. `UV_CACHE_DIR=/tmp/uv-cache just stats`

### Changes
1. Reworked `src/game/TGreatPower.cpp` to keep target functions class-owned while avoiding unresolved-symbol churn:
   1. switched global-state access in new class bodies to fixed-address reads (`0x6A21BC`, `0x6A4280`, `0x6A43D0`) instead of typed extern globals,
   2. added first-pass class-owned bodies for:
      1. `0x00403C15` `thunk_ExecuteAdvisoryPromptAndApplyActionType1_At00403c15`,
      2. `0x00404CE1` `thunk_TryDispatchNationActionViaUiContextOrFallback_At00404ce1`,
   3. kept `0x004014A6`, `0x00401AD2`, `0x00405AC9` as class thunks with bridge calls for compile stability.
2. Fixed compile/link breakages introduced during this pass:
   1. resolved unresolved externals by removing type-mangled extern globals,
   2. corrected local call-signature typing (`slot21` return type).

### Results
1. Full loop is green again (`build`, `detect`, targeted compares, `stats` all succeeded).
2. Targeted compare status after class-owned body attempt:
   1. `0x00401172`: `100.00%`
   2. `0x004014A6`: `0.00%`
   3. `0x00401AD2`: `0.00%`
   4. `0x00403C15`: `0.00%`
   5. `0x00404CE1`: `0.00%`
   6. `0x00405AC9`: `0.00%`
3. Global snapshot:
   1. aligned functions: `79 / 12973`
   2. average similarity: `2.57%`
4. Interpretation:
   1. class-ownership goal was achieved for these methods with a clean build,
   2. this specific first-pass body shape did not improve similarity on the selected addresses.

## 2026-03-01 22:05 UTC - `TGreatPower` thunk + real-address split

### Commands
1. `just sync-ownership`
2. `just regen-stubs`
3. `just build`
4. `UV_CACHE_DIR=/tmp/uv-cache just detect`
5. `UV_CACHE_DIR=/tmp/uv-cache just compare 0x00403C15`
6. `UV_CACHE_DIR=/tmp/uv-cache just compare 0x00404CE1`
7. `UV_CACHE_DIR=/tmp/uv-cache just compare 0x00405AC9`
8. `UV_CACHE_DIR=/tmp/uv-cache just compare 0x004E1D50`
9. `UV_CACHE_DIR=/tmp/uv-cache just compare 0x004DDBB0`
10. `UV_CACHE_DIR=/tmp/uv-cache just compare 0x004DDA90`
11. `UV_CACHE_DIR=/tmp/uv-cache just compare 0x004E8540`
12. `UV_CACHE_DIR=/tmp/uv-cache just compare 0x004E8750`
13. `UV_CACHE_DIR=/tmp/uv-cache just stats`

### Changes
1. Kept thunk indirection at thunk addresses:
   1. `0x00403C15` (`TGreatPower::thunk_ExecuteAdvisoryPromptAndApplyActionType1_At00403c15`)
   2. `0x00404CE1` (`TGreatPower::thunk_TryDispatchNationActionViaUiContextOrFallback_At00404ce1`)
   3. `0x00405AC9` (`TGreatPower::thunk_QueueInterNationEventType0FForNationPairContext_At00405ac9`)
2. Added real-code addresses from Ghidra with `// FUNCTION` markers:
   1. `0x004E1D50` (`ExecuteAdvisoryPromptAndApplyActionType1`)
   2. `0x004DDBB0` (`TryDispatchNationActionViaUiContextOrFallback`)
   3. `0x004DDA90` (`TGreatPower::QueueInterNationEventType0FForNationPairContext`)
   4. `0x004E8540` (`TGreatPower::QueueMapActionMissionFromCandidateAndMarkState`)
   5. `0x004E8750` (`TGreatPower::ComputeAdvisoryMapNodeScoreFactorByCaseMetric`)
3. Avoided fragile typed-extern global linkages by reading these globals through symbol-backed fixed addresses:
   1. `0x006A21BC` (`g_pUiRuntimeContext`)
   2. `0x006A4280` (`g_apSecondaryNationStateSlots`)
   3. `0x006A43D0` (`g_pDiplomacyTurnStateManager`)

### Results
1. Build/detect loop is green again.
2. Targeted compare snapshot:
   1. `0x00403C15`: `66.67%`
   2. `0x00404CE1`: `0.00%`
   3. `0x00405AC9`: `0.00%`
   4. `0x004E1D50`: `20.32%`
   5. `0x004DDBB0`: `35.42%`
   6. `0x004DDA90`: `0.00%`
   7. `0x004E8540`: `25.00%`
   8. `0x004E8750`: `0.00%`
3. Global metric delta:
   1. average similarity: `2.59%` (`+0.20 pp` from the broken intermediate state).

## 2026-03-02 17:11 UTC - `TGreatPower` targeted similarity pass (`0x4E8540`, `0x4DDA90`)

### Commands
1. `just build`
2. `just detect`
3. `just compare 0x004E8750`
4. `just compare 0x004E8540`
5. `just compare 0x004DDA90`
6. `just compare 0x004DDBB0`

### Changes
1. `0x004E8540` (`QueueMapActionMissionFromCandidateAndMarkState`) shape pass:
   1. removed mission-queue null guard branch,
   2. restored fail-and-continue nil path with `MessageBoxA` and `thunk_TemporarilyClearAndRestoreUiInvalidationFlag`,
   3. kept candidate-state updates in original order (`+0x970` / `+0xAF0` writes).
2. `0x004DDA90` (`QueueInterNationEventType0FForNationPairContext`) shape pass:
   1. removed queue-manager null guard,
   2. collapsed to direct thunk dispatch with fixed-address queue manager read.
3. `0x004E8750` experiment notes:
   1. attempted broad case expansion (cases `3/4/7`) regressed and was rolled back,
   2. retained prior higher-scoring baseline implementation.
4. `0x004DDBB0` experiment notes:
   1. argument-shape rewrite regressed and was rolled back to guarded baseline.

### Results
1. `0x004E8540`: `21.58% -> 44.16%` (`+22.58 pp`)
2. `0x004DDA90`: `20.51% -> 26.67%` (`+6.16 pp`)
3. `0x004E8750`: `34.25%` (baseline retained after rollback)
4. `0x004DDBB0`: `37.89%` (higher than pre-pass baseline)
5. Build/detect loop remains green after all rollbacks and retained changes.

## 2026-03-02 18:02 UTC - `TGreatPower` non-zero body expansion (`0x4DDFC0`, `0x4E9060`, `0x4DC9F0`, `0x4DBD20`)

### Commands
1. `just promote src/game/TGreatPower.cpp --address 0x00407392 --overwrite-existing`
2. `just promote src/game/TGreatPower.cpp --address 0x004DDFC0 --address 0x004E9060`
3. `just sync-ownership`
4. `just regen-stubs`
5. `just build`
6. `just detect`
7. `just compare 0x00406915`
8. `just compare 0x004070E5`
9. `just compare 0x00407DB0`
10. `just compare 0x004097FF`
11. `just compare 0x004DDFC0`
12. `just compare 0x004E9060`
13. `just compare 0x004DC9F0`
14. `just compare 0x004DBD20`
15. `just stats`

### Changes
1. Converted zero wrappers to real member-forwarding in `src/game/TGreatPower.cpp`:
   1. `0x00406915` -> `ComputeMapActionContextCompositeScoreForNation`.
   2. `0x004070E5` -> `ApplyDiplomacyPolicyStateForTargetWithCostChecks`.
   3. `0x00407DB0` -> `RefreshGreatPowerRelationPanelsAndDispatchDeltaSummary`.
   4. `0x004097FF` -> `RebuildNationResourceYieldCountersAndDevelopmentTargets`.
2. Added/ported non-zero member bodies at real addresses:
   1. `0x004DDFC0` (`ApplyDiplomacyPolicyStateForTargetWithCostChecks`).
   2. `0x004E9060` (`ComputeMapActionContextCompositeScoreForNation`).
   3. `0x004DC9F0` (`RefreshGreatPowerRelationPanelsAndDispatchDeltaSummary`).
   4. `0x004DBD20` (`RebuildNationResourceYieldCountersAndDevelopmentTargets`).
3. Repeated `sync-ownership + regen-stubs` after each manual marker addition to prevent stale stub ownership from shadowing manual implementations in reccmp compares.

### Results
1. Targeted compares:
   1. `0x004DDFC0`: `25.77%`.
   2. `0x004E9060`: `9.52%`.
   3. `0x004DC9F0`: `57.63%`.
   4. `0x004DBD20`: `13.74%`.
2. Project-wide stats (`just stats`):
   1. aligned functions: `86` (`+7`).
   2. not aligned vs original: `12887` (`-7`).
   3. average similarity: `2.67%` (`+0.08 pp`).
3. Build/detect stayed green across the full pass.

## 2026-03-02 18:20 UTC - `TGreatPower` shape pass + real-body split (`0x4E9060`, `0x4DEDF0`, `0x40862A`)

### Commands
1. `just compare 0x004E9060`
2. `just compare 0x004DDFC0`
3. `just format src/game/TGreatPower.cpp`
4. `just build`
5. `just detect`
6. `just compare 0x004E9060`
7. `just promote src/game/TGreatPower.cpp --address 0x0040862A --overwrite-existing`
8. `just sync-ownership`
9. `just regen-stubs`
10. `just build`
11. `just detect`
12. `just compare 0x004DEDF0`
13. `just compare 0x0040862A`
14. `just compare 0x004DC9F0`
15. `just stats`

### Changes
1. `0x004E9060` (`ComputeMapActionContextCompositeScoreForNation`) shape/data pass:
   1. fixed advisory-factor thunk arity to 4 args and forwarded `selectedCandidateIndex`,
   2. corrected relationship-list init/list-call shape (`+0x2C` path),
   3. narrowed candidate-priority scratch loop to 7-slot form for this pass.
2. Promoted `0x0040862A` block from Ghidra and normalized it into manual style.
3. Split thunk-vs-real ownership for immediate diplomacy side effects:
   1. `0x0040862A` kept as thunk wrapper,
   2. real implementation moved to `0x004DEDF0` (`ApplyImmediateDiplomacyPolicySideEffects`).
4. Ran `just sync-ownership && just regen-stubs` after new markers to remove dropped-duplicate-address conflicts.

### Results
1. `0x004E9060`: `24.90% -> 30.99%`.
2. `0x004DEDF0`: `0.00% -> 17.79%` (manual body now active).
3. `0x0040862A`: remains `0.00%` (pure-jump thunk shape still unresolved in no-inline-asm policy).
4. Stability anchors:
   1. `0x004DC9F0`: still `100%`,
   2. `0x004DDFC0`: still `25.77%`.
5. `just stats`: average similarity `2.68%` (small uptick), aligned count unchanged (`87`).

## 2026-03-02 18:28 UTC - `TGreatPower` `0x4DEDF0` prologue/register pass

### Commands
1. `just format src/game/TGreatPower.cpp`
2. `just build`
3. `just detect`
4. `just compare 0x004DEDF0`
5. `just compare 0x004E9060`

### Changes
1. Added local `#pragma optimize("y", on)` around `0x004DEDF0` (`ApplyImmediateDiplomacyPolicySideEffects`) to reduce frame-prologue drift under `/Oy-` baseline.

### Results
1. `0x004DEDF0`: `17.79% -> 19.93%`.
2. `0x004E9060`: stable at `30.99%`.
3. Build/detect remained green.

## 2026-03-02 18:27 UTC - `TGreatPower` additional function ports (`0x4E7B50`, `0x4E7C50`)

### Commands
1. `just format src/game/TGreatPower.cpp`
2. `just build`
3. `just detect`
4. `just compare 0x004E7B50`
5. `just compare 0x004E7C50`
6. `just sync-ownership`
7. `just regen-stubs`
8. `just build`
9. `just detect`
10. `just compare 0x004E7B50`
11. `just compare 0x004E7C50`
12. `just compare 0x004DEDF0`
13. `just stats`

### Changes
1. Added manual implementations in `src/game/TGreatPower.cpp`:
   1. `0x004E7B50` `QueueDiplomacyProposalCodeWithAllianceGuards`.
   2. `0x004E7C50` `ApplyImmediateDiplomacyPolicySideEffectsWithSelectionHook`.
2. Added corresponding member declarations to `class TGreatPower` in the same file.
3. Ran ownership + stub regeneration so reccmp binds these addresses to manual code (not generated stubs).

### Results
1. `0x004E7B50`: `29.73%`.
2. `0x004E7C50`: `50.00%`.
3. Anchor check:
   1. `0x004DEDF0`: `19.93%` (stable).
4. `just stats`:
   1. aligned functions: `87` (no change),
   2. average similarity: `2.68%` (`+0.01 pp`).

## 2026-03-02 18:29 UTC - `TGreatPower` diplomacy queue pair (`0x4083F5`, `0x4DEFD0`)

### Commands
1. `just format src/game/TGreatPower.cpp`
2. `just sync-ownership`
3. `just regen-stubs`
4. `just build`
5. `just detect`
6. `just compare 0x004083F5`
7. `just compare 0x004DEFD0`
8. `just compare 0x004E7B50`
9. `just compare 0x004E7C50`
10. `just stats`

### Changes
1. Replaced `0x004083F5` placeholder with member-forward thunk to `QueueDiplomacyProposalCodeForTargetNation`.
2. Added first-pass manual body for `0x004DEFD0` (`QueueDiplomacyProposalCodeForTargetNation`) with queue object `+0x84C` and vtable slot `+0x38` dispatch.
3. Added corresponding member declaration and removed unused global prototype in `src/game/TGreatPower.cpp`.
4. Re-ran ownership/stub sync to ensure both addresses map to manual code.

### Results
1. `0x004083F5`: `100.00%`.
2. `0x004DEFD0`: `29.63%`.
3. `0x004E7B50`: `29.73%` (stable).
4. `0x004E7C50`: `50.00%` (stable).
5. `just stats`:
   1. aligned functions: `88` (`+1`),
   2. not aligned vs original: `12885` (`-1`),
   3. average similarity: `2.70%` (`+0.01 pp`).

## 2026-03-02 18:35 UTC - `TGreatPower` method ports (`0x4DD470`, `0x4DF5C0`) + thunk wiring

### Commands
1. `just promote src/game/TGreatPower.cpp --address 0x004DD470 --address 0x004DF5C0`
2. `just format src/game/TGreatPower.cpp`
3. `just sync-ownership`
4. `just regen-stubs`
5. `just build`
6. `just detect`
7. `just compare 0x00406FE1`
8. `just compare 0x00408017`
9. `just compare 0x00408076`
10. `just compare 0x004DD470`
11. `just compare 0x004DF5C0`
12. `just stats`

### Changes
1. Promoted real Ghidra bodies and normalized to compile-safe manual code:
   1. `0x004DD470` `ResetDiplomacyNeedSlots7012AndRefreshIfModeGateMatches`.
   2. `0x004DF5C0` `DispatchTurnEvent2103WithNationFromRecord`.
2. Replaced no-op thunk bodies with real dispatch paths:
   1. `0x00408017` now forwards to `0x004DD470`.
   2. `0x00408076` now forwards to `0x004DF5C0`.
   3. `0x00406FE1` now performs queue-transition + secondary-slot update path (first pass).
3. Kept `0x004085EE` as no-op after unresolved-symbol attempt; retained build stability.
4. Converted promoted `GHIDRA_FUNCTION` markers to `FUNCTION` markers and re-synced ownership/stubs.

### Results
1. `0x00408017`: `100.00%`.
2. `0x00408076`: `100.00%`.
3. `just stats`:
   1. aligned functions: `90` (`+2`),
   2. not aligned vs original: `12883` (`-2`),
   3. average similarity: `2.72%` (`+0.03 pp`).

## 2026-03-02 18:38 UTC - `TGreatPower` first-pass body import (`0x4E73F0`)

### Commands
1. `just format src/game/TGreatPower.cpp`
2. `just sync-ownership`
3. `just regen-stubs`
4. `just build` (failed once with `C2374`, then fixed and reran)
5. `just detect`
6. `just compare 0x004E73F0`
7. `just stats`

### Changes
1. Added manual owned body for `0x004E73F0` `WrapperFor_HandleCityDialogHintClusterUpdate_At004e73f0`.
2. Preserved first-pass call order:
   1. pre-handler call (`0x00408143`),
   2. six short payload writes from `+0x964`,
   3. `+0x970`/`+0xAF0` blob writes,
   4. queue apply/refresh (`+0x14`/`+0x48`),
   5. queue replay loop over `1..0x70` through message slot `+0xB4`.
3. Compile-only fix for MSVC500 loop-variable redeclaration (`for (int i)` -> `for (int j)`).

### Results
1. Build/detect remained green after normalization.
2. `just stats`: no aggregate movement in this pass (`aligned 90`, `avg 2.72%`), which is expected for a heavy first-pass wrapper body before ABI/prologue tuning.

## 2026-03-02 18:47 UTC - `TGreatPower` large-body ports (`0x4DE860`, `0x4DF5F0`)

### Commands
1. `just format src/game/TGreatPower.cpp`
2. `just sync-ownership`
3. `just regen-stubs`
4. `just build`
5. `just detect`
6. `just compare 0x00401CBC`
7. `just compare 0x004097FA`
8. `just compare 0x004DE860`
9. `just compare 0x004DF5F0`
10. `just stats`

### Changes
1. Added real method implementations in `src/game/TGreatPower.cpp`:
   1. `0x004DE860` `ApplyJoinEmpireMode0GlobalDiplomacyReset`.
   2. `0x004DF5F0` `ProcessPendingDiplomacyProposalQueue`.
2. Rewired thunk entries to real methods:
   1. `0x00401CBC` now calls member `ProcessPendingDiplomacyProposalQueue`.
   2. `0x004097FA` now calls member `ApplyJoinEmpireMode0GlobalDiplomacyReset`.
3. Added helper thunk declarations + address constants needed for these bodies.
4. Fixed one compile regression (`C2197` wrong call arity) by correcting `DipSlot28Fn` signature in the new reset body.

### Results
1. Build/detect: pass.
2. Compare snapshot:
   1. `0x004DE860`: `26.16%`.
   2. `0x004DF5F0`: `9.49%`.
   3. `0x00401CBC`: `100.00%` (thunk wrapper).
   4. `0x004097FA`: `0.00%` (thunk wrapper still call-shape mismatch).
3. `just stats`:
   1. aligned functions: `90` (unchanged),
   2. average similarity: `2.73%` (small uptick).

## 2026-03-02 18:50 UTC - `TGreatPower` additional body pass (`0x406CA3`)

### Commands
1. `just format src/game/TGreatPower.cpp`
2. `just build`
3. `just detect`
4. `just compare 0x00406CA3`
5. `just stats`

### Changes
1. Replaced `0x00406CA3` no-op with a first-pass relation-summary body:
   1. mode gate via slot `+0x28`,
   2. localization-based threshold gate,
   3. diplomacy matrix scan (`thisSlot * 0x17 + slot`) for hostile/positive counters,
   4. writes aggregate counters back to runtime fields.

### Results
1. Build/detect: pass.
2. `0x00406CA3`: still `0.00%` in this simplified pass.
3. `just stats`: no aggregate movement (`aligned 90`, avg similarity `2.73%`).
4. Decision: keep this owned implementation for now and defer deep SEH/string-shape tuning; continue prioritizing high-throughput large functions that produce immediate non-zero scores.

## 2026-03-02 19:03 UTC - `TGreatPower` runtime-subsystem init body (`0x4D8CC0`)

### Commands
1. `just build`
2. `just detect`
3. `just compare 0x004D8CC0` (initial run showed duplicate annotation against stubs)
4. `just sync-ownership`
5. `just regen-stubs`
6. `just build`
7. `just detect`
8. `just compare 0x004D8CC0`
9. `just compare 0x004DE860`
10. `just compare 0x004DF5F0`
11. `just compare 0x00409291`
12. `just stats`

### Changes
1. Added real method body `0x004D8CC0` `InitializeNationStateRuntimeSubsystems` in `src/game/TGreatPower.cpp`.
2. Preserved first-pass subsystem shape from Ghidra:
   1. nation identity bootstrap call,
   2. runtime-cache lookup from localization slot `+0x40`,
   3. city model + production init,
   4. minister object allocation/constructor/init calls,
   5. repeated pointer-list allocations (`+0x848/+0x84C/+0x850..`),
   6. diplomacy arrays reset (`+0xB2/+0xE0/+0x918`),
   7. late list objects (`+0x89C/+0x908/+0x90C`) and default flags.
3. Fixed compare plumbing for new address ownership by re-running `just sync-ownership` and `just regen-stubs` before compare.

### Results
1. `0x004D8CC0`: `32.14%`.
2. Adjacent checks stayed stable:
   1. `0x004DE860`: `26.16%`.
   2. `0x004DF5F0`: `9.49%`.
3. `0x00409291` remained `0.00%` (expected thin thunk call-shape mismatch; real body address owns meaningful similarity now).
4. `just stats`: aggregate unchanged (`aligned 90`, average similarity `2.73%`).

## 2026-03-02 19:06 UTC - `TGreatPower` release-owned-objects body (`0x4D9160`)

### Commands
1. `just build`
2. `just sync-ownership`
3. `just regen-stubs`
4. `just build`
5. `just detect`
6. `just compare 0x004D9160`
7. `just compare 0x00405DE4`
8. `just compare 0x004D8CC0`
9. `just stats`

### Changes
1. Added real method body `0x004D9160` `ReleaseOwnedGreatPowerObjectsAndDeleteSelf`.
2. Converted `0x00405DE4` `TGreatPower_VtblSlot07` to dispatch through the new class method (same semantic role, no free-function fallback).
3. Implemented first-pass owned-release flow:
   1. releases major pointers using vtable slots `+0x1C/+0x24/+0x38/+0x58`,
   2. clears the `+0x850` pointer array in loop,
   3. releases/clears `+0x898/+0x89C/+0x908/+0x90C/+0x44/+0x90`,
   4. final delete-style virtual dispatch through `field00[1]` with argument `1`.

### Results
1. `0x004D9160`: `37.38%`.
2. `0x00405DE4`: remained `100.00%` after dispatch conversion.
3. `0x004D8CC0`: remained `32.14%`.
4. `just stats`: aggregate unchanged (`aligned 90`, average similarity `2.73%`).

## 2026-03-02 19:37 UTC - `TGreatPower` typed field-layout extraction pass

### Commands
1. `just format src/game/TGreatPower.cpp`
2. `just build`
3. `just detect`
4. `just compare 0x004D92E0`
5. `just compare 0x004DB380`
6. `just compare 0x004DBF00`

### Changes
1. Expanded `class TGreatPower` from a minimal shell to an offset-accurate layout covering the active runtime region up to `+0x960`, with typed members and explicit padding gaps.
2. Migrated class-state access from raw `self + offset` expressions to typed members in high-impact methods:
   1. `ReleaseOwnedGreatPowerObjectsAndDeleteSelf` (`0x004D9160`)
   2. `InitializeGreatPowerMinisterRosterAndScenarioState` (`0x004D92E0`)
   3. `UpdateGreatPowerPressureStateAndDispatchEscalationMessage` (`0x004DB380`)
   4. `AdvanceOwnedRegionDevelopmentCountersAndDispatchEvents` (`0x004DBF00`)
3. Kept function bodies compile-safe and shape-preserving (no inline asm / no callconv hacks), while replacing owned fields with named members (`pField848`, `field8f0`, `fieldB2`, etc.).

### Results
1. Build/detect loop is stable after the layout migration.
2. `0x004D92E0`: unchanged at `3.12%` (expected for a layout-only refactor).
3. `0x004DB380` and `0x004DBF00`: still unresolved in compare (`Failed to find a match at address`), which is currently a pairing/reachability issue rather than compilation.

## 2026-03-02 19:52 UTC - fixed reccmp pairing for `0x004DB380` and `0x004DBF00`

### Commands
1. `just build`
2. `just detect`
3. `just compare 0x004DB380`
4. `just compare 0x004DBF00`

### Root cause
1. `// FUNCTION:` markers for these two methods had descriptive comment lines between marker and signature.
2. reccmp parsed the next line as function identity and used the comment text as function name, causing `Failed to match function` / `Failed to find a match at address`.

### Fix
1. Moved descriptive comments above each marker and kept marker directly adjacent to function signature in `src/game/TGreatPower.cpp`.

### Results
1. `0x004DB380`: now paired and compared at `14.47%`.
2. `0x004DBF00`: now paired and compared at `27.79%`.

## 2026-03-02 20:40 UTC - readability pass with score guardrails (`TGreatPower`)

### Commands
1. `just compare 0x004D92E0`
2. `just compare 0x004DB380`
3. `just compare 0x004DBD20`
4. `just compare 0x004DBF00`
5. `just format src/game/TGreatPower.cpp`
6. `just build`
7. `just compare 0x004D92E0`
8. `just compare 0x004DB380`
9. `just compare 0x004DBD20`
10. `just compare 0x004DBF00`

### Changes
1. Tried a typed-view cleanup in `0x004DBD20`; score dropped (`13.74% -> 11.76%`), so reverted it.
2. Kept only naming-level cleanup in `0x004DBF00`:
   1. clearer typedef names (`RegionListCountFn`, `GlobalMapMetricFn`, etc.),
   2. clearer local names (`regionOrdinal`, `pendingStage`, `needsRedraw`, `orderCapabilityState`).
3. No control-flow or call-shape changes kept in final code.

### Results
1. `0x004D92E0`: `3.12%` (unchanged).
2. `0x004DB380`: `14.47%` (unchanged).
3. `0x004DBD20`: `13.74%` (restored to baseline).
4. `0x004DBF00`: `27.79%` (unchanged).

## 2026-03-02 20:48 UTC - post-commit readability iteration (`TGreatPower`)

### Commands
1. `just format src/game/TGreatPower.cpp`
2. `just build`
3. `just compare 0x004DDFC0`
4. `just compare 0x004D92E0`
5. `just compare 0x004DB380`
6. `just compare 0x004DBD20`
7. `just compare 0x004DBF00`

### Changes
1. `0x004DB380` (`UpdateGreatPowerPressureStateAndDispatchEscalationMessage`):
   1. renamed internal typedef/locals for intent (`GreatPowerGetIntFn`, `basePressure`, `pressureBand`, `pressureCounter`, `escalationCounter`, `drainAmount`).
2. `0x004DBF00` (`AdvanceOwnedRegionDevelopmentCountersAndDispatchEvents`):
   1. introduced named aliases for stage counters (`stage1CounterA/B/C/D`, `stage2CounterA/B/C`) and reused them in stage checks/updates.
3. `0x004DBD20` (`RebuildNationResourceYieldCountersAndDevelopmentTargets`):
   1. replaced raw terrain/city offsets with named constants (`kTerrainResourceTypeOffset`, `kTerrainGateFlagOffset`, etc.).
4. `0x004DDFC0` (`ApplyDiplomacyPolicyStateForTargetWithCostChecks`):
   1. removed raw self-offset accesses in favor of typed members (`fieldB2`, `fieldA0`).

### Results
1. `0x004DDFC0`: `25.77%` -> `25.77%` (unchanged).
2. Anchors unchanged:
   1. `0x004D92E0`: `3.12%`
   2. `0x004DB380`: `14.47%`
   3. `0x004DBD20`: `13.74%`
   4. `0x004DBF00`: `27.79%`

## 2026-03-02 20:55 UTC - cleanup pass on `0x004DE860` and `0x004DEDF0`

### Commands
1. `just format src/game/TGreatPower.cpp`
2. `just build`
3. `just compare 0x004DE860`
4. `just compare 0x004DEDF0`
5. `just compare 0x004DDFC0`
6. `just compare 0x004DB380`
7. `just compare 0x004DBD20`
8. `just compare 0x004DBF00`

### Changes
1. `0x004DE860` (`ApplyJoinEmpireMode0GlobalDiplomacyReset`):
   1. replaced a large `self + offset` block with typed member access (`field0e`, `field10`, `pField94/pField98/pField9c`, `fieldA2..fieldB0`, `fieldB2`, `fieldE0`, `field10e..field250`, `field280`, `field840/field844`, `pField84c`, `pField848`, `pField894`),
   2. kept unknown byte-slices (`+0x14`, `+0x8A0`) as raw memory access only,
   3. added local constants for repeated diplomacy/policy literals.
2. `0x004DEDF0` (`ApplyImmediateDiplomacyPolicySideEffects`):
   1. removed raw `self +` reads for `fieldA0` and `pField848`,
   2. added local constants for policy codes and loop bounds.

### Results
1. `0x004DE860`: `26.16%` -> `26.42%` (improved).
2. `0x004DEDF0`: `19.93%` -> `19.93%` (unchanged).
3. Other tracked functions unchanged:
   1. `0x004DDFC0`: `25.77%`
   2. `0x004DB380`: `14.47%`
   3. `0x004DBD20`: `13.74%`
   4. `0x004DBF00`: `27.79%`

## 2026-03-02 20:57 UTC - small typed-member cleanup (`0x004DEFD0`)

### Commands
1. `just format src/game/TGreatPower.cpp`
2. `just build`
3. `just compare 0x004DEFD0`
4. `just compare 0x004DE860`
5. `just compare 0x004DEDF0`
6. `just compare 0x004DB380`
7. `just compare 0x004DBD20`
8. `just compare 0x004DBF00`

### Changes
1. `0x004DEFD0` (`QueueDiplomacyProposalCodeForTargetNation`):
   1. replaced raw `this + 0x84C` with `this->pField84c`.

### Results
1. `0x004DEFD0`: `29.63%` (new tracked local score; no observed regression from this cleanup).
2. Existing tracked scores remained unchanged:
   1. `0x004DE860`: `26.42%`
   2. `0x004DEDF0`: `19.93%`
   3. `0x004DB380`: `14.47%`
   4. `0x004DBD20`: `13.74%`
   5. `0x004DBF00`: `27.79%`

## 2026-03-02 20:59 UTC - typed-member cleanup in `0x004DF5F0`

### Commands
1. `just format src/game/TGreatPower.cpp`
2. `just build`
3. `just compare 0x004DF5F0`
4. `just compare 0x004DEFD0`
5. `just compare 0x004DE860`
6. `just compare 0x004DEDF0`
7. `just compare 0x004DB380`
8. `just compare 0x004DBD20`
9. `just compare 0x004DBF00`

### Changes
1. `0x004DF5F0` (`ProcessPendingDiplomacyProposalQueue`):
   1. replaced raw queue pointer load (`this + 0x84C`) with `this->pField84c`,
   2. replaced raw policy lookup (`this + 0xB2 + idx*2`) with `this->fieldB2[idx]`.

### Results
1. `0x004DF5F0`: remained `9.49%`.
2. Tracked neighboring scores remained unchanged:
   1. `0x004DEFD0`: `29.63%`
   2. `0x004DE860`: `26.42%`
   3. `0x004DEDF0`: `19.93%`
   4. `0x004DB380`: `14.47%`
   5. `0x004DBD20`: `13.74%`
   6. `0x004DBF00`: `27.79%`

## 2026-03-02 21:03 UTC - batched cleanup pass (`0x004E73F0`, `0x004DF5F0`, `0x004DE860`)

### Commands
1. `just format src/game/TGreatPower.cpp`
2. `just build`
3. `just compare 0x004E73F0`
4. `just compare 0x004DF5F0`
5. `just compare 0x004DEFD0`
6. `just compare 0x004DE860`
7. `just compare 0x004DEDF0`
8. `just compare 0x004DB380`
9. `just compare 0x004DBD20`
10. `just compare 0x004DBF00`

### Changes
1. Extended `TGreatPower` tail layout past `+0x960`:
   1. `field964[6]`,
   2. `field970[0x180]`,
   3. `fieldAF0[0x70]`,
   4. `pFieldB60`.
2. `0x004E73F0` (`WrapperFor_HandleCityDialogHintClusterUpdate_At004e73f0`):
   1. replaced raw offsets `+0x964`, `+0x970`, `+0xAF0`, `+0xB60` with typed members.
3. `0x004DE860` (`ApplyJoinEmpireMode0GlobalDiplomacyReset`):
   1. replaced remaining `0x17` loop bound with `kNationSlotCount`.
4. `0x004DEFD0` (`QueueDiplomacyProposalCodeForTargetNation`):
   1. simplified payload initialization to `{0, 0}`.
5. `0x004DF5F0` (`ProcessPendingDiplomacyProposalQueue`):
   1. introduced local constants for major nation count and policy codes,
   2. replaced char-literal control flags with `0/1`,
   3. kept call/branch shape unchanged.

### Results
1. New tracked function:
   1. `0x004E73F0`: `9.66%`.
2. Existing tracked functions unchanged:
   1. `0x004DF5F0`: `9.49%`
   2. `0x004DEFD0`: `29.63%`
   3. `0x004DE860`: `26.42%`
   4. `0x004DEDF0`: `19.93%`
   5. `0x004DB380`: `14.47%`
   6. `0x004DBD20`: `13.74%`
   7. `0x004DBF00`: `27.79%`

## 2026-03-02 21:05 UTC - second batched cleanup pass (`0x004DF5F0` naming + literals)

### Commands
1. `just format src/game/TGreatPower.cpp`
2. `just build`
3. `just compare 0x004DF5F0`
4. `just compare 0x004E73F0`
5. `just compare 0x004DE860`
6. `just compare 0x004DEDF0`
7. `just compare 0x004DB380`
8. `just compare 0x004DBD20`
9. `just compare 0x004DBF00`

### Changes
1. `0x004DF5F0` (`ProcessPendingDiplomacyProposalQueue`):
   1. renamed queue/proposal counters and handler fn locals for readability (`queueIndex`, `proposalIndex`, `applyProposalByIndex`, `removeProposalByIndex`, `applyPolicyToNation`),
   2. normalized commit flag usage to `0/1`,
   3. added local constants for proposal codes and major-nation loop bound.
2. No control-flow or call-order changes.

### Results
1. Scores unchanged on touched and anchor functions:
   1. `0x004DF5F0`: `9.49%`
   2. `0x004E73F0`: `9.66%`
   3. `0x004DE860`: `26.42%`
   4. `0x004DEDF0`: `19.93%`
   5. `0x004DB380`: `14.47%`
   6. `0x004DBD20`: `13.74%`
   7. `0x004DBF00`: `27.79%`

## 2026-03-02 21:07 UTC - logic-shape cleanup in `0x004DE860`

### Commands
1. `just format src/game/TGreatPower.cpp`
2. `just build`
3. `just compare 0x004DE860`
4. `just compare 0x004DF5F0`
5. `just compare 0x004E73F0`
6. `just compare 0x004DB380`
7. `just compare 0x004DBD20`
8. `just compare 0x004DBF00`

### Changes
1. `0x004DE860` (`ApplyJoinEmpireMode0GlobalDiplomacyReset`):
   1. removed dead/unreachable normalization branches in secondary-owner handling,
   2. kept effective behavior explicit: when encoded owner state is `>= 200`, normalize via `-200` before ownership comparison.
2. This is a behavior-preserving control-flow cleanup of already-equivalent logic, not just naming.

### Results
1. `0x004DE860`: `26.42%` -> `28.52%` (improved).
2. Other tracked functions remained unchanged:
   1. `0x004DF5F0`: `9.49%`
   2. `0x004E73F0`: `9.66%`
   3. `0x004DEDF0`: `19.93%`
   4. `0x004DB380`: `14.47%`
   5. `0x004DBD20`: `13.74%`
   6. `0x004DBF00`: `27.79%`

## 2026-03-02 21:10 UTC - structural cleanup in `0x004DEDF0` (beyond naming)

### Commands
1. `just format src/game/TGreatPower.cpp`
2. `just build`
3. `just compare 0x004DEDF0`
4. `just compare 0x004DE860`
5. `just compare 0x004DF5F0`
6. `just compare 0x004E73F0`
7. `just compare 0x004DB380`
8. `just compare 0x004DBD20`
9. `just compare 0x004DBF00`

### Changes
1. `0x004DEDF0` (`ApplyImmediateDiplomacyPolicySideEffects`):
   1. hoisted repeated thunk/vtable casts into local typed callables (`isNationEligible`, `hasDipFlag84`, `getDipRelation`, `hasDipRelation`, `setDipState`, `applyPolicyToNation`),
   2. reused those callables across both policy loops to remove repeated cast-heavy expressions.
2. `0x004DE860` and `0x004DF5F0` remain on the new typed-member/constant shape from prior passes.

### Results
1. `0x004DEDF0`: `19.93%` -> `26.90%` (large improvement).
2. Other tracked scores unchanged:
   1. `0x004DE860`: `28.52%`
   2. `0x004DF5F0`: `9.49%`
   3. `0x004E73F0`: `9.66%`
   4. `0x004DB380`: `14.47%`
   5. `0x004DBD20`: `13.74%`
   6. `0x004DBF00`: `27.79%`

## 2026-03-02 21:24 UTC - deserializer/proposal-queue shape pass + thunk correction

### Commands
1. `just session-loop 20 200 20`
2. `just format src/game/TGreatPower.cpp`
3. `just build`
4. `just compare 0x004D92E0`
5. `just compare 0x004DF5F0`
6. `just compare 0x00406CA3`

### Changes
1. `0x004D92E0` (`InitializeGreatPowerMinisterRosterAndScenarioState`):
   1. corrected stream/count shape: parameter is treated as stream handle, and town loop count now comes from stream slot `+0x3C` return instead of pointer-value reuse,
   2. updated dependent branches (`townCount > 0`) and kept stream-handle pass-through to `pField90c` slot `+0x18`.
2. `0x004DF5F0` (`ProcessPendingDiplomacyProposalQueue`):
   1. added shared-string init/release envelope (`InitializeSharedStringRefFromEmpty` / `ReleaseSharedStringRefIfNotEmpty`) matching Ghidra shape,
   2. switched queue gating to short proposal count semantics and `static_cast<short>(proposalIndex)` loop exit,
   3. aligned embargo/mutual-defense decision flow closer to Ghidra branch shape.
3. `0x00406CA3` (`BuildGreatPowerRelationshipDeltaSummaryAndDispatchMessage`):
   1. replaced incorrect full-body rewrite with a call-through wrapper to `CompileGreatPowerRelationshipDeltaLinesAndDispatchMessage` (thunk shape).

### Results
1. `0x00406CA3`: `0.00%` -> `66.67%` (major fix; was implemented as wrong function kind).
2. `0x004DF5F0`: `9.49%` -> `10.60%`.
3. `0x004D92E0`: `3.12%` -> `3.13%` (small positive movement).
4. No regressions observed on sampled neighboring `TGreatPower` anchors in this pass:
   1. `0x004DE860`: `28.52%`
   2. `0x004DEDF0`: `26.90%`

## 2026-03-02 21:29 UTC - high-impact stream-shape pass in `0x004D92E0`

### Commands
1. `just format src/game/TGreatPower.cpp`
2. `just build`
3. `just compare 0x004D92E0`
4. `just compare 0x004DF5F0`
5. `just compare 0x00406CA3`
6. `just compare 0x004DE860`
7. `just compare 0x004DEDF0`
8. `just stats`

### Changes
1. `0x004D92E0` (`InitializeGreatPowerMinisterRosterAndScenarioState`):
   1. removed stream/vtable null-guard branches and made stream slot reads unconditional (closer to original deserializer assumptions),
   2. kept previously-fixed `townCount` behavior (count from stream slot `+0x3C`) and short/int loop shape.
2. `0x004DF5F0` and `0x00406CA3` left on the prior improved shapes for regression checks.

### Results
1. `0x004D92E0`: `3.13%` -> `13.51%` (major improvement).
2. `0x004DF5F0`: `10.60%` (unchanged).
3. `0x00406CA3`: `66.67%` (unchanged).
4. `0x004DE860`: `28.52%` (unchanged).
5. `0x004DEDF0`: `26.90%` (unchanged).
6. Global `just stats` summary remained stable on aligned count (`90`) after this pass.

## 2026-03-02 22:00 UTC - cast-isolation + shape pass in `0x004DF5F0` and `0x004DEDF0`

### Commands
1. `just format src/game/TGreatPower.cpp`
2. `just build`
3. `just compare 0x004DF5F0`
4. `just compare 0x004DEDF0`
5. `just compare 0x004DE860`
6. `just compare 0x004D92E0`

### Changes
1. Added typed helper bridges at file scope for queue/diplomacy/UI calls:
   1. proposal queue slot reads and count,
   2. diplomacy slots `+0x44`, `+0x70`, `+0x7C`, `+0x84`,
   3. UI slot `+0x90`,
   4. event queue + turn-event13 dispatch,
   5. `field00` slot calls (`0x28`, `0x73`, `0x7B`, `0x7C`, `0xA1`).
2. `0x004DF5F0` (`ProcessPendingDiplomacyProposalQueue`):
   1. removed nested inline cast chains from the body and switched to helper calls,
   2. preserved queue/proposal loop and cooldown/embargo/mutual-defense branch shape.
3. `0x004DEDF0` (`ApplyImmediateDiplomacyPolicySideEffects`):
   1. switched cast-heavy body calls to typed helpers,
   2. removed defensive null-gates in the hot path where original shape calls directly (`pField848` queue write and diplomacy manager usage),
   3. kept policy branch semantics (`0x130`/`0x12E`) and slot-loop behavior.

### Results
1. `0x004DF5F0`: `10.60%` -> `30.15%`.
2. `0x004DEDF0`: `26.90%` -> `31.65%`.
3. Anchors checked for regressions:
   1. `0x004DE860`: `28.52%` (unchanged),
   2. `0x004D92E0`: `21.80%` (unchanged).

## 2026-03-02 22:03 UTC - helper extraction pass in `0x004DE860`

### Commands
1. `just format src/game/TGreatPower.cpp`
2. `just build`
3. `just compare 0x004DE860`
4. `just compare 0x004DEDF0`
5. `just compare 0x004DF5F0`

### Changes
1. Added typed helper bridges for repeated call patterns in `TGreatPower`:
   1. object release at vtable slot `+0x1C`,
   2. terrain/nation/secondary reset dispatches (`+0x68`, `+0x94`, `+0x48`),
   3. `field00` slots `0x5C`, `0xA5`, `0x12`, `0x75`,
   4. diplomacy slots `+0x74` and `+0x28`.
2. Rewired `0x004DE860` (`ApplyJoinEmpireMode0GlobalDiplomacyReset`) to use those helpers and removed branchy null-gate wrappers around diplomacy slot calls in the hot reset loops.
3. Preserved loop/control structure and reset constants; this was a cast-isolation/shape pass, not a semantic rewrite.

### Results
1. `0x004DE860`: `28.52%` -> `28.73%`.
2. Regression checks:
   1. `0x004DEDF0`: `31.65%` (unchanged),
   2. `0x004DF5F0`: `30.15%` (unchanged).

## 2026-03-02 22:35 UTC - reapply fuller `0x004DDFC0` + promote `0x004DF010` into real C++

### Commands
1. `just format src/game/TGreatPower.cpp`
2. `just build`
3. `just compare 0x004DDFC0`
4. `just promote src/game/TGreatPower.cpp --address 0x004DF010`
5. `just sync-ownership`
6. `just regen-stubs`
7. `just build`
8. `just compare 0x004DF010`
9. `just compare 0x004DDFC0`
10. `just compare 0x004DF5F0`

### Changes
1. Reapplied fuller branch coverage in `0x004DDFC0` (`ApplyDiplomacyPolicyStateForTargetWithCostChecks`) with explicit compatibility checks and policy-path handling.
2. Promoted `0x004DF010` with `just promote`, then replaced raw Ghidra output with compile-safe member-method C++:
   1. added `TGreatPower::ApplyAcceptedDiplomacyProposalCode(short)` declaration,
   2. added typed helper wrappers for this path (`slot13`, diplomacy `slot78`, event dedup queue, terrain `slot4C`, generic nation-state notify),
   3. preserved proposal switch shape and major side-effect paths (relation code updates, event queueing, alliance propagation loop, target nation callback).
3. Synced ownership and regenerated stubs so `0x004DF010` is owned only in manual source (no duplicate stub annotation).

### Results
1. `0x004DF010` (`ApplyAcceptedDiplomacyProposalCode`): now compiles and compares at `12.79%` (previously stub/zero-grade).
2. `0x004DDFC0`: `19.94%` after fuller reapply.
3. `0x004DF5F0`: `30.15%` unchanged (regression check).

## 2026-03-02 22:40 UTC - grant-path promotion pass in `TGreatPower`

### Commands
1. `just format src/game/TGreatPower.cpp`
2. `just sync-ownership`
3. `just regen-stubs`
4. `just build`
5. `just compare 0x004DE5E0`
6. `just compare 0x004DF010`
7. `just compare 0x004DF5F0`
8. `just compare 0x004DDFC0`
9. `just promote src/game/TGreatPower.cpp --address 0x004DE700`
10. `just promote src/game/TGreatPower.cpp --address 0x004DE790`
11. `just format src/game/TGreatPower.cpp`
12. `just sync-ownership`
13. `just regen-stubs`
14. `just build`
15. `just compare 0x004DE700`
16. `just compare 0x004DE790`
17. `just compare 0x004DE5E0`
18. `just compare 0x004DF5F0`
19. `just stats`

### Changes
1. Converted promoted raw block `0x004DE5E0` into compile-safe member method:
   1. `RevokeDiplomacyGrantForTargetAndAdjustInfluence(int)`.
   2. Added typed terrain helper for vtable slot `+0x38`.
2. Promoted and converted two adjacent affordability methods from stubs:
   1. `0x004DE700` `CanAffordDiplomacyGrantEntryForTarget(short, unsigned short)`.
   2. `0x004DE790` `CanAffordAdditionalDiplomacyCostAfterCommitments(short)`.
3. Added corresponding method declarations to `TGreatPower` class and removed raw GHIDRA function bodies/comments.
4. Synced ownership and regenerated stubs after each promotion so manual ownership remains single-source per address.

### Results
1. `0x004DE5E0`: `32.35%` (new non-zero owned body).
2. `0x004DE700`: `47.46%` (new non-zero owned body).
3. `0x004DE790`: `65.12%` (new non-zero owned body).
4. Regression anchors remained stable:
   1. `0x004DF5F0`: `30.15%`.
   2. `0x004DF010`: `12.79%`.
   3. `0x004DDFC0`: `19.94%`.
5. Aggregate `just stats`:
   1. aligned functions: `90` (unchanged),
   2. average similarity: `2.76%` (`+0.01pp`).

## 2026-03-02 22:44 UTC - existing-code shape tuning for grant affordability helpers

### Commands
1. `just format src/game/TGreatPower.cpp`
2. `just build`
3. `just compare 0x004DE700`
4. `just compare 0x004DE790`
5. `just compare 0x004DE5E0`
6. `just compare 0x004DF5F0`
7. `just format src/game/TGreatPower.cpp`
8. `just build`
9. `just compare 0x004DE700`
10. `just compare 0x004DE790`
11. `just compare 0x004DF5F0`
12. `just stats`

### Changes
1. Focused on improving existing owned bodies, not adding new promotions.
2. `0x004DE700` (`CanAffordDiplomacyGrantEntryForTarget`):
   1. reshaped arithmetic to closer original form (`0x3FFF` mask first, early sign gate branch, bitmask-style positive-budget clamp).
3. `0x004DE790` (`CanAffordAdditionalDiplomacyCostAfterCommitments`):
   1. tried the same bitmask-clamp form, then reverted this method to its previous branch-clamp shape because it regressed.
4. No changes to neighboring heavy functions in this pass.

### Results
1. `0x004DE700`: `47.46%` -> `59.74%`.
2. `0x004DE790`: temporary `65.12%` -> `61.22%` during probe, then restored to `65.12%` after revert.
3. Regression anchors:
   1. `0x004DE5E0`: `32.35%` (unchanged),
   2. `0x004DF5F0`: `30.15%` (unchanged).
4. Aggregate `just stats` stayed stable:
   1. aligned functions: `90`,
   2. average similarity: `2.76%`.

## 2026-03-02 22:47 UTC - existing-code cleanup and targeted guard removal

### Commands
1. `just format src/game/TGreatPower.cpp`
2. `just build`
3. `just compare 0x004DE5E0`
4. `just compare 0x004DE700`
5. `just compare 0x004DE790`
6. `just compare 0x004DF5F0`

### Changes
1. Kept `INSTRUCTIONS.md` general-only (removed function-specific heuristics added in the previous pass).
2. `0x004DE5E0` (`RevokeDiplomacyGrantForTargetAndAdjustInfluence`):
   1. removed extra defensive null guards not present in original hot path,
   2. switched grant gate to signed `<= 0` shape after mask.
3. Kept recent `0x004DE700`/`0x004DE790` tuning state unchanged.

### Results
1. `0x004DE5E0`: `32.35%` -> `33.00%`.
2. `0x004DE700`: `59.74%` (unchanged).
3. `0x004DE790`: `65.12%` (unchanged).
4. Regression anchor:
   1. `0x004DF5F0`: `30.15%` (unchanged).

## 2026-03-02 23:04 UTC - pointer arithmetic cleanup pass in `TGreatPower`

### Commands
1. `just format src/game/TGreatPower.cpp`
2. `just build`
3. `just compare 0x004DE860`
4. `just compare 0x004E8750`
5. `just compare 0x004E9060`
6. `just stats`

### Changes
1. Added typed memory views for repeated raw-offset access:
   1. `TDiplomacyTurnStateManagerRelationView` (`0x79C` relation matrix),
   2. `TTerrainDescriptorNationSlotView` (`0x0C`/`0x0E` nation slots),
   3. `TGlobalMapStateScoreView` and `TGlobalMapCityScoreRecord` (city score table/value).
2. Replaced pointer arithmetic helpers with typed accessors:
   1. `Diplomacy_ReadRelationMatrix79C`,
   2. `TerrainDescriptor_GetEncodedNationSlot`,
   3. `TerrainDescriptor_GetFallbackNationSlot`,
   4. new global map helpers (`ReadGlobalMapStateScoreView`, `GlobalMapState_ReadCityScoreValue`).
3. Reworked `ApplyJoinEmpireMode0GlobalDiplomacyReset` setup loops to remove direct `this + offset` writes:
   1. candidate flags now use `GreatPower_GetCandidateNationFlags(this)`,
   2. baseline needs now use `GreatPower_GetNeedLevelByNation(this)`,
   3. terrain descriptor traversal switched from raw cursor comparison to indexed table iteration.
4. Removed remaining local raw-offset reads in:
   1. `ComputeAdvisoryMapNodeScoreFactorByCaseMetric`,
   2. `ComputeMapActionContextCompositeScoreForNation`.

### Results
1. Build: green.
2. Targeted compares:
   1. `0x004DE860`: `25.04%`,
   2. `0x004E8750`: `34.25%` (no regression),
   3. `0x004E9060`: `31.69%` (no regression).
3. Aggregate `just stats` unchanged:
   1. aligned functions: `90`,
   2. average similarity: `2.76%`.

## 2026-03-02 23:14 UTC - replaced helper-casts with real typed class fields

### Commands
1. `just format src/game/TGreatPower.cpp`
2. `just build`
3. `just compare 0x004DE860`
4. `just compare 0x004E8750`
5. `just compare 0x004E9060`

### Changes
1. Removed stopgap helper-casts:
   1. `GreatPower_GetCandidateNationFlags`,
   2. `GreatPower_GetNeedLevelByNation`.
2. Promoted layout to typed fields in `TGreatPower`:
   1. `field14_needLevelByNation[0x17]` (plus `field42` tail),
   2. `field8a0_candidateNationFlags[0x17]` (plus `pad_8b7`).
3. Updated call sites to use direct typed fields instead of `reinterpret_cast` and `this + offset` access.

### Results
1. Build: green.
2. Targeted compares unchanged:
   1. `0x004DE860`: `25.04%`,
   2. `0x004E8750`: `34.25%`,
   3. `0x004E9060`: `31.69%`.

## 2026-03-02 23:20 UTC - codified typed-field rule and scanned for remaining cast-layout cases

### Commands
1. `rg -n "return reinterpret_cast...|self + 0x..." src`
2. `just format src/game/TGreatPower.cpp`
3. `just build`
4. `just compare 0x00407392`
5. `just compare 0x004DC9F0`

### Changes
1. Added new general rule in `INSTRUCTIONS.md`:
   1. promote repeated offset/cast access into typed class fields or typed view structs when layout is stable.
2. Converted two immediate `TGreatPower` cases from `this + offset` to direct typed field access:
   1. `thunk_ApplyIndexedResourceDeltaAndAdjustNationTotals_At00407392`:
      1. `field198`, `field844`, `field840`, `field910`,
   2. `RefreshGreatPowerRelationPanelsAndDispatchDeltaSummary`:
      1. `pField894`.
3. Repo scan identified remaining high-volume cast-layout hotspots:
   1. `src/game/TGreatPower.cpp` (constructor/reset-heavy blocks),
   2. `src/game/trade_screen.cpp`,
   3. `src/game/TCivDescription.cpp`,
   4. `src/game/object_pool.cpp`.

### Results
1. Build: green.
2. `0x004DC9F0`: `100%` match retained.
3. `0x00407392`: remains non-matching (`0.00%`) and currently decompiled as full body rather than original jump-thunk shape.

## 2026-03-02 23:39 UTC - TGreatPower typed-view cleanup without score regression on core anchors

### Commands
1. `just format src/game/TGreatPower.cpp`
2. `just build`
3. `just compare 0x004DBD20`
4. `just compare 0x004DBF00`
5. `just compare 0x004DE860`
6. `just compare 0x004E1D50`

### Changes
1. Added typed external-layout views used repeatedly by `TGreatPower`:
   1. `TSecondaryNationStateOwnerView`,
   2. `TNationStateFlagsView`,
   3. `TLocalizationRuntimeView`,
   4. `TObArrayModeView`,
   5. `TTerrainStateRecordView`,
   6. extended `TGlobalMapStateScoreView` and `TGlobalMapCityScoreRecord`,
   7. `TCityOrderCapabilityStateView`.
2. Added typed helpers:
   1. `ReadLocalizationRuntimeView`,
   2. `GlobalMapState_GetTerrainRecord`,
   3. `GlobalMapState_GetCityRecord`,
   4. `DecodeSecondaryNationOwnerSlot`.
3. Replaced repeated raw offset access with typed fields/views in active code paths:
   1. nation busy flag (`+0xA0`) now via `NationState_IsBusyA0` typed view,
   2. secondary owner decode (`+0x0C/+0x0E`) now via typed helper in war-transition/advisory/join-empire paths,
   3. localization runtime index (`+0x40`) now via `TLocalizationRuntimeView`,
   4. ob-array mode writes (`+0x14`) now via `TObArrayModeView`,
   5. selected vtable byte-offset fetches converted to indexed vtable slots (`0x94/0x98/0x4C/0x30`).
4. Kept `0x004DBD20` body in its previous shape after testing to avoid a similarity drop.

### Results
1. Build: green.
2. Targeted compare results:
   1. `0x004DBD20`: `13.74%` (restored, no regression),
   2. `0x004DBF00`: `27.79%` (unchanged),
   3. `0x004DE860`: `25.04%` -> `25.44%`,
   4. `0x004E1D50`: `20.32%` (tracked during typed-view conversion).

## 2026-03-02 23:55 UTC - promoted additional TGreatPower aid/policy helpers and removed one remaining `this+offset` read

### Commands
1. `just promote src/game/TGreatPower.cpp --address 0x004DCE10 --address 0x004DCE90 --address 0x004DD340 --address 0x004DD3B0 --address 0x004DD3F0 --address 0x004DD430`
2. `just format src/game/TGreatPower.cpp`
3. `just sync-ownership`
4. `just regen-stubs`
5. `just build`
6. `just detect`
7. `just compare 0x004DCE10`
8. `just compare 0x004DCE90`
9. `just compare 0x004DD340`
10. `just compare 0x004DD3B0`
11. `just compare 0x004DD3F0`
12. `just compare 0x004DD430`
13. `just promote src/game/TGreatPower.cpp --address 0x004DD740 --address 0x004DDA20 --address 0x004DE2D0 --address 0x004DF580`
14. `just format src/game/TGreatPower.cpp`
15. `just sync-ownership`
16. `just regen-stubs`
17. `just build`
18. `just detect`
19. `just compare 0x004DD740`
20. `just compare 0x004DDA20`
21. `just compare 0x004DE2D0`
22. `just compare 0x004DF580`

### Changes
1. Promoted and converted 10 new `TGreatPower` member functions from autogen to compile-safe manual C++:
   1. `SetNationResourceNeedCurrentByType` (`0x004DCE10`)
   2. `TryIncrementNationResourceNeedTargetTowardCurrent` (`0x004DCE90`)
   3. `AddAmountToAidAllocationMatrixCellAndTotal` (`0x004DD340`)
   4. `SumAidAllocationMatrixColumnForTarget` (`0x004DD3B0`)
   5. `SumAidAllocationMatrixAllCells` (`0x004DD3F0`)
   6. `ComputeRemainingDiplomacyAidBudget` (`0x004DD430`)
   7. `GetDiplomacyExternalStateB6ByTarget` (`0x004DD740`)
   8. `DecrementDiplomacyCounterA2ByValue` (`0x004DDA20`)
   9. `ResetDiplomacyPolicyAndGrantEntriesPreserveRecurringGrants` (`0x004DE2D0`)
   10. `ResetNationDiplomacyProposalQueue` (`0x004DF580`)
2. Added missing method declarations for the above in the `TGreatPower` class section.
3. Added matrix constants used by the aid-allocation helpers:
   1. `kAidAllocationRowCount = 0x10`
   2. `kAidAllocationColumnCount = 0x17`
4. Removed one remaining direct object-offset stream read by modeling the field directly:
   1. split `pad_8b8` to include `field8c8_serializedFlags[0x0D]`
   2. replaced `reinterpret_cast<unsigned char*>(this) + 0x8C8` with `this->field8c8_serializedFlags`.

### Results
1. Build: green after both promotion batches and ownership/stub sync.
2. Newly promoted function similarities:
   1. `0x004DCE10`: `30.77%`
   2. `0x004DCE90`: `16.67%`
   3. `0x004DD340`: `23.33%`
   4. `0x004DD3B0`: `73.33%`
   5. `0x004DD3F0`: `100% match`
   6. `0x004DD430`: `48.65%`
   7. `0x004DD740`: `0.00%`
   8. `0x004DDA20`: `40.00%`
   9. `0x004DE2D0`: `47.89%`
   10. `0x004DF580`: `40.00%`

### Project-level checkpoint
1. `just stats` after this iteration:
   1. aligned functions: `91` (`+1`),
   2. not aligned vs original: `12882` (`-1`),
   3. average similarity: `2.80%` (`+0.03 pp`).

## 2026-03-02 23:54 UTC - field reconstruction and cast-reduction pass in `TGreatPower`

### Commands
1. `just promote src/game/TGreatPower.cpp --address 0x004DD0C0 --address 0x004DD310 --address 0x004DDD50 --address 0x004DF370 --address 0x004EA470`
2. `just format src/game/TGreatPower.cpp`
3. `just sync-ownership`
4. `just regen-stubs`
5. `just build`
6. `just detect`
7. `just compare 0x004DD0C0`
8. `just compare 0x004DD310`
9. `just compare 0x004DDD50`
10. `just compare 0x004DF370`
11. `just compare 0x004EA470`
12. `just stats`

### Changes
1. Promoted and converted new `TGreatPower` bodies from autogen:
   1. `0x004DD0C0` `SetDiplomacyColonyBoycottFlagForTargetAndRefreshMinorNations`
   2. `0x004DD310` `ReleaseDiplomacyTrackedObjectSlots850`
   3. `0x004DDD50` `IsDiplomacyState1C6UnsetAndCounterPositiveForTarget`
   4. `0x004DF370` `QueueInterNationEventForProposalCode12D_130`
   5. `0x004EA470` `RebuildNationResourceYieldsAndRollField134Into136`
2. Reconstructed two obvious non-pointer fields and removed related casts:
   1. `pField8f8` -> `field8f8` (`int`)
   2. `pField960` -> `field960` (`int`)
3. Removed raw `this + 0x8C8` style state usage from prior pass by keeping typed `field8c8_serializedFlags`.
4. Reduced cast-heavy queue metadata access by introducing typed view:
   1. `TProposalQueueCountView`
   2. `ProposalQueue_GetCount` now reads typed `count` field.
5. Reduced pointer-arithmetic casts inside `RebuildNationResourceYieldCountersAndDevelopmentTargets`:
   1. switched to typed `TTerrainStateRecordView` / `TGlobalMapCityScoreRecord` table access,
   2. added helper `CityRecord_ReadDevelopmentAccumulatorAt82` to isolate legacy overlapping layout reads.

### Results
1. Build: green.
2. Targeted comparisons after this pass:
   1. `0x004EA470`: `100% match`
   2. `0x004DD310`: `82.76%`
   3. `0x004DF370`: `42.45%`
   4. `0x004DDD50`: `33.33%`
   5. `0x004DD0C0`: `17.98%`
   6. `0x004DBD20`: `17.12%` (tracked after typed-table rewrite)
3. Project stats (`just stats`):
   1. aligned functions: `92`
   2. not aligned vs original: `12881`
   3. average similarity: `2.82%`

## 2026-03-03 00:05 UTC - cast cleanup + typed table pointers in `TGreatPower`

### Commands
1. `just format src/game/TGreatPower.cpp`
2. `just build`
3. `just detect`
4. `just compare 0x004DBD20`
5. `just compare 0x004DD0C0`
6. `just compare 0x004DDD50`
7. `just compare 0x004EA470`
8. `just stats`

### Changes
1. Reconstructed `TGlobalMapStateScoreView` table fields to typed pointers:
   1. `terrainStateTable` -> `TTerrainStateRecordView*`
   2. `cityScoreTable` -> `TGlobalMapCityScoreRecord*`
2. Removed cast-only accessors in table helpers:
   1. `GlobalMapState_GetTerrainRecord` now does direct typed indexing.
   2. `GlobalMapState_GetCityRecord` now does direct typed indexing.
   3. `CityRecord_ReadDevelopmentAccumulatorAt82` now reads via `linkedRegionIds[0x20 + i]`.
3. Removed pointer-to-int payload casts from event wrappers by fixing function-pointer signatures:
   1. `QueueInterNationEventWithPayload`
   2. `SendTurnEvent13WithPayload`
4. Kept higher-scoring body shape for `0x004DDD50` after a failed simplification attempt.

### Results
1. Build: green.
2. Anchor compares after pass:
   1. `0x004EA470`: `100%`
   2. `0x004DDD50`: `59.09%` (restored from regressed `35.90%`)
   3. `0x004DD0C0`: `20.00%`
   4. `0x004DBD20`: `17.12%`
3. Project stats unchanged:
   1. aligned functions: `92`
   2. average similarity: `2.82%`

## 2026-03-03 00:07 UTC - loop-shape trial for `0x004DD0C0`

### Commands
1. `just format src/game/TGreatPower.cpp`
2. `just build`
3. `just detect`
4. `just compare 0x004DD0C0`

### Changes
1. Reworked minor-nation iteration in
   `SetDiplomacyColonyBoycottFlagForTargetAndRefreshMinorNations` to explicit
   address-cursor form (`0x006A429C..0x006A42DC`) to better mimic original
   loop shape.

### Results
1. Build: green.
2. Similarity unchanged:
   1. `0x004DD0C0`: `20.00%`.

## 2026-03-03 00:16 UTC - promoted 4 more `TGreatPower` methods and restored green pipeline

### Commands
1. `just promote src/game/TGreatPower.cpp --address 0x004E22B0 --address 0x004E2330 --address 0x004E2500 --address 0x004E27B0`
2. `just normalize-markers`
3. `just format src/game/TGreatPower.cpp`
4. `just sync-ownership`
5. `just regen-stubs`
6. `just build`
7. `just detect`
8. `just compare 0x004E22B0`
9. `just compare 0x004E2330`
10. `just compare 0x004E2500`
11. `just compare 0x004E27B0`
12. `just compare 0x004EA470`
13. `just stats`

### Changes
1. Promoted and converted four new member functions from autogen into compile-safe C++:
   1. `AddRegionIdToNationOwnedRegionListAndTriggerExpansionActionIfThresholdMet` (`0x004E22B0`)
   2. `ApplyDiplomacyTargetTransitionAndClearGrantEntry` (`0x004E2330`)
   3. `ReleaseTrackedObjectsByMapOwnerAndUnassignedEntries` (`0x004E2500`)
   4. `DispatchNationDiplomacySlotActionByMode` (`0x004E27B0`)
2. Added missing class declarations for the four promoted methods.
3. Replaced raw GHIDRA `__thiscall`/`code*` bodies with member-method implementations and typed helper usage.
4. Fixed MSVC loop-scope redeclaration issue (`index`) in `ReleaseTrackedObjectsByMapOwnerAndUnassignedEntries`.
5. Synced ownership and regenerated stubs to keep address ownership consistent.

### Results
1. Build: green.
2. Compare snapshot:
   1. `0x004E22B0`: `17.86%`
   2. `0x004E2330`: `33.49%`
   3. `0x004E2500`: `17.22%`
   4. `0x004E27B0`: `25.81%`
   5. anchor `0x004EA470`: `100%`
3. Project stats (`just stats`) improved and returned to expected baseline:
   1. aligned functions: `92`
   2. not aligned vs original: `12881`
   3. average similarity: `2.83%`
   4. signal: `GOOD`
