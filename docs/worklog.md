# Worklog

## 2026-02-23

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
