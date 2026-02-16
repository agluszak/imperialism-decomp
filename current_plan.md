# Imperialism Decompilation Current Plan

Last updated: 2026-02-16 (active pass, university unlock/gating trace)

## Goal
Decompile and document the entire game in Ghidra, with legible names/types/comments and verified runtime behavior.

## Completed
- [x] City screen building pipeline pass (major):
  - Renamed/documented core city dialog and building action functions.
  - Mapped core city-building icon ranges and slot/upgrade structure with user-confirmed assets.
- [x] Engineer construction order pipeline:
  - Confirmed and documented depot/port/rail/fort order types and cost handling.
  - Renamed key helpers (`GetHexDirectionBetweenTiles`, `ApplyRailSectionEndpointDirectionFlags`, queue helpers).
- [x] Civilian command/report/ledger control flow:
  - Documented `CTRL+Disband` -> civilian ledger path and normal disband confirmation path.
  - Documented report dialog/rescind flow and refund behavior.
- [x] Recruitment commit/writeback pipeline:
  - Confirmed `CommitCityRecruitmentOrderDelta` as key writeback point.
  - Confirmed separate civilian vs specialist commit branches.
  - Confirmed support-command injection path (`QueueCityRecruitmentSupportCommandsIfDeficit`).
- [x] Database updates:
  - Stored confirmed engineer cost/order-type corrections in Neo4j.
  - Synced fort tech unlock correction to `Large Artillery`.
- [x] Map civilian action legibility pass:
  - Renamed/documented `ResolveCivilianTileOrderActionCode`, `CanAssignCivilianOrderToTile`, `HandleCivilianTileOrderAction`.
  - Mapped action-dispatch branches for engineer/report/order routing.
- [x] Map command panel dispatch pass:
  - Renamed/documented `HandleMapCommandPanelAction`.
  - Confirmed `done`/`dfnd`/`latr` command tags and `garr` split (`Ctrl` ledger vs normal disband).
- [x] Map interaction mode/cycle pass:
  - Renamed/documented `SetMapInteractionMode` and `CycleMapInteractionSelectionAfterHandledClick`.
  - Confirmed no-candidate path clears selection (matches “last unit deselected” behavior).
- [x] Civilian work-order cost/marker pass:
  - Renamed/documented `QueueCivilianWorkOrderWithCostCheck`.
  - Confirmed per-class marker/sfx table initialization and cash subtraction path.
- [x] Command type semantics trace:
  - Confirmed `SetCivWorkOrderTypeAndDuration` duration table and explicit command behavior.
  - Confirmed rollover handling: type `2` persists, type `3/4` auto-clear to idle.
  - Updated plate comments for `HandleMapCommandPanelAction` and `QueueImmediateCivilianCommandAndCycleSelection` with final semantics.
- [x] Civilian order helper legibility cleanup:
  - Renamed/documented `IsCivilianOrderInReportableState` (`0x005c2980`).
  - Renamed/documented `IsMappedShortcutKeyPressed` (`0x005d4890`).
  - Renamed/documented `LookupOrderCompatibilityMatrixValue` (`0x004f1f20`).
  - Renamed/documented `TryShowCivilianCompletionMilestoneNotification` (`0x005038b0`).
- [x] `HandleMapClickByInteractionMode` deep pass:
  - Verified mode-based click dispatch and post-action cycling behavior.
  - Confirmed command routing sequence into tile action handlers and queue helpers.
- [x] University requirement/capability legibility chunk:
  - Renamed globals: `DAT_00651030` -> `g_anUniversityRequirementIdByRecruitRow`, `DAT_00696d98` -> `g_abUniversityRequirementLevelById`.
  - Updated `RenderUniversityRecruitmentRequirementGrid` prototype/locals/comments to show dependency-table and capability-level lookups.
  - Added structured plate comments to university requirement/availability functions.
- [x] City capability unlock helper naming chunk:
  - Renamed `FUN_005afba0` -> `ApplyCityOrderCapabilityUnlockByTechId`.
  - Renamed `FUN_005af980` -> `UpdateCityOrderCapabilityUnlockProgress`.
  - Forced re-decompilation of `AdvanceGlobalTurnStateMachine` so unlock helper names propagate in rollover flow.
- [x] University bitmap/tag extraction chunk:
  - Confirmed in `BuildUniversityRecruitmentRows`: `9928 -> civ4`, `9930 -> civ5`, `9936 -> civ8`.
  - Added disassembly tags/comments for `9926` forester block and related `clu3` setup.

## In Progress
- [x] Plan maintenance for this session:
  - Refreshed completed items and queued next execution chunks.
  - Continue autonomous passes without waiting for prompts unless blocked.
- [ ] University recruitment legibility pass:
  - Refine types/names/comments around recruitment context/slider/commit/support.
  - Tie tech gating checks in capability/dependency tables to specific recruit rows.
- [ ] `OpenCityViewProductionDialog` variable/type cleanup:
  - Improve remaining generic/undefined locals where practical.
  - Keep behavior docs aligned with observed UI states.
- [ ] Map icon-state and command semantics consolidation:
  - Finish mapping `400/409/418` family transitions to concrete state fields.
  - Finish mapping tile cache bytes (`+0x11/+0x12/+0x13`) to exact unit-state variants.
- [ ] Turn-rollover execution pass:
  - Civilian order rollover rules are confirmed.
  - Remaining: complete recruitment/order executor chain map with exact phase placement.

## Next Tasks Queue
- [ ] University recruitment gating extraction (immediate):
  - Finalize row-to-unit mapping for all `clu*` rows and reconcile with baseline/default capability bytes at `+0x467`.
  - Map forester/rancher/driller unlock rows to concrete tech IDs from capability switch paths.
  - Name and document the function(s) that transform capability unlock flags into recruit-row visibility/index values.
- [ ] `OpenCityViewProductionDialog` cleanup pass:
  - Rename remaining generic locals (`piVar1`, `iVar2`, stack aliases) and normalize ambiguous pseudo-callback variables.
  - Add concise inline comments for queue-state checks and OK/Cancel command wiring.
- [ ] Trace turn-rollover executors:
  - Recruitment order consumption and resource/workforce application timing.
  - Confirm final phase entry point(s) inside global turn-state transitions.
- [ ] Civilian order persistence fields:
  - Identify order state field(s) that hold sleep/no-orders/working transitions.
  - Confirm where immediate UI icon changes are committed to map icon state cache.
- [ ] Strategic-map icon-state pass:
  - Identify exact selectors for normal/selected/working icon variants.
  - Confirm where animation state is toggled after productive orders are queued.
- [ ] Persist incremental findings:
  - Write validated claims/evidence/function links to Neo4j continuously.
  - Save Ghidra after each stable analysis chunk.

## Working Rules
- Execute continuously without waiting for prompts.
- Ask only if analysis is blocked or conflicting with observed gameplay evidence.
- Prefer verified behavior from disassembly/runtime evidence over inferred labels.

## Session Update (2026-02-16, map/civilian persistence pass)

### Completed This Pass
- [x] Civilian order action-chain readability improvements:
  - Renamed locals in `HandleCivilianTileOrderAction`, `ResolveCivilianTileOrderActionCode`, and `HandleCivilianReportDecision`.
  - Replaced plate comments with algorithm/params/returns for report and cost-check paths.
- [x] Cost table labeling for rescind/build logic:
  - Added labels: `g_adwEngineerRailBuildCostByTerrainType` (`0x006531d8`), `g_adwCivilianWorkOrderCostByClass` (`0x00653194`), `g_awEngineerFortBuildCostByLevel` (`0x0065318a`).
- [x] Strategic-map working-animation overlay mapping:
  - Renamed `FUN_0050e070` -> `BlitStrategicMapUnitActivityOverlayFrame`.
  - Renamed thunk `0x00405880` -> `ThunkBlitStrategicMapUnitActivityOverlayFrame`.
  - Confirmed `RenderStrategicMapTileCell` uses tile cache byte `+0x18` as activity overlay frame selector.
- [x] GOB string-anchor validation for civilian UI:
  - Confirmed in extracted string tables:
    - `strtbl-1186`: `Civilian Report`, `Rescind Orders`, `Confirm Orders`
    - `strtbl-1273`: `Next Unit`, `Sleep`, `No orders this turn`
    - `strtbl-1274`: `Disband Civilian`
    - `strtbl-4041`: `Construction Options`
  - Added these anchors into relevant plate comments.
- [x] Civilian order persistence mapping (save/load):
  - Documented and re-prototyped `SerializeUnitOrderCoreState` / `DeserializeUnitOrderCoreState`.
  - Documented and re-prototyped `SerializeCivUnitOrderState` / `DeserializeCivUnitOrderState`.
  - Confirmed civilian-specific remaining-turn field persisted at offset `+0x24`.
- [x] Work-order lifecycle mapping:
  - Confirmed `SetCivWorkOrderTypeAndDuration` writes type/owner and initializes duration table.
  - Confirmed `AdvanceCivWorkOrderAndApplyCompletion` decrements productive order timers and applies completion on zero.
  - Renamed `IsCivilianOrderInReportableState` -> `IsCivilianOrderInIdleSelectionState` to match actual predicate behavior.

### New Immediate Tasks
- [ ] Finish mapping order-type -> concrete gameplay action names for all civ types (5/6/7/8/10/11/12/13) in the completion/apply path.
- [ ] Decompile and rename `ApplyCompletedCivWorkOrderToMapState` to fully map resource/tile mutations and icon-state updates.
- [ ] Trace where map icon variant family (`400/409/418` and working animation) is committed from unit-order state into tile cache bytes.
- [ ] Continue replacing remaining high-impact `DAT_*` globals in civilian/map interaction pipeline once semantics are fully verified.


## Session Update (2026-02-16, map command panel + stack controls)

### Completed This Pass
- [x] Mapped civilian command control tags in dispatcher:
  - In `HandleMapCommandPanelAction`, confirmed and documented:
    - `done` -> immediate command type `4` (`No orders this turn`)
    - `dfnd` -> immediate command type `2` (`Sleep`)
    - `latr` -> immediate command type `3` (`Next Unit`)
    - `garr` -> `Disband Civilian`; with CTRL held it opens civilian ledger instead.
- [x] Mapped stack-slot UI refresh path:
  - Renamed `FUN_0058ec50` -> `RefreshCivilianStackButtonsForTile`.
  - Confirmed `stk0..stk5` are per-tile civilian stack slots bound to linked entries at tile `+0x20` chain.
  - Confirmed command buttons `dfnd/latr/done` are enabled only when a stack unit is selected.
- [x] Global naming cleanup for readability:
  - Renamed `DAT_006a43dc` -> `g_pSelectedCivilianOrderState`.
  - Renamed `DAT_006a43d4` -> `g_pGlobalMapState`.
- [x] Civilian tile selection/report pass refinement:
  - Renamed and documented `HandleCivilianTileSelectionOrReportClick` and `ResolveCivilianTileSelectionOrReportActionCode`.
  - Re-applied structured plate comments with GOB/embedded text context for civilian report flow.

### Observations
- Embedded-string anchors still coexist with GOB-backed labels.
  - Embedded confirmed in EXE: `Civilian Report`, `Construction Options`.
  - Expected GOB-backed controls remain validated via extracted tables (`Next Unit`, `Sleep`, `No orders this turn`, `Disband Civilian`).

### Next Immediate Tasks
- [ ] Continue map-order state path from command click -> order queue -> icon state cache write.
- [ ] Rename/document `FUN_0058f3c0` (called from stack refresh) after clarifying its nation/capability counting role.
- [ ] Reduce remaining high-impact globals in this path (`DAT_006a21bc`, `DAT_006a43ec`) once semantics are verified.

## Session Update (2026-02-16, civilian panel counters + runtime globals)

### Completed This Pass
- [x] Global readability cleanup in map/civilian path:
  - Renamed `DAT_006a21bc` -> `g_pUiRuntimeContext`.
  - Renamed `DAT_006a43ec` -> `g_pSfxPlaybackSystem`.
- [x] Command-panel counter function recovery:
  - Renamed `FUN_0058f3c0` -> `UpdateCivilianOrderTargetTileCountsForOwnerNation`.
  - Renamed thunk `0x00404d8b` -> `ThunkUpdateCivilianOrderTargetTileCountsForOwnerNation`.
  - Confirmed it computes 5 target buckets from tile profile ids using `DAT_00698F58` for current civilian class.
- [x] Civilian panel refresh cleanup:
  - Re-prototyped and documented `RefreshCivilianCommandPanelForSelection`.
  - Confirmed `unit` + `back` control flow and class-change-triggered recomputation of target counters.
- [x] Icon-state cache tracing extension:
  - Revalidated `InitializeStrategicMapTileIconStateCache` and `ResetTileIconCacheFromProfile` behavior:
    - tile `+0x11` seeded from profile lookup using tile `+0x13`.
    - tile `+0x12` reset to `0xFF`.

### Next Immediate Tasks
- [ ] Resolve and rename `DAT_00698F58` as civilian-class-to-target-profile lookup table.
- [ ] Finish mapping where icon family variants (normal/selected/no-orders/working) write into tile cache bytes (`+0x11/+0x12/+0x18`) during command queueing.
- [ ] Continue reducing duplicated thunk/base naming collisions in map-order functions when found.

## Session Update (2026-02-16, target-profile table + panel rendering)

### Completed This Pass
- [x] Target profile lookup labeling:
  - Added label `g_anTargetTileProfileByCivilianClassAndSlot` at `0x00698f58`.
  - Verified table is consumed by both panel counter logic and panel icon rendering path.
- [x] Function naming/prototype cleanup:
  - Renamed `FUN_0058f3c0` -> `UpdateCivilianOrderTargetTileCountsForOwnerNation`.
  - Re-applied structured plate comments for:
    - `HandleMapCommandPanelAction`
    - `UpdateCivilianOrderTargetTileCountsForOwnerNation`
    - `RefreshCivilianCommandPanelForSelection`
- [x] Thunk/base collision reduction:
  - Renamed key thunk duplicates (`ThunkSetActiveCivilianSelection`, `ThunkCanAssignCivilianOrderToTile`, `ThunkSelectFirstAvailableCivilianForNation`, etc.) to keep symbol search unambiguous.

### Findings
- `g_anTargetTileProfileByCivilianClassAndSlot` is indexed as:
  - `[civilianClass * 5 + bucket]` -> tile profile id (or `-1`).
- Panel rendering path (`FUN_005903c0`) uses the same profile table to draw target-profile icons, confirming linkage between computed counters and UI representation.

### Next Immediate Tasks
- [ ] Rename/document `FUN_005903c0` (civilian panel render path) now that table semantics are confirmed.
- [ ] Continue tracing command queue callbacks that write final icon-state selectors for normal/selected/no-orders/working states.
- [ ] Map remaining icon-state write points into `tile+0x11/+0x12/+0x18` for full state-transition documentation.
