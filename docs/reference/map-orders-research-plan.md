# Map Civilian Orders Plan

Date: 2026-02-15

## Goal

Make map-order decompilation legible and confirm where civilian orders are stored/committed/persisted.

## Confirmed So Far

- Click dispatch chain is identified and renamed:
  - `HandleMapClickByInteractionMode @ 0x005964b0`
  - `TryHandleMapContextAction @ 0x0055a020`
  - `GetMapContextActionCode @ 0x00559a70`
  - `TryQueueMapOrderFromTileAction @ 0x0055a160`
  - `OpenMapEntryOrderDialog @ 0x00597f80`
- Active map-order entry pointer:
  - `GetActiveMapOrderEntry @ 0x005979f0` -> `DAT_006A3FBC + 0x14`
- Order commit path identified:
  - `RebuildMapOrderEntryChildren @ 0x00553f10`
  - `MoveMapOrderEntryToQueueHeadIfValid @ 0x00557080`
  - `FinalizeQueuedMapOrderEntry @ 0x005642e0`
- Entry command fields written in queue path:
  - `entry + 0x08` command type
  - `entry + 0x0C` command target/context
- Global queue head used by commit:
  - `g_pNavyOrderManager + 0x04`
- Global save/load integration confirmed:
  - `LoadGlobalSystemsFromSave @ 0x0049e6a0` (vfunc `+0x18` deserialize pass)
  - `SaveGlobalSystemsToStream @ 0x0049eb30` (vfunc `+0x14` serialize pass)
  - includes both `g_pActiveMapContextState` and `g_pNavyOrderManager`
- Improvement-order cash timing confirmed for two order bits:
  - `QueueMapImprovementOrderBit10` sets tile bit `0x10`, deducts `2000` at queue time
  - `QueueMapImprovementOrderBit04` sets tile bit `0x04`, deducts `3000` at queue time
- Handler/token anchors identified:
  - `g_aMapImprovementOrderVtable @ 0x006588F0`
  - `g_awMapContextActionLabelTokenByCommand @ 0x0065C2F0`
  - `g_anMapActionClassToImprovementOpIndex @ 0x00658964`
- Command resolver coverage:
  - `ResolveMapOrderCommandFromActionContext` returns `0x0C/0x0D/0x0E/0x0F` (+ fallback `0x01`)
  - `ResolveMapOrderCommandFromProvinceContext` returns `0x10` (+ fallback `0x01`)
- Type-setter caller mapping recovered:
  - `ResolveAndQueuePortZoneMapOrder` drives `type6` vs `type3` selection from port-zone mask logic.
  - `TryQueueProvinceOrderFromContextMessage` drives `type5` for province-target path.
  - `ProcessMapOrderEntryContextMode` drives alternate `type9` path.
  - `QueueMissionOrdersByPriorityForContext` (mission AI vtable path) uses:
    - `type9` when node context matches requested context
    - `type1` promotion path otherwise
- Engineer transport bit mapping confirmed:
  - `bit 0x04` = port marker/pending
  - `bit 0x10` = rail marker/pending
  - anchored by `DumpAndResetMapScriptState` (`port %d` / `rail %d` log lines)
- Action class -> improvement op index mapping decoded:
  - `3->0`, `4->1`, `7->2`, `8->3`, `9->4`, `11->5`, `12->6`, `13->7`
  - `-1` entries are unmapped/no-op classes
  - op `5`/`6` are code-confirmed rail/port handlers respectively

## Next Steps

1. Confirm civilian-only branch mapping
- Prove which tile classes/actions map to player civilian units (vs naval/mission AI paths).
- Tie `action code 11` dialog path to civilian type ids and icon ids `400..426`.

2. Decode entry structure by offsets
- Name key fields for active entry object (`+0x08`, `+0x0C`, `+0x10`, `+0x14`, `+0x1C`, `+0x1E`, `+0x28`, `+0x2C`).
- Resolve child-node structure used by `RebuildMapOrderEntryChildren`.

3. Find save/load handlers for map orders
- Done at global level (save/load pass includes active context + order manager).
- Next: isolate civilian-specific sublists/fields inside serialized payload.

4. Civilian order semantics
- Map command type values (`0xC..0x10` branches observed in queue path) to concrete civilian actions.
- Extend deduction timing beyond the two confirmed improvement bits (`0x04`, `0x10`).
- Resolve op indices `7/8/9` handler semantics to concrete in-game improvement names.
- Tie command IDs to exact UI verbs (build rail, build port, depot/hub variants) via label token decode.

5. Ghidra readability pass
- Replace remaining `iVar*/uVar*` locals in core functions.
- Rename critical DAT_* globals used by map-order flow.
- Add final plate/inline comments at commit and mode-switch decision points.

## Checklist

- [x] Dispatch chain renamed
- [x] Active entry pointer location found
- [x] Core commit queue functions identified
- [x] Save/load path touching order manager confirmed
- [x] Cash deduction timing confirmed for improvement bit-0x04 and bit-0x10
- [x] Command-id branches (`0x0C..0x10`) located and documented
- [x] Rail vs port bit semantics confirmed (0x10 rail, 0x04 port)
- [ ] Civilian-specific action mapping confirmed
- [ ] Entry structure fully typed/named
- [ ] Save/load fields mapped to civilian-only order entries
- [ ] Resource/cash deduction timing confirmed for all civilian command types

## Incremental Update (2026-02-15, map click continuation)

Completed this pass:
- Renamed `FUN_00597a80` -> `CycleMapInteractionSelectionAfterHandledClick` and documented as post-click interaction-mode cycler.
- Renamed `FUN_00599090` -> `OpenMapContextActionDialogByType` and documented as action-code `2..8` dialog/context branch.
- Confirmed call contract from assembly at `TryHandleMapContextAction+0x7B`:
  - `ECX = DAT_006A21BC[0x3C]` manager
  - pushes: cached context (`DAT_006A3ED8`), `actionCode-2`, `GetMapActionContextByTileIndex(tile)`.

Implication for civilian-order mapping:
- Action classes `7..13` currently map to context-dialog path (`2..8`) before queue finalization.
- Queue writes that set concrete order type/target still concentrate in `TryQueueMapOrderFromTileAction` and downstream commit/finalize helpers.

Recent rename:
- `FUN_00554a80` -> `GetMinActionThresholdFromEntryChildren` (+ thunk rename).

Research value:
- Confirms queue/label logic is not only class-based; it is further constrained by per-child thresholds via `DAT_00698124`.

New renderer anchor:
- `RenderStrategicMapTileCell @ 0x0051EB40` now documented.
- Contains direct source-rect reference to icon id 400-series (`left=400`, width `0x14`) in overlay path.

This gives a concrete entrypoint for decoding `400..426` state transitions.

Current icon-mapping status:
- Direct constant hits for `400/409/418` from byte-pattern search were mostly UI template/resource-builder paths, not strategic-map order logic.
- Strong renderer anchor remains `RenderStrategicMapTileCell` with explicit `left=400` source rect blit.
- `409/418` likely come through renderer helper/vfunc paths (`DAT_006A21A8` methods at offsets `+0x80/+0x84`) rather than a simple static table in this function.

Newly clarified mode split in `CycleMapInteractionSelectionAfterHandledClick`:
- Mode 0 -> civilian list scan/select (`SelectFirstAvailableCivilianForNation`, `SetActiveCivilianSelection`).
- Mode 1 -> province scan/select (`FindNextSelectableProvinceForNation`, `SetActiveProvinceSelection`).
- Mode 2 -> map-order-entry chain selection (`DAT_006A3FC8` traversal).

Strategic-map icon draw indirection confirmed:
- `RenderStrategicMapTileCell` calls `g_pStrategicMapViewSystem` vfunc `+0x80/+0x84`.
- Targets recovered and named (`DrawStrategicMapUnitIcon`, `DrawStrategicMapUnitIconOverlay`).
- Overlay source rows are mapped through `g_anStrategicMapOverlaySourceRowByIconId`.

This is the current best path for finishing exact `400/409/418` state decoding.

## Incremental Update (2026-02-15, continued)

Completed this pass:
- Renamed order-navigation helpers for readability:
  - `0x00599770` -> `SelectNextValidMapOrderEntryFromCursor`
  - `0x005998A0` -> `TrySelectNextValidMapOrderEntry`
  - `0x005999F0` -> `ResetMapInteractionToCivilianMode`
- Renamed strategic icon cache initializer:
  - `0x0051CC60` -> `InitializeStrategicMapTileIconStateCache`
- Added plate comments and disassembly comments documenting:
  - order-entry field offsets,
  - icon cache lookup maps,
  - mode-reset semantics.

Newly confirmed data model details:
- Map order entry persistence fields:
  - `+0x08` order type code
  - `+0x0C` action/province context pointer
  - `+0x1E/+0x20/+0x22/+0x24` slider values reflected in `RefreshMapOrderEntryPanel`
- Strategic tile icon cache map (`tile[0x13] -> tile[0x11]`):
  - `[-1,-1,0,20,5,17,18,1,-1,-1,-1,-1,-1,2,-1]`
- Additional slot updater map (`FUN_0051D970`):
  - `{22,21,6}` writes into `tile[0x11]` or `tile[0x12]`.

Interpretation:
- Civilian icon families (`400..408`, `409..417`, `418..426`) are likely assembled from:
  - base class index + mode/state offset
  - tile cache bytes (`+0x11/+0x12/+0x13/+0x17`)
  - draw-time vfunc routing in `RenderStrategicMapTileCell` (`+0x80/+0x84`).

Next concrete step:
- Trace runtime writers of `tile+0x17` (overlay selector) and `tile+0x12` in non-editor interaction paths to pin exact selected/no-orders transitions against known icon ranges.

## Incremental Update (2026-02-15, tile-cache writer split)

Completed:
- Renamed/editor-documented tile cache mutation cluster:
  - `0x0051CE60` -> `DispatchStrategicMapTileEditAction`
  - `0x0051D4F0` -> `ApplyTileIconProfileFromEditorSelection`
  - `0x0051D970` -> `ApplyTileIconOverlayFromEditorSelection`
  - `0x0051DA60` -> `ResetTileIconCacheFromProfile`
- Renamed `0x00504E90` -> `BuildMapTileActionContextMenu` and documented as menu/UI assembly path.

Key conclusion:
- Direct writes to `tile+0x11/+0x12/+0x13` are concentrated in this editor-style dispatcher path.
- Normal order queue flow (`TryQueueMapOrderFromTileAction` -> `Rebuild...` -> `Move...` -> `Finalize...`) persists order-entry fields, not tile icon cache bytes directly.
- Additional confirmation:
  - `ThunkSetMapOrderType6AndQueue`
  - `ThunkSetMapOrderType3Or4AndQueue`
  only set entry type/context, rebuild child list, relink queue nodes, and call finalize; no `tile+0x11/+0x12/+0x17` writes were observed.

Impact on 400/409/418 mapping work:
- We should now prioritize runtime derivation path in `RenderStrategicMapTileCell` and upstream state providers for `tile+0x17` (overlay selector) rather than chasing editor mutation handlers.

## Incremental Update (2026-02-15, region/order continuation)

Completed this pass:
- Renamed and documented map-region pipeline helpers:
  - `SmoothCityRegionOwnershipByNeighborSampling` (`0x00528E50`)
  - `BuildCityRegionBorderOverlaySegments` (`0x0052C1A0`)
  - `ReindexContiguousCityRegionIds` (`0x0052D1F0`)
  - `MergeSmallCityRegionsAndCompactIds` (`0x0052D750`)
- Renamed map-order preview helpers:
  - `UpdateMapOrderEntryTilePreviewSlot` (`0x00523170`)
  - `RenderMapOrderEntryTilePreview` (`0x00523640`)
  - `DrawHexNeighborConnectionMask` (`0x00522CF0`)

Newly confirmed:
- City-region passes use city tile field `tile+0x04` as region class (`regionId + 0x17` encoding).
- `UpdateMapOrderEntryTilePreviewSlot` caches tile-preview slot index in `tile+0x10`.
- This region/overlay pipeline is adjacent to strategic-map visuals but distinct from order-entry commit persistence fields.

Still open:
- Find direct non-editor runtime writer of `tile+0x17` to finalize `400..408` vs `409..417` vs `418..426` state transitions in gameplay mode.

## Incremental Update (2026-02-15, civilian order commit chain)

Completed this pass:
- Decompiled and validated core click->queue path:
  - `TryQueueMapOrderFromTileAction` (`0x0055A160`)
  - `ResolveMapOrderCommandFromActionContext` (`0x00554300`)
  - `ResolveMapOrderCommandFromProvinceContext` (`0x00554460`)
  - `ApplyMapOrderTypeAndQueue` (`0x005540B0`)
  - `FinalizeQueuedMapOrderEntry` (`0x005642E0`)
- Decompiled `TryHandleMapContextAction` (`0x0055A020`) and confirmed action-code 11 behavior.

Key confirmed behavior:
- Map click is consumed in one of two ways:
  - immediate context-action handling (`TryHandleMapContextAction`), or
  - order queue path (`TryQueueMapOrderFromTileAction`).
- In queue path, order-entry fields are written immediately:
  - `entry+0x08` = internal order type
  - `entry+0x0C` = target context pointer
- After write, chain is always:
  - `ThunkRebuildMapOrderEntryChildren`
  - `ThunkMoveMapOrderEntryToQueueHeadIfValid`
  - `ThunkFinalizeQueuedMapOrderEntry`

Implication for user-observed icon behavior:
- Immediate icon/state flip after issuing an order matches code path: queue + finalize happen in-click, not deferred to turn rollover.
- Turn rollover is for execution/progress, not for the initial visual state switch.

Action/context code mapping recovered:
- `ResolveMapOrderCommandFromActionContext` returns command IDs in `{0x0C,0x0D,0x0E,0x0F}` (or fallback `0x01`).
- `TryQueueMapOrderFromTileAction` maps these IDs to internal entry-type writes (`type 1/3/6` + special branch).
- `ResolveMapOrderCommandFromProvinceContext` returns `0x10` on success, mapped to `entry type 5`.

Related UI behavior confirmed:
- `TryHandleMapContextAction` action code `0x0B` opens entry-order dialog for tile-linked entry (dialog path, not direct queue write).

Open item after this pass:
- We still need the exact non-editor runtime producer of the icon selector bytes feeding renderer (`tile+0x11/+0x12/+0x17`) to finalize exact `400..408` vs `409..417` vs `418..426` transitions.

## Incremental Update (2026-02-15, civ work-order object model)

Completed this pass:
- Recovered and renamed core civ unit-order object methods:
  - `RegisterUnitOrderWithOwnerManager` (`0x005C2530`)
  - `SetCivWorkOrderTypeAndDuration` (`0x005C29F0`)
  - `AdvanceCivWorkOrderAndApplyCompletion` (`0x005C2A90`)
  - `RelinkCivUnitByTileIndex` (`0x005C2B70`)
  - `ApplyCompletedCivWorkOrderToMapState` (`0x004D4390`)
- Added plate comments for the above to capture turn-processing behavior.

Newly confirmed runtime behavior:
- Civ unit-order objects are registered into an owner manager via manager vfunc `+0x30` in `RegisterUnitOrderWithOwnerManager`.
- Productive civ work orders are timed:
  - remaining turns stored at `+0x24`,
  - decremented each update tick in `AdvanceCivWorkOrderAndApplyCompletion`.
- On timer expiry:
  - `ApplyCompletedCivWorkOrderToMapState` mutates map/tile state (improvements/resource/flags/routes depending on order type),
  - order type resets to idle (`0`).

Tile attachment model confirmed:
- `RelinkCivUnitByTileIndex` writes into tile occupant chain head at `tile+0x20` (in tile stride `0x24`) and updates unit prev/next links.
- This is the concrete linkage between unit object and visible map tile presence.

Implication for user notes:
- Productive orders staying animated until completion is directly explained by the countdown + completion apply path.
- Idle/no-order visual state after completion is consistent with order type reset in `AdvanceCivWorkOrderAndApplyCompletion`.

Still open:
- Exact function that performs initial tile assignment (`RelinkCivUnitByTileIndex` caller) for newly recruited civilians at turn rollover.

## Incremental Update (2026-02-15, click->queue bridge + civ vtable completion)

Completed this pass:
- Renamed remaining civ work-order lifecycle functions:
  - `0x005C2940` -> `InitializeCivWorkOrderState`
  - `0x005C29B0` -> `TickCivWorkOrderCountdownAndComplete`
- Added plate comments in Ghidra for both functions.
- Confirmed top-level click dispatch branch:
  - `HandleMapClickByInteractionMode` mode `2` calls `TryQueueMapOrderFromTileAction`.
  - This is the concrete productive-order queue path after overlay/context prechecks.
- Added/updated plate comments for:
  - `TryQueueMapOrderFromTileAction` (`0x0055A160`)
  - `InitializeCivWorkOrderState` (`0x005C2940`)
  - `TickCivWorkOrderCountdownAndComplete` (`0x005C29B0`)

Civ unit-order vtable map (code-confirmed):
- Base pointer written by `InitializeCivUnitOrderObject`: `PTR_GetCivUnitOrderTypeName_0066EE60`
- `0x0066EE60` -> `GetCivUnitOrderTypeName`
- `0x0066EE64` -> `DestroyCivUnitOrderObject`
- `0x0066EE74` -> `SerializeCivUnitOrderState`
- `0x0066EE78` -> `DeserializeCivUnitOrderState`
- `0x0066EE88` -> `RelinkCivUnitByTileIndex`
- `0x0066EE8C` -> `AdvanceCivWorkOrderAndApplyCompletion`
- `0x0066EE90` -> `ClearCivUnitTileLink`
- `0x0066EE94` -> `SetCivWorkOrderTypeAndDuration`
- `0x0066EE98` -> `ResetCivWorkOrderAndRefreshCounters`

Interpretation aligned with user gameplay notes:
- Productive order issue is immediate on click (queue + finalize in same interaction path).
- Productive work remains active via turn countdown (`+0x24`) and completes through
  `TickCivWorkOrderCountdownAndComplete` -> `ApplyCompletedCivWorkOrderToMapState`.
- Completion resets order type to idle (`0`), matching observed return to normal/non-working state.

Still open (next concrete target):
- Resolve owner-manager turn loop that invokes civ virtual update methods and performs first tile relink for freshly recruited civilians at rollover.

## Incremental Update (2026-02-15, turn-state rollover anchor)

Completed this pass:
- Improved legibility in `OpenCityViewProductionDialog` (`0x004CE5A0`):
  - prototype normalized to `void __thiscall OpenCityViewProductionDialog(int nBuildingSlotId, int* pCityStateData, int nDialogFlags)`.
  - preserved existing high-value inline comments and refreshed decompilation.
- Renamed helper:
  - `0x0057F0E0` -> `IsNationProfileInMinorRange100To199`
- Added strong rollover plate-comment anchor in:
  - `GameFlow::HandleStateTransition` (`0x0057DA70`)

Key rollover finding:
- In state `0x15`, the game-flow loop iterates all active nations and calls:
  - nation vfunc `+0x2B8` (pre-pass)
  - nation vfunc `+0x108` (main per-nation pass)
- `+0x108` is now the strongest candidate path for queued civilian order turnover/relink work (including where recruited civilians likely become map-linked at turn rollover).

Still open:
- Resolve concrete function behind nation vfunc `+0x108` (requires nation vtable resolution or call-target recovery from constructor/vtable tables).

## Incremental Update (2026-02-15, manual rollover narrowing)

Completed this pass:
- Renamed and documented rollover-prep functions now visible in state `0x15` path:
  - `0x00518130` -> `RecomputeTileStrategicScoreHeatmap`
  - `0x0053FE30` -> `RecomputeNationOrderPriorityMetrics`
  - `0x004E6520` -> `RelinkTileUnitsToCountryOrderManager`
  - `0x004E6740` -> `ShowCountryOrderTransferNotification`
  - `0x004E6150` -> `ReassignUnitOrdersForCountryTargetChange`
  - previously: `0x0057F0E0` -> `IsNationProfileInMinorRange100To199`

Rollover flow (now clearer in decompilation):
- State `0x15` order:
  1. `RecomputeTileStrategicScoreHeatmap()`
  2. `RecomputeNationOrderPriorityMetrics()`
  3. per-nation vfunc `+0x2B8`
  4. per-nation vfunc `+0x108`
- This confirms `+0x108` is executed after strategic/economic recomputation and remains the best candidate for applying queued turn orders (including civilian appearance/relink effects).

Tooling limitation encountered:
- Ghidra script execution is currently broken in this runtime:
  - Java provider throws ClassCastException (`GhidraPlaceholderBundle` cast failure)
  - Python provider unavailable (`Ghidra was not started with PyGhidra`)
- As a result, vcall-slot scanning had to remain manual for this pass.
