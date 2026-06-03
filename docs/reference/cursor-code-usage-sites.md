# Cursor Code Usage Sites (Imperialism.exe)

Date: 2026-02-16
Scope: code/memory locations used to load and apply cursor handles for mapped cursor IDs.

## Runtime Cursor Table

- Runtime table base: `g_pUiRuntimeContext - 0x0F8C` (resolved memory base around `0x006A211C`)
- Entry width: `4` bytes (`HCURSOR`)
- Access pattern: `SetCursor(*(HCURSOR *)(g_pUiRuntimeContext - 0xF8C + token * 4))`
- Known write sites into table base region:
  - `0x0049DBEA`
  - `0x0049DC60`

## Key Loader Functions

| Address | Function | What it does |
|---|---|---|
| `0x005D5100` | `LoadTurnEventCursorTable` | Loads resource IDs `1000..1053` via loop into runtime cursor table (`this+0x14`) |
| `0x005D5140` | `LoadTurnEventCursorByResourceIdOffset1000` | Calls `LoadCursorA(module, MAKEINTRESOURCE(id))` |

## Key Selector/Setter Functions

| Address | Function | Cursor-use behavior |
|---|---|---|
| `0x00595810` | `SetMappedCursorOrDefaultArrow` | Uses mapped token -> cursor table, else default arrow |
| `0x005958B0` | `UpdateMapCursorForTileAndAction` | Computes action token, sets cursor from table (or arrow) |
| `0x005A8CA0` | `SetMappedCursorOrDefaultArrowAlt` | Alternate mapped-token cursor path |
| `0x005A8D40` | `UpdateHexGridHoverCursorAndHighlight` | Tactical/hex hover token -> cursor table |
| `0x0048C250` | `UpdateMapCursorFromSelectionContext` | Refresh path before map cursor update |
| `0x005DEF70` | `SetCursorFromResourceE4AndClampRange` | Loads cursor resource `0xE4` and clamps cursor bounds |

## Diplomacy Context Functions

| Address | Function | Cursor-context behavior |
|---|---|---|
| `0x005D7FC0` | `SetCursorRangeAndRefreshMainPanel` | Loads `curs` panel and sets range (`0x2B6C..0x2B67`) |
| `0x005D8040` | `HandleTurnEvent7D8_ActivateDiplomacyMapView` | Diplomacy map-view cursor context setup |
| `0x005D83B0` | `HandleTurnEvent7DE_RefreshTradeDiplomacyCityTransportSummary` | Diplomacy/trade summary cursor context setup |

## Status

- This is enough to trace when mapped cursor handles are selected in code paths.
- Remaining gap: exact per-ID dispatch branch for each individual cursor token is runtime-derived (action/token resolution), not fully hardcoded as direct literals for every ID.

## Low-Hanging Renames Applied

### Cursor/token helpers

- `0x00495650` -> `IsPointInsideHitRegion`
- `0x00492b70` -> `thunk_StringSharedRef_AssignFromPtr`
- `0x005123e0` -> `ComputeStridedRecordAddress6C`
- `0x005a86d0` -> `ConvertScreenPointToHexGridCoordClamped`
- `0x005a0a90` -> `ResolveTacticalHoverCursorToken`
- `0x005a05a0` -> `ComputeTacticalHoverCursorStateIndex`
- `0x004a4930` -> `LookupMapCursorTokenByStateIndex`
- `0x004a4960` -> `ComputeMapCursorStateIndex`
- `0x004a4aa0` -> `LookupCivilianMapCursorTokenByStateIndex`
- `0x004a4c80` -> `ComputeCivilianMapCursorStateIndex`
- `0x004d2930` -> `LookupCivilianTileOrderCursorTokenByActionIndex`
- `0x005a3370` -> `DispatchTacticalActionByHoverStateIndex`
- `0x00406CDF` -> `thunk_DispatchTacticalActionByHoverStateIndex`
- `0x005a3d30` -> `IsTacticalTargetTileReachableForAction`
- `0x00406B09` -> `thunk_IsTacticalTargetTileReachableForAction`

### QuickDraw path used by cursor hover/selection rendering

- `0x00494700` -> `BeginScopedMapQuickDrawContext`
- `0x004948b0` -> `EndScopedMapQuickDrawContext`
- `0x00495000` -> `SetQuickDrawFillColor`
- `0x00495070` -> `SetQuickDrawStrokeColor`
- `0x004950f0` -> `SetQuickDrawFillColorFromPaletteIndex`
- `0x004953a0` -> `ResetQuickDrawStrokeState`
- `0x00495920` -> `ApplyHitRegionToClipState`
- `0x00495a30` -> `SnapshotHitRegionToClipCache`
- `0x00497320` -> `AcquireReusableQuickDrawSurface`
- `0x00497390` -> `ReleaseOrCacheQuickDrawSurface`
- `0x005a99e0` -> `DrawHexSelectionOutlineSegments`
- `0x00498b50` -> `AssertQuickDrawFlag6A1DC8NonZero`
- `0x00498b80` -> `AssertQuickDrawFlag6A1DCCNonZero`

### Shared string helper used in cursor control path

- `0x006057a7` -> `StringSharedRef_AssignFromPtr`

### Tactical packet helper used by hover-state dispatch

- `0x005A0D60` -> `QueueTacticalEventPacket232A`
- `0x0040400C` -> `thunk_QueueTacticalEventPacket232A`

### Cursor-state dependency helpers (map/tactical)

- `0x0059B010` -> `IsTacticalControllerOwnedByActiveNation`
- `0x004020C2` -> `thunk_IsTacticalControllerOwnedByActiveNation`
- `0x005A0420` -> `ComputeHexNeighborTileIndices`
- `0x004032EC` -> `thunk_ComputeHexNeighborTileIndices`
- `0x00514290` -> `GetTileNormalizedMovementClassId`
- `0x00402B1C` -> `thunk_GetTileNormalizedMovementClassId`
- `0x00515E50` -> `TileHasMovementClassId`
- `0x00403D78` -> `thunk_TileHasMovementClassId`
- `0x005C3490` -> `GetUnitMovementClassId`
- `0x00407E64` -> `thunk_GetUnitMovementClassId`
- `0x005D5710` -> `UpdateTurnEventPaletteByCode`
- `0x00407AE5` -> `thunk_UpdateTurnEventPaletteByCode`
- `0x005A0550` -> `IsHexNeighborTileIndex`
- `0x00404C2D` -> `thunk_IsHexNeighborTileIndex`
- `0x005A0C50` -> `HandleTacticalBattleCommandTag`
- `0x00409002` -> `thunk_HandleTacticalBattleCommandTag`
- `0x005A0EA0` -> `AdvanceToNextTacticalUnitTurnStep`
- `0x00404700` -> `thunk_AdvanceToNextTacticalUnitTurnStep`
- `0x005A1010` -> `SetCurrentTacticalUnitSelection`
- `0x00402CCA` -> `thunk_SetCurrentTacticalUnitSelection`
- `0x005A10E0` -> `ProcessTacticalUnitState1TurnStep`
- `0x00407D3D` -> `thunk_ProcessTacticalUnitState1TurnStep`
- `0x005A1520` -> `MoveTacticalUnitTowardTile`
- `0x00403FBC` -> `thunk_MoveTacticalUnitTowardTile`
- `0x005A16E0` -> `BuildPathToTargetByDistanceField`
- `0x0040833C` -> `thunk_BuildPathToTargetByDistanceField`
- `0x005A1910` -> `MoveTacticalUnitBetweenTiles`
- `0x00403134` -> `thunk_MoveTacticalUnitBetweenTiles`
- `0x005A1A20` -> `ResolveTacticalReactionChecksForTile`
- `0x00405ACE` -> `thunk_ResolveTacticalReactionChecksForTile`
- `0x005A4460` -> `BuildTacticalDistanceFieldForSide`
- `0x00408A67` -> `thunk_BuildTacticalDistanceFieldForSide`
- `0x005A9B40` -> `UpdateTacticalActionControlBitmapForCurrentUnit`
- `0x004059E8` -> `thunk_UpdateTacticalActionControlBitmapForCurrentUnit`
- `0x005A8860` -> `InvalidateTacticalHexTileRect`
- `0x004029F5` -> `thunk_InvalidateTacticalHexTileRect`
- `0x005A9CC0` -> `TriggerTacticalUiUpdate2711`
- `0x004024D2` -> `thunk_TriggerTacticalUiUpdate2711`
- `0x005A9BB0` -> `SpawnTacticalUiMarkerAtUnitTile`
- `0x00405678` -> `thunk_SpawnTacticalUiMarkerAtUnitTile`

### Data labels

- `0x006A590C` -> `g_pCursorControlPanel`
- `0x0049DBEA` -> `loc_WriteUiRuntimeCursorTableBase_A`
- `0x0049DC60` -> `loc_WriteUiRuntimeCursorTableBase_B`
