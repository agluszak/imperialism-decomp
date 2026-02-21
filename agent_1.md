# Agent 1 Working Notes (Trade Screen Dehardcoding)

Last updated: 2026-02-16 (late evening)

## Current Goal
Reverse engineer and dehardcode the Imperialism trade screen bitmap usage, then persist verified mappings and evidence into Neo4j.

## Confirmed Bitmap IDs (from user + code)
- 2101 (`0x835`): trade background (pre-oil)
- 2102 (`0x836`): trade background (post-oil)
- 2111 (`0x83f`) / 2125 (`0x84d`): Bid pressed/unpressed pair
- 2113 (`0x841`) / 2127 (`0x84f`): Offer pressed/unpressed pair
- 2121 (`0x849`) / 2123 (`0x84b`): decrease/increase offer arrow base states set in trade setup
- 2112 (`0x840`) / 2126 (`0x84e`): bid secondary state pair
- 2114 (`0x842`) / 2128 (`0x850`): offer secondary state pair
- 2120 (`0x848`): additional trade control bitmap assigned in setup path

## Confirmed Function-Level Findings
- `InitializeTradeScreenBitmapControls` (`0x004601b0`, renamed from `FUN_004601b0`): main trade screen setup; confirmed literal bitmap pushes into picture setter (`CALL [vtable+0x1c8]`) for:
  - `0x840`, `0x842`, `0x848`, `0x849`, `0x84b`, `0x84e`, `0x850`
  - plus previously confirmed `0x835`, `0x836`, `0x841`
- `SetTradeBidControlBitmapState` (`0x00587bb0`): toggles `2111/2125`.
- `SetTradeOfferControlBitmapState` (`0x00587dd0`): toggles `2113/2127`.
- `IsTradeBidControlActionable` (`0x00587980`): checks bid bitmap states.
- `IsTradeOfferControlActionable` (`0x00587a10`): checks offer bitmap states.
- `SetTradeBidSecondaryBitmapState` (`0x00587aa0`): toggles `2112/2126`.
- `SetTradeOfferSecondaryBitmapState` (`0x00588030`): toggles `2114/2128`.
- `FUN_004ccf30`: contains `0x84c` in assert path (not a direct bitmap assignment).
- `DispatchTurnEventPacketThroughDialogFactory` (`0x0048cfd0`) and `FUN_00598a50`: contain `PUSH 0x846` as assert line numbers, not bitmap assignments.
- `SetPressedStateAdjustPictureBitmapByOne` (`0x00571620`, newly created/renamed): pressed-state handler that updates control state flag and calls picture setter with bitmap ID `+1` (pressed) or `-1` (released) from current ID at offset `+0x84`.
- Vtable trace: class built via `thunk_FUN_00583b50` (`0x00404331 -> 0x00583b50`, vtable `0x663540`) has slot `+0x1c0 = 0x004080d0 -> 0x00571620`, linking trade arrow controls to this `+/-1` bitmap derivation logic.
- Practical tag mapping in `InitializeTradeScreenBitmapControls`: `left -> 0x849 (2121)`, `rght -> 0x84b (2123)`, `gree -> 0x848 (2120)`; pressed arrow variants are derived by the `+/-1` handler.
- Trade sell-control panel function cluster renamed and verified:
  - `CreateTradeSellControlPanel` (`0x00587010`)
  - `ConstructTradeSellControlPanel` (`0x005870b0`)
  - `DestroyTradeSellControlPanel` (`0x005870e0`)
  - `InitializeTradeSellControlState` (`0x00587130`)
  - `HandleTradeSellControlCommand` (`0x005873e0`)
  - `IsTradeSellControlAtMinimum` (`0x00587900`)
  - `GetTradeSellControlValue` (`0x00587950`)
- `HandleTradeSellControlCommand` handles sell-quantity and arrow flow using control tags:
  - `Sell` (`0x53656c6c`)
  - ` bar` (`0x62617220`)
  - `left` (`0x6c656674`)
  - `rght` (`0x72676874`)
  - `gree` (`0x67726565`)
- Created/renamed thunk wrappers and linked to the sell-control panel vtable:
  - `thunk_HandleTradeSellControlCommand` (`0x00403e22`)
  - `thunk_InitializeTradeSellControlState` (`0x00407e7d`)
  - `thunk_IsTradeSellControlAtMinimum` (`0x0040486d`)
  - `thunk_GetTradeSellControlValue` (`0x00405a97`)
- Vtable slot map for sell-control panel class (`0x00665a70`):
  - `+0x3c -> 0x00403e22 -> 0x005873e0`
  - `+0xdc -> 0x00407e7d -> 0x00587130`
  - `+0x1cc -> 0x0040486d -> 0x00587900`
  - `+0x1d4 -> 0x00405a97 -> 0x00587950`
- Additional selection/dispatch path findings:
  - `UpdateTradeResourceSelectionByIndex` (`0x00586170`, renamed from `FUN_00586170`) iterates resource controls and broadcasts command `0x1f` (selected) / `0x20` (unselected) via virtual slot `+0x3c`.
  - `thunk_DispatchPanelControlEvent` (`0x004023ab`) maps event classes `0x1f`, `0x20`, `0x21` to virtual slot `+0x1c0`.
  - This bridges selection events directly into per-class bitmap-state handlers; for compatible classes this includes `SetPressedStateAdjustPictureBitmapByOne` (`0x00571620`) with bitmap `+/-1` behavior.
  - `HandleTradeMoveControlAdjustment` (`0x00586e70`, renamed from `FUN_00586e70`) handles move-control increment/decrement (`0x64`/`0x65`) and then forwards into `thunk_DispatchPanelControlEvent`.
- Trade move-control cluster mapped and renamed (all in `0x00588xxx` region):
  - `InitializeTradeMoveAndBarControls` (`0x00586d60`)
  - `ClampAndApplyTradeMoveValue` (`0x00588950`)
  - `UpdateTradeMoveControlsFromDrag` (`0x00588c60`)
  - `HandleTradeMoveStepCommand` (`0x00588ff0`)
  - `UpdateTradeMoveControlsFromScaledDrag` (`0x005899f0`)
  - `HandleTradeMovePageStepCommand` (`0x00589da0`)
  - `RefreshTradeMoveBarAndTurnControl` (`0x0058a690`)
  - `HandleTradeMoveArrowControlEvent` (`0x0058a940`)
  - Common behavior: tag-based lookup of `move`/`avai`/`bar`/`left`/`rght`/`Sell` controls and callback updates through host `+0x1d0`.
- Trade move control panel constructor families mapped:
  - `CreateTradeMoveControlPanelBasic` (`0x00586c40`) / `ConstructTradeMoveControlPanelBasic` (`0x00586ce0`) -> vtable `0x00665838`
  - `CreateTradeMoveStepControlPanel` (`0x00588a30`) / `ConstructTradeMoveStepControlPanel` (`0x00588af0`) -> vtable `0x00665ed0`
  - `CreateTradeMoveScaledControlPanel` (`0x00589660`) / `ConstructTradeMoveScaledControlPanel` (`0x00589720`) -> vtable `0x00666318`
  - `CreateTradeMoveArrowControlPanel` (`0x0058a4d0`) / `ConstructTradeMoveArrowControlPanel` (`0x0058a590`) -> vtable `0x00666760`
- Added thunk wrappers for move cluster entry points:
  - `thunk_ClampAndApplyTradeMoveValue` (`0x00402df6`)
  - `thunk_UpdateTradeMoveControlsFromDrag` (`0x00405af6`)
  - `thunk_HandleTradeMoveStepCommand` (`0x0040611d`)
  - `thunk_UpdateTradeMoveControlsFromScaledDrag` (`0x00404d04`)
  - `thunk_HandleTradeMovePageStepCommand` (`0x004091ce`)
  - `thunk_RefreshTradeMoveBarAndTurnControl` (`0x004058a8`)
  - `thunk_HandleTradeMoveArrowControlEvent` (`0x00406965`)
  - `thunk_ConstructTradeMoveStepControlPanel` (`0x00401d11`)
  - `thunk_ConstructTradeMoveScaledControlPanel` (`0x00404c3c`)
- Vtable confirmation for control class at `0x006611e0`:
  - `+0xa4 -> thunk_FUN_0048b1c0` (sets internal field and optionally refreshes)
  - `+0xa8 -> thunk_FUN_0048b070` (sets value and optionally refreshes)
  - `+0x1c0 -> thunk_SetControlStateFlagAndMaybeRefresh` (`0x0040516e -> 0x0048e810`)
  - `+0x1c8 -> thunk_SetPictureResourceIdAndRefresh` (`0x00408454 -> 0x0048f570`)
- Orphan decode note:
  - Created `FUN_005663c0` from undecoded bytes due `0x843` pattern hit; decomp shows compare/draw helper with no current xrefs, not immediately useful for trade-screen bitmap mapping.

## Open Questions / Hypotheses
- Confirmed: pressed arrow states are framework-derived (`2121 -> 2122`, `2123 -> 2124`) via `+/-1` logic in `0x00571620`.
- `2118` classified as assert-line literal only (not mapped to bitmap assignment path).
- Remaining unresolved direct hardcoded IDs in trade context: `2115`, `2116`, `2117`, `2119`.
- New constraint: `0x848` (`2120`) controls in `InitializeTradeScreenBitmapControls` are created through `0x0040123f` (`vtable 0x6611e0`) whose `+0x1c0` handler is non-toggle; this weakens the simple `2120 -> 2119` derivation hypothesis for that path.
- Additional false-positive note: raw `0x845` hits (`2117`) at `0x0055188E`/`0x0055234E` resolve to mid-instruction bytes, not direct bitmap-assignment instructions.
- Opcode-boundary scan update:
  - No `PUSH imm32` sites for `2115/2116/2117/2119` (`68 43/44/45/47 08 00 00`).
  - `2118` (`0x846`) appears as `PUSH 0x846` only at `0x0048d031` and `0x00598ae3` in assert/failure paths.
  - Raw dword hits for `0x844` and `0x846` are non-instruction-byte matches in tested locations.
- New directional hypothesis:
  - Unresolved trade IDs (`2115/2116/2117/2119`) are more likely to come from non-literal base bitmap states inside controls reached through the `0x1f/0x20 -> +0x1c0` dispatch path than from direct hardcoded literals.
  - The `0x006611e0` class path uses generic state setters and direct picture setter (`+0x1c8`), but current mapped callsites still do not expose direct literals for `2115/2116/2117/2119`.

## TODO
- [x] Re-decompile `0x004601b0` attempt (decompiler still times out); switched to disassembly-context workflow.
- [x] Trace literal hits for `0x844/0x845/0x846/0x847/0x84c` and classify.
- [x] Persist newly confirmed function↔bitmap mapping and evidence/claims in Neo4j.
- [x] Update Neo4j research tasks with latest arrow-state tracing status.
- [x] Identify concrete runtime path that selects pressed arrow variants (`2122`, `2124`).
- [x] Verify pressed-state selection is generic control behavior (`base_bitmap_id +/- 1`) in control-class method `0x00571620`.
- [x] Continue naming/documenting nearby `FUN_00586xxx`/`FUN_00587xxx` small-view handlers to isolate trade screen control flow.
- [ ] Find where/if `2115`, `2116`, `2117`, `2119` are consumed (table-driven path, alternate class, or dead resources).
- [x] Run direct field write/compare opcode scan for unresolved IDs (`2115/2116/2117/2119`) against picture-id offset patterns (`+0x84`) and record evidence (no matches).
- [x] Run opcode-boundary literal scan (`PUSH imm32`) for unresolved IDs and classify residual hits (`2118` remains assert-only).
- [ ] Trace command IDs `0x64/0x65/0x67/0x68/0x69/0x6a` in `HandleTradeSellControlCommand` to caller event dispatch to support tag-command dehardcoding.
- [x] Trace selection event bridge: `0x1f/0x20` (`UpdateTradeResourceSelectionByIndex`) -> `thunk_DispatchPanelControlEvent` -> virtual slot `+0x1c0`.
- [ ] Enumerate concrete control instances/classes in the selection path and read their base bitmap IDs to test `2115/2116/2117/2119` coverage.
- [x] Map and rename adjacent trade move-control cluster (`0x00588xxx`) and associated control tags.
- [x] Map trade move control panel constructor families and vtable anchors (`0x665838`, `0x665ed0`, `0x666318`, `0x666760`).
- [ ] Continue from `HandleTradeMoveArrowControlEvent`/`HandleTradeMoveStepCommand` callers to find where control base bitmap IDs are sourced at runtime.

## Immediate Next Step
Trace unresolved IDs `2115/2116/2117/2119` by enumerating control instances reached by `UpdateTradeResourceSelectionByIndex` and checking each class's `+0x1c0` state handler/base bitmap values.

## Working Thread (Low-Hanging)
- Try quickest derivation proofs first:
  - If `0x848` controls are instantiated with the same class that uses `SetPressedStateAdjustPictureBitmapByOne` (`0x00571620`), then `0x847` (`2119`) can be explained as derived (`0x848 - 1`).
  - Defer deep/class-wide renaming; only add names/comments when directly useful to close a bitmap mapping.
  - Reuse confirmed tag mapping (`left/rght/gree`) to drive dehardcoding table extraction before chasing unresolved IDs.

## Cross-Screen Pivot Notes (Diplomacy)
- Diplomacy screen is partially identified at event/view level:
  - `HandleTurnEvent7D8_ActivateDiplomacyMapView` (`0x005d8040`) is mapped as the primary diplomacy-map activation path.
  - `HandleTurnEvent7DE_RefreshTradeDiplomacyCityTransportSummary` (`0x005d83b0`) refreshes the shared order-summary controls.
  - Event `0x0547` branch verifies `TDiplomacyMapView` and writes selected nation slot to `main + 0x90`.
- Still missing:
  - A trade-style, dedicated diplomacy bitmap initializer equivalent to `InitializeTradeScreenBitmapControls` has not been isolated/named yet.
- New literal extraction (MCP script + disassembly-neighborhood pass):
  - In both `0x005d8040` and `0x005d83b0`, the `curs` path calls vfunc `+0x204` with literal pair `0x2B67` (`11111`) and `0x2B6C` (`11116`).
  - Additional nearby pair appears in summary/title path: `0x2B6B` (`11115`) with `0x2B6C` (`11116`) before helper setup and `+0x1c8`.
  - Observed call-context constants:
    - `0x2730` (localization group used with indexes `0x1E`, `0x1C`, `0x02`),
    - `0x2735` (used with indexes `0x05`, `0x06`),
    - tags `dipl`, `tran`, `Bpot`, `tool`, `main`, `curs`.
  - Cross-function scan result:
    - `+0x204` callsites repeatedly use `11111/11116` across many turn-event handlers (`0x005d73df`, `0x005d76d6`, `0x005d7d21`, `0x005d7ff9`, `0x005d80b1`, `0x005d843e`, `0x005d87f3`, `0x005d8a94`, `0x005d8e48`, `0x005da0be`, `0x005da1e3`, `0x005da3f9`, etc.), indicating shared event-UI cursor/resource range wiring.
  - Correction (code-confirmed): these are not bitmap IDs.
    - `SetCursorRangeAndRefreshMainPanel` (`0x005d7fc0`) explicitly calls `(*curs + 0x204)(0x2B6C, 0x2B67)`.
    - `LoadTurnEventCursorTable` (`0x005d5100`) and `LoadTurnEventCursorByResourceIdOffset1000` (`0x005d5140`) load cursor handles via `LoadCursorA`.
    - Classification for `11111/11115/11116`: cursor resource/range IDs (or cursor-table related selectors), pending final on-disk mapping.
- Deeper tabsenu table inspection completed (new script + findings):
  - Added reusable inspector: `scripts/inspect_tabsenu_tables.py`.
  - Confirmed `NEWS.TAB` schema: `360 x 24-byte` big-endian records indexing into `NEWS.TEX` (`col1/col2/col3/col4` offset-span metadata, `col5=200` constant).
  - Confirmed extensionless `tabsenu.gob_TABLE_S9..S15` files are plaintext command scripts (`tech/zone/army/...`) and correlate with binary `S*.SCN` tag counts.
  - Confirmed `S*.SCN` as tag-driven binary command stream with fixed-size families (`tech=12`, `army/rela/ware/capa/emba=16`, `port/rail=8`, `ship/labo=20`, etc.).
  - Confirmed `S*.MAP` has strong fixed-record stride signal: `309312 / 36 = 8592` records.
  - Confirmed `TABLE_DATA/001..004.TAB` are compact byte-domain matrices (`0..4`), each `450` bytes.
- Cursor-resource location confirmation (new extraction pass):
  - No `CURSOR` / `GROUP_CURSOR` / `ICON` resource types are present in local `Data/*.gob` files.
  - `Imperialism.exe` contains cursor resources:
    - type `1` (`cursor`) ids `7..63`,
    - type `12` (`group_cursor`) names `~C1000..~C1054` plus `227`.
  - Extracted into workspace:
    - `Data/extracted_cursors_exe/cursor` (`57` files),
    - `Data/extracted_cursors_exe/group_cursor` (`56` files),
    - `Data/extracted_cursors_exe/icon` (`6` files),
    - `Data/extracted_cursors_exe/group_icon` (`3` files).
  - This aligns with code path:
    - `LoadTurnEventCursorTable` (`0x005d5100`) loading cursor ids `1000..1053`.
  - Rename normalization completed:
    - `Data/extracted_cursors_exe/cursor`: normalized to numeric-id filenames with `.cur` extension (`7.cur..63.cur`).
    - `Data/extracted_cursors_exe/group_cursor`: normalized to numeric-id filenames with `.cur` extension (`1000.cur..1054.cur`, plus `227.cur`).
  - Usability conversion completed:
    - Added `scripts/build_cursor_pngs.py` to rebuild valid single-image `.cur` containers from raw `RT_CURSOR` blobs and export PNG previews.
    - Generated outputs:
      - `Data/extracted_cursors_exe/cursor_stdcur` + `Data/extracted_cursors_exe/cursor_png` (`57` each),
      - `Data/extracted_cursors_exe/group_cursor_stdcur` + `Data/extracted_cursors_exe/group_cursor_png` (`57` each; group `1013` emits `1013_1`, `1013_2`).
  - User semantic mapping ingested (2026-02-16):
    - Wrote id-based cursor semantics (`48` entries) into Neo4j:
      - `Cursor` nodes `cursor_exe_<raw_id>` for identified IDs (`8..59` subset),
      - linked to EXE resources via new relationships to `Resource` nodes:
        - `resource:exe:cursor:<id>` (`RT_CURSOR`)
        - `resource:exe:group_cursor:<id>` (`RT_GROUP_CURSOR`)
      - linked to screens:
        - `screen_terrain_map` (`19`),
        - `screen_tactical_battle` (`6`),
        - `screen_diplomacy` (`23`).
    - Added safety document: `cursor-semantics-exe.md`.
    - Added pointer section in `cursor-resource-mapping.md` to semantic overlay file.
  - Cursor usage in code/memory linked (2026-02-16):
    - Added function nodes and links in Neo4j for runtime selection/setter paths:
      - `0x00595810` `SetMappedCursorOrDefaultArrow`
      - `0x005958b0` `UpdateMapCursorForTileAndAction`
      - `0x005a8ca0` `SetMappedCursorOrDefaultArrowAlt`
      - `0x005a8d40` `UpdateHexGridHoverCursorAndHighlight`
      - `0x0048c250` `UpdateMapCursorFromSelectionContext`
      - `0x005def70` `SetCursorFromResourceE4AndClampRange`
      - plus diplomacy context handlers (`0x005d7fc0`, `0x005d8040`, `0x005d83b0`) and loaders (`0x005d5100`, `0x005d5140`).
    - Added `Offset` node: `offset_ui_runtime_cursor_table_minus_f8c` (`g_pUiRuntimeContext - 0x0F8C`) with `READS_OFFSET` links from selector functions.
    - Recorded known write sites for cursor table base region: `0x0049dbea`, `0x0049dc60`.
    - Added safety document: `cursor-code-usage-sites.md`.
  - Cursor-focused low-hanging renames applied in Ghidra (2026-02-16):
    - Cursor/token helpers:
      - `0x00495650` -> `IsPointInsideHitRegion`
      - `0x005123e0` -> `ComputeStridedRecordAddress6C`
      - `0x005a86d0` -> `ConvertScreenPointToHexGridCoordClamped`
      - `0x005a0a90` -> `ResolveTacticalHoverCursorToken`
    - QuickDraw helpers used in hover cursor rendering:
      - `0x00494700` -> `BeginScopedMapQuickDrawContext`
      - `0x004948b0` -> `EndScopedMapQuickDrawContext`
      - `0x00495000` -> `SetQuickDrawFillColor`
      - `0x00495070` -> `SetQuickDrawStrokeColor`
      - `0x004953a0` -> `ResetQuickDrawStrokeState`
      - `0x00495920` -> `ApplyHitRegionToClipState`
      - `0x00495a30` -> `SnapshotHitRegionToClipCache`
      - `0x00497320` -> `AcquireReusableQuickDrawSurface`
      - `0x00497390` -> `ReleaseOrCacheQuickDrawSurface`
      - `0x005a99e0` -> `DrawHexSelectionOutlineSegments`
    - Data labels:
      - `0x006a590c` -> `g_pCursorControlPanel`
      - `0x0049dbea` -> `loc_WriteUiRuntimeCursorTableBase_A`
      - `0x0049dc60` -> `loc_WriteUiRuntimeCursorTableBase_B`
    - Synced these function names into Neo4j (`14` upserts).
  - Cursor-focused low-hanging renames pass #2 (2026-02-16):
    - Map/civilian cursor-token table helpers:
      - `0x004a4930` -> `LookupMapCursorTokenByStateIndex`
      - `0x004a4960` -> `ComputeMapCursorStateIndex`
      - `0x004a4aa0` -> `LookupCivilianMapCursorTokenByStateIndex`
      - `0x004d2930` -> `LookupCivilianTileOrderCursorTokenByActionIndex`
    - QuickDraw fill helper:
      - `0x004950f0` -> `SetQuickDrawFillColorFromPaletteIndex`
    - Forced redecompilation confirmed these names propagate into:
      - `UpdateMapCursorForTileAndAction` (`0x005958b0`)
      - `UpdateHexGridHoverCursorAndHighlight` (`0x005a8d40`)
    - Synced pass #2 names into Neo4j (`5` upserts).
  - Cursor-focused low-hanging renames pass #3 (2026-02-16):
    - Added civilian cursor state-index helper:
      - `0x004a4c80` -> `ComputeCivilianMapCursorStateIndex`
    - Added shared-string helper names used in cursor control path:
      - `0x006057a7` -> `StringSharedRef_AssignFromPtr`
      - `0x00492b70` -> `thunk_StringSharedRef_AssignFromPtr`
    - Named remaining quickdraw assertion guards seen in cursor path:
      - `0x00498b50` -> `AssertQuickDrawFlag6A1DC8NonZero`
      - `0x00498b80` -> `AssertQuickDrawFlag6A1DCCNonZero`
    - Forced redecompilation confirmed `UpdateMapCursorFromSelectionContext` now shows named helpers end-to-end.
  - Cursor-focused low-hanging renames pass #4 (2026-02-16):
    - Added tactical hover state-index helper:
      - `0x005a05a0` -> `ComputeTacticalHoverCursorStateIndex`
    - Forced redecompilation confirmed `ResolveTacticalHoverCursorToken` now shows:
    - state-index computation (`ComputeTacticalHoverCursorStateIndex`),
      - table mapping to cursor tokens.
  - Cursor-focused low-hanging renames pass #5 (2026-02-16):
    - Tactical hover/action dispatch helpers:
      - `0x005a3370` -> `DispatchTacticalActionByHoverStateIndex`
      - `0x00406cdf` -> `thunk_DispatchTacticalActionByHoverStateIndex`
      - `0x005a3d30` -> `IsTacticalTargetTileReachableForAction`
      - `0x00406b09` -> `thunk_IsTacticalTargetTileReachableForAction`
    - Tactical packet helper used by state `6` dispatch:
      - `0x005a0d60` -> `QueueTacticalEventPacket232A`
      - `0x0040400c` -> `thunk_QueueTacticalEventPacket232A`
    - Forced redecompilation confirmed `DispatchTacticalActionByHoverStateIndex` now references `thunk_QueueTacticalEventPacket232A`.
    - Synced pass #5 names into Neo4j (`6` upserts).
  - Cursor-focused low-hanging renames pass #6 (2026-02-16):
    - Tactical ownership/neighbor helpers:
      - `0x0059b010` -> `IsTacticalControllerOwnedByActiveNation`
      - `0x004020c2` -> `thunk_IsTacticalControllerOwnedByActiveNation`
      - `0x005a0420` -> `ComputeHexNeighborTileIndices`
      - `0x004032ec` -> `thunk_ComputeHexNeighborTileIndices`
    - Map/civilian movement-class helpers used by cursor-state logic:
      - `0x00514290` -> `GetTileNormalizedMovementClassId`
      - `0x00402b1c` -> `thunk_GetTileNormalizedMovementClassId`
      - `0x00515e50` -> `TileHasMovementClassId`
      - `0x00403d78` -> `thunk_TileHasMovementClassId`
      - `0x005c3490` -> `GetUnitMovementClassId`
      - `0x00407e64` -> `thunk_GetUnitMovementClassId`
    - Additional turn-event helper in cursor-adjacent region:
      - `0x005d5710` -> `UpdateTurnEventPaletteByCode`
      - `0x00407ae5` -> `thunk_UpdateTurnEventPaletteByCode`
    - Forced redecompilation confirms `ComputeTacticalHoverCursorStateIndex` and `ComputeCivilianMapCursorStateIndex` now read significantly clearer.
    - Synced pass #6 names into Neo4j (`14` upserts, including packet helper pair for consistency).
  - Cursor-focused low-hanging renames pass #7 (2026-02-16):
    - Tactical helper for local hex-neighbor membership:
      - `0x005a0550` -> `IsHexNeighborTileIndex`
      - `0x00404c2d` -> `thunk_IsHexNeighborTileIndex`
    - Tactical command-tag dispatcher:
      - `0x005a0c50` -> `HandleTacticalBattleCommandTag`
      - `0x00409002` -> `thunk_HandleTacticalBattleCommandTag`
    - Command tags observed in dispatcher: `done`, `auto`, `retr`, `skip`, `targ`.
    - Synced pass #7 names into Neo4j (`4` upserts).
  - Cursor-focused low-hanging renames pass #8 (2026-02-16):
    - Tactical unit-selection/turn-step helpers:
      - `0x005a0ea0` -> `AdvanceToNextTacticalUnitTurnStep`
      - `0x00404700` -> `thunk_AdvanceToNextTacticalUnitTurnStep`
      - `0x005a1010` -> `SetCurrentTacticalUnitSelection`
      - `0x00402cca` -> `thunk_SetCurrentTacticalUnitSelection`
      - `0x005a10e0` -> `ProcessTacticalUnitState1TurnStep`
      - `0x00407d3d` -> `thunk_ProcessTacticalUnitState1TurnStep`
    - Tactical movement/reaction mini-cluster:
      - `0x005a1520` -> `MoveTacticalUnitTowardTile`
      - `0x00403fbc` -> `thunk_MoveTacticalUnitTowardTile`
      - `0x005a16e0` -> `BuildPathToTargetByDistanceField`
      - `0x0040833c` -> `thunk_BuildPathToTargetByDistanceField`
      - `0x005a1910` -> `MoveTacticalUnitBetweenTiles`
      - `0x00403134` -> `thunk_MoveTacticalUnitBetweenTiles`
      - `0x005a1a20` -> `ResolveTacticalReactionChecksForTile`
      - `0x00405ace` -> `thunk_ResolveTacticalReactionChecksForTile`
      - `0x005a4460` -> `BuildTacticalDistanceFieldForSide`
      - `0x00408a67` -> `thunk_BuildTacticalDistanceFieldForSide`
    - Tactical UI follow-up helpers:
      - `0x005a9b40` -> `UpdateTacticalActionControlBitmapForCurrentUnit`
      - `0x004059e8` -> `thunk_UpdateTacticalActionControlBitmapForCurrentUnit`
      - `0x005a8860` -> `InvalidateTacticalHexTileRect`
      - `0x004029f5` -> `thunk_InvalidateTacticalHexTileRect`
      - `0x005a9cc0` -> `TriggerTacticalUiUpdate2711`
      - `0x004024d2` -> `thunk_TriggerTacticalUiUpdate2711`
      - `0x005a9bb0` -> `SpawnTacticalUiMarkerAtUnitTile`
      - `0x00405678` -> `thunk_SpawnTacticalUiMarkerAtUnitTile`
    - Forced redecompilation now shows tactical turn-step flow with named pathing/movement/reaction helpers.
    - Synced pass #8 names into Neo4j (`24` upserts).
  - Cursor-focused low-hanging renames pass #9 (2026-02-16):
    - Tactical command-tag handlers:
      - `0x005a35a0` -> `HandleTacticalCommandTag_mine`
      - `0x00402dfb` -> `thunk_HandleTacticalCommandTag_mine`
      - `0x005a36d0` -> `HandleTacticalCommandTag_digg`
      - `0x004052e0` -> `thunk_HandleTacticalCommandTag_digg`
      - `0x005a38e0` -> `HandleTacticalCommandTag_raly`
      - `0x004065af` -> `thunk_HandleTacticalCommandTag_raly`
      - `0x005a3f10` -> `HandleTacticalCommandTag_targ`
      - `0x00405b4b` -> `thunk_HandleTacticalCommandTag_targ`
      - `0x005a4370` -> `HandleTacticalCommandTag_depl`
      - `0x004015dc` -> `thunk_HandleTacticalCommandTag_depl`
    - Saved `Imperialism.exe` after rename batch.
    - Synced pass #9 names into Neo4j (`10` upserts).
  - Cursor-focused low-hanging renames pass #10 (2026-02-16):
    - Additional tactical command handlers from `HandleTacticalBattleCommandTag` (`done/retr/skip` path):
      - `0x0059b040` -> `HandleTacticalCommandTag_skip`
      - `0x0059fd10` -> `HandleTacticalCommandTag_retr`
      - `0x0059af20` -> `SelectNextTacticalUnitForDoneCommand`
      - `0x0059fe40` -> `ApplyTacticalDoneSelectionAndRefreshUi`
    - Forced redecompilation of `0x005a0c50` now shows tag flow with named helpers:
      - `done` -> `SelectNextTacticalUnitForDoneCommand` + `ApplyTacticalDoneSelectionAndRefreshUi`
      - `retr` -> `HandleTacticalCommandTag_retr`
      - `skip` -> `HandleTacticalCommandTag_skip`
      - `targ` -> `HandleTacticalCommandTag_targ`
    - Saved `Imperialism.exe` after this pass.
    - Synced pass #10 names into Neo4j (`4` upserts).
  - Cursor-focused low-hanging renames pass #11 (2026-02-16):
    - Batched thunk wrappers for pass #10 tactical command helpers:
      - `0x004055e2` -> `thunk_HandleTacticalCommandTag_skip`
      - `0x004057f9` -> `thunk_HandleTacticalCommandTag_retr`
      - `0x0040809e` -> `thunk_SelectNextTacticalUnitForDoneCommand`
      - `0x00407333` -> `thunk_ApplyTacticalDoneSelectionAndRefreshUi`
    - Scripted boundary check for `0x005a3529` shows this is currently an unmaterialized block between:
      - previous function `DispatchTacticalActionByHoverStateIndex` (`0x005a3370`)
      - next function `HandleTacticalCommandTag_mine` (`0x005a35a0`)
      - block includes `mine` path instructions and a call through `0x004028c4` (thunk to `FUN_005a3c20`).
    - Saved `Imperialism.exe` after this pass.
    - Per user guidance, stop syncing low-level per-function renames to Neo4j; reserve Neo4j updates for high-level concepts only.
  - Cursor-focused low-hanging renames pass #12 (2026-02-16):
    - Shared tactical side-pool helper used by `mine` path:
      - `0x005a3c20` -> `ConsumeTacticalSideResourcePoolAndInvalidateIfEmpty`
      - `0x004028c4` -> `thunk_ConsumeTacticalSideResourcePoolAndInvalidateIfEmpty`
    - Forced redecompilation of `HandleTacticalCommandTag_mine` confirms helper name propagation.
    - Saved `Imperialism.exe` after this pass.
  - Cursor-focused low-hanging renames pass #13 (2026-02-16):
    - Localized UI prompt wrapper used across tactical/options flows:
      - `0x005de990` -> `ShowLocalizedUiPromptByGroupAndIndex`
      - `0x004075a9` -> `thunk_ShowLocalizedUiPromptByGroupAndIndex`
    - Verified propagation in `HandleTacticalBattleCommandTag`:
      - `retr` confirmation now calls `thunk_ShowLocalizedUiPromptByGroupAndIndex(0x273d,0x32,1,1)`.
    - Saved `Imperialism.exe` after this pass.
  - Cursor-focused low-hanging renames pass #14 (2026-02-16):
    - Tactical turn-state finalizer and placement helper:
      - `0x0059fdb0` -> `FinalizeTacticalTurnStateAndQueueEvent232A`
      - `0x00401023` -> `thunk_FinalizeTacticalTurnStateAndQueueEvent232A`
      - `0x005a55c0` -> `TryPlaceTacticalUnitOnTileAndAdvanceSelection`
    - Forced redecompilation confirmed propagation in:
      - `HandleTacticalCommandTag_retr` (`thunk_FinalizeTacticalTurnStateAndQueueEvent232A`)
      - `TryPlaceTacticalUnitOnTileAndAdvanceSelection` (same finalizer in active-unit branch)
    - Saved `Imperialism.exe` after this pass.
  - Cursor-focused low-hanging renames pass #15 (2026-02-16):
    - Hex-grid coordinate helper used by tactical combat resolution:
      - `0x005a59a0` -> `ConvertHexTileIndexToRowAndDoubleColumn`
      - `0x00407b44` -> `thunk_ConvertHexTileIndexToRowAndDoubleColumn`
    - Forced redecompilation confirmed usage in tactical attack distance/chance path.
    - Saved `Imperialism.exe` after this pass.
  - Cursor-focused low-hanging renames pass #16 (2026-02-16):
    - Tactical attack/damage pair:
      - `0x005a5730` -> `ResolveTacticalAttackAgainstTileOccupant`
      - `0x005a63c0` -> `ApplyTacticalDamageAndDeathState`
      - `0x00406023` -> `thunk_ApplyTacticalDamageAndDeathState`
    - Forced redecompilation confirmed attack flow now reads with named conversion + damage helpers.
    - Saved `Imperialism.exe` after this pass.
  - Signature/Variable cleanup pass #17 (2026-02-16):
    - Added meaningful prototypes where behavior is clear:
      - `ConvertHexTileIndexToRowAndDoubleColumn(int tileIndex, uint *outRow, int *outDoubleColumn)`
      - `ShowLocalizedUiPromptByGroupAndIndex(int uiStringIndex, int uiStringGroup, int promptFlagA, int promptFlagB)`
      - `ConsumeTacticalSideResourcePoolAndInvalidateIfEmpty(int tileIndex, int consumeAmount)`
      - `FinalizeTacticalTurnStateAndQueueEvent232A(void)` with `__thiscall`
      - `TryPlaceTacticalUnitOnTileAndAdvanceSelection(int pUnit, int targetTileIndex)`
      - `ResolveTacticalAttackAgainstTileOccupant(int pAttackerUnit, int targetTileIndex)`
      - `ApplyTacticalDamageAndDeathState(float damageAmount, int damageMode)`
    - Easy meaningful variable renames:
      - `ConsumeTacticalSideResourcePoolAndInvalidateIfEmpty`: `iVar1` -> `sideBandIndex`, `iVar2` -> `remainingPool`
      - `ShowLocalizedUiPromptByGroupAndIndex`: `cVar1` -> `promptResult`
    - Saved `Imperialism.exe` after this pass.
  - Struct-first extraction pass #18 (2026-02-16):
    - Created new tactical structs (identity-first, conservative field naming):
      - `/TacticalBattleUnit` (size `0x40`) with validated fields:
        - `tileIndex` (`+0x08`), `stateCode` (`+0x1C`), `ownerSideIndex` (`+0x20`),
          plus conservative stat/flag placeholders used in attack/deploy code paths.
      - `/TacticalBattleController` (size `0x58`) with validated fields:
        - `activeSideIndex` (`+0x0C`), `phaseFlag` (`+0x10`), `pCurrentUnit` (`+0x1C`),
          `pTileThreatOrMoveTable` (`+0x24`), `sideBandBaseIndex` (`+0x34`),
          `isDeploymentPreviewDisabled` (`+0x49`), `sideResourcePool0` (`+0x54`),
          plus conservative pointer/int placeholders.
    - Applied struct usage where API support allowed:
      - `TryPlaceTacticalUnitOnTileAndAdvanceSelection(TacticalBattleUnit *pUnit, int targetTileIndex)`
      - `ResolveTacticalAttackAgainstTileOccupant(TacticalBattleUnit *pAttackerUnit, int targetTileIndex)`
      - `HandleTacticalBattleCommandTag(int commandTag)` and related helpers normalized to `__thiscall`.
    - Important API constraint:
      - `this` auto-parameter typing cannot be changed via MCP (`set_parameter_type` endpoint missing; `set_local_variable_type` cannot retype auto `this` in ECX).
      - Result: signatures still show `void * this`; local/explicit unit parameters are typed.
    - Easy meaningful local typing/renaming in tactical core:
      - `ResolveTacticalAttackAgainstTileOccupant`:
        - locals now include `pController` (`TacticalBattleController *`),
          `pDefenderUnit`/`pActiveUnit` (`TacticalBattleUnit *`),
          `targetRow` (`float`), `targetDoubleColumn` (`int`), `attackerRow` (`uint`), `rangeChanceFactor` (`float`).
      - `TryPlaceTacticalUnitOnTileAndAdvanceSelection`:
        - `canPlace`, `targetRow`, `nextUnitSelection`, `pSideListCursor`.
      - `ConsumeTacticalSideResourcePoolAndInvalidateIfEmpty`:
        - `sideBandIndex`, `remainingPool` typed as `int`.
    - Saved `Imperialism.exe` after this pass.

## Diplomacy Low-Hanging TODO
- [x] Extract direct bitmap literals/tag wiring from `HandleTurnEvent7D8_ActivateDiplomacyMapView` and `0x005d83b0` summary handler.
- [ ] Resolve exact meaning of cursor-range IDs `11111`, `11115`, `11116` (no longer treated as bitmaps).
- [x] Extract `TABLE` resources from local `Data/tabsenu.gob` into workspace path `Data/extracted_tables/tabsenu` (43 files).
- [x] Run deeper structural inspection over extracted table groups (`NEWS.TAB`, `NEWS.TEX`, `S*.SCN`, `S*.MAP`, `TABLE_DATA/*.TAB`) and document first schema pass.
- [ ] Decode semantic meaning of `TABLE_DATA/001..004.TAB` cell values and select canonical dimensions (`30x15` vs `25x18`) with gameplay correlation.
- [ ] Trace `BuildTurnEventDialogUiByCode` branch wiring for `0x7D8/0x7DE` and name the concrete diplomacy window constructor(s).
- [ ] Ask user for semantic labels for extracted cursor IDs (`group_cursor -> cursor` table already generated).
- [ ] Refine placeholder cursor labels with user confirmation:
  - land military variants (`12/13/14`),
  - navy variants (`19..24`),
  - sapper variants (`30/31`).
- [ ] Resolve exact per-ID dispatch branches (token source functions) for diplomacy grants/subsidies and tactical variants.
- [x] Continue low-hanging cursor renames: inspect remaining `thunk_FUN_*` in `UpdateMapCursorFromSelectionContext` (`thunk_FUN_00492b70`, `thunk_FUN_00498b80`, `thunk_FUN_00498b50`) and rename only if behavior is provable.
- [x] Continue low-hanging cursor renames in tactical/map movement dependency path (`0x0059b010`, `0x005a0420`, `0x00514290`, `0x00515e50`, `0x005c3490`) where behavior is provable.
- [ ] Continue low-hanging cursor renames in map cursor resolver path around `thunk_GetMapContextActionLabelTokenByActionCode` and `thunk_ResolveCivilianTileSelectionOrReportActionCode` if helper internals can be named without speculation.
- [ ] Consider renaming tactical range geometry helper `FUN_005a3a70` only after validating semantics across all callers.
- [ ] Continue struct-first extraction by typing tactical `this` pointers in UI (manual Ghidra retype required for auto-parameter `this`) and then converting controller fields from placeholder names to semantic names.
- [ ] Continue low-hanging renames in diplomacy-adjacent `0x005d44xx..0x005d47xx` wrappers only after proving concrete localization semantics.
- [x] Continue low-hanging tactical renames around `FUN_005a0ea0`, `FUN_005a1010`, `FUN_005a10e0` once unit-cycle semantics are confirmed across callers.
- [x] Continue low-hanging tactical renames around `FUN_005a3f10`, `FUN_005a36d0`, `FUN_005a1910` call-chain command handlers where tag intent is already known (`targ`, etc.).
- [x] Recover Ghidra MCP connection and rerun pending tactical command-handler renames (`mine/digg/raly/targ/depl` cluster).

## Ops Notes (2026-02-17)
- [x] Local Python env setup with `uv` in repo:
  - `.venv` recreated on CPython `3.12.12`.
  - Installed: `pyhidra==1.3.0`, `jpype1==1.6.0`, `packaging==26.0`.
- [x] Confirmed Ghidra install path from user:
  - `/home/andrzej.gluszak/Downloads/ghidra_12.0.2_PUBLIC_20260129/ghidra_12.0.2_PUBLIC`
- [x] Backed up Imperialism Ghidra project files:
  - Source: `/home/andrzej.gluszak/code/personal/imperialism-decomp.gpr`
  - Source: `/home/andrzej.gluszak/code/personal/imperialism-decomp.rep`
  - Archive: `/home/andrzej.gluszak/code/personal/imperialism_knowledge/backups/imperialism-ghidra-20260217_002107.tar.gz`
  - Checksum: `/home/andrzej.gluszak/code/personal/imperialism_knowledge/backups/imperialism-ghidra-20260217_002107.tar.gz.sha256`
- [ ] Next: wire repo-local pyhidra launcher against `imperialism-decomp.gpr` + `Imperialism.exe` program and resume struct-mining without MCP.
- pyghidra migration note (2026-02-17):
  - Installed `pyghidra==3.0.2` in repo `.venv` (`jpype1==1.5.2`).
  - `pyhidra==1.3.0` still importable, but prefer `pyghidra` going forward.
  - Verified working open against existing project while GUI Ghidra is open:
    - `pyghidra.start(install_dir=Path('/home/andrzej.gluszak/Downloads/ghidra_12.0.2_PUBLIC_20260129/ghidra_12.0.2_PUBLIC'))`
    - `pyghidra.open_program(..., project_location='/home/andrzej.gluszak/code/personal', project_name='imperialism-decomp', program_name='Imperialism.exe', analyze=False, nested_project_location=False)`
    - Result: opened program successfully (`Imperialism.exe`, image base `0x00400000`).
  - Next default automation route: pyghidra scripts (avoid MCP dependency for heavy scans/renaming).
- pyghidra API validation (non-deprecated path):
  - `pyghidra.open_project('/home/andrzej.gluszak/code/personal', 'imperialism-decomp', create=False)`
  - `with pyghidra.program_context(project, '/Imperialism.exe') as program:` opened successfully.
- Project relocation (2026-02-17):
  - Moved Ghidra Imperialism project files into repo root:
    - `/home/andrzej.gluszak/code/personal/imperialism_knowledge/imperialism-decomp.gpr`
    - `/home/andrzej.gluszak/code/personal/imperialism_knowledge/imperialism-decomp.rep`
  - Old parent location no longer contains project files.
  - TODO: use project location `/home/andrzej.gluszak/code/personal/imperialism_knowledge` for all `pyghidra.open_project(...)` calls.
- Environment metadata (2026-02-17): added `/home/andrzej.gluszak/code/personal/imperialism_knowledge/pyproject.toml` with pinned deps from current `.venv` (`ghidra-stubs`, `java-stubs-converted-strings`, `jpype1`, `packaging`, `pyghidra`).
- Git/LFS setup (2026-02-17):
  - Installed `git-lfs` and ran `git lfs install`.
  - Added LFS tracking rule: `*.gzf` in `.gitattributes`.
  - Updated `.gitignore` to exclude live Ghidra project blobs:
    - `imperialism-decomp.gpr`
    - `imperialism-decomp.rep/`
    - `*.lock`, `*.lock~`
  - Created `exports/.gitkeep` for storing exported Ghidra snapshot artifacts under version control (with LFS for `.gzf`).
- Git remote switch (2026-02-17): set `origin` to `git@github.com:agluszak/imperialism-decomp.git`.
- `git ls-remote origin` returned no refs (likely empty/new remote repository) but command succeeded (remote reachable).
- Snapshot export (2026-02-17): exported Ghidra snapshot via `pyghidra` + `GzfExporter`.
  - File: `/home/andrzej.gluszak/code/personal/imperialism_knowledge/exports/Imperialism-20260217_003824.gzf`
  - Checksum file: `/home/andrzej.gluszak/code/personal/imperialism_knowledge/exports/Imperialism-20260217_003824.gzf.sha256`
  - Export path validated against project file `/Imperialism.exe`.
- pyghidra live session rename pass (2026-02-17, post-LFS setup):
  - Switched to long-lived Python REPL workflow for faster iteration.
  - Verified dialog factory callback registry (`InitializeTurnEventDialogFactoryRegistry`) and scanned callback handlers for event-code compares.
  - Applied/saved conservative event-group renames:
    - `0x0046fd10`: `FUN_0046fd10` -> `BuildTurnEventDialogForEvent7DE`
    - `0x00407531`: `thunk_FUN_0046fd10` -> `thunk_BuildTurnEventDialogForEvent7DE`
    - `0x004295a0`: `FUN_004295a0` -> `BuildTurnEventDialogForEventGroup7D8_547_548_7E0_7E1`
    - `0x00403f99`: `thunk_FUN_004295a0` -> `thunk_BuildTurnEventDialogForEventGroup7D8_547_548_7E0_7E1`
    - `0x0043dbc0`: `FUN_0043dbc0` -> `BuildTurnEventDialogForEventGroup7DE_7DD_546`
    - `0x00407013`: `thunk_FUN_0043dbc0` -> `thunk_BuildTurnEventDialogForEventGroup7DE_7DD_546`
  - Confirmed these are event-group handlers by decompiled compares on `param_2` (e.g., `0x7DE`, `0x7D8`, `0x7DD`, `0x546`, `0x547`, `0x548`, `0x7E0`, `0x7E1`).
  - Save status: `project.save()` executed after renames.
  - Known limitation encountered:
    - `InitializeTradeScreenBitmapControls` (`0x00409773`) decompile intermittently fails in this headless REPL pass; no rename done there yet.

## TODO (current)
- [ ] Continue short-block REPL workflow (avoid long multi-line block state issues).
- [ ] Re-run targeted decompilation for `0x00409773` and adjacent trade callbacks to map bitmap IDs `2101/2102` and `2111..2128` directly in code.
- [ ] Once direct bitmap wiring is confirmed in one handler, rename that handler and its thunk with concrete trade-screen semantics.

## MCP Recovery + Low-Hanging Pass (2026-02-17)
- MCP workflow restored and validated end-to-end (`ghidra-mcp` + `neo4j`).
- Ran `instructions.md` workflow on live selection `0x004b4d50`:
  - confirmed boundaries/analysis/completeness,
  - corrected prototype parsing issue for `__thiscall`,
  - finalized signature as `ToggleCityPowerPlantUpgradeOrder(void *this, bool fEnableUpgrade)`,
  - rewrote structured plate comment (Algorithm/Parameters/Returns/Special Cases/Magic Numbers).
- Low-hanging rename cluster completed for selectable-text entry iteration helpers used in trade selection paths:
  - `0x004919a0` -> `InitializeSelectableTextOptionEntryIteratorContext`
  - `0x00491a00` -> `BeginSelectableTextOptionEntryIterator`
  - `0x00491a70` -> `AdvanceSelectableTextOptionEntryIterator`
  - `0x00491ab0` -> `IsSelectableTextOptionEntryIteratorValid`
  - thunks:
    - `0x00403bbb` -> `thunk_InitializeSelectableTextOptionEntryIteratorContext`
    - `0x00405754` -> `thunk_BeginSelectableTextOptionEntryIterator`
    - `0x00404368` -> `thunk_AdvanceSelectableTextOptionEntryIterator`
    - `0x00406c4e` -> `thunk_IsSelectableTextOptionEntryIteratorValid`
- Additional low-hanging diplomacy/cursor-adjacent renames:
  - `0x005c4a40` -> `EnableAndProcessFlagWithSharedStringCleanup`
  - `0x00404d54` -> `thunk_EnableAndProcessFlagWithSharedStringCleanup`
  - `0x004e3620` -> `ComputeMaskedWordSumFromOffsetE0_Count23`
  - `0x00401f23` -> `thunk_ComputeMaskedWordSumFromOffsetE0_Count23`
  - `0x00401226` -> `thunk_UpdateMapCursorFromSelectionContext`
- Signature/variable cleanup where semantics are clear:
  - `0x00586170` `UpdateTradeResourceSelectionByIndex(int nResourceIndex)` (`__thiscall`)
    - locals renamed to `pCurrentEntry`, `fIteratorValid`, `pMatchedEntry`.
  - `0x005797c0` `SetSelectedTextOptionByTag(int nSelectedTag, bool fRedrawChangedEntries)` (`__thiscall`)
    - locals renamed to `iIterOrVtable`, `pCurrentEntry`, `fEntryShouldBeSelected`.
  - Both functions received structured plate comments.
- Neo4j sync (high-level only):
  - Upserted 15 renamed `Function` nodes (`last_updated=2026-02-17`).
  - Added concept node:
    - `concept_ui_selectable_text_option_entry_iteration`
  - Added claim:
    - `claim_ui_selectable_text_option_entry_iterator_cluster_20260217`
  - Linked claim -> concept/functions via `ASSERTS`.

## TODO (next low-hanging)
- [x] Continue around `HandleTurnEvent7D8_ActivateDiplomacyMapView` / `HandleTurnEvent7DE_RefreshTradeDiplomacyCityTransportSummary` by renaming remaining obvious wrappers (`thunk_FUN_005c4590`, nearby `0x005d44xx..0x005d47xx`) only when call intent is unambiguous.
- [ ] Inspect iterator-context struct layout behind `InitializeSelectableTextOptionEntryIteratorContext` and type fields if trivial (avoid deep struct audit for now).
- [ ] Resume unresolved trade bitmap IDs (`2115/2116/2117/2119`) by tracing concrete control instances in `UpdateTradeResourceSelectionByIndex` selection path.

## MCP Diplomacy Flavor-Text Pass (2026-02-17, continued)
- Completed low-hanging rename/signature/comment pass around `0x005d44xx..0x005d47xx` and shared style helper path.
- Renamed flavor-text generation cluster:
  - `0x005d4410` -> `SetSharedStringFromMappedFlavorTextWithLengthClamp`
  - `0x00408b89` -> `thunk_SetSharedStringFromMappedFlavorTextWithLengthClamp`
  - `0x005d4550` -> `SetSharedStringFromRotatingFlavorTextBySlot`
  - `0x004089db` -> `thunk_SetSharedStringFromRotatingFlavorTextBySlot`
  - `0x005d46b0` -> `GenerateMappedFlavorTextByTableSlot`
  - `0x00405312` -> `thunk_GenerateMappedFlavorTextByTableSlot`
  - `0x005d46e0` -> `GenerateMappedFlavorTextByCurrentContextNation`
  - `0x00403a76` -> `thunk_GenerateMappedFlavorTextByCurrentContextNation`
  - `0x005d4720` -> `GenerateMappedFlavorTextUntilValidationPasses`
  - `0x00408e8b` -> `thunk_GenerateMappedFlavorTextUntilValidationPasses`
- Renamed style/shared-string helper path:
  - `0x005c4590` -> `ApplyUiTextStyleAndThemeFlags`
  - `0x0040263a` -> `thunk_ApplyUiTextStyleAndThemeFlags`
  - `0x0056d5c0` -> `BuildSharedStringFromMappedFlavorTextIndex`
  - `0x0040709a` -> `thunk_BuildSharedStringFromMappedFlavorTextIndex`
- Signature updates (safe wrappers only):
  - `GenerateMappedFlavorTextByTableSlot(void* pDstSharedRef, short nTableSlot)`
  - `GenerateMappedFlavorTextByCurrentContextNation(void* pDstSharedRef)`
  - `GenerateMappedFlavorTextUntilValidationPasses(void* pDstSharedRef, short nMappedFlavorCode)`
  - `SetSharedStringFromMappedFlavorTextWithLengthClamp(void* pDstSharedRef, int nTableSlot)`
  - `SetSharedStringFromRotatingFlavorTextBySlot(void* pDstSharedRef, int nSlotIndex)`
  - `BuildSharedStringFromMappedFlavorTextIndex(void* pDstSharedRef, int nMappedFlavorIndex)`
  - `ApplyUiTextStyleAndThemeFlags(int* pControl, int nThemeCode, int nStyleArgA, int nStyleArgB, int nStyleArgC)`
- Added plate comments for all functions above.
- Forced redecompile validation confirmed name propagation into:
  - `RebuildMapContextAndGlobalMapState`
  - `FUN_0050f740`
  - `FUN_00577030`
- Observed behavior summary:
  - `DAT_0066ef30` acts as slot->mapped-code table feeding the flavor-text dispatch.
  - `GenerateMappedFlavorTextUntilValidationPasses` uses 18-way dispatch (`mod 0x12`) and retries while `thunk_FUN_005d4240` returns non-zero.
  - `SetSharedStringFromMappedFlavorTextWithLengthClamp` enforces `len <= 12` in the non-localized generation path when `DAT_006a43f0 == 0`.
  - `SetSharedStringFromRotatingFlavorTextBySlot(-1)` clears rotation counters at `DAT_006a5af0`.
- Neo4j sync (high-level only):
  - Upserted 14 renamed `Function` nodes.
  - Added concept: `concept_mapped_flavor_text_generation`.
  - Added claim: `claim_mapped_flavor_text_dispatch_cluster_20260217`.
  - Linked claim -> concept/functions via `ASSERTS`.

## TODO (updated low-hanging)
- [ ] Confirm exact character/limit semantics for `ShouldRetryMappedFlavorTextGeneration` / `FindCharIndexInStringPtrOrMinusOne` and refine signatures if needed.
- [ ] Decode semantic mapping of `DAT_0066ef30` entries (which flavor family each slot maps to), then ask user for in-game meaning labels where needed.
- [ ] Resume unresolved trade bitmap IDs (`2115/2116/2117/2119`) by tracing concrete control instances in `UpdateTradeResourceSelectionByIndex` selection path.

## MCP Diplomacy Flavor-Text Mini-Pass (2026-02-17, validator helpers)
- Additional conservative helper renames:
  - `0x005d4240` -> `ShouldRetryMappedFlavorTextGeneration`
  - `0x0040636b` -> `thunk_ShouldRetryMappedFlavorTextGeneration`
  - `0x005fee99` -> `FindCharIndexInStringPtrOrMinusOne`
- Prototypes updated (provisional, may need refinement after deeper disassembly check):
  - `ShouldRetryMappedFlavorTextGeneration(bool-returning helper)`
  - `FindCharIndexInStringPtrOrMinusOne(int-returning helper)`
- Forced redecompile verification:
  - `GenerateMappedFlavorTextUntilValidationPasses` now explicitly shows retry via
    `thunk_ShouldRetryMappedFlavorTextGeneration(...)`.
- Data-table extraction:
  - Added label: `g_adwFlavorTextMappedCodeBySlot` at `0x0066EF30`.
  - Raw table values (`23` dword entries): `[0, 9, 16, 14, 17, 8, 2, 5, 12, 11, 13, 6, 6, 6, 6, 4, 7, 1, 1, 10, 15, 10, 10]`.
- Neo4j sync (high-level/provisional):
  - Upserted 3 renamed `Function` nodes.
  - Added provisional claim: `claim_mapped_flavor_text_retry_validator_20260217`
    linked to `concept_mapped_flavor_text_generation` and helper function nodes.
  - Added confirmed mapping-table claim: `claim_flavor_text_slot_mapping_table_66ef30_20260217`.

## MCP Trade Initializer Disassembly Pass (2026-02-17, post-interrupt)
- Applied user guidance: keep Neo4j for high-level concepts only; capture detailed evidence in Ghidra comments + this file.
- Renamed wrapper to remove collision:
  - `0x00409773` -> `thunk_InitializeTradeScreenBitmapControls`
  - Core remains `InitializeTradeScreenBitmapControls` at `0x004601b0` (MCP decompiler still times out; disassembly workflow used).
- Added MCP-run extraction script:
  - `scripts/find_trade_bitmap_pushes.py`
  - Purpose: enumerate `PUSH` immediates in range `0x830..0x860` inside `0x004601b0`.
  - Result: `162` hits.
  - Confirmed IDs present in initializer body:
    - `0x835` (`2101`), `0x836` (`2102`)
    - `0x840` (`2112`), `0x841` (`2113`), `0x842` (`2114`)
    - `0x848` (`2120`), `0x849` (`2121`), `0x84b` (`2123`)
    - `0x84e` (`2126`), `0x850` (`2128`)
  - Not observed in this specific push scan:
    - `0x83f` (`2111`), `0x84d` (`2125`) (consistent with dedicated bid-state toggler paths).
- Added targeted disassembly comments in the initializer:
  - `0x004602e9` -> `0x836` post-oil background
  - `0x0046674d` -> `0x835` pre-oil background
  - `0x00460718` -> `0x849` left/decrease arrow base
  - `0x004607ad` -> `0x84b` right/increase arrow base
  - `0x00460841` -> `0x848` gree control base
  - `0x00460aad` -> `0x840` bid secondary base
  - `0x00460b3f` -> `0x842` offer secondary base
  - `0x004605f1` -> `0x84e` bid secondary alt
  - `0x00460683` -> `0x850` offer secondary alt
  - `0x00462c78` / `0x004696e3` -> `0x841` offer base repeats
  - Function entry comments at `0x004601b0` and `0x00409773` also added.

## TODO (trade disassembly next)
- [ ] Annotate one canonical `0x841`/`0x84f` pair site in trade row setup (Offer base/alt visual states) with explicit state wording.
- [x] Trace `0x83f`/`0x84d` (`2111/2125`) in dedicated bid-state functions and add matching in-place disassembly comments.
- [ ] Continue unresolved IDs (`2115/2116/2117/2119`) via selection-path control-instance tracing (`UpdateTradeResourceSelectionByIndex` chain).

## MCP Trade Global Bitmap Push Scan (2026-02-17)
- Added MCP-run script:
  - `scripts/find_global_bitmap_pushes.py`
  - Purpose: global instruction scan for `PUSH` of `[2101,2102,2111,2113,2125,2127]`.
- Script findings (`24` hits) confirmed the dedicated bid/offer state selectors:
  - `SetTradeBidControlBitmapState`:
    - `0x00587c0d` -> `0x84D` (`2125`)
    - `0x00587c14` -> `0x83F` (`2111`)
  - `SetTradeOfferControlBitmapState`:
    - `0x00587e31` -> `0x84F` (`2127`)
    - `0x00587e38` -> `0x841` (`2113`)
- Added disassembly comments at those exact addresses with pair semantics.
- Additional comments added at repeat setup sites for `0x841`:
  - `0x00465270`
  - `0x0046bcdb`
- Current state:
  - `2101/2102` confirmed and commented in trade initializer.
  - `2111/2125` confirmed and commented in bid-state setter.
  - `2113/2127` confirmed and commented in offer-state setter.
- Remaining unresolved trade IDs: `2115/2116/2117/2119`.

## MCP Startup + Message Pump Pass (2026-02-17)
- Objective pivot: decode startup chain, window class/window creation, and message pump low-hanging fruit.
- Confirmed entry points:
  - program entry label: `0x00400000`
  - external/runtime entry function: `entry` at `0x005e98b0`
- Entrypoint call chain (high level):
  - `entry (0x005e98b0)` does CRT setup (heap/TLS/argv/envp), then calls
    `CallMfcAppLifecycleEntry (0x005fa7c2)` at `0x005e99fd`.
  - `CallMfcAppLifecycleEntry` is a 4-arg trampoline into
    `DispatchMfcAppLifecycle (0x0060d3fc)` (AfxWinMain-like handoff).
- WinAPI usage mapping via targeted import xref script:
  - `GetMessageA` callers include:
    - `PumpMfcThreadMessageCore (0x0060694f)`
    - `DispatchContextHelpTrackingMessage (0x006197f7)`
  - `TranslateMessage` + `DispatchMessageA` also used in `PumpMfcThreadMessageCore`.
  - `PeekMessageA` used by:
    - `RunMfcThreadMessageLoopCore (0x006063cd)`
    - `RunModalLoopWithIdleMessages (0x0060a60a)`
    - `DispatchPendingMessagesWithoutTranslate (0x0060a073)`
    - `PumpUiMessagesAndBackgroundTasks (0x004868c0)`
    - plus context-help helpers.
  - `RegisterClassA` used in:
    - `RegisterWindowClassIfNeeded (0x00608892)`
  - `CreateWindowExA` used in:
    - `CreateWindowExWithPreCreateHook (0x00608115)`
- New low-risk renames:
  - `FUN_006148af` -> `EnsureFrameAcceleratorTablesLoaded`
  - `FUN_0061c76d` -> `LoadAcceleratorTableFromResourceId`
- Ghidra comments added:
  - plate comments on `entry`, `CallMfcAppLifecycleEntry`, `DispatchMfcAppLifecycle`,
    `RunMfcThreadMessageLoopCore`, `PumpMfcThreadMessageCore`,
    `CreateWindowExWithPreCreateHook`, `RegisterWindowClassIfNeeded`,
    `EnsureFrameAcceleratorTablesLoaded`, `LoadAcceleratorTableFromResourceId`.
  - disassembly comment at `0x005e99fd` marking CRT -> app/framework handoff.

## TODO (startup/mfc low hanging)
- [ ] Identify concrete app class virtual targets used by `DispatchMfcAppLifecycle` (`[ESI+0x58/0x5c/0x70/0x8c]` and `[EAX+0x60]`) and rename if still generic.
- [ ] Rename `DispatchPendingMessagesWithoutTranslate (0x0060a073)` if semantics become clearer (currently generic but likely accurate).
- [ ] Map top-level game window proc registration path from `RegisterWindowClassIfNeeded` to final wndproc and tag with WM_* responsibilities.

## MCP Startup + Message Pump Pass (2026-02-17, continuation)
- Resolved key import-slot pointers used in startup window wrappers via MCP script:
  - `0x006ab2ac` -> `PTR_CreateWindowExA_006ab2ac`
  - `0x006ab3ec` -> `PTR_GetClassInfoA_006ab3ec`
  - `0x006ab2bc` -> `PTR_RegisterClassA_006ab2bc`
  - `0x006ab0d4` -> `PTR_lstrcatA_006ab0d4`
  - `0x006ab3f0` -> `PTR_LoadMenuA_006ab3f0`
  - `0x006ab510` -> `PTR_LoadAcceleratorsA_006ab510`
- Additional low-hanging startup/window renames:
  - `FUN_0060893b` -> `FormatAndRegisterWindowClass`
  - `FUN_0060a794` -> `RegisterMfcWindowClassesByFlags`
  - `FUN_00493d80` -> `RegisterGameWindowClass_64B740`
- Added lifecycle-stage comments in `DispatchMfcAppLifecycle (0x0060d3fc)` on virtual calls:
  - `0x0060d427` pre-init gate virtual
  - `0x0060d433` init/run decision virtual
  - `0x0060d443` main-window fallback virtual
  - `0x0060d448` fallback-exit virtual
  - `0x0060d44f` run virtual (return propagated)
- Added/updated plate comments on:
  - `FormatAndRegisterWindowClass`
  - `RegisterMfcWindowClassesByFlags`
  - `RegisterGameWindowClass_64B740`

## TODO (startup/window path)
- [ ] Resolve concrete class/object type behind `DispatchMfcAppLifecycle` `EDI` object and map vtable offsets (`+0x58/+0x5c/+0x70/+0x8c`) to canonical MFC method names.
- [ ] Trace `RegisterAmbitGameWindowClass` -> created window instance -> final wndproc dispatch path to identify primary game wndproc entry and WM message fanout functions.
- [ ] Rename `FUN_006080ce` / `FUN_0060820b` callers of `CreateWindowExWithPreCreateHook` once creation-phase semantics are confirmed.

## MCP Startup + Message Pump Pass (2026-02-17, window-create wrappers)
- Decoded and renamed core window-creation helper wrappers:
  - `FUN_006080ce` -> `CreateWindowFromRectAndParent`
  - `FUN_0060820b` -> `CreateChildWindowFromRect`
  - `FUN_006081d9` -> `EnsureMainFrameClassNameAssigned`
  - `FUN_00613d23` -> `EnsureIconFrameClassNameAssigned`
- Behavior notes confirmed from disassembly:
  - `CreateWindowFromRectAndParent` computes x/y/w/h from a RECT-like struct and forwards to `CreateWindowExWithPreCreateHook`.
  - `CreateChildWindowFromRect` does same but ORs style with `0x40000000` (`WS_CHILD`).
  - `EnsureMainFrameClassNameAssigned` lazily ensures class flag `0x1` is registered and sets class-name pointer to `0x6707f0`.
  - `EnsureIconFrameClassNameAssigned` lazily ensures class flag `0x8` is registered and sets class-name pointer to `0x670828`.
- Additional comments placed at key callsites:
  - `0x0060810a` (delegate to `CreateWindowExWithPreCreateHook`)
  - `0x0060823d` (`WS_CHILD` style force)
  - `0x00483de9` / `0x00493dbb` notes tying registration flow to wndproc `0x64B740`.

## TODO (startup/window path, narrowed)
- [ ] Recover function at `0x64B740` (if missing function boundary) and label as probable primary game wndproc.
- [ ] Trace where `RegisterAmbitGameWindowClass` / `RegisterGameWindowClass_64B740` are invoked via vtable/indirect dispatch and annotate init sequence.
- [ ] Continue replacing `FUN_005e58ab`..`FUN_005e67ec` bucket around class-flag registration with semantic names as patterns emerge.

## MCP Startup + Message Pump Pass (2026-02-17, wndproc/classname correction + loop detail)
- Corrected earlier assumption: `0x64B740` and `0x648380` are class-name strings, not code pointers.
  - `0x0064b740` detected string: `AmbitMcWindow`
  - `0x00648380` detected string: `AmbitGameWindow`
- Renamed data labels:
  - `sAmbitMcWindowClassName` at `0x0064b740`
  - `sAmbitGameWindowClassName` at `0x00648380`
- Confirmed default/proc pointers used in window dispatch helper:
  - `PTR_DefWindowProcA_006ab48c`
  - `PTR_CallWindowProcA_006ab2a0`
- Renamed class registration function:
  - `RegisterGameWindowClass_64B740` -> `RegisterAmbitMcWindowClass`
- Added missing thunk functions (via create_function):
  - `thunk_RegisterAmbitMcWindowClass` at `0x004083a5`
  - `thunk_RegisterAmbitGameWindowClass` at `0x00409804`
- Message loop/API comments tightened:
  - `RunMfcThreadMessageLoopCore` and `PumpMfcThreadMessageCore` comments now explicitly mention `PeekMessageA` / `GetMessageA` / `TranslateMessage` / `DispatchMessageA` roles.
  - Callsite comments added at `0x006063f1`, `0x0060695c`, `0x0060697c`, `0x00606983`.
- Updated class registration comments to refer to class-name pointers (not wndproc pointers).

## TODO (next immediate low-hanging)
- [ ] Trace source of class wndproc pointer (`WNDCLASS.lpfnWndProc`) populated from `PTR_DefWindowProcA_006ab48c` path and identify framework subclass hook point that injects custom message handling.
- [ ] Resolve virtual hooks in `RunMfcThreadMessageLoopCore` (`[vtable+0x64/+0x68/+0x6c/+0x70]`) into named semantics (OnIdle/IsIdleMessage/PumpMessage-like).
- [ ] Explore refs to `RunImperialismThreadMainLoop` from data/vtables (`0x0063e32c`, `0x0066fe58`) to name owning class/object.

## Cross-Cut TODOs (user-requested: try each item)

### 1) Find all class-name strings
- [~] Build automated candidate extraction from strings matching class/window/wnd/dialog/frame tokens.
- [~] Correlate candidates with `RegisterClassA` / `GetClassInfoA` / class registration wrappers.
- [ ] Separate true window-class names from generic UI/help text strings.
- [ ] Promote high-confidence class strings to stable labels/comments.

Progress/results:
- Added script: `new_scripts/list_candidate_class_strings.py`.
- Ran it and got strong candidates with callers, including:
  - `AmbitMcWindow` (`sAmbitMcWindowClassName`)
  - `AmbitGameWindow` (`sAmbitGameWindowClassName`)
  - `AfxWnd42s`, `AfxFrameOrView42s`, `AfxMDIFrame42s`, `ToolbarWindow32`, `tooltips_class32`.
- Confirmed and corrected earlier misunderstanding: class-name strings are data, not wndproc code addresses.

### 2) Find all classes (or class-like structures)
- [~] Start with virtual-call-site mapping in startup/message-loop classes.
- [ ] Expand to vtable cluster discovery and ownership mapping (object + methods).
- [ ] Decide confidence thresholds for naming inferred classes vs keeping provisional labels.

Progress/results:
- Added script: `new_scripts/list_virtual_call_sites_in_function.py`.
- Ran on:
  - `DispatchMfcAppLifecycle` (`0x0060d3fc`) -> vcall offsets `+0x58/+0x5c/+0x70/+0x8c` (+ nested `+0x60`).
  - `RunMfcThreadMessageLoopCore` (`0x006063cd`) -> vcall offsets `+0x64/+0x68/+0x6c/+0x70`.
- This gives a concrete, repeatable base for class/method reconstruction.

### 3) Functionalize missing functions (not marked as functions)
- [x] Implement conservative auto-recovery script for direct CALL/JMP targets in executable memory.
- [~] Run in bounded batches and review created functions.
- [ ] Perform second pass with stricter exclusions for suspected data/jumptable targets.

Progress/results:
- Added script: `new_scripts/create_missing_functions_from_direct_branches.py`.
- Ran with cap=15; successfully created 15 functions:
  - `FUN_004c6fb0`, `FUN_00515de0`, `FUN_00534ed0`, `FUN_00531110`, `FUN_005966a0`,
    `FUN_0052fd80`, `FUN_004be3f0`, `FUN_00487f90`, `FUN_00487a00`, `FUN_0048ca40`,
    `FUN_00534f50`, `FUN_00534ca0`, `FUN_0052efb0`, `FUN_004dcc30`, `FUN_0048c9e0`.
- No destructive cleanup applied; next step is triage/naming on low-hanging subset.

## Continuation (2026-02-17, no-stop pass)
- Tried each requested area and advanced all three.
- Additional class-string low-hanging labels applied:
  - `sAfxWnd42sClassName` @ `0x006707f0`
  - `sAfxFrameOrView42sClassName` @ `0x00670828`
  - `sAfxMDIFrame42sClassName` @ `0x00670818`
  - `sToolbarWindow32ClassName` @ `0x00671080`
  - `sTooltipsClass32ClassName` @ `0x006745bc`
  - `sAfxOldWndProcPropName` @ `0x00670858`
- Note on auto-created functions: many are tiny stubs with bytes like `C3 90 90 90` or `C2 xx xx 90`; these are likely valid thunk/adapter epilog stubs, not necessarily false positives.

## Next immediate queue
- [ ] Add filter to missing-function script to optionally skip tiny `ret-only` entries unless referenced by >1 caller.
- [ ] Run second missing-function batch with stricter heuristics (e.g., skip destinations beginning with `RET` opcodes) and compare yield.
- [ ] Continue class-name extraction by excluding obvious non-class UI text and focusing on registration-call reachable strings.

## Direct Aggressive Discovery Pass (2026-02-17, no MCP)
- User requested direct execution (terminal/headless), not MCP.
- Added direct pyghidra scanner with progress logs:
  - `new_scripts/aggressive_discovery_pyghidra.py`
- Headless run command (works):
  - `HOME=/tmp XDG_CONFIG_HOME=/tmp JAVA_TOOL_OPTIONS='-Djava.awt.headless=true' .venv/bin/python new_scripts/aggressive_discovery_pyghidra.py ...`
- Output written:
  - `exports/aggressive_discovery_20260217.json`
- Run summary (from script logs):
  - `class_string_hits=220`
  - `vtable_candidates=220` (raw found 1019)
  - `virtual_call_functions=140`
  - `virtual_call_offsets=120`
  - elapsed ~`9.65s`
- Script logs now show clear progress per phase/block/function-scan.

## Direct Aggressive Labeling Pass (2026-02-17, no MCP)
- Added direct type-name label applier:
  - `new_scripts/apply_type_name_labels_from_aggressive_json.py`
- Switched applier to `pyghidra.open_program(..., analyze=False)` so edits persist in headless mode.
- Applied 90 aggressive type-name labels from high-confidence `T*/C*...(Dialog|Window|View|Frame|Wnd)` candidates.
- Verification pass confirms persistence:
  - `sTypeName_*` symbol count = `90`.
  - examples: `sTypeName_CMainFrame`, `sTypeName_CMcWindow`, `sTypeName_TGameWindow`, `sTypeName_TTradeScreenView`.

## Direct Vtable Candidate Labeling (2026-02-17)
- Added direct vtable candidate labeler:
  - `new_scripts/apply_vtable_candidate_labels.py`
- Applied labels to top 80 candidates from JSON output.
- Verification pass confirms persistence:
  - `g_vtblCandidate_*` symbol count = `80`.
  - examples: `g_vtblCandidate_0066f120_len65`, `g_vtblCandidate_0063e8b0_len32`, multiple len30 clusters.

## Environment Notes (direct mode)
- `pyproject.toml` updated to pin `jpype1==1.5.2` per user request.
- Removed `java-stubs-converted-strings==0.1.0` from project deps because it hard-required `jpype1>=1.6.0` and made resolution unsatisfiable.
- `uv run` project mode still blocked by package-build layout (no Python package folder); direct `.venv/bin/python` path remains the reliable execution mode for these scripts.

## TODO (aggressive continuation)
- [ ] Promote top virtual-call cluster functions (from JSON) into naming candidates by family (`0x1c8/0xa4/0xa8` UI-control family etc.), batch-rename low-risk `FUN_*` entries.
- [ ] Split vtable candidate clusters into likely class families by shared leading function tuples; assign family labels (e.g., trade/dialog/city-view families).
- [ ] Add a direct exporter that emits CSV subsets (`class_names.csv`, `vtable_candidates.csv`, `vcall_clusters.csv`) for quick manual triage.

## Aggressive Continuation (2026-02-17, direct/headless)

### Vtable family grouping (done)
- Added script: `new_scripts/export_vtable_families.py`.
- Generated family exports from `exports/aggressive_discovery_20260217.json`:
  - `exports/vtable_families_20260217.json`
  - `exports/vtable_families_20260217.csv`
- Summary:
  - `14` vtable families total.
  - Top families:
    - `VF001`: count `82` (signature starts with turn-event/city-dialog no-op thunk quartet), run length `30`.
    - `VF002`: count `70` (city-dialog dispatch/forward quartet), run length `16`.
    - `VF003`: count `33` (city-dialog payload/copy/get/set quartet), run length `23`.

### Batch rename by virtual-call cluster (done)
- Added script: `new_scripts/batch_rename_fun_by_vcall_cluster.py`.
- Dry-run validated naming scheme and scope.
- Applied run with:
  - `--min-vcalls 20 --limit 70`
- Result:
  - `56` direct `FUN_*` rename operations completed (`renamed=56 skipped=0 failed=0`).
- Names now include family semantics, e.g.:
  - `Cluster_UiControlA4A8_1C8_0046fd10`
  - `Cluster_UiControlA4A8_1C8_30_0044af90`
  - `Cluster_UiControlA4A8_1C8_1E4_0044fbc0`
  - `Cluster_StateMachine18_4C_00545940`
- Verification:
  - `Cluster_*` function names now present in project (includes thunk mirrors auto-associated by Ghidra naming behavior).

## TODO (next aggressive slice)
- [ ] Promote `VF001`/`VF002`/`VF003` to explicit family root labels and attach short family comments (class-lifecycle hints).
- [ ] Generate per-family function membership CSV from `Cluster_*` names + vtable family to accelerate manual semantic naming.
- [ ] Raise second rename wave threshold down to `min_vcalls >= 15` with collision guard, then selectively revert obvious false-family assignments.
- Environment follow-up:
  - Installed `jpype1==1.5.2` into `.venv` via `uv pip install --python .venv/bin/python jpype1==1.5.2`.
  - Verified: `.venv/bin/python` now reports `jpype 1.5.2`.
- Exported cluster rename listing for review:
  - `exports/cluster_functions_20260217.csv` (`79` `Cluster_*` functions currently present, including thunk-mirrored aliases).

## Aggressive Wave 2 (2026-02-17, stricter guard)
- Updated `new_scripts/batch_rename_fun_by_vcall_cluster.py` with stricter guardrails:
  - family-support gate for generic `Vcall_*` clusters (`--min-family-support`, default 2)
  - small-body skip threshold (`--skip-small-body-bytes`, default 6)
  - strict target-name collision check (skip if name exists at different address)
  - richer summary metrics (`skipped_low_support`, `skipped_small_body`, `skipped_name_collision`)
- Dry-run:
  - `--min-vcalls 15 --limit 140 --min-family-support 2 --skip-small-body-bytes 6 --dry-run`
  - Output: `candidates=42`, `skipped_low_support=46`.
- Applied run (same args, no dry-run):
  - Result: `renamed=9`, `skipped=33`, `failed=0`.
- Post-wave verification:
  - `Cluster_*` total now `90` functions.
  - Updated export: `exports/cluster_functions_20260217.csv` (`rows=90`).

## Next TODO after Wave 2
- [ ] Manual pass over new `Cluster_Vcall_*` names added in wave 2 to upgrade high-confidence ones into semantic names.
- [ ] Add explicit allowlist families for future waves (avoid accidental `Vcall_*` singleton leakage).
- [ ] Re-run discovery JSON after current renames so future clustering uses latest names as context.

## Post-Wave Refresh + Semantic Upgrade Candidates (2026-02-17)

### Discovery refresh after cluster renames (done)
- Re-ran aggressive discovery to capture updated symbol context:
  - `exports/aggressive_discovery_20260217_post_wave2.json`
- Summary:
  - `class_string_hits=238`
  - `vtable_candidates=260`
  - `virtual_call_functions=180`
  - `virtual_call_offsets=120`

### Updated vtable family export (done)
- Re-exported families from refreshed JSON:
  - `exports/vtable_families_20260217_post_wave2.json`
  - `exports/vtable_families_20260217_post_wave2.csv`
- Family count is now `19` (top family sizes: `110`, `71`, `35`).

### Semantic upgrade candidate generation (done)
- Added script:
  - `new_scripts/generate_cluster_vcall_upgrade_candidates.py`
- Output:
  - `exports/cluster_vcall_upgrade_candidates_20260217.csv`
  - `exports/cluster_vcall_upgrade_candidates_20260217.json`
- Scope:
  - analyzed `33` `Cluster_Vcall_*` functions.
  - each row includes vcall stats, top callees, top string hits, inferred domain, and suggested name.

### High-confidence semantic hint rename wave (done)
- Added script:
  - `new_scripts/apply_cluster_hint_renames.py`
- Applied conservative threshold:
  - `--min-score 2`
- Result:
  - `6` renamed, `0` skipped, `0` failed.
- Renames applied:
  - `Cluster_Vcall_1C_74_7C_0050bea0` -> `Cluster_CityHint_0050bea0`
  - `Cluster_Vcall_28_84_EC_004cc820` -> `Cluster_CityHint_004cc820`
  - `Cluster_Vcall_0C_1C_20_00577030` -> `Cluster_TurnEventHint_00577030`
  - `Cluster_Vcall_0C_1C_28_004ad7a0` -> `Cluster_UiHint_004ad7a0`
  - `Cluster_Vcall_1C8_0046503c` -> `Cluster_TradeHint_0046503c`
  - `Cluster_Vcall_1C8_0046baa7` -> `Cluster_TradeHint_0046baa7`
- Verification confirmed those six names persisted.

### Export refresh
- Regenerated cluster listing after hint renames:
  - `exports/cluster_functions_20260217.csv` (`rows=90`).

## TODO (immediate continuation)
- [ ] Run a second semantic hint wave at `min-score >= 1`, but require at least one non-generic named callee match to avoid noisy domain tags.
- [ ] Generate a review diff (`before/after`) for `Cluster_*` names to quickly spot false-positive hints.
- [ ] Start replacing `Cluster_*` (high-confidence subset only) with concrete semantic names where gameplay behavior is already known (trade/diplomacy/turn-event families first).

## Continuation (2026-02-17, per user "go")
- Executed post-hint discovery refresh:
  - `exports/aggressive_discovery_20260217_post_hints.json`
  - Summary: `class_string_hits=238`, `vtable_candidates=280`, `virtual_call_functions=220`.
- Re-generated vtable family exports against post-hint dataset:
  - `exports/vtable_families_20260217_post_hints.json`
  - `exports/vtable_families_20260217_post_hints.csv`
  - Families remain `19`; top family count increased (`VF001=124`) due converged naming.

### Semantic hint wave (score>=1 + evidence guard)
- Updated `apply_cluster_hint_renames.py` with option:
  - `--require-non_generic-callee`
- Applied run:
  - `--min-score 1 --require-non_generic-callee`
- Result:
  - `renamed=18`, `skipped=6`, `failed=0`.
- Cluster family mix now includes hint families:
  - `CityHint`, `TurnEventHint`, `TradeHint`, `MapHint`, `UiHint`, `MilitaryHint`.
- Refreshed cluster export:
  - `exports/cluster_functions_20260217.csv` (`rows=90`).

### Residual unresolved `Cluster_Vcall_*`
- Re-ran candidate generator on latest dataset:
  - `exports/cluster_vcall_upgrade_candidates_20260217_post_hints.csv`
  - `exports/cluster_vcall_upgrade_candidates_20260217_post_hints.json`
- Remaining `Cluster_Vcall_*` count: `9`
- All 9 currently score `Unknown` (no reliable domain signal from callees/strings), so no safe additional semantic-hint rename was applied.

## TODO (next best move)
- [ ] Build deeper evidence for remaining 9 residual `Cluster_Vcall_*` by tracing callers + upstream class-family membership (instead of direct keyword heuristics).
- [ ] For each remaining residual, inspect one representative callsite in decompiled context and upgrade names manually where semantics are obvious.

### Deep-evidence attempt on residual `Cluster_Vcall_*` (2026-02-17)
- Tried caller/xref evidence for residual `Cluster_Vcall_*` set (post-hint):
  - Most had no meaningful caller list in current analysis view.
- Tried non-exec table pointer scan for exact function-address dword hits:
  - No hits for the remaining 9 (`table_hits=0` for all), suggesting either indirect runtime resolution, thunk-path-only access, or currently missing xref recovery.
- Outcome:
  - kept remaining 9 as unresolved `Cluster_Vcall_*` placeholders for now.
  - no additional unsafe heuristic renames applied.

## 1+2 Pass Completion (2026-02-17, direct/headless)

### (1) Residual `Cluster_Vcall_*` evidence report (done)
- Added script:
  - `new_scripts/generate_residual_cluster_vcall_evidence.py`
- Outputs:
  - `exports/residual_cluster_vcall_evidence_20260217.json`
  - `exports/residual_cluster_vcall_evidence_20260217.csv`
- Findings:
  - residual set size: `9`
  - for 8/9 entries: `aliases=0`, `callers=0`, `data_refs=0`
  - one exception: `Cluster_Vcall_14_1C_48_004d9c70` had `aliases=1`, `callers=3`, `data_refs=4`
- Conclusion:
  - no strong static evidence yet for safe semantic renames on remaining 8 unresolved Vcall clusters.

### (2) Promote vtable families to named roots + slot labels (done)
- Added script:
  - `new_scripts/apply_named_vtable_family_labels.py`
- Applied to top 12 families from:
  - `exports/vtable_families_20260217_post_hints.json`
- Output mapping:
  - `exports/vtable_family_named_map_20260217.csv`
- Labels applied:
  - root + first 6 slots per family (`Slot00..Slot05`)
- Result:
  - `created=84`, `skipped=0`, `failed=0`
- Example new root labels:
  - `g_vtblFamily_TurnEventCityDialogCore_Root` @ `0x0063f658`
  - `g_vtblFamily_CityDialogDispatchCore_Root` @ `0x0063edb8`
  - `g_vtblFamily_CityDialogPayloadStateCore_Root` @ `0x0063eb24`
  - `g_vtblFamily_CityProductionDialogCore_Root` @ `0x0063ea58`
  - `g_vtblFamily_TurnViewManagerCore_Root` @ `0x0066f120`

## TODO (after 1+2)
- [ ] Manually inspect `Cluster_Vcall_14_1C_48_004d9c70` call/data refs (the only residual with evidence) and attempt semantic upgrade.
- [ ] Build a second evidence pass for the remaining 8 residuals by tracing indirect dispatch sites from named vtable family roots instead of direct xrefs.
- [ ] Normalize family naming collisions (`CityDialogPayloadStateCore` currently used for multiple VF IDs) into more specific sibling names where feasible.

### Follow-up on residual with real evidence (2026-02-17)
- Used `exports/residual_cluster_vcall_evidence_20260217.json` to inspect the only residual with non-zero caller/data evidence:
  - `Cluster_Vcall_14_1C_48_004d9c70`
- Evidence context:
  - appears alongside city-dialog/turn-event payload slots (`HandleTurnEventVtableSlot24CopyPayloadBuffer`, `Cluster_CityHint_004d92e0`, etc.) in multiple table neighborhoods.
- Applied safe upgrade:
  - `Cluster_Vcall_14_1C_48_004d9c70` -> `Cluster_CityHint_004d9c70`.
- Current residual unresolved `Cluster_Vcall_*` count: `8`.
- Refreshed `exports/cluster_functions_20260217.csv` after rename.

## Continuation (2026-02-17, residual trace + startup/window low-hanging pass)

### Residual `Cluster_Vcall_*` re-trace (done)
- Re-ran family-root trace with:
  - `new_scripts/trace_residual_vcall_via_family_roots.py`
- Outputs:
  - `exports/residual_vcall_family_trace_20260217.json`
  - `exports/residual_vcall_family_trace_20260217.csv`
- Findings:
  - residual set still `8`:
    - `Cluster_Vcall_14_1C_24_004ec540`
    - `Cluster_Vcall_24_28_3C_004f1b70`
    - `Cluster_Vcall_00_04_2C_0050a9f0`
    - `Cluster_Vcall_34_84_214_00520670`
    - `Cluster_Vcall_48_4C_68_00531550`
    - `Cluster_Vcall_48_4C_68_00533380`
    - `Cluster_Vcall_0C_84_C8_00590cb0`
    - `Cluster_Vcall_38_40_44_005b8080`
  - all 8 still have no family-root slot hits and no static callers in this analysis pass.

### Startup / main-window / message-pump helpers (low-hanging rename wave)
- Pivoted to user-requested startup/window API area (RegisterClass/CreateWindow/DefWindowProc/GetMessage/PeekMessage/SetWindowLong/GetWindowLong helpers).
- Applied conservative rename + comment wave for 24 high-confidence `FUN_*` routines:
  - `FUN_00607eb2` -> `HandleCbtCreateWindowHookAndSubclass`
  - `FUN_00607c10` -> `DispatchSubclassedWindowProcWithAfxProps`
  - `FUN_0060933b` -> `ResolveTopLevelOwnerFromChildChain`
  - `FUN_00607318` -> `GetWindowStyleViaSiteOrHandle`
  - `FUN_00607332` -> `GetWindowExStyleViaSiteOrHandle`
  - `FUN_0060a9c4` -> `SubclassWindowAndCacheOriginalWndProc`
  - `FUN_0060aa6e` -> `RestoreOriginalWndProcAndDetachHandleMap`
  - `FUN_005ec730` -> `ProbeProcessorFeatureApiOrFallbackInit`
  - `FUN_005ff5e1` -> `RunCommonFileDialogModalWithOwnerDisable`
  - `FUN_00606d4d` -> `UpdateCommandUiEnableStateAndFocus`
  - `FUN_00607562` -> `SetFocusViaSiteOrHandle`
  - `FUN_00613f5a` -> `EnsureViewActiveAndSynchronizeFocus`
  - `FUN_00607b73` -> `AttachWindowHandleToCWndAndSite`
  - `FUN_00607b2f` -> `GetOrCreateCWndFromHandle`
  - `FUN_00607c0a` -> `GetAfxSubclassWndProcEntry`
  - `FUN_00609253` -> `FindAncestorFrameFromWindowChain`
  - `FUN_00607dbe` -> `HandleMouseActivateForegroundSwitch`
  - `FUN_006079b3` -> `CaptureWindowRectAndStyleSnapshot`
  - `FUN_006079d6` -> `ApplyPostInitWindowCenteringHeuristic`
  - `FUN_00607e36` -> `DispatchCtlColorMessagesOrSubclassProc`
  - `FUN_00607bdb` -> `AfxSubclassWndProcCore`
  - `FUN_00607520` -> `IsWindowEnabledViaSiteOrHandle`
  - `FUN_006092dc` -> `ResolveTopParentOwnerFromWindow`
  - `FUN_0060a147` -> `PrepareCtlColorTextAndBkColors`

### Easy signature improvements (done)
- Updated return types for obvious wrapper helpers:
  - `GetWindowStyleViaSiteOrHandle` -> `uint`
  - `GetWindowExStyleViaSiteOrHandle` -> `uint`
  - `IsWindowEnabledViaSiteOrHandle` -> `int` (BOOL-like)
  - `ResolveTopParentOwnerFromWindow` -> `void *`

## TODO (next low-hanging pass)
- [ ] Continue startup path from `entry` (`0x005e98b0`) into CRT/game bootstrap split and assign stable names to pre-main init blocks.
- [ ] Identify the first explicit app/window creation handoff after CRT (`RegisterAmbitGameWindowClass` / `CreateWindowExWithPreCreateHook` chain) and annotate with short flow comments.
- [ ] Revisit the remaining 8 `Cluster_Vcall_*` only after new callers emerge from additional function recovery or xref improvements (no safe rename signal yet).

## Continuation (2026-02-17, bootstrap TLS/helper family batch)

### Startup bootstrap inspection
- Re-checked `entry` (`0x005e98b0`) and `CallMfcAppLifecycleEntry` (`0x005fa7c2`):
  - both are already in good shape semantically.
  - main handoff path remains:
    - `entry` -> `CallMfcAppLifecycleEntry` -> `DispatchMfcAppLifecycle` -> `InitializeMfcAppStateFromEntryArgs`.

### Low-hanging TLS/thread-state rename batch (done)
- While tracing `EnsureCreateWindowCbtHook` / `ReleaseCreateWindowCbtHook`, identified a coherent unnamed TLS helper cluster and renamed 9 functions:
  - `FUN_005ea5d0` -> `RaiseMfcSehExceptionWithArgs`
  - `FUN_005ff439` -> `ThrowMfcResourceException`
  - `FUN_00623bdc` -> `InitializeTlsSlotRegistry`
  - `FUN_00623c75` -> `AllocateTlsSlotRegistryIndex`
  - `FUN_00623de4` -> `SetTlsSlotValueWithExpansion`
  - `FUN_00623ff6` -> `GetOrCreatePerThreadTlsSlotObject`
  - `FUN_006240b8` -> `EnsureLazyInitializedPointerUnderLock`
  - `FUN_005e540c` -> `CreateMfcModuleThreadState`
  - `FUN_00623477` -> `ConstructMfcModuleThreadState`
- Added short comments to each renamed function to preserve intent.

### Residual `Cluster_Vcall_*` status
- unchanged from previous pass: `8` unresolved residuals; still no safe static-evidence signal for semantic upgrades.

## TODO (next easiest wins)
- [ ] Continue along callers of `GetOrCreatePerThreadTlsSlotObject` to rename nearby thread/module-state wrappers (`FUN_0060674a`, `FUN_006078c3`, `FUN_0060914d`, etc.) where decomp output is now clearer after TLS helper naming.
- [ ] In startup/UI handoff area, annotate `RegisterAmbitGameWindowClass` and `CreateWindowExWithPreCreateHook` call chain with concise lifecycle comments (class registration -> CBT subclass install -> wndproc dispatch).
- [ ] Keep residual `Cluster_Vcall_*` frozen until new xrefs/callers appear; avoid speculative renames.

## Continuation (2026-02-17, caller-driven wrapper renaming around thread/message state)

### Batch A: thread-message hook and routing core (done)
- Renamed and commented:
  - `FUN_0060674a` -> `DispatchMfcMsgFilterHookProc`
  - `FUN_006078c3` -> `DispatchCWndMessageWithTlsStateScope`
  - `FUN_0060911a` -> `InitializeCmdUiProbeObject`
  - `FUN_0060914d` -> `RouteCommandByIdWithUiProbe`
  - `FUN_00609b66` -> `InvokeOnWndMsgWithCurrentThreadMessage`
  - `FUN_00609b93` -> `RouteCurrentThreadMessageByHwnd`
  - `FUN_00623523` -> `EnsureMfcModuleThreadStateCreated`
  - `FUN_0060ab56` -> `GetThreadCleanupStackHeadPtrPreserveLastError`
  - `FUN_0060ab40` -> `PushThreadCleanupNode`
  - `FUN_0060ab7e` -> `PopThreadCleanupNode`
  - `FUN_0060aab8` -> `NotifyCleanupNodeOnPopIfPending`
- Signature touches:
  - set `int` returns where these wrappers are checked as booleans/results (`DispatchMfcMsgFilterHookProc`, `RouteCommandByIdWithUiProbe`, `InvokeOnWndMsgWithCurrentThreadMessage`, `RouteCurrentThreadMessageByHwnd`).
  - renamed obvious parameters (`nCode/wParam/lParam`, `hWnd`, `pExtra`, etc.).

### Batch B: fallback/menu-handle-map wrapper layer (done)
- Renamed and commented:
  - `FUN_00607a84` -> `InvokeCurrentMessageFallbackHandler`
  - `FUN_00607b57` -> `LookupCWndByHwndNoAttach`
  - `FUN_00608685` -> `DispatchParentNotifyOrRouteByHwnd`
  - `FUN_006086c2` -> `RouteByHwndOrInvokeFallbackHandler`
  - `FUN_0060870c` -> `InvokeOnWndMsgOrFallbackHandler`
  - `FUN_00608737` -> `InvokeOnWndMsgOrFallbackHandlerAlt`
  - `FUN_006087b6` -> `DispatchMenuOrControlNotifyOrFallback`
  - `FUN_0060882f` -> `FindMenuTargetByCommandIdRecursive`
  - `FUN_006094d7` -> `FindDescendantWindowByControlIdRecursive`
  - `FUN_0060d058` -> `GetMenuHandleMapMaybeCreate`
  - `FUN_0060d0c8` -> `GetOrCreateCMenuByHandle`
  - `FUN_0060d0de` -> `LookupCMenuByHandleNoCreate`
  - `FUN_0060d2c0` -> `GetOrCreateHandleMapObjectByHandle`
- Signature touches:
  - set `int` returns for route/query helpers where caller checks value.
  - added parameter names for most obvious cases (`hMenu`, `rootHwnd`, `controlId`, `allowTempAttach`, `menuObj`, `commandId`).

### Batch C: tiny route-or-fallback stubs (done)
- Renamed and commented:
  - `FUN_006091d9` -> `RouteControlNotifyByDlgCtrlIdOrHwnd`
  - `FUN_0060a007` -> `RouteByHwndOrFallbackReturnParam`
  - `FUN_0060a031` -> `InvokeOnWndMsgIfPresentElseFallback`
  - `FUN_0060a052` -> `InvokeOnWndMsgIfPresentElseFallbackAlt`
  - `FUN_0060a0bd` -> `InvokeOnWndMsgOrFallbackReturnParam`
  - `FUN_0060a0e4` -> `HandleCtlColorOrFallbackDispatch`
- Signature touches:
  - set `int` return for non-void variants used as return value in callers.

### Net result of this continuation
- Additional renamed functions this pass: `30`.
- Added concise behavior comments in each renamed function.
- Residual unresolved `Cluster_Vcall_*` remains unchanged at `8` (intentionally frozen).

## TODO (next easiest wins after this pass)
- [ ] Continue with remaining small wrapper islands discovered by caller sweep (`FUN_00615517`, `FUN_00615975`, `FUN_006159b9`, `FUN_0061c83a`, `FUN_0061c856`, `FUN_0061c8e2`, `FUN_0061e606`) using the same route-or-fallback naming style.
- [ ] Re-open startup handoff annotations (`RegisterAmbitGameWindowClass` -> `CreateWindowExWithPreCreateHook` -> subclass/wndproc path) and add brief flow comments.
- [ ] Keep residual `Cluster_Vcall_*` frozen until new xrefs/callers are recovered.

## Continuation (2026-02-17, wrapper island follow-up)

### Batch D: requested wrapper island + immediate scroll-fit helper (done)
- Renamed and commented:
  - `FUN_00615517` -> `HandleSizeMessageRecalcScrollLayout`
  - `FUN_00615975` -> `HandleAxis0ScrollCommandOrRoute`
  - `FUN_006159b9` -> `HandleAxis1ScrollCommandOrRoute`
  - `FUN_0061c83a` -> `ForwardCurrentMessageToLinkedHandlerSlot74`
  - `FUN_0061c856` -> `QueryLinkedHandlerSlot78OrFallback`
  - `FUN_0061c8e2` -> `SetCursorFromTopFrameStateOrFallback`
  - `FUN_0061e606` -> `NotifySlotD0UnlessCode1AfterFallback`
- Also renamed direct helper in same flow:
  - `FUN_00614f95` -> `ApplyScaleToFitExtentsAndRecalc`
- Signature touches:
  - set `int` returns on boolean/result wrappers:
    - `QueryLinkedHandlerSlot78OrFallback`
    - `SetCursorFromTopFrameStateOrFallback`
  - renamed obvious parameters (`thisObj`, `extentX`, `extentY`, `scrollCode`, `scrollPos`, `routeFlag`, etc.).

### Why this batch is low-risk
- All renames are based on direct fallback+dispatch behavior visible in decomp (no gameplay semantic guessing).
- Naming style stays structural (`Axis0/Axis1`, `slot 0x74/0x78/0xD0`, fallback handlers).

### Residual status
- `Cluster_Vcall_*` remains unchanged at `8` (still intentionally frozen).

## TODO (next easiest wins)
- [ ] Continue same style for neighboring wrappers in the same band (`FUN_0061c725`, `FUN_0061c749`, `FUN_0061c90c`, `FUN_0061c9ed`, `FUN_0061cb3a`) before class extraction.
- [ ] Re-open startup handoff annotations (`RegisterAmbitGameWindowClass` -> `CreateWindowExWithPreCreateHook` -> subclass/wndproc path) and add concise flow comments.
- [ ] Keep residual `Cluster_Vcall_*` frozen until new xrefs/callers are recovered.

## Continuation (2026-02-17, neighboring wrapper band + TMacViewMgr linkage)

### Batch E: neighboring wrappers (done)
- Renamed and commented:
  - `FUN_0061c725` -> `RegisterObjectInModuleThreadStateList`
  - `FUN_0061c749` -> `UnregisterObjectFromModuleThreadStateList`
  - `FUN_0061c90c` -> `DispatchCommandUsingStoredFrameIds`
  - `FUN_0061c9ed` -> `IsOwnerChainContainingWindow`
  - `FUN_0061cb3a` -> `ReleaseDeferredDisabledWindowsIfCounterZero`
  - `FUN_0060a916` -> `IsCommandIdNotE001E002OrZero`

### Batch F: supporting list/thread-state primitives (done)
- Renamed and commented:
  - `FUN_00623b4c` -> `PushNodeIntoOffsetLinkedList`
  - `FUN_00623b5f` -> `RemoveNodeFromOffsetLinkedList`
  - `FUN_005e53d8` -> `CreateAfxModuleThreadStateObject`
  - `FUN_0062368b` -> `ConstructAfxModuleThreadStateObject`

### Batch G: TMacViewMgr constructor/destructor wrappers (done)
- Confirmed from `CreateTMacViewMgrObject` call path and runtime-class metadata.
- Renamed and commented:
  - `FUN_0061c5dc` -> `ConstructTMacViewMgrBase`
  - `FUN_0061c6be` -> `DestroyTMacViewMgrBase`
  - `FUN_00484bf0` -> `ConstructTMacViewMgrInPlace`
  - `FUN_00484c70` -> `DestroyTMacViewMgrObject`

### Signature touches in this pass
- Set `int` returns on boolean/query-like wrappers:
  - `DispatchCommandUsingStoredFrameIds`
  - `IsOwnerChainContainingWindow`
  - `IsCommandIdNotE001E002OrZero`
  - `RemoveNodeFromOffsetLinkedList`
- Renamed obvious parameters (`thisObj`, `node`, `targetWnd`, `candidateWnd`, etc.).

### Net additions in this continuation
- Additional renamed functions this pass: `14`.
- All updated with concise comments.

## TODO (next easiest wins after Batch E/F/G)
- [ ] Continue scroll/layout island directly around newly named `ApplyScaleToFitExtentsAndRecalc` and `RecalculateScrollBarsAndLayout` (`FUN_00615020`, `FUN_00615152`, `FUN_006151d6`, `FUN_00615277`, `FUN_00615329`, `FUN_0061537b`, `FUN_006153fe`, `FUN_0061553f`, `FUN_006155ed`, `FUN_00615647`, `FUN_006156bc`, `FUN_006158ee`).
- [ ] Re-open startup handoff annotations (`RegisterAmbitGameWindowClass` -> `CreateWindowExWithPreCreateHook` -> subclass/wndproc path) and add concise flow comments.
- [ ] Keep residual `Cluster_Vcall_*` frozen until new xrefs/callers are recovered.

## Continuation (2026-02-17, scroll/layout island around RecalculateScrollBarsAndLayout)

### Batch H: scroll-view geometry + mapping helpers (done)
- Renamed and commented:
  - `FUN_00615020` -> `SetScrollSizesAndRecalcLayout`
  - `FUN_00615152` -> `GetScrollPositionLogical`
  - `FUN_006151d6` -> `ScrollToPositionLogical`
  - `FUN_00615277` -> `GetScrollPositionDeviceWithCenterOffset`
  - `FUN_00615329` -> `SetDeviceScrollOffsetAndReposition`
  - `FUN_0061537b` -> `FillOutsideClientBands`
  - `FUN_006153fe` -> `ResizeParentFrameToFitClient`
  - `FUN_0061553f` -> `CenterViewOnPoint`
  - `FUN_006155ed` -> `GetScrollBarSizeAdjustments`
  - `FUN_00615647` -> `ComputeTrueClientSize`
  - `FUN_006156bc` -> `ComputeScrollBarVisibilityAndLayout`
  - `FUN_006158ee` -> `CalcWindowRectForScrollState`
- Additional direct-flow rename:
  - `FUN_00614ebf` -> `PrepareDeviceContextForScrollView`

### Signature touches in Batch H
- set `int` return for `ComputeTrueClientSize` (used as boolean fit check).
- added high-confidence parameter names for map/size/rect helpers (`mapMode`, `sizeTotal`, `outPt`, `xPos`, `yPos`, `adjustType`, etc.).

### Confidence note
- This batch is based on explicit API/DC behavior (`LPtoDP`, `DPtoLP`, `AdjustWindowRectEx`, scrollbar size/visibility calculations), so semantic risk is low.

## TODO (next easiest wins after Batch H)
- [ ] Continue nearby scroll-view support functions in same block (`FUN_00614e71`, `FUN_0061416e`, `FUN_00615152` callers) and evaluate if class-structured naming can start there.
- [ ] Re-open startup handoff annotations (`RegisterAmbitGameWindowClass` -> `CreateWindowExWithPreCreateHook` -> subclass/wndproc path) and add concise flow comments.
- [ ] Keep residual `Cluster_Vcall_*` frozen until new xrefs/callers are recovered.

## Continuation (2026-02-17, `TMacViewMgr` class extraction attempt)

### Struct extracted (done)
- Created datatype:
  - `/Imperialism/Classes/TMacViewMgr` (size `0xD0` / `208` bytes).
- Added known/high-confidence fields at key offsets:
  - vtable pointer (`0x00`), hwnd slot (`0x1C`), map/scroll size group (`0x40..0x60`),
  - linked handler (`0x68`), scale-to-fit mode (`0x88`),
  - deferred-disable state (`0xA0`, `0xA4`),
  - recalc/flags/owned pointers (`0xB0..0xCC`), etc.
- Renamed vtable symbol:
  - `g_vtbl_TMacViewMgr` @ `0x006488d8`.

### Member signatures bound to `TMacViewMgr*` (done)
- Replaced legacy zero-parameter signatures with explicit `__thiscall` member signatures for core methods (constructors/destructors + scroll/layout + message wrappers).
- Examples now correctly typed:
  - `TMacViewMgr * __thiscall ConstructTMacViewMgrBase(TMacViewMgr * thisObj)`
  - `void __thiscall SetScrollSizesAndRecalcLayout(TMacViewMgr * thisObj, int mapMode, int * sizeTotal, int * sizePage, int * sizeLine)`
  - `int __thiscall ComputeTrueClientSize(TMacViewMgr * thisObj, int * outClientSize, int * outScrollBarSize)`
  - `void __thiscall RecalculateScrollBarsAndLayout(TMacViewMgr * thisObj)`
- Current count:
  - `33` function signatures now contain `TMacViewMgr`.

### Caveat
- Field names are currently mixed:
  - high-confidence names for scroll/layout-related offsets,
  - conservative `field_xx` placeholders where semantics are still uncertain.

## TODO (next extraction refinement)
- [ ] Refine uncertain `TMacViewMgr` fields (`field_3c`, `field_64`, `field_94`, `field_98`, `field_9c`, `field_b4`, `field_c8`) by tracing reads/writes in typed methods.
- [ ] Extract/label the likely base-class slice vs. `TMacViewMgr`-specific extension region.
- [ ] Continue startup handoff annotations as separate track.

## Continuation (2026-02-17, deepening `TMacViewMgr` extraction)

### Vtable materialization (done)
- Materialized full `g_vtbl_TMacViewMgr` surface:
  - created per-slot labels `g_vtbl_TMacViewMgr_Slot00..Slot47`,
  - added per-target labels `TMacViewMgr_SlotXX_Target`,
  - created missing function records for previously unmaterialized vtable targets (`29` newly created in that pass).
- Result:
  - all 48 slot targets now resolve to explicit functions in Ghidra.

### Member signature binding follow-up (done)
- After first struct extraction, many functions still had legacy zero-arg prototypes.
- Applied explicit `__thiscall` signatures with `TMacViewMgr * thisObj` across core ctor/dtor + scroll/layout + wrapper methods.
- Result:
  - `33` function signatures now contain `TMacViewMgr`.
  - `g_vtbl_TMacViewMgr` label persisted at `0x006488d8`.

### Message map extraction for `TMacViewMgr` (done)
- Decoded message map entry stride as `0x18` and enumerated `20` entries from `TMacViewMgr_MessageMapEntries`.
- Named handler functions from message/command metadata (low-risk naming):
  - `TMacViewMgr_OnMsg_WM_CREATE`
  - `TMacViewMgr_OnMsg_WM_PAINT`
  - `TMacViewMgr_OnMsg_WM_CHAR`
  - `TMacViewMgr_OnMsg_WM_ACTIVATE`
  - `TMacViewMgr_OnMsg_WM_ACTIVATEAPP`
  - `TMacViewMgr_OnMsg_WM_ERASEBKGND`
  - `TMacViewMgr_OnMsg_MSG_030F`
  - `TMacViewMgr_OnMsg_MSG_0311`
  - `TMacViewMgr_OnMsg_0x0464`
  - `TMacViewMgr_OnMsg_0x0BC0`
  - `TMacViewMgr_OnCommand_ID_8009`
  - `TMacViewMgr_OnCommand_ID_800C`
  - `TMacViewMgr_OnCommand_ID_800D`
  - `TMacViewMgr_OnCommand_ID_8013`
  - `TMacViewMgr_OnCommand_ID_E143_E147`
  - `TMacViewMgr_OnCommand_ID_E146`
- Kept already-meaningful existing names where present:
  - `EnterFrameContextHelpMode`
  - `thunk_DispatchStartupCommand100ToAppSingleton`
  - `thunk_HandleCustomMessage2420DispatchTurnEvent`

### Current limitation
- Remaining uncertain fields (`field_3c`, `field_64`, `field_94`, `field_98`, `field_9c`, `field_b4`, `field_c8`) still mostly only show explicit writes in constructor path with weak independent behavioral signal.
- No forced speculative renames applied for these fields.

## TODO (next extraction refinement after message-map pass)
- [ ] Use newly materialized message handlers and slot targets to infer additional field semantics before renaming uncertain `field_xx` members.
- [ ] Partition `TMacViewMgr` into probable base/derived slices now that vtable + message map are explicit.
- [ ] Keep startup-handoff annotation track separate and continue in parallel.

## Continuation (2026-02-17, low-hanging rename pass from TODO: scroll/DC wrapper support)

### What I did (done)
- Read TODO and took the easiest nearby block around `PrepareDeviceContextForScrollView` / `RecalculateScrollBarsAndLayout`.
- Decompiled caller/callee cluster around:
  - `FUN_00614e71`, `FUN_0061416e`,
  - `FUN_00612bea`, `FUN_00613845`, `FUN_006138b7`,
  - `FUN_006095d2`, `FUN_0060962a`, `FUN_0060965d`, `FUN_0060968d`, `FUN_006096d0`, `FUN_0060971d`, `FUN_0060976a`,
  - wrapper-base helpers `FUN_00612682`, `FUN_0061274c`, `FUN_00612783`, `FUN_006127ca`, `FUN_0061389b`,
  - exception helper `FUN_00613c75`.
- Applied only structural, API-driven names (no speculative gameplay semantics), and added concise function comments.

### Renamed in this pass
- First batch:
  - `FUN_00612bea` -> `SetMapModeOnOutputAndAttribDc`
  - `FUN_00613845` -> `ConstructWindowDcForViewHandle`
  - `FUN_006138b7` -> `DestroyWindowDcAndReleaseHandle`
  - `FUN_0060968d` -> `ShowScrollBarWithParentFallback`
  - `FUN_006096d0` -> `SetScrollInfoWithParentFallback`
  - `FUN_0060962a` -> `SetScrollRangeWithParentFallback`
  - `FUN_0060976a` -> `ComputeScrollThumbTrackPos`
- Second batch:
  - `FUN_0061389b` -> `DestroyWindowDcAndMaybeFree`
  - `FUN_00612682` -> `ConstructDcWrapperBase`
  - `FUN_0061274c` -> `AttachHdcToDcWrapper`
  - `FUN_00612783` -> `DetachHdcFromDcWrapper`
  - `FUN_006127ca` -> `DestroyDcWrapperAndDeleteOwnedHdc`
  - `FUN_006095d2` -> `SetScrollPosWithParentFallback`
  - `FUN_0060965d` -> `GetScrollRangeWithParentFallback`
  - `FUN_0060971d` -> `GetScrollInfoWithParentFallback`
  - `FUN_00613c75` -> `ThrowMfcResourceException`

### Notes
- One direct `p.save(...)` call failed once with `Unable to lock due to active transaction`; reopened and verified renamed symbols persisted in project state.
- I intentionally skipped renaming `FUN_00614e71` and `FUN_0061416e` for now because semantics are still partially ambiguous and not worth overfitting names yet.

## TODO (next easiest wins after this pass)
- [ ] Finish the two ambiguous neighbors with one more focused decomp pass:
  - `FUN_00614e71` (constructor chain/vtable init),
  - `FUN_0061416e` (DC-side flag update from prepared context).
- [ ] Continue low-risk wrapper renames in same corridor (`FUN_00613803`, `FUN_006138f9`, `FUN_00613791`) if they remain generic and call patterns stay consistent.
- [ ] Keep `TMacViewMgr` uncertain fields (`field_3c`, `field_64`, `field_94`, `field_98`, `field_9c`, `field_b4`, `field_c8`) frozen until stronger evidence appears in message/vtable handlers.

## Continuation (2026-02-17, immediate follow-up corridor batch)

### Batch 3: `GetDC` / `BeginPaint` wrapper corridor (done)
- Renamed and commented:
  - `FUN_00613791` -> `ConstructClientDcForViewHandle`
  - `FUN_00613803` -> `DestroyClientDcAndReleaseHandle`
  - `FUN_006138f9` -> `ConstructPaintDcForViewHandle`
  - `FUN_00612696` -> `DestroyDcWrapperBaseAndMaybeFree`

### Updated count snapshot
- Re-ran headless count script (`CountRenamedFunctions.java`) after batches above:
  - `TOTAL_FUNCTIONS=10010`
  - `USER_DEFINED_FUNCTION_SYMBOLS=1974`
  - `NON_GENERIC_NAMES=2794`

## TODO (next low-risk rename pass)
- [ ] Resolve/rename the two remaining ambiguous neighbors only after one more decomp sanity pass:
  - `FUN_00614e71`
  - `FUN_0061416e`
- [ ] Continue one-call wrapper cleanup around `BeginScopedMapQuickDrawContext` / `EndScopedMapQuickDrawContext` callers if behavior remains strictly DC setup/teardown.
- [ ] Keep residual `Cluster_Vcall_*` and uncertain `TMacViewMgr field_xx` names unchanged until stronger evidence.

## Continuation (2026-02-17, ctor/dtor-driven class extraction)

### Extracted class family: `CDC` / `CClientDC` / `CWindowDC` / `CPaintDC`
- Promoted previously structural names into class-oriented ctor/dtor names:
  - `ConstructDcWrapperBase` -> `ConstructCDC`
  - `DestroyDcWrapperAndDeleteOwnedHdc` -> `DestroyCDCAndDeleteOwnedHdc`
  - `DestroyDcWrapperBaseAndMaybeFree` -> `ScalarDeleteCDC`
  - `ConstructClientDcForViewHandle` -> `ConstructCClientDCFromViewHandle`
  - `DestroyClientDcAndReleaseHandle` -> `DestroyCClientDCAndReleaseHandle`
  - `ConstructWindowDcForViewHandle` -> `ConstructCWindowDCFromViewHandle`
  - `DestroyWindowDcAndReleaseHandle` -> `DestroyCWindowDCAndReleaseHandle`
  - `ConstructPaintDcForViewHandle` -> `ConstructCPaintDCFromViewHandle`
- Vtable labels extracted:
  - `g_vtbl_CDC` @ `0x0067241c`
  - `g_vtbl_CClientDC` @ `0x0067249c`
  - `g_vtbl_CWindowDC` @ `0x0067251c`
  - `g_vtbl_CPaintDC` @ `0x0067259c`
- Datatypes added under `/Imperialism/Classes`:
  - `CDC` (0x14)
  - `CClientDC` (0x14)
  - `CWindowDC` (0x14)
  - `CPaintDC` (0x54)
- Added concise class-role comments on ctor/dtor anchors.

### Extracted class-like RAII context from ctor/dtor pair
- Renamed ctor/dtor pair:
  - `BeginScopedMapQuickDrawContext` (`0x00494700`) -> `ConstructScopedMapQuickDrawContext`
  - `EndScopedMapQuickDrawContext` (`0x004948b0`) -> `DestroyScopedMapQuickDrawContext`
- Renamed overload/variant:
  - `FUN_004947e0` -> `ConstructScopedMapQuickDrawContextWithPaletteToken`
- Renamed tiny wrappers to thunk form to avoid duplicate canonical names:
  - `0x00401d70` -> `thunk_ConstructScopedMapQuickDrawContext`
  - `0x00408035` -> `thunk_DestroyScopedMapQuickDrawContext`
- Added datatype:
  - `/Imperialism/Classes/ScopedMapQuickDrawContext` (0x18),
  - layout captures embedded `CClientDC`-compatible storage at `0x00..0x13` and `pViewState` at `0x14`.

## TODO (next ctor/dtor-driven extraction)
- [ ] Resolve the two ambiguous nearby helpers before naming as class members:
  - `FUN_00614e71`
  - `FUN_0061416e`
- [ ] Look for additional constructor/destructor pairs in the same map-draw corridor and extract corresponding class datatypes first, then rename wrappers.
- [ ] Keep uncertain `TMacViewMgr field_xx` names frozen until stronger slot/message evidence.

## Continuation (2026-02-18, diplomacy low-hanging pass)

### What I did (done)
- Focused directly on diplomacy event-code builders and renamed remaining generic clusters:
  - `0x004295a0`:
    - `Cluster_UiControlA4A8_1C8_30_004295a0` -> `BuildTurnEventDialogResourcesForEvent547Or7D8`
    - `0x00403f99` -> `thunk_BuildTurnEventDialogResourcesForEvent547Or7D8`
  - `0x0046fd10`:
    - `Cluster_UiControlA4A8_1C8_0046fd10` -> `BuildTurnEventDialogResourcesForEvent7DE`
    - `0x00407531` -> `thunk_BuildTurnEventDialogResourcesForEvent7DE`
- Added explicit event discriminator comments:
  - `0x004295c2`: `0x7D8` gate.
  - `0x004295da`: secondary discriminator via `-0x547` path.
  - `0x0046fd2b`: `0x7DE` gate.
- Added plate comment on `BuildTurnEventDialogResourcesForEvent7DE` noting dense command-id block (`0xFA1..0xFB9`) used by summary controls.

### Constructor cleanup in diplomacy path (done)
- Renamed pure ctor-style `FUN_*` + thunk wrappers used by the above builders:
  - `FUN_004f3b80` -> `ConstructPictureResourceEntry_Vtbl00655b68`
  - `FUN_004304a0` -> `ConstructUiResourceEntry_Vtbl0063fe60`
  - `FUN_004308d0` -> `ConstructPictureResourceEntry_Vtbl006404b0`
  - `FUN_00430520` -> `ConstructUiResourceEntry_Vtbl00640060`
  - `FUN_00430630` -> `ConstructPictureResourceEntry_Vtbl00640258`
  - `FUN_004303a0` -> `ConstructUiResourceEntry_Vtbl0063fa70`
  - `FUN_00430320` -> `ConstructUiResourceEntry_Vtbl0063f878`
  - `FUN_00430420` -> `ConstructUiResourceEntry_Vtbl0063fc68`
  - `FUN_00591e70` -> `ConstructPictureResourceEntry_Vtbl00668588`
- Kept one behavior-backed semantic rename:
  - `FUN_00583b50` -> `ConstructTradeQuantityArrowPictureEntry`
    - rationale: previously verified `+0x1C0` callback path driving +/-1 trade amount bitmap behavior.

### New extracted diplomacy constants (for user labeling)
- In `BuildTurnEventDialogResourcesForEvent7DE` (`0x0046fd10`), recurring command-id-like constants include:
  - `4001..4025` (`0xFA1..0xFB9`) and especially repeated `4020..4024` (`0xFB4..0xFB8`-adjacent blocks).
  - Repeating observed pattern:
    - `0xFA1..0xFA9` (`4001..4009`) sequence blocks,
    - each block repeatedly paired with `0xFB4`/`0xFB5` (`4020/4021`),
    - later blocks `0xFAA..0xFB2` (`4010..4018`) pair with `0xFB6`/`0xFB7` (`4022/4023`).
  - Strong direction hint from inline tag literals:
    - `0xFB4`/`0xFB6` appear with `'left'` (`0x6c656674`) context pushes,
    - `0xFB5`/`0xFB7` appear with `'rght'` (`0x72676874`) context pushes.
  - Additional singleton ids in same function path:
    - `0xFB3` (`4019`), `0xFB8` (`4024`), `0xFB9` (`4025`).
- In `BuildTurnEventDialogResourcesForEvent547Or7D8` (`0x004295a0`), additional control-id-like values include:
  - `4068..4071` (`0xFE4..0xFE7`),
  - `4100, 4101, 4103, 4106, 4107, 4108` (`0x1004,0x1005,0x1007,0x100A,0x100B,0x100C`),
  - `4139..4141` (`0x102B..0x102D`).
- Follow-up constant xref pass found extra `0xFB0..0xFB3` usage outside the builder:
  - `FUN_0056ee50` uses `0xFB0`, `0xFB1` and fetches controls tagged `'cred'` / `'cre2'`.
  - `FUN_0056efc0` uses `0xFB2`, `0xFB3`, toggles `DAT_006a4084`, and also updates `'cred'` / `'cre2'`.
  - Both currently have no straightforward code xrefs (likely callback-table reached), so they were left unnamed for now.

## TODO (next diplomacy low-hanging)
- [ ] Decode one full `0x7DE` command-id block end-to-end (`0xFA1..0xFB9`) into concrete button/control semantics by tracing dispatch handlers for those IDs.
- [ ] Ask user for semantic labels for recovered diplomacy command-id groups once exact control grouping is dumped (especially `0xFA1..0xFB9` and `0xFE4..0x100C` families).
- [ ] Decode callback-table linkage for `FUN_0056ee50` / `FUN_0056efc0` and rename if `'cred'/'cre2'` semantics can be confirmed beyond ID-based behavior.
- [ ] Rename remaining small wrapper/helpers in the `0x004295a0` / `0x0046fd10` construction path only when each wrapper has unambiguous ctor/callback behavior.

## Continuation (2026-02-18, rename pass resumed)

### Runtime note
- `ghidra-mcp` bridge was up, but endpoint `127.0.0.1:8089` returned connection-refused during this pass.
- Continued with direct `pyghidra` edits to avoid stalling rename momentum.

### Renamed (low-hanging, diplomacy-adjacent)
- Constructor/list-helper cleanup (canonical functions):
  - `FUN_00430250` -> `ConstructPictureResourceEntry_Vtbl0063f650`
  - `FUN_00572de0` -> `ConstructPictureResourceEntry_Vtbl00660b48`
  - `FUN_00426f60` -> `GetUiLinkedListNodePayload`
  - `FUN_00426ec0` -> `PushUiLinkedListNodeWithPayload`
  - `FUN_00427100` -> `SetUiResourcePairValues`
  - `FUN_00430b50` -> `ConstructUiResourceEntry_Vtbl00640940`
  - `FUN_005b5420` -> `ConstructUiTextResourceEntry_Vtbl0066cbc8`
  - `FUN_00427060` -> `ReplaceUiResourceContextPairBuffer`
  - `FUN_004f8f70` -> `ConstructUiResourceEntry_Vtbl00655fb0`
- Command/tag handlers in the same discovered control-ID corridor:
  - `FUN_0056ee50` -> `UpdateTaggedControlsCredCre2WithBitmapIdsFb0Fb1`
  - `FUN_0056efc0` -> `ToggleTaggedControlsCredCre2WithBitmapIdsFb2Fb3AndForwardCommand`
  - `FUN_0056b2b0` -> `HandleDialogCommandTagSaveLoadPrefQuitCred`

### Renamed wrappers (existing thunk functions)
- `0x0040374c` -> `thunk_ConstructPictureResourceEntry_Vtbl0063f650`
- `0x00408ee5` -> `thunk_ConstructPictureResourceEntry_Vtbl00660b48`
- `0x004020db` -> `thunk_GetUiLinkedListNodePayload`
- `0x00401eba` -> `thunk_PushUiLinkedListNodeWithPayload`
- `0x0040284c` -> `thunk_SetUiResourcePairValues`
- `0x00408873` -> `thunk_ConstructUiResourceEntry_Vtbl00640940`
- `0x00408814` -> `thunk_ConstructUiTextResourceEntry_Vtbl0066cbc8`
- `0x00402207` -> `thunk_ReplaceUiResourceContextPairBuffer`
- `0x0040214e` -> `thunk_ConstructUiResourceEntry_Vtbl00655fb0`

### Added plate comments
- `0x0056ee50`: notes cred/cre2 tagged-control update path with IDs `0xFB0/0xFB1`.
- `0x0056efc0`: notes toggle path with IDs `0xFB2/0xFB3` + command forward.
- `0x0056b2b0`: notes save/load/pref/quit/cred/newg tag dispatch behavior.

## TODO (next easiest wins after this pass)
- [ ] Investigate non-function jump stubs at `0x00405795`, `0x00402f4f`, `0x00405574` (currently instruction-level JMP sites to the three newly renamed handlers); create thunk functions only if that improves callgraph readability without introducing bad boundaries.
- [ ] Keep mapping `4005..4018` unresolved resource rows as placeholders until user provides exact per-resource order.
- [ ] Resume direct callback-table linkage for `UpdateTaggedControlsCredCre2WithBitmapIdsFb0Fb1` / `ToggleTaggedControlsCredCre2WithBitmapIdsFb2Fb3AndForwardCommand`.

## Continuation (2026-02-18, game-logic-focused pass; non-UI)

### What I targeted
- User requested pivot to gameplay logic rather than UI controls.
- Chosen low-risk slice:
  - tactical battle-side/battle-state setup helpers,
  - shared RNG primitive used by tactical/pathing/turn handlers,
  - widely-used shared-string runtime helpers (non-UI infra).

### Renamed (gameplay-facing)
- Tactical battle setup:
  - `FUN_0059b1b0` -> `InitializeTacticalSideFromArmyUnitList`
  - `FUN_0059f890` -> `BuildTacticalBattleStateFromBothSides`
  - wrapper normalization:
    - `0x00402c0c` -> `thunk_InitializeTacticalSideFromArmyUnitList`
    - `0x0040877e` -> `thunk_BuildTacticalBattleStateFromBothSides`
- Thread-local RNG:
  - `FUN_005e83e0` -> `SetThreadLocalRandomSeed`
  - `FUN_005e83f0` -> `GenerateThreadLocalRandom15`
    - behavior verified: `seed = seed * 0x343FD + 0x269EC3`, returns `(seed >> 16) & 0x7FFF`.

### Renamed (non-UI runtime helpers used by gameplay paths)
- `FUN_005ed7f0` -> `GetOrCreateCrtThreadDataFromTls`
- `FUN_006057de` -> `AllocateSharedStringBufferForLength`
- `FUN_0060584a` -> `DecrementSharedStringRefCountAndFree`
- `FUN_0060588b` -> `EnsureUniqueSharedStringBuffer`
- `FUN_00605ae0` -> `ConcatenateTwoBuffersToSharedString`
- `FUN_00605b21` -> `AssignSharedStringConcatRefAndRef`
- `FUN_00605b87` -> `AssignSharedStringConcatRefAndCStr`
- `FUN_00605bfb` -> `AssignSharedStringConcatCStrAndRef`
- `FUN_00605c6f` -> `AppendBufferToSharedString`
- `FUN_00605cf5` -> `AppendSingleByteToSharedStringFromArg`
- `FUN_00605d22` -> `EnsureSharedStringCapacityPreserveLength`
- `FUN_00605d71` -> `SetSharedStringLengthAndTerminator`
- `FUN_005e9cf0` -> `CopyMemoryPossiblyOverlapping`

### Added comments
- Plate comments added for:
  - `InitializeTacticalSideFromArmyUnitList`,
  - `BuildTacticalBattleStateFromBothSides`,
  - `GenerateThreadLocalRandom15`.

## TODO (next non-UI low-hanging)
- [ ] Continue tactical gameplay extraction around unresolved callers of `GenerateThreadLocalRandom15` in tactical clusters (`0x0059bxxx`, `0x0059fxxx`, `0x005a4xxx`) where side effects are concrete.
- [ ] Decode and rename unit-wrapper ctor currently invoked as `thunk_FUN_005a5f20` in tactical side initialization (high value for battle-unit data layout understanding).
- [ ] Validate whether `AppendSingleByteToSharedStringFromArg` is strictly char-append and tighten naming/signature once one caller stack pattern is confirmed.

## Continuation (2026-02-18, money/trade+diplomacy logic pass)

### User request focus
- Find low-hanging logic related to money/trade calculations (not just UI).

### High-signal constants and tables recovered
- `DAT_00696948` decoded in-memory as:
  - `1000, 3000, 5000, 10000, 95, 90, 75, 50, 25, 0, 300, 0`
- `DAT_00696950` first entries mirror percentage controls:
  - `95, 90, 75, 50, 25, 0, 300, 0`
- These constants are used directly by diplomacy action handlers for grant/subsidy-like controls and policy toggles.

### Renames applied (money/trade+diplomacy cluster)
- `FUN_004ddfc0` -> `ApplyDiplomacyPolicyStateForTargetWithCostChecks`
- `FUN_004de5e0` -> `RevokeDiplomacyGrantForTargetAndAdjustInfluence`
- `FUN_004f4ec0` -> `RenderDiplomacyMatrixRowStatusIcons`
- `HandleSelectedNationActionCommand` (`0x004f5410`) -> `HandleDiplomacySelectedNationActionCommand`
- `FUN_0052fe90` -> `AllocateDiplomacyAidBudgetAcrossTargets`
- `FUN_00580790` -> `FormatDiplomacyNoticeTextByPolicyOrGrantCode`

### Wrapper/thunk renames
- `0x004070e5` -> `thunk_ApplyDiplomacyPolicyStateForTargetWithCostChecks`
- `0x00405c0e` -> `thunk_RenderDiplomacyMatrixRowStatusIcons`

### Comments added in Ghidra
- `HandleDiplomacySelectedNationActionCommand`:
  - documented policy-state family (`0x12D..0x134`) and grant/percentage table usage.
- `AllocateDiplomacyAidBudgetAcrossTargets`:
  - documented tiered allocation steps (`1000/3000/5000/10000`) and compatibility-priority passes.
- `RenderDiplomacyMatrixRowStatusIcons`:
  - documented mode-driven icon source (`nation+0xE0`, percentage tables, and `nation+0xB2` policy states).

### Direct behavior notes (verified in decomp)
- `AllocateDiplomacyAidBudgetAcrossTargets` chunks budget in tiers (`1000`, `3000`, `5000`, `10000`) and applies funds to targets based on compatibility classes.
- `RevokeDiplomacyGrantForTargetAndAdjustInfluence` reads per-target committed amount at `this+0xE0`, clears/refunds influence path, and adjusts relation signal through compatibility hooks.
- `FormatDiplomacyNoticeTextByPolicyOrGrantCode` emits diplomacy strings for:
  - policy codes (`0x12D..0x131`) and
  - grant amount notices (`1000`, `3000`, `5000`, `10000`).

## TODO (next money/trade low-hanging)
- [ ] Rename local variables + parameter names in `HandleDiplomacySelectedNationActionCommand` for action-index clarity (`case 0..0xD`).
- [ ] Decode and name virtual slots used in diplomacy nation object (`+0x1D0`, `+0x1D4`, `+0x1E8`, `+0x48`, `+0x160`) from this cluster.
- [ ] Confirm exact semantic split of `0x133` vs `0x134` in code comments (currently policy-state pair with asymmetric cost checks).

## Continuation (2026-02-18, diplomacy action decode follow-up)

### Additional helper renames applied
- `FUN_004f5e00` -> `ResolveDiplomacyActionFromClickAndUpdateTarget`
- `FUN_004f7400` -> `ShowDiplomacyActionRejectedNotice`
- `FUN_004f74f0` -> `ValidateDiplomacyProposalTargetAndShowBlockedDetails`
- wrappers:
  - `0x00406ed3` -> `thunk_ResolveDiplomacyActionFromClickAndUpdateTarget`
  - `0x004079fa` -> `thunk_ShowDiplomacyActionRejectedNotice`
  - `0x0040489a` -> `thunk_ValidateDiplomacyProposalTargetAndShowBlockedDetails`

### Global/data labels applied
- `DAT_00696948` -> `g_awDiplomacyGrantAndTradePolicyValueTable`
- `DAT_00696950` -> `g_awDiplomacyTradePolicyIconValueTable`
- `DAT_006a2fbc` -> `g_fDiplomacyNationMatrixRectInitialized`
- `DAT_006a3008` -> `g_rcDiplomacyNationMatrixHitBounds`

### Comments added/updated
- `HandleDiplomacySelectedNationActionCommand` plate comment now includes direct switch mapping:
  - `actionId 2..6` => policy set `0x12D..0x131` (join empire / alliance / non-aggression / peace / war families)
  - `actionId 7..8` => grants using `1000/3000/5000/10000` with recurring bit behavior (`+0x4000`)
  - `actionId 9..11` => trade-policy values via `95/90/75/50/25/0/300`
  - `actionId 14..15` => policy states `0x133/0x134`
- `ResolveDiplomacyActionFromClickAndUpdateTarget` plate comment:
  - returns current action id from `this+0xBC`,
  - updates target nation index at `this+0xC2`,
  - returns `0` when click is outside diplomacy matrix bounds.
- EOL comments added for diplomacy value-table entries at:
  - `0x00696948` (grant/trade values)
  - `0x00696950` (trade-policy icon values)

### Current ambiguity to resolve with user hints
- Exact UI-semantics split among `actionId 9/10/11` (all currently route through trade-policy value writes) needs confirmation against in-game control mapping.
- `actionId 12` toggles a nation-side flag via `+0x160` and `nation+0x918[target]`; likely colony-boycott related but not finalized.

## Continuation (2026-02-18, trade-screen low-hanging pass)

### Renames applied
- `Cluster_TradeHint_0046503c` -> `BuildTradeBoardDialogUiLayoutVariantA`
- `Cluster_TradeHint_0046baa7` -> `BuildTradeBoardDialogUiLayoutVariantB`
- `GetTradeSellControlValue` (`0x00587950`) -> `QueryTradeSellControlQuantity`
- `0x00405a97` -> `thunk_QueryTradeSellControlQuantity`

### Comments added
- `BuildTradeBoardDialogUiLayoutVariantA` and `BuildTradeBoardDialogUiLayoutVariantB`:
  - both build full Board-of-Trade UI tree (headers, resource rows, quantity arrows, move bar, row labels).
  - marked as likely variant pair with minor style/control differences (candidate pre/post-oil layouts, runtime confirmation pending).
- `HandleTradeSellControlCommand`:
  - documented command-id behavior:
    - `100`: increment sell quantity (+1 path with cap checks),
    - `0x65`: decrement,
    - `0x69`: clamp/set to maximum available,
    - `0x6A`: set zero,
    - default delegates to move-control adjustment.
- `QueryTradeSellControlQuantity`:
  - documented lookup via child control tag `Sell` and vfunc `+0x1E8`.

### Money/trade behavior confirmed in this pass
- Sell quantity controls are constrained by nation/resource availability checks before quantity apply.
- Trade board command paths include explicit max/zero and drag/page behavior coordination across row tags (`0sr..6sr`, `0am..`, `0dg..`).

## Continuation (2026-02-18, diplomacy action-id source mapping)

### Newly decoded action-selector handlers (renamed)
- `FUN_004f7f10` -> `EnterDiplomacyTreatyActionSelectionMode`
- `FUN_004f7f80` -> `HandleDiplomacyTreatyActionTagSelection`
- `FUN_004f85d0` -> `EnterDiplomacyGrantActionSelectionMode`
- `FUN_004f8650` -> `HandleDiplomacyGrantAmountTagSelection`
- `FUN_004f8d50` -> `EnterDiplomacyTradePolicySelectionMode`
- `FUN_004f8dd0` -> `HandleDiplomacyTradePolicyTagSelection`
- `FUN_004facc0` -> `EnterDiplomacyTargetNationSelectionMode`

### Key mapping recovered from code
- `HandleDiplomacyTreatyActionTagSelection` converts `0rcs..6rcs` tags into action IDs:
  - `0rcs -> 2`, `1rcs -> 3`, `2rcs -> 4`, `3rcs -> 5`, `4rcs -> 6`, `5rcs -> 14`, `6rcs -> 15`
- Combined with notice/policy decoding:
  - `2` join empire (`0x12D`)
  - `3` alliance (`0x12E`)
  - `4` non-aggression (`0x12F`)
  - `5` peace (`0x130`)
  - `6` war (`0x131`)
  - `14` consulate path (`0x133`)
  - `15` embassy path (`0x134`)
- `HandleDiplomacyGrantAmountTagSelection`:
  - sets action `7` (one-time grant) or `8` (recurring grant), and amount index in `this+0xC0`.
- `HandleDiplomacyTradePolicyTagSelection`:
  - sets amount/policy index in `this+0xC0`,
  - action `11` when value is `300` (boycott-all-style path),
  - action `9` for values `< 96` (subsidy-percent family),
  - action `10` for remaining policy values,
  - action `12` on `link` tag path.

### Notes
- Main dispatcher comment (`HandleDiplomacySelectedNationActionCommand`) updated with the decoded action map above.
- This resolves most of the prior ambiguity around action IDs `9..12`; only exact UI wording for action `10` remains uncertain.

## Continuation (2026-02-18, diplomacy map/selection helpers)

### Additional renames applied
- `FUN_004f3ea0` -> `BuildDiplomacyNationOverlayGeometryAndHitMasks`
- `0x00406d61` -> `thunk_BuildDiplomacyNationOverlayGeometryAndHitMasks`
- `FUN_004fcea0` -> `SetDiplomacyNationSelectionFilterAndRefreshRows`
- `0x00406b4a` -> `thunk_SetDiplomacyNationSelectionFilterAndRefreshRows`

### Behavior notes
- `BuildDiplomacyNationOverlayGeometryAndHitMasks`:
  - builds per-nation map overlay rectangles, anchor positions, and per-pixel hit masks for diplomacy map interaction.
- `SetDiplomacyNationSelectionFilterAndRefreshRows`:
  - writes selection-filter index to object state (`this+0x90`),
  - updates header/title token (`0x1393`/`0x1394+` family),
  - refreshes row controls `man0..man6`.
- `EnterDiplomacyTargetNationSelectionMode` calls `SetDiplomacyNationSelectionFilterAndRefreshRows(0)`, confirming action `13` is a target-selection mode setup rather than a final policy action.

## Continuation (2026-02-18, diplomacy row-builder mapping)

### Additional renames
- `FUN_004f7ac0` -> `BuildDiplomacyTreatyActionRowsFromRcsTagBase`
- `FUN_004f8780` -> `BuildDiplomacyTradePolicyRowsFromTraTagBase`

### Notes
- `BuildDiplomacyTreatyActionRowsFromRcsTagBase` uses `0rcs..6rcs` tag family and fills row text/controls for treaty-style actions (including consulate/embassy pair).
- `BuildDiplomacyTradePolicyRowsFromTraTagBase` uses `traa..` tag family for subsidy/boycott/link-style rows.
- `BuildTurnEventDialogResourcesForEvent547Or7D8` annotated as mixed event-resource factory that embeds diplomacy selector tags (`0rcs..6rcs`, `traa..`) rather than a diplomacy-only function.

## Continuation (2026-02-18, non-diplomacy trade control internals)

### Renames applied (trade control class internals)
- `FUN_00586cc0` -> `GetLiteralTypeName_TAmtBarCluster`
- `FUN_00586d10` -> `DestructTAmtBarClusterMaybeFree`
- `FUN_00587090` -> `GetLiteralTypeName_TTradeCluster`
- `FUN_00588ad0` -> `GetLiteralTypeName_TIndustryCluster`
- `FUN_00588b20` -> `DestructTIndustryClusterMaybeFree`
- `FUN_00589700` -> `GetLiteralTypeName_TRailCluster`
- `FUN_00589760` -> `DestructTRailClusterMaybeFree`
- `FUN_0058a570` -> `GetLiteralTypeName_TShipyardCluster`
- `FUN_0058a5c0` -> `DestructTShipyardClusterMaybeFree`
- `FUN_0058aed0` -> `GetLiteralTypeName_TTraderAmtBar`
- `FUN_0058aef0` -> `ConstructTTraderAmtBar_Vtbl00666ba0`
- `FUN_0058af30` -> `DestructTTraderAmtBarMaybeFree`
- `0x00407e69` -> `thunk_ConstructTTraderAmtBar_Vtbl00666ba0`

### Comments added (trade move/sell behavior)
- `HandleTradeMoveControlAdjustment`:
  - documented `100` / `0x65` +/- step behavior and availability clamp.
- `UpdateTradeMoveControlsFromDrag` and `UpdateTradeMoveControlsFromScaledDrag`:
  - documented drag-to-value mapping and visual refresh invalidation path.
- `HandleTradeMovePageStepCommand`:
  - documented page step use of `this+0x8E` as page-size unit.
- `RefreshTradeMoveBarAndTurnControl`:
  - documented bar+turn control repaint/update flow.
- `HandleTradeMoveArrowControlEvent`:
  - documented tag-based `left` / `rght` arrow handling.
- `InitializeTradeSellControlState`:
  - documented sell/bar/arrow enable-state init using nation/resource context.
- `ClampAndApplyTradeMoveValue`:
  - documented clamp path and zero-edge fallback behavior.

### Why this is useful
- This makes the trade-control family legible without over-committing to uncertain gameplay semantics.
- It also exposes reusable class naming patterns (`*Cluster`, `TTraderAmtBar`) that can be reused for adjacent unresolved constructors/destructors.

## Continuation (2026-02-18, non-UI diplomacy/economy turn application)

### Focus
- Per user request, pivoted away from UI and traced where diplomacy/trade commitments are actually applied during turn simulation.

### Renames applied (core non-UI cluster)
- `FUN_004f01e0` -> `ApplyDiplomacyInterNationStatesForTurn`
- `FUN_004df5f0` -> `ProcessPendingDiplomacyProposalQueue`
- `FUN_004dedf0` -> `ApplyImmediateDiplomacyPolicySideEffects`
- `FUN_004e50d0` -> `ResolveAndApplyDiplomacyPolicyTransition`
- `FUN_004e5300` -> `TriggerNationWarTransitionHandlersIfNeeded`
- `FUN_004e4ff0` -> `CanInitiateJoinEmpireProposalToTarget`
- `FUN_004e4fa0` -> `SetNationTradePolicyValueForTargetAndNotify`
- `FUN_004e4ee0` -> `IsDiplomacyPolicyAllowedForTargetClassState`
- `FUN_004e45f0` -> `IsPolicyCodeInSpecialNationPolicySet`
- `FUN_004e41c0` -> `DeserializeDiplomacyNationStateFromStream`
- `FUN_004e4390` -> `SerializeDiplomacyNationStateToStream`
- `FUN_004e46a0` -> `RebuildDiplomacyEconomicPressureFromMapState`

### Wrapper/thunk renames
- `0x00401cbc` -> `thunk_ProcessPendingDiplomacyProposalQueue`
- `0x0040862a` -> `thunk_ApplyImmediateDiplomacyPolicySideEffects`
- `0x00407658` -> `thunk_CanInitiateJoinEmpireProposalToTarget`
- `0x004062df` -> `thunk_DeserializeDiplomacyNationStateFromStream`
- `0x00409354` -> `thunk_SerializeDiplomacyNationStateToStream`

### Strongest recovered non-UI economy path
- `ApplyDiplomacyInterNationStatesForTurn`:
  - iterates nation pairs each turn,
  - reads and applies per-target commitment arrays at nation offsets around `+0xE0` and `+0xB2`,
  - dispatches nation callbacks that apply per-turn effects (including value-bearing paths from diplomacy grant state),
  - updates special relation matrix flags for `0x133/0x134`,
  - handles war-state (`0x131`) branch-specific updates.

### Supporting behavior recovered
- `ResolveAndApplyDiplomacyPolicyTransition` handles non-UI transition outcomes for `0x12D/0x12F/0x130` and applies side effects/event routing.
- `RebuildDiplomacyEconomicPressureFromMapState` reconstructs influence/economic pressure aggregates from map ownership/resource distribution and applies weighted influence callbacks.
- Stream serialization pair (`Deserialize...`/`Serialize...`) confirms diplomacy/economy state is persisted as a dedicated nation-state block.

## TODO (next non-UI economy pass)
- [x] Decode nation callback slots used in `ApplyDiplomacyInterNationStatesForTurn` (notably `+0x94`, `+0x1D8`, `+0x284`) and rename/materialize linked methods/thunks.
- [ ] Trace direct caller chain to `ApplyDiplomacyInterNationStatesForTurn` from turn state machine (`AdvanceGlobalTurnStateMachine` neighborhood) and add named bridge functions.
- [ ] Resolve exact semantics of commitment array at `nation+0xE0` (one-time vs recurring grant payload lifecycle) by tracing write+clear points outside UI.

## Continuation (2026-02-18, non-UI diplomacy callback-slot decode)

### What was decoded (from vtables used by turn pass)
- Nation-state vtable family (`0x0065b728`, `0x0065b3d0`, `0x0065ba80`, `0x0065b078`) callback slots in `ApplyDiplomacyInterNationStatesForTurn`:
  - `+0x94` -> `thunk_ApplyImmediateDiplomacyPolicySideEffects` -> `ApplyImmediateDiplomacyPolicySideEffects` (`0x004dedf0`)
  - `+0x1D8` -> `thunk_RevokeDiplomacyGrantForTargetAndAdjustInfluence` (`0x00404a66`) -> `RevokeDiplomacyGrantForTargetAndAdjustInfluence` (`0x004de5e0`)
  - `+0x284` -> `thunk_ApplyDiplomacyRelationCodeAndNotifyThirdPartyIfNeeded` (`0x00406fe1`) -> `ApplyDiplomacyRelationCodeAndNotifyThirdPartyIfNeeded` (`0x004e27f0`)
- Turn-state manager vtable (`0x00654d90`) slots used directly in this pass:
  - `+0x44` -> `thunk_IsNationPairRelationStateCode6` (`0x004062a3`) -> `IsNationPairRelationStateCode6` (`0x004ef540`)
  - `+0x84` -> `thunk_IsPrimaryNationSlotIndex` (`0x004088ff`) -> `IsPrimaryNationSlotIndex` (`0x004f1f50`)

### Additional low-hanging renames applied
- `FUN_004f21f0` -> `SelectDiplomacyTargetNationFromCandidateSet`
- `0x00401893` -> `thunk_SelectDiplomacyTargetNationFromCandidateSet`
- `FUN_004ef540` -> `IsNationPairRelationStateCode6`
- `FUN_004f1f50` -> `IsPrimaryNationSlotIndex`
- `FUN_004e27f0` -> `ApplyDiplomacyRelationCodeAndNotifyThirdPartyIfNeeded`
- `0x004062a3` -> `thunk_IsNationPairRelationStateCode6`
- `0x004088ff` -> `thunk_IsPrimaryNationSlotIndex`
- `0x00404a66` -> `thunk_RevokeDiplomacyGrantForTargetAndAdjustInfluence`
- `0x00406fe1` -> `thunk_ApplyDiplomacyRelationCodeAndNotifyThirdPartyIfNeeded`

### Comments added in Ghidra
- `ApplyDiplomacyInterNationStatesForTurn`:
  - added explicit callback-slot mapping note tying `+0x44/+0x84/+0x94/+0x1D8/+0x284` to concrete renamed methods.
- `SelectDiplomacyTargetNationFromCandidateSet`:
  - added behavior note for direct (`+0x98`) vs candidate-array (`+0x88`) target resolution path.
- `ApplyDiplomacyRelationCodeAndNotifyThirdPartyIfNeeded`:
  - documented main relation update call and special-case third-party notification path for codes `1` / `0x132`.

## TODO (next non-UI economy pass, narrowed)
- [ ] Decode concrete game meaning of relation state `6` used by `IsNationPairRelationStateCode6` (currently code-level only).
- [ ] Trace direct caller chain to `ApplyDiplomacyInterNationStatesForTurn` from turn state machine (`AdvanceGlobalTurnStateMachine` neighborhood) and add named bridge functions.
- [ ] Resolve exact semantics of commitment array at `nation+0xE0` (one-time vs recurring grant payload lifecycle) by tracing write+clear points outside UI.

## Continuation (2026-02-18, turn-state bridge naming around diplomacy apply)

### New bridge-oriented renames
- `FUN_0057b9e0` -> `ConstructTurnFlowStateManagerVtable00662a58`
- `0x00408495` -> `thunk_ConstructTurnFlowStateManagerVtable00662a58`
- `FUN_0057b940` -> `CreateTurnFlowStateManager`
- `FUN_0057bbf0` -> `InitializeTurnFlowStateDefaults`

### Caller-chain evidence recovered
- `ConstructTurnFlowStateManagerVtable00662a58` writes vtable `PTR_LAB_00662a58`.
- In that vtable (base `0x00662a58`), slot `+0x4C` is `thunk_AdvanceGlobalTurnStateMachine` (`0x00403b0c`).
- `AdvanceGlobalTurnStateMachine` calls manager vtable `+0x30`, which resolves (for manager vtable `0x00654d90`) to `thunk_ApplyDiplomacyInterNationStatesForTurn`.
- Constructor/initer call path now named in startup/reinit neighborhood:
  - `InitializeGlobalRuntimeSystemsFromConfig` -> `thunk_ConstructTurnFlowStateManagerVtable00662a58` -> `InitializeTurnFlowStateDefaults`
  - `ReinitializeGameFlowAndPostTurnEventCode` -> `thunk_ConstructTurnFlowStateManagerVtable00662a58` (reset path)

### Comments added
- `AdvanceGlobalTurnStateMachine`:
  - noted that vtable `+0x30` dispatch is the per-turn non-UI diplomacy/economy commit path.
- `ConstructTurnFlowStateManagerVtable00662a58`:
  - noted that its vtable slot `+0x4C` maps to `thunk_AdvanceGlobalTurnStateMachine`.

## TODO (next non-UI economy pass, narrowed again)
- [ ] Decode concrete game meaning of relation state `6` used by `IsNationPairRelationStateCode6` (currently code-level only).
- [ ] Finish runtime side of caller-chain mapping: identify which event/tick handlers invoke turn-flow vtable slot `+0x4C` during normal gameplay.
- [ ] Resolve exact semantics of commitment array at `nation+0xE0` (one-time vs recurring grant payload lifecycle) by tracing write+clear points outside UI.

## Continuation (2026-02-18, turn-flow vtable slot decode and helper naming)

### Correction
- Confirmed turn-flow class vtable base is `0x00662a58`, so:
  - `thunk_AdvanceGlobalTurnStateMachine` is slot `+0x4C` (not `+0x90`).
  - prior `+0x90` mentions were offset-from-`0x00662a14` table view artifacts.

### New turn-flow slot helper renames (high-confidence)
- `FUN_0057d8b0` -> `GetTurnFlowStateCounter2C`
- `FUN_0057d950` -> `IncrementTurnFlowStateCounter2C`
- `FUN_0057d970` -> `PostMainWindowCommand100ForTurnFlow`
- `FUN_0057f110` -> `IsTurnFlowPhaseOutsideRange4To5`
- `FUN_0057f140` -> `RefreshEligibleNationTurnPhaseHandlers`
- `FUN_0057f200` -> `DispatchEligibleNationTurnCallback158`
- thunk materialization + renames:
  - `0x004021ee` -> `thunk_GetTurnFlowStateCounter2C`
  - `0x00402d1a` -> `thunk_IncrementTurnFlowStateCounter2C`
  - `0x004053d5` -> `thunk_PostMainWindowCommand100ForTurnFlow`
  - `0x00404138` -> `thunk_IsTurnFlowPhaseOutsideRange4To5`
  - `0x00405092` -> `thunk_RefreshEligibleNationTurnPhaseHandlers`
  - `0x00406861` -> `thunk_DispatchEligibleNationTurnCallback158`

### Additional turn-flow telemetry helper renames
- `FUN_005431a0` -> `ClearTurnResumeNationPendingBitAndMaybeFlushTelemetry`
- `FUN_005410f0` -> `ProcessPendingDiplomacyThenDispatchTurnEvent29A`
- `FUN_005414f0` -> `QueueTimeEmitPacketAndDispatchTurnEvent29A`
- `FUN_00542120` -> `SetTimeEmitPacketGameFlowTurnId`
- thunks:
  - `0x00404e30` -> `thunk_ClearTurnResumeNationPendingBitAndMaybeFlushTelemetry`
  - `0x00401514` -> `thunk_ProcessPendingDiplomacyThenDispatchTurnEvent29A`
  - `0x00406168` -> `thunk_QueueTimeEmitPacketAndDispatchTurnEvent29A`
  - `0x00407f63` -> `thunk_SetTimeEmitPacketGameFlowTurnId`

### New call-path evidence (runtime dispatch side)
- Direct g_pLocalizationTable-associated callsites invoking turn-flow slot `+0x4C` confirmed in:
  - `HandleStartupCommand100` (`0x00413950`)
  - `ShowNationSelectDialogAndRedispatchCurrentTurnEvent` (`0x00413d20`)
  - `HandleCustomMessage2420DispatchTurnEvent` (`0x00485920`)
  - `DispatchTurnEvent7DDForActiveNation` (`0x00511ed0`)
  - plus internal recursive progression sites inside `AdvanceGlobalTurnStateMachine`.

## TODO (turn-flow continuation)
- [x] Name prior unresolved `FUN_004ea830` (`GetCachedAiCityActionContextBias`); revisit only if later evidence ties it to different subsystem semantics.
- [ ] Name `FUN_005c1580` once its event semantics are confirmed.
- [ ] Continue mapping message/event pump bridge into `HandleCustomMessage2420DispatchTurnEvent` and identify main-loop source of `0x2420` posts during standard turn progression.
- [ ] Resolve exact semantics of commitment array at `nation+0xE0` (one-time vs recurring grant payload lifecycle) by tracing write+clear points outside UI.

## Continuation (2026-02-18, game-logic low-hanging AI development pass)

### Focus
- Kept to low-hanging non-UI logic: AI city/industry development scoring and planning path used by `SelectBestCityDevelopmentFromResourcePools`.
- Avoided speculative class extraction; only renamed high-confidence helpers and direct data tables.

### New function/thunk renames applied
- `FUN_004ea610` -> `ComputeAiIndustryActionCostFromSlot`
- `FUN_004ea700` -> `ComputeAiCityActionCostFromSlotAndMode`
- `FUN_004ea830` -> `GetCachedAiCityActionContextBias`
- `FUN_004eb190` -> `PlanAiDevelopmentActionsFromResourcePools`
- `FUN_005c3400` -> `GetCityActionGateValueFromOrderTemplate`
- `FUN_005c3450` -> `GetCityActionGateValueBySlot`
- `FUN_005c34b0` -> `GetCityActionCategoryCodeBySlot`
- `FUN_005c3580` -> `GetNormalizedCityActionResourceCostPercent`
- `FUN_00550090` -> `GetNormalizedIndustryActionResourceCostPercent`
- thunks:
  - `0x0040142e` -> `thunk_ComputeAiIndustryActionCostFromSlot`
  - `0x00404cf0` -> `thunk_ComputeAiCityActionCostFromSlotAndMode`
  - `0x00408012` -> `thunk_GetCachedAiCityActionContextBias`
  - `0x00402e82` -> `thunk_PlanAiDevelopmentActionsFromResourcePools`
  - `0x00401695` -> `thunk_GetCityActionGateValueFromOrderTemplate`
  - `0x00403300` -> `thunk_GetCityActionGateValueBySlot`
  - `0x00401b31` -> `thunk_GetCityActionCategoryCodeBySlot`
  - `0x004081d9` -> `thunk_GetNormalizedCityActionResourceCostPercent`
  - `0x00401f55` -> `thunk_GetNormalizedIndustryActionResourceCostPercent`

### New game-logic data labels
- `DAT_00695cd2` -> `g_cityActionAiCostRuleTable`
- `DAT_00695528` -> `g_cityActionCategoryCodeBySlot`
- `DAT_0066eb88` -> `g_cityActionResourceCostTable`
- `DAT_0066ed30` -> `g_cityActionResourceCostDivisors`
- `DAT_00695b50` -> `g_industryActionCostWeightResCode09`
- `DAT_00695b70` -> `g_industryActionCostWeightResCode08`
- `DAT_00695b90` -> `g_industryActionCostWeightResCode10`
- `DAT_00695bb0` -> `g_industryActionCostWeightResCode0B`
- `DAT_00695bd0` -> `g_industryActionCostWeightResCode03`
- `DAT_00695bf0` -> `g_industryActionCostWeightResCode0C`
- `DAT_006a2ea0` -> `g_cachedAiCityActionContextBias0`
- `DAT_006a2ea4` -> `g_cachedAiCityActionContextBias1`
- `DAT_006a2ea8` -> `g_cachedAiCityActionContextBias2`
- `DAT_006967d8` -> `g_cachedAiCityActionContextBiasTurnKey`
- `DAT_006967d4` -> `g_cachedAiCityActionContextBiasNationId`

### Notes
- `GetCachedAiCityActionContextBias` refreshes a 3-value cache keyed by `g_pLocalizationTable` vfunc `+0x3c`.
- `ComputeAiCityActionCostFromSlotAndMode` consumes a 14-byte-per-slot row in `g_cityActionAiCostRuleTable` and optionally adds cached context bias for mode `0`.
- `PlanAiDevelopmentActionsFromResourcePools` repeatedly chooses/apply best city/industry action candidates until limits/budget cut off.
- Important pyghidra persistence detail: transaction-only edits did not survive until `program.save(...)` was explicitly called.

## TODO (turn-flow + AI logic continuation, updated)
- [x] Name prior unresolved `FUN_004ea830` with game-logic semantics.
- [ ] Name `FUN_005c1580` after confirming whether it is runtime turn-flow bridge or mixed UI/event-resource setup.
- [ ] Continue mapping message/event pump bridge into `HandleCustomMessage2420DispatchTurnEvent` and identify main-loop source of `0x2420` posts during standard turn progression.
- [ ] Resolve exact semantics of commitment array at `nation+0xE0` (one-time vs recurring grant payload lifecycle) by tracing write+clear points outside UI.

## Continuation (2026-02-18, diplomacy thunk islands + relation matrix naming)

### Focus
- Stayed on game logic and cleaned up non-function thunk islands in diplomacy range.
- Targeted relation-matrix getter/setter around the `IsNationPairRelationStateCode6` path.

### Materialized + renamed thunk islands (non-function -> function)
- `0x0040127b` -> `thunk_RebuildDiplomacyEconomicPressureFromMapState`
- `0x004017c1` -> `thunk_ReassignUnitOrdersForCountryTargetChange`
- `0x004017cb` -> `thunk_IsDiplomacyPolicyAllowedForTargetClassState`
- `0x00401843` -> `thunk_ResolveAndApplyDiplomacyPolicyTransition`
- `0x00402b44` -> `thunk_IsPolicyCodeInSpecialNationPolicySet`
- `0x00405b0f` -> `thunk_TriggerNationWarTransitionHandlersIfNeeded`
- `0x004071f3` -> `thunk_SetNationTradePolicyValueForTargetAndNotify`
- `0x00408076` -> `thunk_DispatchTurnEvent2103WithNationFromRecord`
- `0x00401627` -> `thunk_ApplyDiplomacyTargetTransitionAndClearGrantEntry`

### New/updated game-logic renames
- `FUN_004e2330` -> `ApplyDiplomacyTargetTransitionAndClearGrantEntry`
- `FUN_004f1b10` -> `GetNationPairRelationCode`
- `FUN_004f1b70` -> `SetNationPairRelationCodeAndApplySideEffects`
- `FUN_004f2050` -> `CountNationRelationsWithCode2`
- new thunks:
  - `0x004066ef` -> `thunk_GetNationPairRelationCode`
  - `0x00405bc3` -> `thunk_SetNationPairRelationCodeAndApplySideEffects`
  - `0x004034bd` -> `thunk_CountNationRelationsWithCode2`

### Comments added
- `ApplyDiplomacyTargetTransitionAndClearGrantEntry`:
  - documents `param_3` branch behavior (`500`, `200`, default), including `+0xE0` clear and `+0xB2` clear on `500`.
- `GetNationPairRelationCode`:
  - documents relation matrix read at `this+0xBBE`.
- `SetNationPairRelationCodeAndApplySideEffects`:
  - documents symmetric write + update stamp and code-switch side effects.
- `IsNationPairRelationStateCode6`:
  - documents that it is a thin predicate over `GetNationPairRelationCode(...) == 6`.

## TODO (game-logic continuation, narrowed)
- [ ] Decode semantic meaning of relation codes `2..6` by tracing concrete callsites that pass literal codes into `SetNationPairRelationCodeAndApplySideEffects`.
- [ ] Name `FUN_005c1580` after confirming whether it is runtime turn-flow bridge or mixed UI/event-resource setup.
- [ ] Continue mapping message/event pump bridge into `HandleCustomMessage2420DispatchTurnEvent` and identify main-loop source of `0x2420` posts during standard turn progression.
- [ ] Resolve exact semantics of commitment array at `nation+0xE0` (one-time vs recurring grant payload lifecycle) by tracing write+clear points outside UI.

## Continuation (2026-02-18, relation-code-6 queue path)

### New renames
- `FUN_004f09c0` -> `QueueNationPairForRelationCode6Transition`
- `0x00409165` -> `thunk_QueueNationPairForRelationCode6Transition`
- `FUN_004f0a10` -> `ProcessQueuedRelationCode6Transitions`
- `0x00406aaf` -> `thunk_ProcessQueuedRelationCode6Transitions`

### Why this matters
- This is the concrete runtime path that feeds relation code `6` updates into `SetNationPairRelationCodeAndApplySideEffects`.
- `ProcessQueuedRelationCode6Transitions` also performs follow-up coalition-like checks through relation-code `2` scans, which narrows where semantic decoding of code `2` should focus.

### Comments added
- `QueueNationPairForRelationCode6Transition`:
  - notes queue insert at `this+0x635` and immediate `+0x74(...,6,1)` dispatch.
- `ProcessQueuedRelationCode6Transitions`:
  - notes dequeue/apply flow and post-transition event/scan behavior.

## TODO (next game-logic pass)
- [ ] Decode relation code semantics by linking literal code writes in `SetNationPairRelationCodeAndApplySideEffects` switch cases (`2..6`) to concrete diplomacy actions/events (`0x19`, `0x1a`, `0x131`, etc.).
- [ ] Name `FUN_005c1580` after confirming whether it is runtime turn-flow bridge or mixed UI/event-resource setup.
- [ ] Continue mapping message/event pump bridge into `HandleCustomMessage2420DispatchTurnEvent` and identify main-loop source of `0x2420` posts during standard turn progression.
- [ ] Resolve exact semantics of commitment array at `nation+0xE0` (one-time vs recurring grant payload lifecycle) by tracing write+clear points outside UI.

## Continuation (2026-02-18, diplomacy relation semantics pass)

### Key evidence gathered
- Decompiled `ApplyAcceptedDiplomacyProposalCode` (`0x004df010`) and confirmed accepted policy-code handling:
  - `0x12E` path writes relation code `2` via matrix `+0x78(...,2)` and runs third-party war-join callback path (`+0x284(...,2,...)`).
  - `0x12F` path writes relation code `3` via `+0x78(...,3)`.
  - `0x130` path writes relation code `4` via `+0x78(...,4)`.
- Combined with prior action mapping (`actionId 2..6 => policy 0x12D..0x131`) this yields high-confidence relation semantics:
  - `2 = alliance`
  - `3 = non-aggression`
  - `4 = peace`
  - `6 = war` (already supported by queue/dispatch path and case side effects).

### Renames updated to semantic names
- `IsNationPairRelationStateCode6` -> `IsNationPairAtWar`
- `thunk_IsNationPairRelationStateCode6` -> `thunk_IsNationPairAtWar`
- `GetNationPairRelationCode` -> `GetNationPairDiplomacyRelationCode`
- `thunk_GetNationPairRelationCode` -> `thunk_GetNationPairDiplomacyRelationCode`
- `SetNationPairRelationCodeAndApplySideEffects` -> `SetNationPairDiplomacyRelationAndApplySideEffects`
- `thunk_SetNationPairRelationCodeAndApplySideEffects` -> `thunk_SetNationPairDiplomacyRelationAndApplySideEffects`
- `CountNationRelationsWithCode2` -> `CountNationAllianceRelationsForNation`
- `thunk_CountNationRelationsWithCode2` -> `thunk_CountNationAllianceRelationsForNation`
- `QueueNationPairForRelationCode6Transition` -> `QueueNationPairWarTransition`
- `thunk_QueueNationPairForRelationCode6Transition` -> `thunk_QueueNationPairWarTransition`
- `ProcessQueuedRelationCode6Transitions` -> `ProcessQueuedWarTransitions`
- `thunk_ProcessQueuedRelationCode6Transitions` -> `thunk_ProcessQueuedWarTransitions`
- `QueueRelationCode6TransitionAndNotifyThirdPartyIfNeeded` -> `QueueWarTransitionAndNotifyThirdPartyIfNeeded`
- `thunk_QueueRelationCode6TransitionAndNotifyThirdPartyIfNeeded` -> `thunk_QueueWarTransitionAndNotifyThirdPartyIfNeeded`
- `FUN_004df010` -> `ApplyAcceptedDiplomacyProposalCode`
- materialized `0x00403909` -> `thunk_ApplyAcceptedDiplomacyProposalCode`

### Signature cleanup attempt
- Updated return types on core helpers where safe:
  - `GetNationPairDiplomacyRelationCode` -> `short`
  - `IsNationPairAtWar` -> `bool`
  - `QueueNationPairWarTransition` / `ProcessQueuedWarTransitions` -> `void`
- Parameter-name updates for these functions were attempted, but this program region currently has sparse/implicit parameter metadata in DB, so parameter renaming did not fully stick.

### Comments updated
- `SetNationPairDiplomacyRelationAndApplySideEffects`:
  - added inferred mapping note (`2 alliance`, `3 non-aggression`, `4 peace`, `6 war`).
- `ApplyAcceptedDiplomacyProposalCode`:
  - documented proposal-code to relation-code mapping (`0x12E/0x12F/0x130`).
- War queue callback/process functions:
  - clarified war-transition semantics and third-party notification behavior.

## TODO (next game-logic pass, updated)
- [x] Decode high-confidence semantics for relation codes `2/3/4/6` and reflect them in names/comments.
- [ ] Resolve remaining ambiguous relation code `5` semantics in `SetNationPairDiplomacyRelationAndApplySideEffects` and map to concrete diplomacy action/UI wording.
- [ ] Name `FUN_005c1580` after confirming whether it is runtime turn-flow bridge or mixed UI/event-resource setup.
- [ ] Continue mapping message/event pump bridge into `HandleCustomMessage2420DispatchTurnEvent` and identify main-loop source of `0x2420` posts during standard turn progression.
- [ ] Resolve exact semantics of commitment array at `nation+0xE0` (one-time vs recurring grant payload lifecycle) by tracing write+clear points outside UI.

## Continuation (2026-02-18, diplomacy manager vtable thunk cleanup)

### Focus
- Continued low-hanging game-logic cleanup by materializing missing vtable thunk slots and renaming high-confidence relation helpers.

### New renames/materializations
- `FUN_004ef600` -> `HasAnyWarRelationForNation`
- `0x00407f7c` -> `thunk_HasAnyWarRelationForNation`
- `FUN_004f1b40` -> `SetNationPairDiplomacyRelationWithFinalFlag`
- `0x0040973c` -> `thunk_SetNationPairDiplomacyRelationWithFinalFlag`
- `0x004e0440` (new materialized tiny function) -> `NoOpNationDiplomacyCallback` (`RET 4`)
- `0x004090b1` -> `thunk_NoOpNationDiplomacyCallback`
- `0x00401a9b` materialized/disassembled -> `thunk_FUN_004fb6e0` (new explicit thunk in manager vtable tail slot)

### Notes
- This pass cleaned unresolved pointers in diplomacy manager/nation-state vtable slots (`+0x4C`, `+0x78`, `+0x214`, `+0x284`) so call graph traversal no longer dead-ends on raw addresses.
- `HasAnyWarRelationForNation` is now explicitly named and documented as an `IsNationPairAtWar` scan over nation slots `0..22`.
- `SetNationPairDiplomacyRelationWithFinalFlag` is now explicit as a thin wrapper over `SetNationPairDiplomacyRelationAndApplySideEffects(..., finalFlag=1)`.

## TODO (next low-hanging game-logic pass)
- [ ] Resolve relation code `5` semantics in `SetNationPairDiplomacyRelationAndApplySideEffects` (currently the only remaining unclear code in the relation-state switch).
- [x] Decode `FUN_004fb6e0` (reachable via manager vtable `+0x284`) and rename.
- [ ] Name `FUN_005c1580` after confirming whether it is runtime turn-flow bridge or mixed UI/event-resource setup.
- [ ] Continue mapping message/event pump bridge into `HandleCustomMessage2420DispatchTurnEvent` and identify main-loop source of `0x2420` posts during standard turn progression.

## Continuation (2026-02-18, vtable +0x284 target decode)

### Decoded and renamed
- `FUN_004fb6e0` -> `ConstructPictureResourceEntry_Vtbl0063ed78`
- `0x00401a9b` -> `thunk_ConstructPictureResourceEntry_Vtbl0063ed78`

### Findings
- `ConstructPictureResourceEntry_Vtbl0063ed78` is a compact allocator/constructor that:
  - allocates `0x90` bytes,
  - calls `thunk_ConstructPictureResourceEntryBase`,
  - writes vtable `0x0063ed78`,
  - returns the initialized object pointer.
- This confirms manager vtable `+0x284` target currently resolves to a picture-resource entry constructor path rather than direct diplomacy turn-state logic.

## Continuation (2026-02-18, relation code 5 usage check)

### Quick check result
- Scanned all `CALL dword ptr [* + 0x74]` sites and extracted immediate `PUSH` arguments in pre-call windows.
- No literal `5` argument callsites were found for `+0x74` calls (`total_calls_with_imm5 = 0`).

### Implication
- Relation code `5` in `SetNationPairDiplomacyRelationAndApplySideEffects` appears to be either:
  - currently unused by literal callsites, or
  - set only via dynamic/non-literal paths.
- Keep code `5` semantics as unresolved until a dynamic write path is identified.

## Continuation (2026-02-18, class extraction: DiplomacyTurnStateManager)

### Extracted class datatype
- Created `DiplomacyTurnStateManager` in Ghidra datatype manager:
  - path: `/Imperialism/Classes/DiplomacyTurnStateManager`
  - size: `0x18DC`
- Typed global manager pointer:
  - `g_pCivilianTerrainCompatibilityMatrix` (`0x006a43d0`) is now `DiplomacyTurnStateManager *`.

### Key recovered layout fields (current high-confidence subset)
- `+0x000`: `vftable`
- `+0x004`: `relationCodeMatrix17x17` (`short[0x180]`)
- `+0x304`: `pendingPolicyCodeMatrix17x17` (`byte[0x180]`, `0xFF` sentinel init)
- `+0x784/+0x786`: selected nation slots (`0xFFFF` init)
- `+0x78E`: `lastProcessedNationSlot` (`0xFFFF` init)
- `+0x790`: `proposalDispatchCounter`
- `+0x794/+0x798`: queued war-transition state bytes
- `+0xFE0`: `relationUpdateTurnMatrix17x17` (`short[0x180]`, `0xFFFF` init)
- `+0x1402`: `specialRelationFlagsMatrix17x17` (`short[0x180]`)
- `+0x18D4`: `pDiplomacyProposalArray` pointer
- `+0x18D8`: `proposalArrayMode`

### Method signature retyping to class pointer
- Re-typed core methods to explicit first parameter `DiplomacyTurnStateManager * pManager`, including:
  - `ConstructDiplomacyTurnStateManager_Vtbl00654d90`
  - `InitializeDiplomacyTurnStateManagerDefaults`
  - `ApplyDiplomacyInterNationStatesForTurn`
  - `GetNationPairDiplomacyRelationCode`
  - `SetNationPairDiplomacyRelationAndApplySideEffects`
  - `SetNationPairDiplomacyRelationWithFinalFlag`
  - `IsNationPairAtWar`
  - `HasAnyWarRelationForNation`
  - `CountNationAllianceRelationsForNation`
  - `QueueNationPairWarTransition`
  - `ProcessQueuedWarTransitions`
  - `QueueWarTransitionAndNotifyThirdPartyIfNeeded`
  - `ApplyAcceptedDiplomacyProposalCode`

### Notes
- For this binary, keeping these methods on `default` calling convention preserves visible typed class pointer in signatures better than forcing `__thiscall`.
- This is a pragmatic extraction pass: enough structure/method typing for productive RE, with unknown gaps intentionally left for later refinement.

## TODO (next class-aware game-logic pass)
- [ ] Refine `DiplomacyTurnStateManager` unknown gaps (`0x484..0x783`, `0x792..0xFDF`, `0x12E0..0x1401`, `0x1702..0x18D3`) by tracing additional field writes/reads.
- [ ] Resolve relation code `5` semantics in `SetNationPairDiplomacyRelationAndApplySideEffects` (currently still unresolved).
- [ ] Name `FUN_005c1580` after confirming whether it is runtime turn-flow bridge or mixed UI/event-resource setup.
- [ ] Continue mapping message/event pump bridge into `HandleCustomMessage2420DispatchTurnEvent` and identify main-loop source of `0x2420` posts during standard turn progression.

## Continuation (2026-02-18, global `0x006a43d0` sanity check + rename)

### Verification
- Re-checked `0x006a43d0` usage before trusting the old label:
  - total refs: `413` (`410` reads, `3` writes),
  - datatype at address: `DiplomacyTurnStateManager *`.
- The only write sites are lifecycle/reset paths:
  - `DestroyGlobalOrderManagersAndState` (`0x0057bd4c`) writes null,
  - `RebuildGlobalOrderManagersAndCapabilityState` (`0x0057c4d8`, `0x0057c519`) assigns manager pointer values.
- High-frequency readers are diplomacy/turn-state handlers (e.g., `HandleDiplomacySelectedNationActionCommand`, `ApplyAcceptedDiplomacyProposalCode`, `ApplyImmediateDiplomacyPolicySideEffects`, `ProcessQueuedWarTransitions` path neighbors).

### Decision
- Old symbol name `g_pCivilianTerrainCompatibilityMatrix` was misleading for this address.
- Renamed in Ghidra to: `g_pDiplomacyTurnStateManager`.
- Kept type as `DiplomacyTurnStateManager *`.

## Continuation (2026-02-18, diplomacy relation-code follow-up)

### Relation code `5` status
- Re-scanned all `CALL [* + 0x74]` virtual-call sites and extracted nearby argument setup.
- No literal `PUSH 5` was found for any `+0x74` site (`98` total sites, `0` hits with immediate `5`).
- Reconfirmed direct calls on `g_pDiplomacyTurnStateManager` (`0x006a43d0`) mostly push relation code `6` in war-transition paths.
- Conclusion remains: relation code `5` is still unresolved and appears to be dynamic/non-literal in current static pass.

## Continuation (2026-02-18, low-hanging game-logic renames: inter-nation event queue)

### Renamed global and methods
- `DAT_006a43e8` -> `g_pInterNationEventQueueManager`
- `FUN_0055b710` -> `InitializeInterNationEventQueueManager`
- `FUN_0055c970` -> `QueueInterNationEventIntoNationBucket`
- `FUN_0055c9f0` -> `QueueInterNationEventRecordDeduped`
- `FUN_0055cbd0` -> `QueueInterNationEventType0FWithBitmaskMerge`
- `FUN_0055cd00` -> `QueueInterNationEventType11`
- thunks:
  - `thunk_FUN_0055c970` (`0x00404007`) -> `thunk_QueueInterNationEventIntoNationBucket`
  - `thunk_FUN_0055c9f0` (`0x00406758`) -> `thunk_QueueInterNationEventRecordDeduped`
  - `thunk_FUN_0055cbd0` (`0x00403175`) -> `thunk_QueueInterNationEventType0FWithBitmaskMerge`
  - `thunk_FUN_0055cd00` (`0x00401474`) -> `thunk_QueueInterNationEventType11`

### Notes
- Added plate comments on:
  - `QueueInterNationEventRecordDeduped`
  - `InitializeInterNationEventQueueManager`
- Evidence highlights:
  - queue initialization creates per-nation arrays plus a shared event array,
  - event-record queue path deduplicates by `(eventType, nationA/nationB bitset)` before enqueue.

## Continuation (2026-02-18, low-hanging game-logic renames: nation interaction manager)

### Renamed global and init path
- `DAT_006a43cc` -> `g_pNationInteractionStateManager`
- `FUN_005b7a20` -> `ConstructNationInteractionStateManager_Vtbl0066d990`
- `FUN_005b7a90` -> `InitializeNationInteractionStateManagerDefaults`

### Notes
- `InitializeNationInteractionStateManagerDefaults` initializes `0x11` per-nation rows with `0x17` pairwise slots and per-row `CObArray` buckets.
- This keeps naming intentionally generic (`InteractionState`) until row fields are fully decoded.

## TODO (next low-hanging pass)
- [x] Refine `g_pNationInteractionStateManager` row layout into a concrete struct.
- [ ] Improve signatures for `QueueInterNationEvent*` methods (derive typed event-record struct where possible; params are named but still mostly scalar).
- [ ] Continue game-logic-first naming in turn flow (`005c1580` cluster remains mostly UI text/resource construction and is lower priority).

## Continuation (2026-02-18, low-hanging game-logic renames: UI transient object registry)

### Renamed global and lifecycle/helpers
- `DAT_006a43e0` -> `g_pUiTransientObjectRegistry`
- `FUN_004a0aa0` -> `ConstructUiTransientObjectRegistry_Vtbl0064c4e8`
- `FUN_004a0b20` -> `InitializeUiTransientObjectRegistry`
- `FUN_004a0d10` -> `AddObjectToUiTransientRegistry`
- `thunk_FUN_004a0d10` (`0x00402ec8`) -> `thunk_AddObjectToUiTransientRegistry`
- `FUN_004a0fa0` -> `RemoveUiTransientRegistryObjectByTag`
- `thunk_FUN_004a0fa0` (`0x004030a8`) -> `thunk_RemoveUiTransientRegistryObjectByTag`

### Evidence summary
- Add/remove helpers are called from:
  - `InitializeCityBuildingControlRegions`
  - `RenderMapOrderEntryTilePreview`
  - `SpawnTacticalUiMarkerAtUnitTile`
  - `HandleCivilianReportDecision`
  - tactical update path with tag/id `0x2711`.
- `RemoveUiTransientRegistryObjectByTag` iterates registry entries, matches `entry[6] == tag`, then releases the matched object.

## Continuation (2026-02-18, manager class placeholders + global typing)

### Extracted placeholder class datatypes
- Added under `/Imperialism/Classes`:
  - `NationInteractionStateManager` (size `0xAF0`)
  - `UiTransientObjectRegistry` (size `0x30`)
  - `InterNationEventQueueManager` (size `0xF10`)

### Typed globals
- `g_pNationInteractionStateManager` (`0x006a43cc`) -> `NationInteractionStateManager *`
- `g_pUiTransientObjectRegistry` (`0x006a43e0`) -> `UiTransientObjectRegistry *`
- `g_pInterNationEventQueueManager` (`0x006a43e8`) -> `InterNationEventQueueManager *`

### Notes
- Placeholder structs include known anchors only (vftable + key queue/bucket offsets) and explicit padding for unknown spans.
- Attempted to force typed `this` parameters on related `__thiscall` methods; Ghidra still renders `this:void *` for these functions in current state. Kept function names/parameter names and global typing as the reliable improvement for now.

## Continuation (2026-02-18, `NationInteractionStateManager` row concretization)

### Assembly confirmation
- In `InitializeNationInteractionStateManagerDefaults`:
  - row cursor starts at `ECX + 0x0E`,
  - row loop advances with `ADD ESI,0xA0`,
  - helper bucket pointer array is rooted at `ECX + 0xAA8`.
- This confirms row stride is `0xA0` and row block starts at manager offset `+0x08`.

### New datatype
- Added `/Imperialism/Classes/NationInteractionStateRow` (`0xA0`) with current known fields:
  - seed/metric words at `+0x00..+0x12`,
  - `matrixA23` (`word[23]`) at `+0x14`,
  - `matrixB23` (`word[23]`) at `+0x42`,
  - `matrixC23` (`word[23]`) at `+0x70`.

### Updated manager layout
- Replaced `/Imperialism/Classes/NationInteractionStateManager` to include:
  - `nationRows17` at `+0x08` (`NationInteractionStateRow[17]`),
  - `rowAuxBuckets17` at `+0xAA8` (`pointer[17]`),
  - `tailStateAEC` at `+0xAEC`.
- Global pointer type re-applied:
  - `g_pNationInteractionStateManager` (`0x006a43cc`) remains `NationInteractionStateManager *`.

## Continuation (2026-02-18, queue-manager refinement + diplomacy event helper renames)

### Important correction
- Corrected `InterNationEventQueueManager` layout mistake from earlier placeholder pass:
  - `perNationEventBuckets7` is at `+0xED4` (not near `+0x1C`),
  - `sharedEventRecordQueue` is at `+0xEF0`,
  - `perNationUiCounters7` is at `+0xEF4`.
- Replaced `/Imperialism/Classes/InterNationEventQueueManager` with the corrected offsets and re-applied type on `g_pInterNationEventQueueManager` (`0x006a43e8`).

### Added datatype
- `/Imperialism/Classes/InterNationEventRecord` (`0x10`):
  - `eventCode`
  - `nationA`
  - `nationMaskOrNationB`
  - `nationBOrAux`
- Field names intentionally conservative; still needs semantic resolution per event code.

### New helper renames (game-logic side)
- `FUN_004df370` -> `QueueInterNationEventForProposalCode12D_130`
- `FUN_004e5840` -> `ApplyNationStateCode200AndQueueEvent1B`
- `FUN_004e5be0` -> `QueueInterNationEvent17ForState300AffectedNations`
- `FUN_004efeb0` -> `ApplyRelationCode4AndQueueEvent18ForTargetNation`
- `FUN_004dda90` -> `QueueInterNationEventType0FForNationPairContext`
- `FUN_00530fa0` -> `ValidateProposalSelectionAndQueueEvent1C`
- `FUN_004f2820` -> `SetNationPairSpecialRelationFlagAndQueueEvent14Or16`

### Added thunk labels for non-materialized JMP stubs
- `0x00404ea3` -> `thunk_QueueInterNationEventForProposalCode12D_130`
- `0x00407257` -> `thunk_ApplyNationStateCode200AndQueueEvent1B`
- `0x0040209f` -> `thunk_ApplyRelationCode4AndQueueEvent18ForTargetNation`
- `0x00405ac9` -> `thunk_QueueInterNationEventType0FForNationPairContext`
- `0x00408bca` -> `thunk_ValidateProposalSelectionAndQueueEvent1C`

### Signature cleanup
- Re-typed queue APIs with explicit manager pointer and named scalar parameters:
  - `InitializeInterNationEventQueueManager`
  - `QueueInterNationEventIntoNationBucket`
  - `QueueInterNationEventRecordDeduped`
  - `QueueInterNationEventType0FWithBitmaskMerge`
  - `QueueInterNationEventType11`
- Added concise plate comments on:
  - `QueueInterNationEventForProposalCode12D_130`
  - `SetNationPairSpecialRelationFlagAndQueueEvent14Or16`

### Calling-convention note
- Tried default-cconv explicit manager pointer for queue methods, but that degraded callsite decompilation (arguments shifted/cast as pointers in several helpers).
- Reverted queue methods back to `__thiscall` with named non-this params to preserve correct semantics in decompiled callers.

### Event-code enum
- Added `/Imperialism/Enums/InterNationEventCode` and applied it to queue APIs:
  - `QueueInterNationEventIntoNationBucket`
  - `QueueInterNationEventRecordDeduped`
  - `QueueInterNationEventType0FWithBitmaskMerge`
- Current enum entries include currently observed codes:
  - `IN_EVENT_07_FROM_PROPOSAL_130`
  - `IN_EVENT_09_FROM_PROPOSAL_12D`
  - `IN_EVENT_0B_FROM_PROPOSAL_12E`
  - `IN_EVENT_0D_FROM_PROPOSAL_12F`
  - `IN_EVENT_0F_BITMASK_MERGE`
  - `IN_EVENT_11_SIMPLE`
  - `IN_EVENT_14_SPECIAL_RELATION_FLAG_2`
  - `IN_EVENT_16_SPECIAL_RELATION_FLAG_NOT2`
  - `IN_EVENT_17_STATE300_AFFECTED_NATIONS`
  - `IN_EVENT_18_RELATION_CODE4_TARGET`
  - `IN_EVENT_1B_NATION_STATE_CODE200`
  - `IN_EVENT_1C_PROPOSAL_VALIDATION`

## TODO (next low-hanging pass)
- [x] Convert non-materialized JMP thunk labels in this cluster into actual tiny thunk functions where useful.
- [~] Improve signatures for `QueueInterNationEvent*` methods further.
- Done: named params + `InterNationEventCode` enum.
- Remaining: introduce typed queue-entry struct in iterator paths (`thunk_FUN_005e1fa0`/`thunk_FUN_005e2000`) and propagate that type.
- [ ] Continue game-logic-first naming in turn flow (`005c1580` cluster remains mostly UI text/resource construction and is lower priority).

## Continuation (2026-02-18, inter-nation summary dialog cluster renames)

### Renamed functions
- `FUN_0055d200` -> `BuildInterNationEventSummaryRowsForAdvisorDialog`
- `FUN_0055d910` -> `FormatInterNationEventRowTokensToSharedStrings`
- `FUN_0055df50` -> `AppendInterNationEventSummaryTextEntry`
- `FUN_0056b9b0` -> `HandleInterNationEventSummaryDialogCommand`
- `Cluster_TurnEventHint_0056ea20` -> `HandleTurnEventInterNationSummaryDialogCommand`

### Renamed/materialized thunks
- `0x00408fbc` -> `thunk_BuildInterNationEventSummaryRowsForAdvisorDialog`
- `0x00407d56` -> `thunk_HandleInterNationEventSummaryDialogCommand`
- `0x0040581c` -> `thunk_HandleTurnEventInterNationSummaryDialogCommand`

### Notes
- `BuildInterNationEventSummaryRowsForAdvisorDialog` loads localized table strings and composes advisor row text from queue-manager summary entries.
- Command handlers gate \"news\"-style actions on queue-manager pending counters (`g_pInterNationEventQueueManager->perNationUiCounters7[0]` check observed).

## Continuation (2026-02-18, nation-interaction dispatch cluster low-hanging renames)

### Renamed behavior cluster (`00531770..00534450`)
- `FUN_00531770` -> `DispatchNationInteractionAmountByModePolicyA`
- `FUN_00532190` -> `DispatchNationInteractionAmountByModePolicyB`
- `FUN_005328f0` -> `SelectNationInteractionModePriorityTriplet`
- `FUN_00533670` -> `DispatchNationInteractionAmountWithAvailableCap`
- `FUN_00533db0` -> `DispatchNationInteractionAmountWithFallbackVariant`
- `FUN_00534450` -> `DispatchNationInteractionAmountWithSharedSplitCache`

### Thunks materialized/renamed
- `0x00406fc3` -> `thunk_DispatchNationInteractionAmountByModePolicyA`
- `0x00409926` -> `thunk_DispatchNationInteractionAmountByModePolicyB`
- `0x00408486` -> `thunk_SelectNationInteractionModePriorityTriplet`
- `0x0040295a` -> `thunk_DispatchNationInteractionAmountWithAvailableCap`
- `0x0040522c` -> `thunk_DispatchNationInteractionAmountWithFallbackVariant`
- `0x00405e3e` -> `thunk_DispatchNationInteractionAmountWithSharedSplitCache`

### Notes
- Names are intentionally behavior-level (policy/dispatch/cap/split) rather than over-claiming domain semantics.
- All cluster members repeatedly dispatch through `g_pNationInteractionStateManager` vfunc `+0x60`, with variants differing in clamping/fallback and split-cache behavior.

## Continuation (2026-02-18, diplomacy game-logic cursor + acceptance pass)

### Renames applied (saved with `program.save(...)`)
- `FUN_004f5fb0` -> `UpdateDiplomacyMapHoverCursorFromActionSelection`
- `0x00401c53` -> `thunk_UpdateDiplomacyMapHoverCursorFromActionSelection`
- `FUN_004e21b0` -> `ApplyDiplomacyAcceptanceSideEffectsForTargetNation`
- `0x004015aa` -> `thunk_ApplyDiplomacyAcceptanceSideEffectsForTargetNation`

### High-signal game-logic findings
- `UpdateDiplomacyMapHoverCursorFromActionSelection` is the core action->cursor selector for diplomacy map hover:
  - resolves current action via `ResolveDiplomacyActionFromClickAndUpdateTarget`,
  - validates action/target via manager vfunc `+0x5c` (`ValidateDiplomacyActionTypeAgainstTargetAndSetRejectCode`),
  - chooses cursor resource id from a local action-id table, then applies index offset from `this+0xC0` for multi-choice families.
- Recovered action-family cursor indexing behavior:
  - action `7` (grant one-time family): base id + index,
  - action `8` (grant recurring family): base id + index,
  - action `9` (subsidy/trade-policy family): base id + index.
- `ApplyDiplomacyAcceptanceSideEffectsForTargetNation` is nation-state vtable slot `+0x4C` target used by accepted-proposal flows; it applies target-side updates and conditionally triggers callback `+0xB8`.

### Relation-code-5 status update
- Still unresolved directly.
- New link: accepted-proposal paths for `0x12D` route through nation-state vtable `+0x4C` (`ApplyDiplomacyAcceptanceSideEffectsForTargetNation`), so relation-code `5` may be coupled to this acceptance path indirectly.
- Keep as hypothesis until `thunk_FUN_004d7b20` and downstream manager writes are fully traced.

## TODO (next low-hanging game-logic pass)
- [ ] Trace `thunk_FUN_004d7b20` from `ApplyDiplomacyAcceptanceSideEffectsForTargetNation` and identify whether it writes diplomacy relation matrix (`+0xBBE`) with code `5`.
- [ ] Build explicit mapping table: diplomacy action-id -> cursor resource id(s) -> raw cursor id/semantic label (using existing EXE cursor/group-cursor mapping).
- [ ] Continue avoiding deep UI-only clusters; prioritize non-UI diplomacy/turn-state transitions and relation/state write paths.

## Continuation (2026-02-18, relation-code-5 resolution follow-up)

### Additional renames (game-logic path)
- `FUN_004d7b20` -> `ApplyJoinEmpireModeForTargetNation`
- `0x0040236a` -> `thunk_ApplyJoinEmpireModeForTargetNation`
- `ApplyDiplomacyAcceptanceSideEffectsForTargetNation` -> `ApplyJoinEmpireAcceptanceSideEffectsForTargetNation`
- `thunk_ApplyDiplomacyAcceptanceSideEffectsForTargetNation` -> `thunk_ApplyJoinEmpireAcceptanceSideEffectsForTargetNation`

### Concrete evidence recovered
- `ApplyJoinEmpireModeForTargetNation` explicitly writes relation code `5` via manager vfunc `+0x78` when `mode == 1`:
  - once for `(source,target)`,
  - once for `(target,source)`.
- This is the missing direct writer path for relation code `5`; previous scans missed it because calls route through nation-state vtable thunking and non-literal setup.
- `ApplyJoinEmpireAcceptanceSideEffectsForTargetNation` calls `ApplyJoinEmpireModeForTargetNation(target, mode)` and then conditionally triggers target callback `+0xB8`.

### Updated relation-code mapping
- `SetNationPairDiplomacyRelationAndApplySideEffects` comment updated to:
  - `2 = alliance`
  - `3 = non-aggression`
  - `4 = peace`
  - `5 = join-empire/colony relation`
  - `6 = war`

## TODO (next low-hanging game-logic pass, updated)
- [x] Trace `thunk_FUN_004d7b20` from acceptance path and confirm relation-code `5` writes.
- [ ] Build explicit mapping table: diplomacy action-id -> cursor resource id(s) -> raw cursor id/semantic label (using existing EXE cursor/group-cursor mapping).
- [ ] Continue non-UI diplomacy/turn-state path naming; deprioritize deep UI text/resource factories.

## Continuation (2026-02-18, diplomacy action->cursor mapping resolved)

### Additional renames
- `FUN_0054c5a0` -> `DispatchJoinEmpireModeEventPacket24_27`
- `0x00403b07` -> `thunk_DispatchJoinEmpireModeEventPacket24_27`

### Concrete mapping recovered (from `UpdateDiplomacyMapHoverCursorFromActionSelection` local table + RT_GROUP_CURSOR decode)
- `action 2` -> group `1032` -> raw `41` (`join empire / colony`)
- `action 3` -> group `1031` -> raw `40` (`alliance`)
- `action 4` -> group `1030` -> raw `39` (`non-aggression pact`)
- `action 5` -> group `1028` -> raw `37` (`peace`)
- `action 6` -> group `1029` -> raw `38` (`war`)
- `action 7` -> base group `1041` + `this+0xC0` index -> raw `50..53` (one-time grants)
- `action 8` -> base group `1045` + `this+0xC0` index -> raw `54..57` (per-turn grants)
- `action 9` -> base group `1033` + `this+0xC0` index -> raw `42..47` (subsidies)
- `action 11` -> group `1039` -> raw `48` (`boycott all trade`)
- `action 12` -> group `1040` -> raw `49` (`colony boycott`)
- `action 14` -> group `1049` -> raw `58` (`build trade consulate`)
- `action 15` -> group `1050` -> raw `59` (`build embassy`)

### Still unresolved entries in the action->cursor table
- `action 0/1/10` -> group `1051` -> raw `60` (semantics not finalized)
- `action 13` -> group `1011` -> raw `18` (busy/rescind-style cursor; usage semantics in diplomacy path still unclear)

### Comments updated in Ghidra
- `UpdateDiplomacyMapHoverCursorFromActionSelection` plate comment now includes the explicit action->group->raw mapping above.
- `DispatchJoinEmpireModeEventPacket24_27` comment marks it as the join-empire mode packet/event side path called from `ApplyJoinEmpireModeForTargetNation` when localization mode is `1`.

## TODO (next low-hanging game-logic pass, refreshed)
- [x] Build explicit mapping table: diplomacy action-id -> cursor resource id(s) -> raw cursor id/semantic label.
- [ ] Resolve semantics for action `0/1/10` (`raw 60`) and action `13` (`raw 18`) in diplomacy flow.
- [ ] Continue non-UI diplomacy/turn-state path naming; deprioritize deep UI text/resource factories.

## Continuation (2026-02-18, diplomacy cursor semantics refinement)

### Additional evidence (cursor image inspection)
- Inspected extracted cursor previews directly:
  - `Data/extracted_cursors_exe/cursor_png/60.png` is a prohibited/no-action sign.
  - `Data/extracted_cursors_exe/cursor_png/18.png` is a question-mark cursor.

### Refined interpretation for unresolved action states
- `action 0/1/10` (`group 1051 -> raw 60`) now treated as no-action/invalid-target cursor state.
  - aligns with `ResolveDiplomacyActionFromClickAndUpdateTarget` return behavior (`0` outside matrix, `1` self-target special return).
- `action 13` (`group 1011 -> raw 18`) aligns with target-selection/question state (exact UX wording still pending).

### Ghidra comment updates
- `UpdateDiplomacyMapHoverCursorFromActionSelection` comment updated with full action->group->raw table including state-cursor interpretation for `0/1/10/13`.
- `ResolveDiplomacyActionFromClickAndUpdateTarget` comment updated with explicit return-state conventions.

## TODO (next low-hanging game-logic pass, refreshed again)
- [~] Resolve semantics for action `0/1/10` (`raw 60`) and action `13` (`raw 18`) in diplomacy flow.
- `0/1/10`: practically resolved as no-action/invalid-target state.
- Remaining: confirm if action `13` question-mark cursor is exclusively target-selection mode or also reused elsewhere in diplomacy.
- [ ] Continue non-UI diplomacy/turn-state path naming; deprioritize deep UI text/resource factories.

## Continuation (2026-02-18, colony-boycott logic slot decode)

### New renames
- `FUN_004dd0c0` -> `SetDiplomacyColonyBoycottFlagForTargetAndRefreshMinorNations`
- `0x004062cb` -> `thunk_SetDiplomacyColonyBoycottFlagForTargetAndRefreshMinorNations`

### Findings
- This function is the nation-state vtable `+0x160` target used by diplomacy action `12` path.
- Behavior:
  - writes per-target byte flag at `this + 0x918 + targetNation`,
  - iterates minor-nation objects and applies value `100` or `300` based on the new flag state.
- This confirms action `12` as the colony-boycott toggle path at code level (non-UI side).

### Comment updates
- `HandleDiplomacySelectedNationActionCommand` comment now includes action `12` note:
  - action `12` (`iVar3-2 == 10`) toggles colony-boycott via vtable `+0x160` and `+0x918[target]` flag.

## TODO (next low-hanging game-logic pass, narrowed)
- [ ] Confirm whether action `13` question-mark cursor (`group 1011 -> raw 18`) is exclusively target-selection mode or reused in other diplomacy submodes.
- [ ] Continue non-UI diplomacy/turn-state path naming; deprioritize deep UI text/resource factories.

## Continuation (2026-02-18, action-13 writer scan)

### Writer scan results for diplomacy action-state field (`this+0xBC`)
- Targeted scan of `MOV [reg+0xBC], imm` in diplomacy cluster found:
  - `BuildDiplomacyNationOverlayGeometryAndHitMasks` writes `0x0D`.
  - `EnterDiplomacyTargetNationSelectionMode` writes `0x0D`.
  - treaty/grant/trade-mode entry/selectors write the expected other states (`7,8,9,0xA,0xB,0xC,0xE`).
- No direct compare sites for `this+0xBC == 0x0D` were found in the scan pass; behavior is mode-driven by writer paths.

### Interpretation update
- Action `13` (cursor group `1011` / raw `18`, question-mark cursor) is now strongly tied to target-selection mode paths and initializer baseline state.
- This substantially narrows remaining ambiguity for action `13`.

### Comment updates in Ghidra
- `EnterDiplomacyTargetNationSelectionMode`: explicit note that it sets `this+0xBC = 13`.
- `BuildDiplomacyNationOverlayGeometryAndHitMasks`: note that it also writes `this+0xBC = 13` as target-selection baseline state.

## TODO (next low-hanging game-logic pass, updated)
- [x] Confirm whether action `13` question-mark cursor is tied to target-selection mode paths (writer-scan evidence).
- [ ] Optional: verify at runtime whether action `13` is ever reused outside diplomacy target-selection by tracing dynamic state transitions in turn-event handlers.
- [ ] Continue non-UI diplomacy/turn-state path naming; deprioritize deep UI text/resource factories.

## Continuation (2026-02-18, non-UI diplomacy callback family cleanup)

### Batch renames applied (nation-state callback slots)
- `FUN_00540c20` -> `EmitTradePolicyEventAndSetDiplomacyValueForTarget`
- `0x004024a5` -> `thunk_EmitTradePolicyEventAndSetDiplomacyValueForTarget`
- `FUN_004dd040` -> `SetDiplomacyTradePolicyValueForTargetAndMaybeClearGrant`
- `thunk_FUN_004dd040` (`0x00406be0`) -> `thunk_SetDiplomacyTradePolicyValueForTargetAndMaybeClearGrant`
- `FUN_004de790` -> `CanAffordAdditionalDiplomacyCostAfterCommitments`
- `0x0040658c` -> `thunk_CanAffordAdditionalDiplomacyCostAfterCommitments`
- `FUN_004d8c00` -> `GetDiplomacyCounterA2`
- `0x00401708` -> `thunk_GetDiplomacyCounterA2`
- `FUN_004dda20` -> `DecrementDiplomacyCounterA2ByValue`
- `0x0040455c` -> `thunk_DecrementDiplomacyCounterA2ByValue`
- `FUN_004dda60` -> `SumDiplomacyStateArrays198And1C6ForTarget`
- `0x00407545` -> `thunk_SumDiplomacyStateArrays198And1C6ForTarget`
- `FUN_004dd740` -> `GetDiplomacyExternalStateB6ByTarget`
- `0x00404b5b` -> `thunk_GetDiplomacyExternalStateB6ByTarget`
- `FUN_004ddb20` -> `GetDiplomacyState1C6ByTarget`
- `0x0040337d` -> `thunk_GetDiplomacyState1C6ByTarget`
- `FUN_004ddd50` -> `IsDiplomacyState1C6UnsetAndCounterPositiveForTarget`
- `0x00405d76` -> `thunk_IsDiplomacyState1C6UnsetAndCounterPositiveForTarget`
- `FUN_004e2270` -> `DispatchDiplomacyTargetCallbacks34And298`
- `thunk_FUN_004e2270` (`0x00406b2c`) -> `thunk_DispatchDiplomacyTargetCallbacks34And298`

### No-op callback slots materialized/renamed
- `FUN_004e0420` -> `NoOpDiplomacyTargetTransitionCallback`
- `0x00405a9c` -> `thunk_NoOpDiplomacyTargetTransitionCallback`
- `FUN_00541a00` -> `NoOpDiplomacyTargetTransitionCallbackAlt`
- `0x0040553d` -> `thunk_NoOpDiplomacyTargetTransitionCallbackAlt`
- `FUN_004e2190` -> `NoOpDiplomacyWarTransitionCallback`
- `0x00408107` -> `thunk_NoOpDiplomacyWarTransitionCallback`

### Join-empire mode callback branch naming
- `Cluster_TurnEventHint_004de860` -> `ApplyJoinEmpireMode0GlobalDiplomacyReset`
- `0x004097fa` -> `thunk_ApplyJoinEmpireMode0GlobalDiplomacyReset`
- `FUN_004d7c90` -> `ApplyJoinEmpireMode1TargetTransition`
- `0x0040376f` -> `thunk_ApplyJoinEmpireMode1TargetTransition`
- `FUN_004d7d50` -> `ApplyJoinEmpireMode2FinalizeNationNameState`
- `0x00408792` -> `thunk_ApplyJoinEmpireMode2FinalizeNationNameState`
- `FUN_004d7d20` -> `IsDiplomacyTargetClassCode200Match`
- `0x00407e3c` -> `thunk_IsDiplomacyTargetClassCode200Match`

### High-signal findings from this pass
- `SetDiplomacyTradePolicyValueForTargetAndMaybeClearGrant` writes policy value at `this+0x14[target]`; value `300` auto-clears grant via `+0x1D4`.
- `CanAffordAdditionalDiplomacyCostAfterCommitments` is the underlying affordability check for fixed-cost diplomacy actions (`500`, `5000` paths).
- `ApplyJoinEmpireModeForTargetNation` now has explicit mode callback mapping in comments:
  - mode `0` -> `+0x50` (`ApplyJoinEmpireMode0GlobalDiplomacyReset`)
  - mode `1` -> `+0x54` (`ApplyJoinEmpireMode1TargetTransition`)
  - other -> `+0x58` (`ApplyJoinEmpireMode2FinalizeNationNameState`)
- Verified callback-slot coverage in nation-state vtables (`0x0065b078/0x65b3d0/0x65b728/0x65ba80`) has no remaining missing function nodes in the analyzed offset set.

## TODO (next game-logic pass)
- [ ] Decode concrete semantics for nation callback chain used by `DispatchDiplomacyTargetCallbacks34And298` (`+0x34` on `this[0x24]` and local `+0x298`) and rename those targets.
- [ ] Optional runtime-oriented follow-up: confirm whether action `13` state is ever reused outside diplomacy target-selection.

## Continuation (2026-02-18, nation-state constructor/init game-logic pass)

### Constructor/initializer renames
- `FUN_004d89f0` -> `ConstructNationStateBase_Vtbl653938`
- `FUN_004d8cc0` -> `InitializeNationStateRuntimeSubsystems`
- `FUN_00540840` -> `CreateNationStateVariantVtable65B078`
- `FUN_00540e90` -> `CreateNationStateVariantVtable65B3D0`
- `FUN_00541230` -> `CreateNationStateVariantVtable65B728`
- `FUN_005417c0` -> `CreateNationStateVariantVtable65BA80`

### Tracked-object callback chain renames
- `FUN_004de810` -> `ReleaseAllTrackedObjectsFromList89C`
- `0x00402b0d` -> `thunk_ReleaseAllTrackedObjectsFromList89C`
- `FUN_004e2500` -> `ReleaseTrackedObjectsByMapOwnerAndUnassignedEntries`
- `0x00406492` -> `thunk_ReleaseTrackedObjectsByMapOwnerAndUnassignedEntries`

### High-signal findings
- `InitializeNationStateRuntimeSubsystems` sets up core nation-state runtime subsystems (city model/production state, policy+grant arrays, tracked object lists, counters/default flags), i.e. foundational turn-simulation state rather than UI-only behavior.
- `RebuildPrimaryNationStateForSlot` (already named) now reads cleanly against these constructors:
  - allocates variant by mode and vtable (`0x65b078/0x65b3d0/0x65b728/0x65ba80`),
  - initializes via `InitializeNationStateRuntimeSubsystems`,
  - wires object into global nation-state arrays.
- Callback-slot coverage check for nation-state vtables in analyzed offset set shows no remaining missing function nodes.

## TODO (next game-logic pass, updated)
- [ ] Decode concrete semantics for callback chain in `DispatchDiplomacyTargetCallbacks34And298`: identify the object type in `this[0x24]` and rename its `+0x34` target.
- [ ] Optional runtime-oriented follow-up: confirm whether action `13` state is ever reused outside diplomacy target-selection.

## Continuation (2026-02-18, callback-chain decode: `this[0x24]` object resolved)

### Core resolution
- Decoded object at nation-state field `this+0x90` (`this[0x24]`) as a linked-list container of integer region/tile ids (vtable `0x00650a08`).
- This object is built in `InitializeNationStateIdentityAndOwnedRegionList` by scanning map ownership (`0x180` cells) and adding matching ids.

### Renames applied (nation-state wrappers)
- `FUN_004d68f0` -> `InitializeNationStateIdentityAndOwnedRegionList`
- `FUN_004d6ba0` -> `DestroyNationStateOwnedRegionListAndRelease`
- `FUN_004d7d70` -> `RemoveRegionIdFromNationOwnedRegionList`
- `FUN_004d7da0` -> `AddRegionIdToNationOwnedRegionList`
- `FUN_004e22b0` -> `AddRegionIdToNationOwnedRegionListAndMaybeTriggerB8Callback`
- `FUN_004e2270` -> `RemoveRegionIdAndRunTrackedObjectCleanup`
- `thunk_FUN_004e2270` (`0x00406b2c`) -> `thunk_RemoveRegionIdAndRunTrackedObjectCleanup`

### Renames applied (linked-list object methods, vtable `0x650a08`)
- `FUN_004c6740` -> `AddIntToLinkedValueList`
- `FUN_004c67e0` -> `AddIntToLinkedValueListAlt`
- `FUN_004c6880` -> `GetNthIntFromLinkedValueList`
- `FUN_004c68c0` -> `GetLinkedValueListCount`
- `FUN_004c68e0` -> `RemoveNthIntFromLinkedValueList`
- `FUN_004c69a0` -> `ClearLinkedValueList`
- `FUN_004c69e0` -> `RemoveIntFromLinkedValueListByValue`
- `FUN_004c6bf0` -> `DestroyLinkedValueListAndFreeSelf`
- `FUN_004c65d0` -> `SerializeLinkedValueListWithArchiveFlags`
- `FUN_004c6b60` -> `DebugDumpLinkedValueList`
- `FUN_004bec10` -> `DestructLinkedValueListMaybeFree`
- no-op hooks:
  - `FUN_00487f70` -> `NoOpLinkedValueListHook1C`
  - `FUN_00487f90` -> `NoOpLinkedValueListHook20`
- Corresponding thunk names were updated across `0x00403341/0x00407a27/0x004015f5/0x00401857/0x004093c2/0x0040976e/0x004016ea/0x00406884/0x00408e77/0x004059d4/0x00404f89/0x00401933/0x00402de7`.

### Concrete callback semantics recovered
- `this[0x24] + 0x34` (used by `RemoveRegionIdAndRunTrackedObjectCleanup`) -> remove region id by value from linked list.
- `this[0x24] + 0x14` (used by `AddRegionIdToNationOwnedRegionList*`) -> add region id to linked list.
- Local callback `this + 0x298` (already named `ReleaseTrackedObjectsByMapOwnerAndUnassignedEntries`) performs tracked-object cleanup based on map-owner class and unassigned entries.

## TODO (next game-logic pass, refreshed)
- [x] Decode callback chain in former `DispatchDiplomacyTargetCallbacks34And298` and resolve `this[0x24]` object type plus `+0x34` target.
- [ ] Decode callback `+0xB8` triggered by `AddRegionIdToNationOwnedRegionListAndMaybeTriggerB8Callback` (count/threshold path) and rename if high-confidence.
- [ ] Optional runtime-oriented follow-up: confirm whether action `13` state is ever reused outside diplomacy target-selection.

## Continuation (2026-02-18, game-logic pass: nation pending-action state machine)

### Core decode result for former `+0xB8` callback
- Resolved nation-state vtable slot `+0xB8` target chain:
  - thunk slot address `0x00402784` -> `JMP 0x004daa10`
  - target `FUN_004daa10` writes pending-action state/payload arrays:
    - byte state at `this + 0x8c8[index] = 0x32`
    - word payload at `this + 0x8d6[index*2] = payload`
    - guarded by `DAT_00695278 != -3`
- Updated region-add callback name to reflect threshold-trigger semantics.

### Renames applied (saved)
- `FUN_004da5e0` -> `DispatchNationPendingActionEventCodes`
- `FUN_004da860` -> `PromoteNationPendingActionSlot5IfCapabilityActive`
- `FUN_004da8a0` -> `AdvanceNationPendingActionStateMachine`
- `FUN_004daa10` -> `SetNationPendingActionStateAndPayload`
- `FUN_004daa50` -> `QueueNationOrderManagerEntryById`
- `FUN_004daa80` -> `ClearQueuedNationOrdersAndResetOrderManager`
- `FUN_004dab20` -> `ExecuteNationPendingActionStateMachine`
- `FUN_004dae70` -> `HasQueuedCivWorkOrderType7`
- `FUN_004da5c0` -> `NoOpNationPendingActionHook`
- `FUN_004dab00` -> `NoOpNationQueuedOrderHook`
- `AddRegionIdToNationOwnedRegionListAndMaybeTriggerB8Callback` (`0x004e22b0`) -> `AddRegionIdToNationOwnedRegionListAndTriggerExpansionActionIfThresholdMet`
- `0x00404246` -> `thunk_AddRegionIdToNationOwnedRegionListAndTriggerExpansionActionIfThresholdMet`

### Thunk renames (batch)
- `0x00407216` -> `thunk_DispatchNationPendingActionEventCodes`
- `0x0040930e` -> `thunk_AdvanceNationPendingActionStateMachine`
- `0x00402784` -> `thunk_SetNationPendingActionStateAndPayload`
- `0x0040241e` -> `thunk_ExecuteNationPendingActionStateMachine`
- `0x0040548e` -> `thunk_QueueNationOrderManagerEntryById`
- `0x004018f2` -> `thunk_ClearQueuedNationOrdersAndResetOrderManager`
- `0x004023ce` -> `thunk_HasQueuedCivWorkOrderType7`
- `0x00408968` -> `thunk_NoOpNationPendingActionHook`
- `0x00407e23` -> `thunk_NoOpNationQueuedOrderHook`

### Comments added
- Plate comment at `SetNationPendingActionStateAndPayload` with explicit field writes (`+0x8c8`, `+0x8d6`).
- Plate comment at `AddRegionIdToNationOwnedRegionListAndTriggerExpansionActionIfThresholdMet` documenting threshold gates and callback dispatch `(0x0C, -1)`.

## TODO (next game-logic pass)
- [ ] Decode semantics of `FUN_004db7d0` / thunk `0x00402ec3` (reachable-mask/eligibility path touching per-entry flag at `+0x4c`).
- [ ] Decode vtable slot `+0xBC` target `FUN_00540c70` and name underlying queue-manager API (`0x90c` object methods at `+0x30/+0x54`).
- [ ] Inspect and rename remaining nation-state callback thunks in vtable window (`+0x88..+0xA4`) where targets are still generic (`FUN_00540ba0`, `FUN_00540ac0`, `FUN_00540a00`, `FUN_004d6750/6730/6770`, etc.).

## Continuation (2026-02-18, game-logic pass: connectivity/availability mask)

### Decode result
- Resolved nation-state vtable slot `+0xD4` helper chain:
  - thunk slot address `0x00402301` -> `JMP 0x004dbac0`
  - target recursively marks connected owned regions in a byte mask buffer using map adjacency bits.
- Decoded former `FUN_004db7d0` as availability-mask updater for order-entry list entries:
  - allocates/zeroes region mask buffer,
  - seeds connectivity from current entry region,
  - expands based on transport-linked entries,
  - writes availability byte at entry `+0x4c`,
  - optional out pointer returns allocated mask.

### Renames applied (saved)
- `FUN_004dbac0` -> `MarkConnectedOwnedRegionsInMaskRecursive`
- `0x00402301` -> `thunk_MarkConnectedOwnedRegionsInMaskRecursive`
- `FUN_004db7d0` -> `UpdateOrderEntryAvailabilityByConnectedRegionMask`
- `0x00402ec3` -> `thunk_UpdateOrderEntryAvailabilityByConnectedRegionMask`
- `FUN_005b7830` -> `IsOrderEntryTransportLinkedAndEnabled`
- `0x0040454d` -> `thunk_IsOrderEntryTransportLinkedAndEnabled`

### Comments added
- Plate comment at `MarkConnectedOwnedRegionsInMaskRecursive` (connectivity flood-fill semantics).
- Plate comment at `UpdateOrderEntryAvailabilityByConnectedRegionMask` (availability/optional-out-mask behavior).

## TODO (next game-logic pass, refreshed)
- [x] Decode semantics of former `FUN_004db7d0` / thunk `0x00402ec3` and rename.
- [ ] Decode vtable slot `+0xBC` target `FUN_00540c70` and underlying queue-manager object at `this+0x90c` (`+0x30/+0x54` methods).
- [ ] Decode and rename remaining generic nation-state callback nodes in vtable window `+0x88..+0xA4` (especially `FUN_00540ba0`, `FUN_00540ac0`, `FUN_00540a00`, and boolean capability stubs).

## Continuation (2026-02-18, game-logic pass: nation +0xBC split and turn-event routing)

### Key finding
- Nation-state vtable slot `+0xBC` is variant-split behavior:
  - variant path A (`0x00406190 -> 0x00540c70`): dispatches a code-`0x31` tagged turn-event payload (`tag=0x73746172`, "star") and releases payload object.
  - variant path B (`0x0040548e -> 0x004daa50`): enqueues payload object in local order-manager list (`this+0x90c`, manager `+0x30` AddTail-like).
- Corroborated via `HandleTurnEventCodes28_2E_2F_30_31_32` (`0x00549ff0`) case `0x31`, where tagged payload routing can feed nation-state `+0xBC`.

### Renames applied (saved)
- `QueueNationOrderManagerEntryById` (`0x004daa50`) -> `QueueNationOrderManagerPayloadObject`
- `thunk_QueueNationOrderManagerEntryById` (`0x0040548e`) -> `thunk_QueueNationOrderManagerPayloadObject`
- `FUN_00540c70` -> `DispatchTurnEvent31StarPayloadForNationAndReleaseObject`
- `0x00406190` -> `thunk_DispatchTurnEvent31StarPayloadForNationAndReleaseObject`
- `FUN_00549a90` -> `DispatchTurnEvent31TaggedPayload`
- `0x00404598` -> `thunk_DispatchTurnEvent31TaggedPayload`
- `FUN_00549ad0` -> `DispatchTurnEventPacketWithCodeAndPayloadBuffer`
- `0x00405ad3` -> `thunk_DispatchTurnEventPacketWithCodeAndPayloadBuffer`
- `FUN_00549ff0` -> `HandleTurnEventCodes28_2E_2F_30_31_32`

### Comments added
- Plate comment at `DispatchTurnEvent31StarPayloadForNationAndReleaseObject` documenting tagged dispatch+release behavior.
- Plate comment at `QueueNationOrderManagerPayloadObject` documenting local enqueue behavior.
- Plate comment at `HandleTurnEventCodes28_2E_2F_30_31_32` documenting handled code set and `0x31` routing.

## TODO (next game-logic pass, refreshed)
- [x] Decode vtable slot `+0xBC` split behavior and rename both paths.
- [ ] Decode remaining generic nation-state callbacks in `+0x88..+0xA4` with emphasis on capability-flag stubs (`FUN_004d6730/6750/6770/7f60`, `FUN_005408c0/408e0/40f20/412b0/412d0/41840`) by tracing concrete callsites in diplomacy/turn-flow.
- [ ] If confidence allows, promote nation-state field names around pending-action arrays (`+0x8c8/+0x8d6`) into a struct extract pass.

## Continuation (2026-02-18, game-logic pass: capability-flag stub cleanup)

### Renames applied (saved)
- `FUN_004d7f60` -> `ReturnFalseNationStateCapabilityFlag90`
- `FUN_004d6730` -> `ReturnFalseNationStateCapabilityFlag98`
- `FUN_005408c0` -> `ReturnTrueNationStateCapabilityFlag98`
- `FUN_005412b0` -> `ReturnTrueNationStateCapabilityFlag98Alt`
- `FUN_004d6750` -> `ReturnFalseNationStateCapabilityFlag9C`
- `FUN_00540f20` -> `ReturnTrueNationStateCapabilityFlag9C`
- `FUN_004d6770` -> `ReturnFalseNationStateCapabilityFlagA0`
- `FUN_005408e0` -> `ReturnTrueNationStateCapabilityFlagA0`
- `FUN_005412d0` -> `ReturnFalseNationStateCapabilityFlagA0Alt`
- `FUN_00541840` -> `ReturnTrueNationStateCapabilityFlagA0Alt`

### Thunk renames (saved)
- `0x00404d95` -> `thunk_ReturnFalseNationStateCapabilityFlag90`
- `0x0040213f` -> `thunk_ReturnFalseNationStateCapabilityFlag98`
- `0x00406050` -> `thunk_ReturnTrueNationStateCapabilityFlag98`
- `0x00406569` -> `thunk_ReturnTrueNationStateCapabilityFlag98Alt`
- `0x00402040` -> `thunk_ReturnFalseNationStateCapabilityFlag9C`
- `0x00406b45` -> `thunk_ReturnTrueNationStateCapabilityFlag9C`
- `0x0040432c` -> `thunk_ReturnFalseNationStateCapabilityFlagA0`
- `0x00401e88` -> `thunk_ReturnTrueNationStateCapabilityFlagA0`
- `0x00404377` -> `thunk_ReturnFalseNationStateCapabilityFlagA0Alt`
- `0x004038a5` -> `thunk_ReturnTrueNationStateCapabilityFlagA0Alt`

### Notes
- This is intentionally slot-based naming for low-risk progress: these callbacks are tiny constant-return capability gates used by nation-state variants.

## TODO (next game-logic pass, refreshed)
- [x] Clean up nation-state capability gate stubs (`+0x90/+0x98/+0x9C/+0xA0`) with non-generic names.
- [ ] Decode semantics of slot `+0x88` split (`FUN_00540ba0`, `FUN_00541080`, `thunk_FUN_004ddbb0`) and promote to domain names.
- [ ] Decode slot `+0xA4` split (`thunk_FUN_004d6790` vs `FUN_00541b40`) and rename with behavior-based names.
- [ ] Evaluate extracting a `NationPendingActionState` struct around fields `+0x8c8/+0x8d6/+0x8cd..+0x8d4/+0x8e*`.

## Continuation (2026-02-18, game-logic pass: slot +0x88 action-dispatch split)

### Decode result
- Decoded slot `+0x88` callback split for nation-state variants:
  - `TryDispatchNationActionViaUiContextOrFallback` (`0x004ddbb0`): validate via `this->vtable+0x84`; on success dispatch through UI runtime context `+0x98`; on failure call fallback `this->vtable+0x1B0`.
  - `TryDispatchNationActionViaTurnEventOrFallback` (`0x00540ba0`): same validation/fallback pattern, but success path emits turn-event payload.
  - `TryDispatchNationActionViaUiThenTurnEvent` (`0x00541080`): UI-context path first, then emits turn-event payload when successful.
- Renamed shared helper `FUN_005497b0` to `DispatchTurnEvent1AWithNationActionPayload` (packet build/dispatch path).

### Renames applied (saved)
- `FUN_004ddbb0` -> `TryDispatchNationActionViaUiContextOrFallback`
- `0x00404ce1` -> `thunk_TryDispatchNationActionViaUiContextOrFallback`
- `FUN_00540ba0` -> `TryDispatchNationActionViaTurnEventOrFallback`
- `0x00401109` -> `thunk_TryDispatchNationActionViaTurnEventOrFallback`
- `FUN_00541080` -> `TryDispatchNationActionViaUiThenTurnEvent`
- `0x00404273` -> `thunk_TryDispatchNationActionViaUiThenTurnEvent`
- `FUN_005497b0` -> `DispatchTurnEvent1AWithNationActionPayload`
- `0x004022c5` -> `thunk_DispatchTurnEvent1AWithNationActionPayload`

### Comments added
- Plate comments were added on the three slot-`+0x88` target functions documenting validation/dispatch/fallback behavior.

## TODO (next game-logic pass, refreshed)
- [x] Decode slot `+0x88` split and promote to behavior-based names.
- [ ] Decode slot `+0xA4` split (`thunk_FUN_004d6790` vs `FUN_00541b40`) and rename with behavior-based names.
- [ ] Revisit slot `+0x8C` split (`thunk_ApplyImmediateDiplomacyPolicySideEffects` vs `thunk_FUN_004defd0`/`FUN_00540ac0`) and align names to concrete branch semantics.
- [ ] Evaluate extraction of a `NationPendingActionState` struct around fields `+0x8c8/+0x8d6/+0x8cd..+0x8d4/+0x8e*`.

## Continuation (2026-02-18, game-logic pass: slot +0xA4 / +0x8C and proposal-queue cleanup)

### Key findings
- Slot `+0x8C` split is now decoded as local proposal-queue write vs queue+network dispatch:
  - local path writes `[proposalCode, targetNationId]` into nation-local queue object at `this+0x84c`.
  - network path wraps local write and emits turn-event packet code `0x16` with that payload.
- `SetGlobalMapCellSharedLabel` (`0x00515f40`) writes a shared-string label into per-cell global map metadata (`globalMapState[4]` cell entry + `0xA4` string field).
- Slot `+0xA4` split is now represented as no-op vs selected-region map-label update.

### Renames applied (saved)
- `FUN_004defd0` -> `QueueDiplomacyProposalCodeForTargetNation`
- `0x004083f5` -> `thunk_QueueDiplomacyProposalCodeForTargetNation`
- `FUN_00540ac0` -> `QueueDiplomacyProposalCodeForTargetNationAndDispatchTurnEvent16`
- `0x00404eb7` -> `thunk_QueueDiplomacyProposalCodeForTargetNationAndDispatchTurnEvent16`
- `FUN_004e7b50` -> `QueueDiplomacyProposalCodeWithAllianceGuards`
- `FUN_00515f40` -> `SetGlobalMapCellSharedLabel`
- `0x004083cd` -> `thunk_SetGlobalMapCellSharedLabel`
- `FUN_00541b40` -> `SetNationSelectedRegionAndMapCellLabel`
- `0x004039a4` -> `thunk_SetNationSelectedRegionAndMapCellLabel`
- `FUN_004d6790` -> `NoOpNationSelectedRegionAndMapCellLabelHook`
- `0x004075fe` -> `thunk_NoOpNationSelectedRegionAndMapCellLabelHook`
- `FUN_00541d90` -> `SetNationSelectedRegionAndMapCellLabelAlt`
- `0x0040423c` -> `thunk_SetNationSelectedRegionAndMapCellLabelAlt`

### Additional proposal-queue low-hanging renames
- `FUN_004df580` -> `ResetNationDiplomacyProposalQueue`
- `0x004013bb` -> `thunk_ResetNationDiplomacyProposalQueue`
- `FUN_004e7be0` -> `ReplayQueuedDiplomacyProposalRowsAndProcessQueue`
- `0x0040835a` -> `thunk_ReplayQueuedDiplomacyProposalRowsAndProcessQueue`

### Comments added
- Plate comments added to:
  - `QueueDiplomacyProposalCodeForTargetNation`
  - `QueueDiplomacyProposalCodeForTargetNationAndDispatchTurnEvent16`
  - `SetNationSelectedRegionAndMapCellLabel`
  - `NoOpNationSelectedRegionAndMapCellLabelHook`
  - `ResetNationDiplomacyProposalQueue`
  - `ReplayQueuedDiplomacyProposalRowsAndProcessQueue`

## TODO (next game-logic pass, refreshed)
- [x] Decode slot `+0xA4` and `+0x8C` split behavior and rename with concrete semantics.
- [ ] Decode vtable `0x649068` method family at offsets `+0x2C/+0x38/+0x44` to extract a concrete class name for nation field `+0x84c` (currently proposal-queue object).
- [ ] Evaluate extracting a `NationPendingActionState` struct around fields `+0x8c8/+0x8d6/+0x8cd..+0x8d4/+0x8e*`.
- [ ] Continue non-UI game-logic renames from unresolved nation-state callback slots (`+0xC0/+0xC8/+0xCC/+0xD0` families).

## Continuation (2026-02-18, game-logic pass: extracting `0x649068` pointer-record list methods)

### Findings
- Nation fields `+0x848` and `+0x84c` are both instances of the same vtable family (`0x649068`).
- The method set is a fixed-size pointer-record list utility (record size in object field `+0x14`, initialized to `4` in nation-state init), used by diplomacy proposal queue flows at `+0x84c`.

### Renames applied (saved)
- `FUN_004880a0` -> `ClearAndFreeAllPtrListRecords`
- `FUN_004880f0` -> `InvokePtrListResetHook`
- `FUN_00488110` -> `ResetPtrListAndShrinkCapacity`
- `FUN_00488160` -> `GetPtrListEntryByOneBasedIndex`
- `FUN_00488190` -> `RemovePtrListEntryByOneBasedIndexAndFree`
- `FUN_004881d0` -> `RemoveFirstPtrListEntry`
- `FUN_004881f0` -> `UpsertPtrListRecordByComparator`
- `FUN_004882c0` -> `AppendCopiedRecordToPtrList`
- `FUN_00488310` -> `InsertCopiedRecordAtFrontOfPtrList`
- `FUN_00488360` -> `CompareUnsignedIntsAscending`
- `FUN_00488470` -> `InsertCopiedRecordAtFrontOfPtrListAlt`
- `FUN_004884c0` -> `DestructTPtrListMaybeFree`
- `FUN_00488510` -> `GetTPtrListClassName`

### Thunk renames (saved)
- `0x00401159` -> `thunk_ClearAndFreeAllPtrListRecords`
- `0x00404101` -> `thunk_InvokePtrListResetHook`
- `0x00407da6` -> `thunk_ResetPtrListAndShrinkCapacity`
- `0x00409868` -> `thunk_GetPtrListEntryByOneBasedIndex`
- `0x004097d7` -> `thunk_RemovePtrListEntryByOneBasedIndexAndFree`
- `0x0040288d` -> `thunk_RemoveFirstPtrListEntry`
- `0x004088a5` -> `thunk_UpsertPtrListRecordByComparator`
- `0x00407bbc` -> `thunk_AppendCopiedRecordToPtrList`
- `0x00405871` -> `thunk_InsertCopiedRecordAtFrontOfPtrList`
- `0x0040242d` -> `thunk_CompareUnsignedIntsAscending`
- `0x004063fc` -> `thunk_InsertCopiedRecordAtFrontOfPtrListAlt`
- `0x004029be` -> `thunk_DestructTPtrListMaybeFree`
- `0x00402649` -> `thunk_GetTPtrListClassName`

### Comments added
- Plate comment on `UpsertPtrListRecordByComparator` documenting search-by-comparator then insert-copy behavior.

## TODO (next game-logic pass, refreshed)
- [x] Decode slot `+0xA4` and `+0x8C` split behavior and rename with concrete semantics.
- [x] Decode and rename `0x649068` method family enough to treat nation `+0x84c` as a concrete pointer-record list utility.
- [ ] Evaluate extracting a `NationPendingActionState` struct around fields `+0x8c8/+0x8d6/+0x8cd..+0x8d4/+0x8e*`.
- [ ] Continue non-UI game-logic renames from unresolved nation-state callback slots (`+0xC0/+0xC8/+0xCC/+0xD0` families).

## Continuation (2026-02-18, game-logic pass: nation order archive read/write pair)

### Renames applied (saved)
- `FUN_004da3e0` -> `DeserializeNationOrderStateFromArchive`
- `0x00408adf` -> `thunk_DeserializeNationOrderStateFromArchive`
- `FUN_004da500` -> `SerializeNationOrderStateToArchive`
- `0x00408ac6` -> `thunk_SerializeNationOrderStateToArchive`

### Comments added
- Plate comments added to both functions documenting field/object coverage and read/write inversion.

## TODO (next game-logic pass, refreshed)
- [x] Rename clear deserialize/serialize pair for nation order state.
- [ ] Evaluate extracting a `NationPendingActionState` struct around fields `+0x8c8/+0x8d6/+0x8cd..+0x8d4/+0x8e*`.
- [ ] Continue non-UI game-logic renames from remaining generic nation functions in this cluster (`FUN_004dbf00`, `FUN_004dfae0`, `FUN_004e3830`) once their semantics are separated cleanly.

## Continuation (2026-02-18, game-logic pass: resolved remaining nation cluster `0x004dbf00/0x004dfae0/0x004e3830`)

### What was decoded
- `0x004dbf00` iterates owned regions, accumulates per-resource production signals, advances several per-region development counters, writes a compact stage byte into global region state, and dispatches nation callback events when the stage increases.
- `0x004dfae0` picks/validates a nation tile, creates a `FrogCity` marker object, queues it into nation list `this+0x898`, updates map-cell label state, and notifies active UI path when needed.
- `0x004e3830` is a large secondary-nation slot initializer: resets per-resource counters and thresholds, rebuilds owned-resource tallies, chooses a home tile (fallback random candidate path), and seeds slot-specific scalar defaults.

### Renames applied (saved)
- `FUN_004dbf00` -> `AdvanceOwnedRegionDevelopmentCountersAndDispatchEvents`
- `FUN_004dfae0` -> `CreateAndQueueFrogCityMarkerForNationTile`
- `FUN_004e3830` -> `InitializeSecondaryNationStateAndSelectHomeTile`
- `FUN_00518960` -> `SetGlobalRegionDevelopmentStageByte`

### Thunk/materialization updates (saved)
- Created function at `0x0040245f` and renamed to `thunk_AdvanceOwnedRegionDevelopmentCountersAndDispatchEvents`
- Created function at `0x00408553` and renamed to `thunk_CreateAndQueueFrogCityMarkerForNationTile`
- `0x0040401b` -> `thunk_InitializeSecondaryNationStateAndSelectHomeTile`
- `0x004063bb` -> `thunk_SetGlobalRegionDevelopmentStageByte`

### Comments added
- Plate/function comments were added on:
  - `AdvanceOwnedRegionDevelopmentCountersAndDispatchEvents`
  - `CreateAndQueueFrogCityMarkerForNationTile`
  - `InitializeSecondaryNationStateAndSelectHomeTile`

## TODO (next game-logic pass, refreshed)
- [x] Resolve/rename remaining generic nation functions in this cluster (`FUN_004dbf00`, `FUN_004dfae0`, `FUN_004e3830`).
- [ ] Decode `FUN_004dbd20` and align with newly named development-stage flow (`SetGlobalRegionDevelopmentStageByte`) so per-resource counter fields can be named coherently.
- [ ] Decode `FUN_00513980` and rename to concrete tile-candidate predicate semantics used by secondary-nation home-tile selection.
- [ ] Evaluate extracting a compact struct for per-region development counters in global region state (`+0x84..+0x92` fields inside each `0xA8` cell entry).

## Continuation (2026-02-18, game-logic pass: adjacent low-hanging decode around secondary-nation init)

### Additional renames applied (saved)
- `FUN_004dbd20` -> `RebuildNationResourceYieldCountersAndDevelopmentTargets`
- `0x004097ff` -> `thunk_RebuildNationResourceYieldCountersAndDevelopmentTargets`
- `FUN_00513980` -> `IsValidSecondaryNationHomeTileCandidate`
- `0x004081bb` -> `thunk_IsValidSecondaryNationHomeTileCandidate`

### Additional comments added
- Plate/function comments added on:
  - `RebuildNationResourceYieldCountersAndDevelopmentTargets`
  - `IsValidSecondaryNationHomeTileCandidate`

### Notes
- This aligns the `InitializeSecondaryNationStateAndSelectHomeTile` flow with explicit naming for both:
  - the resource-yield/development counter rebuild helper,
  - and the tile-candidate predicate used by home-tile selection fallback.

## TODO (next game-logic pass, refreshed)
- [x] Resolve/rename remaining generic nation functions in the `0x004dbd20..0x004e3830` cluster.
- [ ] Decode `CreateAndQueueFrogCityMarkerForNationTile` callsite intent (`vtable slot context`) to see if `FrogCity` can be replaced by a domain term.
- [ ] Identify and name the struct/class behind marker object vtable `PTR_LAB_0066d7c8` (`FUN_005b6c60`/`FUN_005b6cd0`) and align field names (`+0x14/+0x1c/+0x4d/+0x4f`).
- [ ] Start a new non-UI game-logic lane: turn-economy/trade-money calculation path (find arithmetic sinks feeding treasury deltas per turn).

## Continuation (2026-02-18, game-logic pass: constructor/class-shape low-hanging)

### Constructor-level renames applied (saved)
- `FUN_004e3710` -> `ConstructSecondaryNationState`
- `0x00403800` -> `thunk_ConstructSecondaryNationState`
- `FUN_005b6c60` -> `ConstructFrogCityMarker`
- `0x00403044` -> `thunk_ConstructFrogCityMarker`
- `FUN_005b6cd0` -> `InitializeFrogCityMarkerFields`
- `0x004046b5` -> `thunk_InitializeFrogCityMarkerFields`

### Comments added
- Plate/function comments added on:
  - `ConstructSecondaryNationState`
  - `ConstructFrogCityMarker`
  - `InitializeFrogCityMarkerFields`

### Notes
- This makes the `CreateAndQueueFrogCityMarkerForNationTile` path read end-to-end as constructor + field initialization + queue insertion.
- `ConstructSecondaryNationState` + `InitializeSecondaryNationStateAndSelectHomeTile` are now explicitly paired for future class extraction.

## TODO (next game-logic pass, refreshed)
- [x] Rename constructor/init low-hanging around secondary-nation and FrogCity marker objects.
- [ ] Extract a provisional class label for secondary nation object (vtable rooted at `PTR_LAB_00653c90`) and migrate obvious field names (`homeTile`, counter bands, threshold bands).
- [ ] Extract a provisional class label for FrogCity marker object (vtable `PTR_LAB_0066d7c8`) and name key fields (`tileId`, `owner/slot`, flags).
- [ ] Start turn-economy/trade-money discovery lane (identify treasury delta writers called from turn-flow dispatch).

## Continuation (2026-02-18, game-logic pass: provisional class/vtable labels)

### Data symbol renames applied (saved)
- `PTR_LAB_00653c90` -> `g_vtblSecondaryNationState`
- `PTR_LAB_0066d7c8` -> `g_vtblFrogCityMarker`

### Comments added
- Plate comments added at both vtable roots tying them to constructor/initializer call paths.

## TODO (next game-logic pass, refreshed)
- [x] Add provisional vtable labels for secondary-nation and FrogCity marker object families.
- [ ] Promote key field names in `SecondaryNationState` methods (start with home tile + resource/development counter bands).
- [ ] Promote key field names in `FrogCityMarker` init method (`InitializeFrogCityMarkerFields`) where argument/field semantics are clear.
- [ ] Start turn-economy/trade-money discovery lane (identify treasury delta writers called from turn-flow dispatch).

## Continuation (2026-02-18, game-logic pass: turn-economy/trade-money lane bootstrap)

### Discovery results
- Grant-tier constant scan (`1000/3000/5000/10000`) produced a tight diplomacy-economy cluster:
  - `AllocateDiplomacyAidBudgetAcrossTargets`
  - `RevokeDiplomacyGrantForTargetAndAdjustInfluence`
  - `SetDiplomacyGrantEntryForTargetAndUpdateTreasury`
- Confirmed direct treasury-impact write in revoke path:
  - `RevokeDiplomacyGrantForTargetAndAdjustInfluence` subtracts revoked grant amount from `this+0xAC` and updates relation/notification state.
- Mapped adjacent unknown cluster (`0x004dd140..0x004dd4e0`) as mostly diplomacy matrix/budget maintenance helpers.

## TODO (next game-logic pass, refreshed)
- [x] Bootstrap turn-economy/trade-money lane and identify first concrete treasury-writer cluster.
- [ ] Decode/rename `FUN_004dd140`, `FUN_004dd1b0`, `FUN_004dd270`, `FUN_004dd430` (diplomacy budget/matrix helpers) with conservative semantics.
- [ ] Trace `SetDiplomacyGrantEntryForTargetAndUpdateTreasury` and `CanAffordDiplomacyGrantEntryForTarget` for full treasury delta flow (grant apply/revoke symmetry).
- [ ] Continue class/field naming pass for `SecondaryNationState` and `FrogCityMarker` now that constructor/vtable anchors are in place.

## Continuation (2026-02-18, game-logic pass: diplomacy aid matrix + resource-need vtable cluster)

### Renames applied (saved)
#### Aid-allocation matrix helpers
- `FUN_004dd140` -> `RecomputeDiplomacyAidBudgetScoreFromResourceWeights`
- `FUN_004dd1b0` -> `ResetDiplomacyNeedScoresAndClearAidAllocationMatrix`
- `FUN_004dd270` -> `RefreshDiplomacyNeedScoresAndClearAidAllocationMatrix`
- `FUN_004dd310` -> `ReleaseDiplomacyTrackedObjectSlots850`
- `FUN_004dd3b0` -> `SumAidAllocationMatrixColumnForTarget`
- `FUN_004dd3f0` -> `SumAidAllocationMatrixAllCells`
- `FUN_004dd430` -> `ComputeRemainingDiplomacyAidBudget`
- `FUN_00550e70` -> `GetResourceDescriptorWeightWord0ByType`

#### Thunks for above
- `0x0040790f` -> `thunk_RecomputeDiplomacyAidBudgetScoreFromResourceWeights`
- `0x004048f4` -> `thunk_ResetDiplomacyNeedScoresAndClearAidAllocationMatrix`
- `0x00408134` -> `thunk_RefreshDiplomacyNeedScoresAndClearAidAllocationMatrix`
- `0x00404ccd` -> `thunk_ReleaseDiplomacyTrackedObjectSlots850`
- `0x00401d1b` -> `thunk_SumAidAllocationMatrixColumnForTarget`
- `0x00402c3e` -> `thunk_SumAidAllocationMatrixAllCells`
- `0x0040186b` -> `thunk_ComputeRemainingDiplomacyAidBudget`

#### Resource-need target/current vtable family
- `FUN_004dcd10` -> `ApplyNationResourceNeedTargetsToOrderState`
- `FUN_004dce10` -> `SetNationResourceNeedCurrentByType`
- `FUN_004dce40` -> `IsNationResourceNeedCurrentAtTargetByType`
- `FUN_004dce70` -> `GetNationResourceNeedTargetByType`
- `FUN_004dce90` -> `TryIncrementNationResourceNeedTargetTowardCurrent`
- `FUN_004dcf10` -> `IsNationResourceNeedCurrentSumExceedingCapA6`

#### Thunks for resource-need family
- `0x004031bb` -> `thunk_ApplyNationResourceNeedTargetsToOrderState`
- `0x004091e2` -> `thunk_SetNationResourceNeedCurrentByType`
- `0x00408616` -> `thunk_IsNationResourceNeedCurrentAtTargetByType`
- `0x004066c2` -> `thunk_GetNationResourceNeedTargetByType`
- `0x004091fb` -> `thunk_TryIncrementNationResourceNeedTargetTowardCurrent`
- `0x00407a45` -> `thunk_IsNationResourceNeedCurrentSumExceedingCapA6`

#### Variant overrides / dispatch wrappers
- `FUN_004e7810` -> `RecomputeDiplomacyAidBudgetAndResetNeedScoresAndMatrix`
- `0x00407824` -> `thunk_RecomputeDiplomacyAidBudgetAndResetNeedScoresAndMatrix`
- `FUN_004ea470` -> `RebuildNationResourceYieldsAndRollField134Into136`
- `0x0040121c` -> `thunk_RebuildNationResourceYieldsAndRollField134Into136`
- `FUN_004e78d0` -> `DispatchNationField98CallbackD4`
- `0x00404417` -> `thunk_DispatchNationField98CallbackD4`
- `FUN_004e78f0` -> `DispatchNationField9CCallback4C`
- `0x00402ccf` -> `thunk_DispatchNationField9CCallback4C`
- `FUN_004e7990` -> `DispatchNationField94Callbacks90And94`
- `0x00402126` -> `thunk_DispatchNationField94Callbacks90And94`

### Comments added
- Plate/function comments added to key helpers:
  - `RecomputeDiplomacyAidBudgetScoreFromResourceWeights`
  - `ResetDiplomacyNeedScoresAndClearAidAllocationMatrix`
  - `RefreshDiplomacyNeedScoresAndClearAidAllocationMatrix`
  - `SumAidAllocationMatrixColumnForTarget`
  - `SumAidAllocationMatrixAllCells`
  - `ComputeRemainingDiplomacyAidBudget`
  - `GetResourceDescriptorWeightWord0ByType`
  - `ApplyNationResourceNeedTargetsToOrderState`
  - `SetNationResourceNeedCurrentByType`
  - `IsNationResourceNeedCurrentAtTargetByType`
  - `GetNationResourceNeedTargetByType`
  - `TryIncrementNationResourceNeedTargetTowardCurrent`
  - `IsNationResourceNeedCurrentSumExceedingCapA6`
  - `RecomputeDiplomacyAidBudgetAndResetNeedScoresAndMatrix`
  - `RebuildNationResourceYieldsAndRollField134Into136`

## TODO (next game-logic pass, refreshed)
- [x] Decode/rename aid-allocation matrix helper cluster around `0x004dd140..0x004dd430`.
- [x] Decode/rename resource-need target/current vtable family around `0x004dcd10..0x004dcf10`.
- [ ] Decode `FUN_004dd340` argument semantics and replace with domain name (currently left untouched due ambiguous arg roles).
- [ ] Decode and rename `FUN_004dd470` / `FUN_004dd4e0` (diplomacy fallback assignment / callback-heavy path).
- [ ] Promote function signatures for clearly boolean helpers (`CanAffordDiplomacyGrantEntryForTarget`, `CanAffordAdditionalDiplomacyCostAfterCommitments`) and key vtable methods where arg roles are now known.

## Continuation (2026-02-18, game-logic pass: resolved remaining ambiguous diplomacy matrix/slot helpers)

### Additional renames applied (saved)
- `FUN_004dd340` -> `AddAmountToAidAllocationMatrixCellAndTotal`
- `0x004028f1` -> `thunk_AddAmountToAidAllocationMatrixCellAndTotal`
- `FUN_004dd470` -> `ResetDiplomacyNeedSlots7012AndRefreshIfModeGateMatches`
- `0x00408017` -> `thunk_ResetDiplomacyNeedSlots7012AndRefreshIfModeGateMatches`
- `FUN_004dd4e0` -> `AssignFallbackNationsToUnfilledDiplomacyNeedSlots`
- `0x00408607` -> `thunk_AssignFallbackNationsToUnfilledDiplomacyNeedSlots`

### Why `FUN_004dd340` rename is now safe
- Confirmed from disassembly (not only decomp):
  - accepts 3 args after `this`,
  - computes `index = row * 23 + col`,
  - adds `amount` to matrix cell and to running total `+0x914`,
  - calls `this->vtable+0x38(amount)` before accumulation.

### Comments added
- Plate/function comments added on:
  - `AddAmountToAidAllocationMatrixCellAndTotal`
  - `ResetDiplomacyNeedSlots7012AndRefreshIfModeGateMatches`
  - `AssignFallbackNationsToUnfilledDiplomacyNeedSlots`

## TODO (next game-logic pass, refreshed)
- [x] Decode `FUN_004dd340` and rename with matrix-stride semantics.
- [x] Decode/rename `FUN_004dd470` and `FUN_004dd4e0` with conservative behavior-based names.
- [ ] Promote function signatures for clearly boolean helpers (`CanAffordDiplomacyGrantEntryForTarget`, `CanAffordAdditionalDiplomacyCostAfterCommitments`) and matrix helpers with now-known argument roles.
- [ ] Continue treasury lane: decode helper `thunk_FUN_005033e0` target and surrounding grant UI/event dispatch side effects.

## Continuation (2026-02-18, game-logic pass: treasury helper + signature cleanup)

### Additional renames applied (saved)
- `FUN_005033e0` -> `NoOpDiplomacyPolicyStateChangedHook`
- `0x00403e2c` -> `thunk_NoOpDiplomacyPolicyStateChangedHook`

### Signature updates applied (saved)
- `CanAffordDiplomacyGrantEntryForTarget`
  - now: `bool __thiscall CanAffordDiplomacyGrantEntryForTarget(void * this, short targetNationId, ushort proposedGrantEntry)`
- `CanAffordAdditionalDiplomacyCostAfterCommitments`
  - now: `bool __thiscall CanAffordAdditionalDiplomacyCostAfterCommitments(void * this, short additionalCost)`
- `AddAmountToAidAllocationMatrixCellAndTotal`
  - now: `void __thiscall AddAmountToAidAllocationMatrixCellAndTotal(void * this, int amount, short columnIndex, short rowIndex)`
- `SumAidAllocationMatrixColumnForTarget`
  - now: `int __thiscall SumAidAllocationMatrixColumnForTarget(void * this, short targetNationId)`
- `SumAidAllocationMatrixAllCells`
  - now: `int __thiscall SumAidAllocationMatrixAllCells(void * this)`
- `ComputeRemainingDiplomacyAidBudget`
  - now: `int __thiscall ComputeRemainingDiplomacyAidBudget(void * this)`

### Notes
- `NoOpDiplomacyPolicyStateChangedHook` is an intentional no-op in this build, but is still called by:
  - `SetDiplomacyGrantEntryForTargetAndUpdateTreasury`
  - `SetDiplomacyTradePolicyValueForTargetAndMaybeClearGrant`
  - `ApplyDiplomacyPolicyStateForTargetWithCostChecks`

## TODO (next game-logic pass, refreshed)
- [x] Apply first concrete function signature upgrades where argument/return semantics are clear.
- [ ] Continue signature cleanup for renamed aid/need helpers (`RecomputeDiplomacyAidBudgetScoreFromResourceWeights`, `Reset/RefreshDiplomacyNeedScores...`) once parameter roles are fully confirmed.
- [ ] Decode `DispatchNationField98CallbackD4` / `DispatchNationField9CCallback4C` deeper (identify concrete callee class/slot semantics).
- [ ] Continue treasury lane by tracing remaining direct writers/consumers of field `+0xAC` and grant-entry array `+0xE0`.

## Continuation (2026-02-18, game-logic pass: treasury/+0xAC writer trace follow-up)

### Additional rename applied (saved)
- `FUN_0054b5d0` -> `EmitNationDiplomacyNeedStateSnapshotEvent15`
- `0x00407cbb` -> `thunk_EmitNationDiplomacyNeedStateSnapshotEvent15`

### Why this one is low-risk
- Function clearly packages nation diplomacy-need state into a large payload and dispatches via common event path (`thunk_FUN_005e3d40`) with event code `0x15`.
- Payload includes `+0xAC` aggregate and major related arrays (`+0x13c`, `+0x280`, etc.), so event name stays explicit and conservative.

## TODO (next game-logic pass, refreshed)
- [x] Trace and rename at least one additional `+0xAC`-related emitter/helper outside the immediate `0x004dd***` cluster.
- [ ] Decode large state-machine handler `Cluster_StateMachine18_4C_00545940` enough to replace cluster placeholder with behavior name.
- [ ] Decode `FUN_0054bd20` (large copy/transform path touching `+0xAC`) and map relation to event `0x15` snapshot flow.
- [ ] Continue signature cleanup on renamed helpers where parameter roles are now stable.

## Continuation (2026-02-18, game-logic pass: nation-status dialog and replacement chain)

### Renames applied (saved)
- `FUN_0054cc00` -> `RefreshNationStatusLabelsAndCodesForSlotOrAll`
- `0x00409859` -> `thunk_RefreshNationStatusLabelsAndCodesForSlotOrAll`
- `FUN_0054bd20` -> `ReplaceNationStateForSlotAndRefreshStatus`
- `0x0040510f` -> `thunk_ReplaceNationStateForSlotAndRefreshStatus`
- `FUN_00540cb0` -> `HandleNationLostEventAndReplaceNationStateForSlot`
- `0x00404354` -> `thunk_HandleNationLostEventAndReplaceNationStateForSlot`
- `FUN_0054dfc0` -> `TryInvokeNationStateReplacementForSlot`
- `0x004067f8` -> `thunk_TryInvokeNationStateReplacementForSlot`

### Additional cluster renames (saved)
- `FUN_0054a340` -> `DispatchTaggedGameStateEvent1F20`
- `0x00406efb` -> `thunk_DispatchTaggedGameStateEvent1F20`
- `FUN_0054a410` -> `DispatchTextPairEvent8FromContext`
- `0x004062da` -> `thunk_DispatchTextPairEvent8FromContext`
- `FUN_0054a9d0` -> `IsSpecialNationDialogModeActive`
- `0x00408481` -> `thunk_IsSpecialNationDialogModeActive`
- `FUN_0054b0f0` -> `DispatchSimpleTurnEventEsopWithParam`
- `0x00403dff` -> `thunk_DispatchSimpleTurnEventEsopWithParam`
- `FUN_0054d730` -> `OpenNationStatusDialogAndInitializeRows`
- `0x00402cfc` -> `thunk_OpenNationStatusDialogAndInitializeRows`
- `FUN_0054db40` -> `RefreshNationStatusDialogRowsAndSummaryMessage`
- `0x00404fca` -> `thunk_RefreshNationStatusDialogRowsAndSummaryMessage`
- `FUN_0054e1f0` -> `HandleNationStatusDialogCommand`
- `0x00402324` -> `thunk_HandleNationStatusDialogCommand`

### Signature updates applied (saved)
- `ReplaceNationStateForSlotAndRefreshStatus`
  - `void __thiscall ReplaceNationStateForSlotAndRefreshStatus(void * this, int slotNationId)`
- `RefreshNationStatusLabelsAndCodesForSlotOrAll`
  - `void __thiscall RefreshNationStatusLabelsAndCodesForSlotOrAll(void * this, int slotNationId)`
- `OpenNationStatusDialogAndInitializeRows`
  - `void __thiscall OpenNationStatusDialogAndInitializeRows(void * this, int dialogArg)`
- `RefreshNationStatusDialogRowsAndSummaryMessage`
  - `int __thiscall RefreshNationStatusDialogRowsAndSummaryMessage(void * this)`
- `HandleNationStatusDialogCommand`
  - `void __thiscall HandleNationStatusDialogCommand(void * this, int commandId, pointer commandCtx, int commandArg)`
- `IsSpecialNationDialogModeActive`
  - `bool __thiscall IsSpecialNationDialogModeActive(void * this)`

## TODO (next game-logic pass, refreshed)
- [x] Decode and rename nation replacement chain around `0x0054bd20/0x0054dfc0/0x0054cc00`.
- [x] Rename/annotate nation-status dialog command cluster (`0x0054d730/0x0054db40/0x0054e1f0` plus tagged-event helpers).
- [x] Decode and rename `FUN_0054b8c0` (central status-code reader used in the same dialog flow).
- [ ] Decode `Cluster_StateMachine18_4C_00545940` enough to replace cluster placeholder with behavior name.
- [ ] Continue signature cleanup for remaining renamed helpers with stable arg roles.

## Continuation (2026-02-18, game-logic pass: status-code helpers + class-string low-hanging)

### Nation-status helper renames applied (saved)
- `FUN_0054b8c0` -> `GetNationStatusCodeForSlotOrActiveNation`
- `0x00403b6b` -> `thunk_GetNationStatusCodeForSlotOrActiveNation`
- `FUN_0054b7e0` -> `SetNationStatusCodeForSlotOrActiveAndEmitEvent25`
- `FUN_0054b930` -> `SetNationStatusAwolByNationIdAndDispatchNotices`
- `0x004078c4` -> `thunk_SetNationStatusAwolByNationIdAndDispatchNotices`
- `FUN_0054bce0` -> `InitializeNationStatusEvent25PayloadDefaults`
- `0x00407fc7` -> `thunk_InitializeNationStatusEvent25PayloadDefaults`

### Event packet / class-string backed low-hanging renames (saved)
- `FUN_0054b040` -> `DestructPoseMessageDialogTurnEventPacket`
- `FUN_0054b010` -> `DeletingDestructPoseMessageDialogTurnEventPacket`
- `FUN_0054b060` -> `AllocateAndConstructPoseMessageDialogTurnEventPacket`
- `FUN_0054b0d0` -> `GetPoseMessageDialogPacketTypeName`
- `FUN_0054b4c0` -> `DispatchTurnEventCode9WithTwoTextTokens`
- `FUN_0054b5b0` -> `DispatchTurnEventCode32NoPayload`
- `0x004022c0` -> `thunk_DestructPoseMessageDialogTurnEventPacket`
- `0x00402117` -> `thunk_DispatchTurnEventCode9WithTwoTextTokens`
- `0x004039b3` -> `thunk_DispatchTurnEventCode32NoPayload`
- `FUN_0054d650` -> `AllocateAndConstructTLoungeDialog`
- `FUN_0054d6d0` -> `GetTLoungeDialogTypeName`
- `FUN_0054d6f0` -> `CloseTLoungeDialogAndReleaseChildren`
- `FUN_0054e690` -> `AllocateAndConstructTJoinSelectorDialog`
- `FUN_0054e710` -> `GetTJoinSelectorDialogTypeName`
- `FUN_0054e9a0` -> `HandleTJoinSelectorDialogCommand`
- `FUN_0054ea30` -> `AllocateAndConstructTMadnessButton`
- `FUN_0054ead0` -> `GetTMadnessButtonTypeName`
- `FUN_0054eaf0` -> `InitializeTMadnessButtonFromCurrentBitmapAndEnable`
- `FUN_0054ec20` -> `AllocateAndConstructTMultiMessagePicture`
- `FUN_0054eca0` -> `GetTMultiMessagePictureTypeName`
- `FUN_0054ecc0` -> `HandleTMultiMessagePictureCommand`
- `FUN_0054b1b0` -> `RefreshPoseMessageDialogNationSelectionControls`
- `0x00407eeb` -> `thunk_RefreshPoseMessageDialogNationSelectionControls`
- `FUN_0054aff0` -> `InvokePoseMessageDialogRefreshFromContextField18`

### State-machine rename cleanup (saved)
- `Cluster_StateMachine18_4C_00545940` (`0x00545940`) -> `ProcessDiplomacyTurnStateEventStateMachine`
- `0x00405ffb` -> `thunk_ProcessDiplomacyTurnStateEventStateMachine`
- Added function comment on `ProcessDiplomacyTurnStateEventStateMachine` documenting it as the large switch-driven diplomacy turn-state dispatcher.

### Notes
- Status helper naming is backed by direct writes to status array `this+0xBC` and event dispatch payload containing code `0x25`.
- `SetNationStatusAwolByNationIdAndDispatchNotices` marks matching slot status to `0x61776f6c` (`'awol'`) and updates elimination bitmask `+0xE8`.
- Resolved prior ambiguity around the `+0xD8` mode tag writer:
  - `FUN_0054c630` -> `SetDialogModeTagInitAndInvokeNoOpHook`
  - `0x00407ff9` -> `thunk_SetDialogModeTagInitAndInvokeNoOpHook`
  - `FUN_005e42a0` -> `NoOpDialogModeTagChangedHook`
  - `0x00407f77` -> `thunk_NoOpDialogModeTagChangedHook`

## TODO (next game-logic pass, refreshed)
- [x] Decode and rename `FUN_0054b8c0` (central status-code reader used in nation-status dialog flow).
- [x] Decode/rename adjacent status event helpers (`0x0054b7e0`, `0x0054b930`, `0x0054bce0`).
- [x] Decode large `FUN_0054b1b0` behavior and replace with concrete non-UI/game-flow name.
- [x] Decode and rename `FUN_0054c630` (`+0xD8='init'` mode-tag writer + global side-effect call).
- [x] Decode `Cluster_StateMachine18_4C_00545940` enough to replace cluster placeholder with behavior name.

## Continuation (2026-02-18, game-logic pass: diplomacy queue routing + event helpers)

### Additional renames applied (saved)
- `FUN_005438e0` -> `InitializeEmitEventHeaderWithActiveNation`
- `0x00402a45` -> `thunk_InitializeEmitEventHeaderWithActiveNation`
- `FUN_005446a0` -> `EmitTurnEvent3Mode18WithActiveNation`
- `0x00403b5c` -> `thunk_EmitTurnEvent3Mode18WithActiveNation`
- `FUN_00544720` -> `EmitTurnEvent10ForFlaggedNationSlots`
- `0x00405d0d` -> `thunk_EmitTurnEvent10ForFlaggedNationSlots`
- `FUN_005454b0` -> `ResetNationStatusSlotsAndInitializeNameControls`
- `0x00403378` -> `thunk_ResetNationStatusSlotsAndInitializeNameControls`
- `FUN_005456a0` -> `ResetDialogContextField40AndEmitTurnEvent3Mode18`
- `0x00402bfd` -> `thunk_ResetDialogContextField40AndEmitTurnEvent3Mode18`
- `FUN_00545730` -> `RouteAndProcessDiplomacyTurnStateEventQueue`
- `0x00409160` -> `thunk_RouteAndProcessDiplomacyTurnStateEventQueue`

### Why these are low-risk
- All six core functions are small-to-mid wrappers with direct, observable behavior in decomp:
  - fixed event codes (`3`, `0x10`, `0x18`),
  - explicit active-nation header writes (`0x74696d65` tag + nation byte),
  - straightforward queue drain/defer logic in `RouteAndProcessDiplomacyTurnStateEventQueue` using event-code filters.
- Names stay behavior-first and avoid guessing UI wording or hidden design intent.

## TODO (next game-logic pass, refreshed)
- [x] Rename queue-routing helper around diplomacy state machine dispatch (`0x00545730`) and immediate event-header wrappers.
- [ ] Decode and rename large initializer `FUN_00542be0` (status bootstrap + startup dispatch cluster) with conservative semantics.
- [ ] Continue non-UI diplomacy/turn-state naming around remaining high-impact generic helpers in `0x00542xxx..0x00545xxx` (start with `FUN_00543910` only if split into manageable sub-behaviors).

## Continuation (2026-02-18, game-logic pass: diplomacy startup/bootstrap handlers)

### Additional renames/materialization (saved)
- Created missing thunk function at `0x00408ad5` (previously raw JMP island).
- `FUN_00542be0` -> `InitializeNationStatusSlotsFromNationListAndEmitStartupEvents`
- `0x00408ad5` -> `thunk_InitializeNationStatusSlotsFromNationListAndEmitStartupEvents`
- `FUN_00543910` -> `HandleDiplomacyTurnEventPacketByCode`
- `0x00401d7f` -> `thunk_HandleDiplomacyTurnEventPacketByCode`

### Why these are low-risk
- `InitializeNationStatusSlotsFromNationListAndEmitStartupEvents` directly:
  - initializes per-nation status arrays from availability/eligibility checks,
  - applies callback-provider updates over per-slot data,
  - emits startup event packets (`0x1f`/`0x25` paths, including active-slot busy status snapshot).
- `HandleDiplomacyTurnEventPacketByCode` is a large but explicit switch on packet code (`param_1[0x3c]`) that orchestrates follow-up dispatches and map/nation update payloads; name intentionally remains behavior-level rather than per-case semantic guesses.

## TODO (next game-logic pass, refreshed)
- [x] Decode and rename large initializer `FUN_00542be0` (status bootstrap + startup dispatch cluster) with conservative semantics.
- [x] Continue non-UI diplomacy/turn-state naming around high-impact generic helper `FUN_00543910`.
- [ ] Continue on remaining generic non-UI helpers in this lane (`0x005420a0`, `0x005420d0`, `0x005421a0`, `0x00542ff0`, `0x005430c0`) and promote names only with direct behavioral evidence.

## Continuation (2026-02-18, game-logic pass: diplomacy payload/queue helper quintet)

### Additional renames applied (saved)
- `FUN_005420a0` -> `SetEventPayloadNationIdFromSlotIndex`
- `0x00401bfe` -> `thunk_SetEventPayloadNationIdFromSlotIndex`
- `FUN_005420d0` -> `SetEventPayloadNationIdFromSlotIndexWithSentinelHandling`
- `0x004098f9` -> `thunk_SetEventPayloadNationIdFromSlotIndexWithSentinelHandling`
- `FUN_005421a0` -> `FindActiveNationSlotIndexInGameFlowList`
- `0x004015af` -> `thunk_FindActiveNationSlotIndexInGameFlowList`
- `FUN_00542ff0` -> `InitializeNationStatusControlArraysFromProvider`
- `FUN_005430c0` -> `EnableDiplomacyQueueRoutingAndSetContextField44`
- `0x00401776` -> `thunk_EnableDiplomacyQueueRoutingAndSetContextField44`

### Why these are low-risk
- Direct field writes and branch logic are explicit:
  - payload nation-id mapping from game-flow slot table (`+0x48`),
  - special handling for sentinel slot inputs (`-3/-2/-1`) in one helper,
  - deterministic routing-flag writes (`+0x68/+0x69`) and context store (`+0x44`) in queue setup helper.
- No UI-wording assumptions were added; names remain dataflow/behavior oriented.

## TODO (next game-logic pass, refreshed)
- [x] Continue on remaining generic non-UI helpers in this lane (`0x005420a0`, `0x005420d0`, `0x005421a0`, `0x00542ff0`, `0x005430c0`) and promote names only with direct behavioral evidence.
- [ ] Continue with next non-UI helpers in same corridor (`0x00542560`, `0x00542670`, `0x00542810`, `0x00542900`) and keep names behavior-based.
- [ ] Revisit large `HandleDiplomacyTurnEventPacketByCode` for case-level helper extraction only (no speculative monolithic renames).

## Continuation (2026-02-18, game-logic pass: multiplayer manager class extraction low-hanging)

### Additional renames applied (saved)
- `FUN_00542590` -> `DestructCancelGameOptionsCommand`
- `0x00403549` -> `thunk_DestructCancelGameOptionsCommand`
- `FUN_00542560` -> `DeletingDestructCancelGameOptionsCommand`
- `FUN_005425b0` -> `GetCancelGameOptionsCommandTypeName`
- `FUN_00542650` -> `GetMultiplayerManagerTypeName`
- `FUN_00542670` -> `ConstructMultiplayerManager`
- `FUN_00542810` -> `DestructMultiplayerManager`
- `0x00403ea4` -> `thunk_DestructMultiplayerManager`
- `FUN_005427e0` -> `DeletingDestructMultiplayerManager`
- `FUN_00542900` -> `InitializeMultiplayerManagerForSessionContext`
- `FUN_005427a0` -> `InitializePointerPairToNull`
- `FUN_005427c0` -> `FreePointerIfNotNull`

### Notes
- This pass is still non-UI game logic (session/runtime manager setup and object lifecycle), adjacent to diplomacy packet routing helpers in the same corridor.
- Class-string anchors (`TCancelGameOptionsCommand`, `TMultiplayerMgr`) make ctor/dtor/type-name naming high confidence.

## TODO (next game-logic pass, refreshed)
- [x] Continue with next non-UI helpers in same corridor (`0x00542560`, `0x00542670`, `0x00542810`, `0x00542900`) and keep names behavior-based.
- [ ] Return to diplomacy-specific logic: extract case-level helpers from `HandleDiplomacyTurnEventPacketByCode` (`0x00543910`) for top event-code branches (`2`, `5`) where behavior is already explicit.
- [ ] Continue non-UI callback/vtable cleanup around diplomacy manager globals (`DAT_006a6014` method slots `+0x14/+0x18`) with behavior-backed names only.

## Continuation (2026-02-18, game-logic pass: diplomacy packet support + queue manager cleanup)

### Additional renames applied (saved)
- `FUN_004d7930` -> `AssignSharedStringFromDescriptorNameOrDefault`
- `0x004072f2` -> `thunk_AssignSharedStringFromDescriptorNameOrDefault`
- `FUN_005449b0` -> `BuildTurnEvent2ArraySyncPacketDeltaOrFull`
- `0x00405489` -> `thunk_BuildTurnEvent2ArraySyncPacketDeltaOrFull`
- `FUN_004f2760` -> `BuildTurnEvent2ArraySyncPacketFromBufferAndRefreshBaselineCopy`
- `0x00404057` -> `thunk_BuildTurnEvent2ArraySyncPacketFromBufferAndRefreshBaselineCopy`
- `FUN_0050ec60` -> `InitializeSharedStringRefAndReturnThis`
- `0x00401c67` -> `thunk_InitializeSharedStringRefAndReturnThis`
- `FUN_00515ec0` -> `AssignSharedStringFromIndexedA8EntryNameField`
- `0x0040918d` -> `thunk_AssignSharedStringFromIndexedA8EntryNameField`
- `FUN_0054ae90` -> `CopyA8RecordWithSharedStringAtA4`
- `0x00405fba` -> `thunk_CopyA8RecordWithSharedStringAtA4`
- `FUN_0054d1f0` -> `EmitTurnEvent19NationStateArraysForSlot`
- `0x00406cf3` -> `thunk_EmitTurnEvent19NationStateArraysForSlot`
- `FUN_0054ce80` -> `EmitTurnEvent2CNationStateCompositeForSlot`
- `0x0040235b` -> `thunk_EmitTurnEvent2CNationStateCompositeForSlot`

### Global queue-manager cleanup (saved)
- `FUN_005e33e0` -> `ConstructGlobalTurnEventQueueManager`
- `0x00402b71` -> `thunk_ConstructGlobalTurnEventQueueManager`
- `FUN_005e3450` -> `NoOpInitializeGlobalTurnEventQueueManager`
- `0x00405bc8` -> `thunk_NoOpInitializeGlobalTurnEventQueueManager`
- `FUN_005e3490` -> `DefaultUnhandledTurnEventHookReturnsFalse`
- `0x00404b79` -> `thunk_DefaultUnhandledTurnEventHookReturnsFalse`
- `FUN_005e3ef0` -> `ResetTurnEventQueueRuntimeRecordBuffer`
- `0x00401163` -> `thunk_ResetTurnEventQueueRuntimeRecordBuffer`
- `FUN_005e3f10` -> `FreeTurnEventPacketBuffer`
- `0x004049c6` -> `thunk_FreeTurnEventPacketBuffer`
- `FUN_005e3f30` -> `PopNextTurnEventPacketOrProcessSpecialQueueRecords`
- `0x00403305` -> `thunk_PopNextTurnEventPacketOrProcessSpecialQueueRecords`

### Notes
- `BuildTurnEvent2ArraySyncPacketDeltaOrFull` now captures explicit packet-shape behavior: delta encoding when change density is low, otherwise full-array payload copy.
- `EmitTurnEvent19NationStateArraysForSlot` and `EmitTurnEvent2CNationStateCompositeForSlot` intentionally keep event-code-centric names to avoid over-claiming domain semantics while still removing generic labels.
- Queue-manager rename pass resolves the previously generic `DAT_006a6014` support lane and clarifies why routing code repeatedly calls `PopNextTurnEventPacketOrProcessSpecialQueueRecords`.

## TODO (next game-logic pass, refreshed)
- [x] Continue non-UI callback/vtable cleanup around diplomacy manager globals (`DAT_006a6014` method slots `+0x14/+0x18`) with behavior-backed names only.
- [ ] Return to diplomacy-specific logic: extract case-level helpers from `HandleDiplomacyTurnEventPacketByCode` (`0x00543910`) for top event-code branches (`2`, `5`) where behavior is already explicit.
- [ ] Optional cleanup: inspect `thunk_FUN_004808a0` and `thunk_FUN_005e34f0` used by `PopNextTurnEventPacketOrProcessSpecialQueueRecords` to replace remaining generic transport/error-path names.

## Continuation (2026-02-18, game-logic pass: network transport/error helpers from queue path)

### Additional renames applied (saved)
- `FUN_004808a0` -> `TryReceiveNetworkPacketIntoResizableBuffer`
- `0x004055ab` -> `thunk_TryReceiveNetworkPacketIntoResizableBuffer`
- `FUN_005e34f0` -> `ReportWNetManagerErrorCodeAndNotifyUi`
- `0x00406609` -> `thunk_ReportWNetManagerErrorCodeAndNotifyUi`

### Notes
- `TryReceiveNetworkPacketIntoResizableBuffer` is the low-level receive loop used by queue pop logic; it repeatedly calls network manager vfunc `+0x64` and grows output buffer via `GlobalAlloc/GlobalReAlloc` until terminal status/packet.
- `ReportWNetManagerErrorCodeAndNotifyUi` is the associated status-to-message/error reporting path (`WNetMgr` code mapping, shared-string assignment, UI/log notification).

## TODO (next game-logic pass, refreshed)
- [x] Optional cleanup: inspect `thunk_FUN_004808a0` and `thunk_FUN_005e34f0` used by `PopNextTurnEventPacketOrProcessSpecialQueueRecords` to replace remaining generic transport/error-path names.
- [ ] Return to diplomacy-specific logic: extract case-level helpers from `HandleDiplomacyTurnEventPacketByCode` (`0x00543910`) for top event-code branches (`2`, `5`) where behavior is already explicit.
- [ ] Continue game-logic only: avoid deep UI naming unless directly required by packet/state transitions.

## Continuation (2026-02-18, game-logic pass: turn-event send/probe primitives)

### Additional renames applied (saved)
- `FUN_005e3d40` -> `EnqueueOrSendTurnEventPacketToNation`
- `0x00405a5b` -> `thunk_EnqueueOrSendTurnEventPacketToNation`
- `FUN_005e43e0` -> `ProbeNationReachabilityAndMarkAwolBitmask`
- `0x00403724` -> `thunk_ProbeNationReachabilityAndMarkAwolBitmask`
- `FUN_00480850` -> `TrySendNetworkPacketViaManagerContext`
- `0x0040683e` -> `thunk_TrySendNetworkPacketViaManagerContext`

### Notes
- This closes the last two generic dependencies in `HandleDiplomacyTurnEventPacketByCode` callgraph.
- `EnqueueOrSendTurnEventPacketToNation` now documents the defer-vs-send split and error path (`ReportWNetManagerErrorCodeAndNotifyUi`).
- `ProbeNationReachabilityAndMarkAwolBitmask` captures the `0x2B` probe loop and awol-marking fallback behavior on send failure.

## TODO (next game-logic pass, refreshed)
- [x] Return to diplomacy-specific logic: extract case-level helpers from `HandleDiplomacyTurnEventPacketByCode` (`0x00543910`) for top event-code branches (`2`, `5`) where behavior is already explicit.
- [ ] Continue game-logic only: avoid deep UI naming unless directly required by packet/state transitions.
- [ ] Optional: split large `HandleDiplomacyTurnEventPacketByCode` cases into named helper functions (logical extraction/comments only) for readability without speculative semantics.

## Continuation (2026-02-18, game-logic pass: diplomacy matrix/session emitters)

### Additional renames applied (saved)
- `FUN_0054c800` -> `HandleActiveNationAwolTransitionOrRecovery`
- `0x00405c45` -> `thunk_HandleActiveNationAwolTransitionOrRecovery`
- `FUN_0054c480` -> `EmitTurnEvent26DiplomacyMatrixSnapshot`
- `0x004033af` -> `thunk_EmitTurnEvent26DiplomacyMatrixSnapshot`
- `FUN_0054c8e0` -> `EmitTurnEventEAnd9SessionContextPackets`
- `0x00407e82` -> `thunk_EmitTurnEventEAnd9SessionContextPackets`
- `FUN_0054c6e0` -> `ResetNationStatusArraysAndTurnEventContext`
- `0x0040175d` -> `thunk_ResetNationStatusArraysAndTurnEventContext`

### Notes
- This pass remains in non-UI game logic: state-transition and packet emission routines in the diplomacy turn-event lane.
- Event-code-oriented names (`0x26`, `0xE`, `9`) are used intentionally where payload semantics are clear but narrative/domain labels remain uncertain.

## TODO (next game-logic pass, refreshed)
- [ ] Continue game-logic only: avoid deep UI naming unless directly required by packet/state transitions.
- [ ] Optional: split large `HandleDiplomacyTurnEventPacketByCode` cases into named helper functions (logical extraction/comments only) for readability without speculative semantics.
- [ ] Continue in same lane with remaining ambiguous connectivity helpers (`thunk_FUN_005e42f0`, `thunk_FUN_0049e500`, `FUN_0054cde0`) only if behavior can be proven from callers.

## Continuation (2026-02-18, game-logic pass: connectivity + packet-tag helper cleanup)

### Additional renames applied (saved)
- `FUN_005e42f0` -> `CheckConnectivityOrShowLocalizedWarningAndReturnReady`
- `0x00405088` -> `thunk_CheckConnectivityOrShowLocalizedWarningAndReturnReady`
- `FUN_0049e500` -> `CreateAndQueueTurnEventPacketTagGWEN`
- `0x00407518` -> `thunk_CreateAndQueueTurnEventPacketTagGWEN`
- `FUN_0054cde0` -> `CreateAndQueueTurnEventPacketTagPOGC`
- `0x00407aa9` -> `thunk_CreateAndQueueTurnEventPacketTagPOGC`

### Notes
- Kept packet-tag names explicit (`GWEN`/`POGC`) rather than speculative narrative labels.
- Connectivity helper now captures exact control flow used by awol/recovery transition path: readiness check in localization mode 2, else localized warning dispatch.

## TODO (next game-logic pass, refreshed)
- [x] Continue in same lane with remaining ambiguous connectivity helpers (`thunk_FUN_005e42f0`, `thunk_FUN_0049e500`, `FUN_0054cde0`) only if behavior can be proven from callers.
- [ ] Continue game-logic only: avoid deep UI naming unless directly required by packet/state transitions.
- [ ] Optional: split large `HandleDiplomacyTurnEventPacketByCode` cases into named helper functions (logical extraction/comments only) for readability without speculative semantics.

## Continuation (2026-02-18, game-logic pass: great-power/minor class family callback cleanup)

### Additional renames applied (saved)
- Proxy family:
  - `FUN_00540900` -> `DispatchProxyGreatPowerCallbackSlot1CC`
  - `FUN_00540920` -> `ReturnFalseProxyGreatPowerCapabilityStub`
  - `FUN_00540940` -> `DeletingDestructTProxyGreatPower`
  - `FUN_00540970` -> `DestructTProxyGreatPower`
  - `FUN_005409e0` -> `GetTProxyGreatPowerTypeName`
  - `FUN_00540a00` -> `EmitTurnEvent14ForProxyGreatPowerAction`
- Host family:
  - `FUN_00540f40` -> `DeletingDestructTHostGreatPower`
  - `FUN_00540f70` -> `DestructTHostGreatPower`
  - `FUN_00540fe0` -> `GetTHostGreatPowerTypeName`
  - `FUN_00541170` -> `HandleHostGreatPowerLostStateAndNotifyOrEndSession`
- Client family:
  - `FUN_005412f0` -> `DeletingDestructTClientGreatPower`
  - `FUN_00541320` -> `DestructTClientGreatPower`
  - `FUN_00541390` -> `GetTClientGreatPowerTypeName`
  - `FUN_005413b0` -> `EmitTurnEvent17ClientGreatPowerFlagEnabled`
  - `FUN_00541450` -> `EmitTurnEvent17ClientGreatPowerFlagDisabled`
  - `FUN_005415c0` -> `ApplyClientGreatPowerCommand61AndEmitTurnEvent1E`
  - `FUN_005416b0` -> `ApplyClientGreatPowerCommand69AndEmitTurnEvent1E`
  - `FUN_00541790` -> `DispatchLoseEventForClientGreatPowerSlot`
- Remote great-power family:
  - `FUN_00541860` -> `ReturnFalseRemoteGreatPowerCapabilityStub`
  - `FUN_005419e0` -> `DispatchRemoteGreatPowerCallbackSlot1CC`
  - `FUN_00541a80` -> `DeletingDestructTRemoteGreatPower`
  - `FUN_00541ab0` -> `DestructTRemoteGreatPower`
  - `FUN_00541b20` -> `GetTRemoteGreatPowerTypeName`
  - `FUN_00541be0` -> `RemoveRemoteGreatPowerNationSlotAndNotifyPeers`
- Remote minor family:
  - `FUN_00541c10` -> `AllocateAndConstructTRemoteMinor`
  - `FUN_00541c90` -> `ReturnTrueRemoteMinorCapabilityStub`
  - `FUN_00541cd0` -> `DeletingDestructTRemoteMinor`
  - `FUN_00541d00` -> `DestructTRemoteMinor`
  - `FUN_00541d70` -> `GetTRemoteMinorTypeName`

### Thunk/wrapper notes
- Existing destruct-wrapper thunks renamed:
  - `0x0040554c` -> `thunk_DestructTProxyGreatPower`
  - `0x004011ea` -> `thunk_DestructTHostGreatPower`
  - `0x00403ac1` -> `thunk_DestructTClientGreatPower`
  - `0x0040978c` -> `thunk_DestructTRemoteGreatPower`
  - `0x00406a64` -> `thunk_DestructTRemoteMinor`
- Several raw JMP islands in the `0x0040xxxx` thunk corridor could not be safely materialized as full functions in this pass; fallback user-defined labels were added instead (suffix `_island`) to preserve call-chain readability.

## TODO (next game-logic pass, refreshed)
- [ ] Continue game-logic only: avoid deep UI naming unless directly required by packet/state transitions.
- [ ] Optional: split large `HandleDiplomacyTurnEventPacketByCode` cases into named helper functions (logical extraction/comments only) for readability without speculative semantics.
- [ ] Revisit unresolved no-function JMP islands and materialize true thunk functions only if safe boundaries can be proven.

## Continuation (2026-02-18, game-logic pass: foreign-minister class extraction low-hanging)

### Runtime note
- `ghidra-mcp` endpoint (`127.0.0.1:8089`) was unavailable for this pass, so edits were applied directly via `pyghidra` transaction + `program.save(...)`.

### Additional renames applied (saved)
- Diplomat foreign-minister class core:
  - `FUN_00532760` -> `GetTDiplomatForeignMinisterTypeName`
  - `FUN_00532780` -> `ConstructTDiplomatForeignMinister`
  - `FUN_005327f0` -> `DeletingDestructTDiplomatForeignMinister`
  - `FUN_00532820` -> `DestructTDiplomatForeignMinister`
  - `0x0040680c` -> `thunk_ConstructTDiplomatForeignMinister`
  - `0x00401f37` -> `thunk_DestructTDiplomatForeignMinister`
- Textile foreign-minister class core:
  - `FUN_005330f0` -> `GetTTextileForeignMinisterTypeName`
  - `FUN_00533110` -> `ConstructTTextileForeignMinister`
  - `FUN_00533180` -> `DeletingDestructTTextileForeignMinister`
  - `FUN_005331b0` -> `DestructTTextileForeignMinister`
  - `FUN_005331d0` -> `InitializeTextileForeignMinisterOrderCandidates`
  - `0x00401177` -> `thunk_ConstructTTextileForeignMinister`
  - `0x00406aa0` -> `thunk_DestructTTextileForeignMinister`
- Trader foreign-minister class core:
  - `FUN_00533880` -> `GetTTraderForeignMinisterTypeName`
  - `FUN_005338a0` -> `ConstructTTraderForeignMinister`
  - `FUN_00533910` -> `DeletingDestructTTraderForeignMinister`
  - `FUN_00533940` -> `DestructTTraderForeignMinister`
  - `FUN_00533960` -> `InitializeTraderForeignMinisterOrderCandidates`
  - `0x00403d55` -> `thunk_ConstructTTraderForeignMinister`
  - `0x00407158` -> `thunk_DestructTTraderForeignMinister`
- Turn-event queue helper:
  - `FUN_005e34d0` -> `ResetRuntimeSelectionRecordBufferAndReturnTrue`
  - `0x0040968d` -> `thunk_ResetRuntimeSelectionRecordBufferAndReturnTrue`

### Why this pass is high-confidence
- Type-name getters return class-string anchors directly (`TDiplomatForeignMinister`, `TTextileForeignMinister`, `TTraderForeignMinister`).
- Constructors write distinct vtable roots (`0x00659f48`, `0x0065a008`, `0x0065a0c8`), and paired deleting-destructor wrappers match the standard `dtor + optional free` idiom.
- `Initialize*OrderCandidates` methods build temporary candidate arrays from nation-interaction selectors and cache selected values into object fields, so class-scoped names are behavior-backed without over-claiming detailed semantics.

## TODO (next game-logic pass, refreshed)
- [ ] Continue foreign-minister lane: rename remaining class methods in the same clusters (`0x00532520`, `0x005325e0`, `0x00532650`, `0x00532840`, `0x00533380`, `0x00533780`, `0x00533960` callers) with strictly behavior-backed names.
- [ ] Re-check unresolved `FUN_005c1580` only if tied directly to turn-flow/message dispatch; otherwise deprioritize as UI-resource setup.
- [ ] Return to diplomacy turn-event core (`HandleDiplomacyTurnEventPacketByCode`) for case-level helper naming where event semantics are explicit.

## Continuation (2026-02-18, game-logic pass: foreign-minister behavior methods + thunk materialization)

### Additional renames applied (saved)
- Diplomate-specific behavior methods:
  - `FUN_00532520` -> `QueueDiplomatTwoRandomAvailableTerrainActionsCode133`
  - `FUN_005325e0` -> `QueueDiplomatTwoCompatibleMatrixActionsCode5A`
  - `FUN_00532650` -> `UpdateDiplomatProgressFromProductionSlots2And4`
  - `FUN_00532840` -> `QueueDiplomatWeightedTerrainActionRunCode133`
  - `FUN_00533050` -> `IncrementDiplomatCounter5EByFive`
- Textile/trader behavior methods:
  - `FUN_00533780` -> `UpdateTextileProgressFromProductionSlots1And2`
  - `FUN_00533e90` -> `QueueTraderFourRandomTerrainActionsCode133`
  - `FUN_00533f50` -> `IncrementTraderCounter60ByThree`

### New thunk functions materialized + renamed
- Created and named thunk functions at previously non-function call islands:
  - `0x004032bf` -> `thunk_QueueDiplomatTwoRandomAvailableTerrainActionsCode133`
  - `0x00409345` -> `thunk_QueueDiplomatTwoCompatibleMatrixActionsCode5A`
  - `0x0040183e` -> `thunk_UpdateDiplomatProgressFromProductionSlots2And4`
  - `0x00403a3f` -> `thunk_QueueDiplomatWeightedTerrainActionRunCode133`
  - `0x0040671c` -> `thunk_IncrementDiplomatCounter5EByFive`
  - `0x00401230` -> `thunk_UpdateTextileProgressFromProductionSlots1And2`
  - `0x00405bb9` -> `thunk_QueueTraderFourRandomTerrainActionsCode133`
  - `0x004050ab` -> `thunk_IncrementTraderCounter60ByThree`

### Evidence notes
- Vtable-thunk tracing from class roots confirms class ownership:
  - Diplomat vtable `0x00659f48` routes slots to `0x00532840` and `0x00533050`.
  - Textile vtable `0x0065a008` routes slot `0x17` to `0x00533780`.
  - Trader vtable `0x0065a0c8` routes slots to `0x00533e90` and `0x00533f50`.
- Names intentionally keep explicit code tags (`Code133`, `Code5A`) where semantic labels are not yet fully decoded.

## TODO (next game-logic pass, refreshed)
- [ ] Continue foreign-minister lane around remaining ambiguous shared handlers (`FUN_0052fd80`, no-function target at `0x0052fda0`, and nearby slot-24/slot-25 thunks) and rename only with direct behavior evidence.
- [ ] Re-check unresolved `FUN_005c1580` only if tied directly to turn-flow/message dispatch; otherwise keep deprioritized as UI-resource setup.
- [ ] Return to diplomacy turn-event core (`HandleDiplomacyTurnEventPacketByCode`) for case-level helper naming where event semantics are explicit.

## Continuation (2026-02-18, game-logic pass: shared foreign-minister slot handlers)

### Additional renames applied (saved)
- Shared slot-22/slot-26 handlers:
  - `FUN_0052fd10` -> `RefreshForeignMinisterStateByLocalizationMode`
  - `0x004084b8` -> `thunk_RefreshForeignMinisterStateByLocalizationMode`
  - `FUN_0052fdc0` -> `UpdateNationInteractionEnableFlagsByTerrainAndRelation`
  - `0x00403918` -> `thunk_UpdateNationInteractionEnableFlagsByTerrainAndRelation`
- Shared slot-24/slot-25 no-op handlers:
  - `FUN_0052fd80` -> `NoOpForeignMinisterSlot24Handler`
  - `0x004017df` -> `thunk_NoOpForeignMinisterSlot24Handler`
  - `FUN_0052fda0` -> `NoOpForeignMinisterSlot25Handler` (new function materialized)
  - `0x004049a3` -> `thunk_NoOpForeignMinisterSlot25Handler` (new function materialized)

### Function materialization notes
- Materialized additional missing thunk/no-op islands in this pass:
  - `0x004084b8`, `0x00403918`, `0x004017df`, `0x004049a3`
  - `0x0052fda0` (single-instruction `RET` no-op handler)

### Evidence notes
- `RefreshForeignMinisterStateByLocalizationMode` checks localization mode (`1`/`2`) and then runs a fixed sequence of state-refresh vtable calls.
- `UpdateNationInteractionEnableFlagsByTerrainAndRelation` computes a terrain-availability condition and applies per-nation interaction enable flags gated by diplomacy relation threshold (`< 0x96`).
- Slot-24 and slot-25 handlers are explicit no-op bodies (`RET`) reached via vtable thunks in textile/trader lanes.

## TODO (next game-logic pass, refreshed)
- [x] Continue foreign-minister lane around remaining ambiguous shared handlers (`FUN_0052fd80`, no-function target at `0x0052fda0`, and nearby slot-24/slot-25 thunks) and rename only with direct behavior evidence.
- [ ] Continue in same diplomacy AI lane with unresolved shared handlers (`FUN_0052f430`, `FUN_0052ed50`, `FUN_0052ee20`, `FUN_0052eea0`) that are now clearly vtable-shared across diplomat/textile/trader.
- [ ] Re-check unresolved `FUN_005c1580` only if tied directly to turn-flow/message dispatch; otherwise keep deprioritized as UI-resource setup.
- [ ] Return to diplomacy turn-event core (`HandleDiplomacyTurnEventPacketByCode`) for case-level helper naming where event semantics are explicit.

## Continuation (2026-02-18, game-logic pass: diplomacy AI preference helper extraction)

### Additional renames applied (saved)
- Shared diplomacy-AI preference helpers:
  - `FUN_0052f430` -> `ComputeAverageRelationScoreForNationAcrossEligibleSlots`
  - `FUN_0052ed50` -> `RebuildTerrainPreferenceEntriesAndAssignRanks`
  - `FUN_0052ee20` -> `MapTerrainTypeToPreferenceRank`
  - `FUN_0052eea0` -> `MapPreferenceRankToTerrainType`
  - `FUN_0052ef80` -> `GetPreferenceTerrainTypeByEntryIndex`
  - `FUN_0052ef20` -> `GetPreferenceGroupRankByEntryIndex`
  - `FUN_0052ef50` -> `GetPreferenceScoreByEntryIndex`

### New thunk functions materialized + renamed
- Created and named additional thunk islands for the shared vtable lane:
  - `0x004097aa` -> `thunk_ComputeAverageRelationScoreForNationAcrossEligibleSlots`
  - `0x00402f86` -> `thunk_RebuildTerrainPreferenceEntriesAndAssignRanks`
  - `0x00408201` -> `thunk_MapTerrainTypeToPreferenceRank`
  - `0x00402e96` -> `thunk_MapPreferenceRankToTerrainType`
  - `0x00408323` -> `thunk_GetPreferenceTerrainTypeByEntryIndex`
  - `0x00406e01` -> `thunk_GetPreferenceGroupRankByEntryIndex`
  - `0x00404a7f` -> `thunk_GetPreferenceScoreByEntryIndex`

### Evidence notes
- `ComputeAverageRelationScoreForNationAcrossEligibleSlots` accumulates relation matrix values over eligible slots and normalizes by active-slot count minus one.
- `RebuildTerrainPreferenceEntriesAndAssignRanks` rebuilds terrain preference entries and computes rank/group fields based on ordered score transitions.
- `MapTerrainTypeToPreferenceRank` and `MapPreferenceRankToTerrainType` are inverse lookups over that rebuilt preference entry list.
- Entry-index getters at `0x0052ef20/0x0052ef50/0x0052ef80` return the rank/group/score fields from the same list structure.

## TODO (next game-logic pass, refreshed)
- [x] Continue in same diplomacy AI lane with unresolved shared handlers (`FUN_0052f430`, `FUN_0052ed50`, `FUN_0052ee20`, `FUN_0052eea0`) that are now clearly vtable-shared across diplomat/textile/trader.
- [ ] Continue diplomacy AI lane on remaining shared methods still generic in the same vtable chain (`FUN_0052f4b0`, `FUN_0052f4f0`, `FUN_0052f520`, `FUN_0052f540`, `FUN_0052f730`, `FUN_0052f7b0`).
- [ ] Re-check unresolved `FUN_005c1580` only if tied directly to turn-flow/message dispatch; otherwise keep deprioritized as UI-resource setup.
- [ ] Return to diplomacy turn-event core (`HandleDiplomacyTurnEventPacketByCode`) for case-level helper naming where event semantics are explicit.

## Continuation (2026-02-18, game-logic pass: diplomacy AI shared-state helper extraction)

### Additional renames applied (saved)
- Shared diplomacy-AI state/update helpers:
  - `FUN_0052f4b0` -> `InitializeForeignMinisterStateFlags`
  - `FUN_0052f4f0` -> `AddToForeignMinisterCounterAtIndex`
  - `FUN_0052f520` -> `SetForeignMinisterReadyFlag14`
  - `FUN_0052f540` -> `SetForeignMinisterPrimaryAndSecondaryTargets`
  - `FUN_0052f730` -> `HasAnyOptionDToFMeetingNationThreshold`
  - `FUN_0052f7b0` -> `DispatchForeignMinisterPrimaryAndFallbackNationActions`

### New thunk functions materialized + renamed
- Created and named shared thunk islands for the same vtable lane:
  - `0x004089d6` -> `thunk_InitializeForeignMinisterStateFlags`
  - `0x00405c31` -> `thunk_AddToForeignMinisterCounterAtIndex`
  - `0x00409877` -> `thunk_SetForeignMinisterReadyFlag14`
  - `0x00404a11` -> `thunk_SetForeignMinisterPrimaryAndSecondaryTargets`
  - `0x00401406` -> `thunk_HasAnyOptionDToFMeetingNationThreshold`
  - `0x00405da3` -> `thunk_DispatchForeignMinisterPrimaryAndFallbackNationActions`

### Evidence notes
- `InitializeForeignMinisterStateFlags` writes shared default state bits and conditionally sets readiness based on a signed nation-context value.
- `HasAnyOptionDToFMeetingNationThreshold` performs explicit threshold checks across option IDs `0x0d..0x0f`.
- `DispatchForeignMinisterPrimaryAndFallbackNationActions` dispatches a primary action when configured and includes randomized eligible-nation fallback dispatch bounded by relation/eligibility checks.

## TODO (next game-logic pass, refreshed)
- [x] Continue diplomacy AI lane on remaining shared methods still generic in the same vtable chain (`FUN_0052f4b0`, `FUN_0052f4f0`, `FUN_0052f520`, `FUN_0052f540`, `FUN_0052f730`, `FUN_0052f7b0`).
- [ ] Continue diplomacy AI lane on remaining shared generic helpers in the same chain (`FUN_0052f2b0`, `FUN_0052f180`, `FUN_0052ec80`) with strict behavior-backed naming only.
- [ ] Re-check unresolved `FUN_005c1580` only if tied directly to turn-flow/message dispatch; otherwise keep deprioritized as UI-resource setup.
- [ ] Return to diplomacy turn-event core (`HandleDiplomacyTurnEventPacketByCode`) for case-level helper naming where event semantics are explicit.

## Continuation (2026-02-18, game-logic pass: diplomacy AI stream/delete helper extraction)

### Additional renames applied (saved)
- Shared persistence/lifecycle helpers:
  - `FUN_0052f2b0` -> `SerializeForeignMinisterStateToStreamWriter`
  - `FUN_0052f180` -> `DeserializeForeignMinisterStateFromStreamReader`
  - `FUN_0052ec80` -> `DeleteForeignMinisterAndReleaseOrderArray`

### Thunk rename updates
- Existing thunk functions renamed to match shared helper semantics:
  - `0x004036ac` -> `thunk_SerializeForeignMinisterStateToStreamWriter`
  - `0x004081d4` -> `thunk_DeserializeForeignMinisterStateFromStreamReader`
  - `0x004028e2` -> `thunk_DeleteForeignMinisterAndReleaseOrderArray`

### Evidence notes
- `SerializeForeignMinisterStateToStreamWriter` writes contiguous object fields through stream-vtable writer calls (including tail arrays and mode/version-dependent blocks).
- `DeserializeForeignMinisterStateFromStreamReader` performs the inverse read path and byte-swaps 16-bit field arrays into host order.
- `DeleteForeignMinisterAndReleaseOrderArray` frees the owned array field and then dispatches deleting-dtor behavior via object vtable.

## TODO (next game-logic pass, refreshed)
- [x] Continue diplomacy AI lane on remaining shared generic helpers in the same chain (`FUN_0052f2b0`, `FUN_0052f180`, `FUN_0052ec80`) with strict behavior-backed naming only.
- [ ] Re-check unresolved `FUN_005c1580` only if tied directly to turn-flow/message dispatch; otherwise keep deprioritized as UI-resource setup.
- [ ] Return to diplomacy turn-event core (`HandleDiplomacyTurnEventPacketByCode`) for case-level helper naming where event semantics are explicit.
- [ ] Optional: normalize remaining `thunk_FUN_*` labels in the diplomat/textile/trader vtable corridor where targets are now named and function boundaries are valid.

## Continuation (2026-02-18, game-logic pass: TTed/TBill/TArms foreign-minister class extraction)

### Additional renames applied (saved)
- TTed foreign-minister family:
  - `FUN_005311b0` -> `GetTTedForeignMinisterTypeName`
  - `FUN_005311d0` -> `ConstructTTedForeignMinister`
  - `FUN_00531240` -> `DeletingDestructTTedForeignMinister`
  - `FUN_00531270` -> `DestructTTedForeignMinister`
  - `FUN_00531290` -> `InitializeTedForeignMinisterOrderCandidates`
  - `FUN_00531a10` -> `QueueTedFourRandomAvailableTerrainActionsCode133`
  - `FUN_00531af0` -> `NoOpTedForeignMinisterSlot25Handler` (new function materialized)
  - `FUN_00531b10` -> `SetTedCounter60ToThree`
- TBill foreign-minister family:
  - `FUN_00531bc0` -> `GetTBillForeignMinisterTypeName`
  - `FUN_00531be0` -> `ConstructTBillForeignMinister`
  - `FUN_00531c50` -> `DeletingDestructTBillForeignMinister`
  - `FUN_00531c80` -> `DestructTBillForeignMinister`
  - `FUN_00531ca0` -> `DeserializeTBillForeignMinisterStateWithOrderFlagByte`
  - `FUN_00531ce0` -> `SerializeTBillForeignMinisterStateWithOrderFlagByte`
  - `FUN_00531d20` -> `InitializeBillForeignMinisterOrderCandidates`
- TArms foreign-minister family:
  - `FUN_00533ff0` -> `GetTArmsForeignMinisterTypeName`
  - `FUN_00534010` -> `ConstructTArmsForeignMinister`
  - `FUN_00534080` -> `DeletingDestructTArmsForeignMinister`
  - `FUN_005340b0` -> `DestructTArmsForeignMinister`
  - `FUN_005340d0` -> `InitializeArmsForeignMinisterOrderCandidates`
  - `FUN_00534660` -> `IncrementArmsCounter5EByFive`
- Shared slot no-op:
  - `FUN_00531110` -> `NoOpForeignMinisterSlot32Handler`

### New thunk functions materialized + renamed
- Added/renamed wrapper thunks for the above families:
  - `0x004063e8` -> `thunk_GetTTedForeignMinisterTypeName`
  - `0x00407798` -> `thunk_ConstructTTedForeignMinister`
  - `0x00405218` -> `thunk_DeletingDestructTTedForeignMinister`
  - `0x0040591b` -> `thunk_DestructTTedForeignMinister`
  - `0x00404a20` -> `thunk_InitializeTedForeignMinisterOrderCandidates`
  - `0x004093f9` -> `thunk_QueueTedFourRandomAvailableTerrainActionsCode133`
  - `0x00407405` -> `thunk_NoOpTedForeignMinisterSlot25Handler`
  - `0x004039d1` -> `thunk_SetTedCounter60ToThree`
  - `0x00406fdc` -> `thunk_GetTBillForeignMinisterTypeName`
  - `0x004081b6` -> `thunk_ConstructTBillForeignMinister`
  - `0x00401d8e` -> `thunk_DeletingDestructTBillForeignMinister`
  - `0x00401b7c` -> `thunk_DestructTBillForeignMinister`
  - `0x0040753b` -> `thunk_DeserializeTBillForeignMinisterStateWithOrderFlagByte`
  - `0x00401efb` -> `thunk_SerializeTBillForeignMinisterStateWithOrderFlagByte`
  - `0x004013a2` -> `thunk_InitializeBillForeignMinisterOrderCandidates`
  - `0x0040139d` -> `thunk_GetTArmsForeignMinisterTypeName`
  - `0x00406221` -> `thunk_ConstructTArmsForeignMinister`
  - `0x004079dc` -> `thunk_DeletingDestructTArmsForeignMinister`
  - `0x004048e5` -> `thunk_DestructTArmsForeignMinister`
  - `0x00408b5c` -> `thunk_InitializeArmsForeignMinisterOrderCandidates`
  - `0x004074f0` -> `thunk_IncrementArmsCounter5EByFive`
  - `0x004014dd` -> `thunk_NoOpForeignMinisterSlot32Handler`

### Evidence notes
- Type-name getters return direct class-string anchors (`TTedForeignMinister`, `TBillForeignMinister`, `TArmsForeignMinister`).
- Constructors assign distinct class vtable roots (`0x00659d70`, `0x00659e30`, `0x0065a188`) with expected deleting-dtor pairings.
- `Initialize*OrderCandidates` routines write candidate ID slots at `+0x40..+0x46` and call shared post-processing (`thunk_FUN_0052f570`), matching established naming pattern in earlier minister classes.

## TODO (next game-logic pass, refreshed)
- [x] Optional: normalize remaining `thunk_FUN_*` labels in the diplomat/textile/trader vtable corridor where targets are now named and function boundaries are valid.
- [ ] Continue diplomacy AI lane on remaining shared generic behavior methods still unnamed in the same corridor (`FUN_005308b0`, `FUN_00530b30`, `FUN_00530bb0`, `Cluster_TurnEventHint_00530200`).
- [ ] Re-check unresolved `FUN_005c1580` only if tied directly to turn-flow/message dispatch; otherwise keep deprioritized as UI-resource setup.
- [ ] Return to diplomacy turn-event core (`HandleDiplomacyTurnEventPacketByCode`) for case-level helper naming where event semantics are explicit.

## Continuation (2026-02-18, game-logic pass: TMinister/TForeignMinister base class extraction)

### Additional renames applied (saved)
- TMinister base class:
  - `FUN_0052eb60` -> `GetTMinisterTypeName`
  - `FUN_0052eb80` -> `ConstructTMinister`
  - `FUN_0052eba0` -> `DeletingDestructTMinister`
  - `FUN_0052ebd0` -> `DestructTMinister`
  - `FUN_0052ebf0` -> `InitializeTMinisterBaseOrderArray`
  - `FUN_0052ecc0` -> `DeserializeTMinisterBaseOrderArrayHeader`
  - `FUN_0052ecf0` -> `SerializeTMinisterBaseOrderArrayHeader`
- Shared minister/foreign-minister helpers:
  - `FUN_0052ed20` -> `DispatchNationStateEventCode10`
  - `FUN_0052efb0` -> `NoOpForeignMinisterUtilityStub`
- TForeignMinister base class:
  - `FUN_0052f050` -> `GetTForeignMinisterTypeName`
  - `FUN_0052f070` -> `ConstructTForeignMinister`
  - `FUN_0052f0e0` -> `DeletingDestructTForeignMinister`
  - `FUN_0052f110` -> `DestructTForeignMinister`
  - `FUN_0052f130` -> `InitializeTForeignMinisterStateAndCounters`

### New thunk functions materialized + renamed
- Added/renamed thunks for base-class methods:
  - `0x0040625d` -> `thunk_GetTMinisterTypeName`
  - `0x0040433b` -> `thunk_ConstructTMinister`
  - `0x00401866` -> `thunk_DeletingDestructTMinister`
  - `0x0040293c` -> `thunk_DestructTMinister`
  - `0x0040670d` -> `thunk_InitializeTMinisterBaseOrderArray`
  - `0x00407590` -> `thunk_DeserializeTMinisterBaseOrderArrayHeader`
  - `0x00407af9` -> `thunk_SerializeTMinisterBaseOrderArrayHeader`
  - `0x004045c5` -> `thunk_DispatchNationStateEventCode10`
  - `0x00401acd` -> `thunk_NoOpForeignMinisterUtilityStub`
  - `0x0040377e` -> `thunk_GetTForeignMinisterTypeName`
  - `0x00404912` -> `thunk_ConstructTForeignMinister`
  - `0x00406140` -> `thunk_DeletingDestructTForeignMinister`
  - `0x004085cb` -> `thunk_DestructTForeignMinister`
  - `0x004089ae` -> `thunk_InitializeTForeignMinisterStateAndCounters`

### Evidence notes
- Type-name getters return direct class-string anchors (`TMinister`, `TForeignMinister`).
- Constructors assign base vtables (`0x00659c00`, `0x00659cb0`) and initialize the same state regions reused by all concrete foreign-minister subclasses.
- `InitializeTMinisterBaseOrderArray` allocates/attaches the shared `CObArray` order list (`+8`) and sets baseline capacity.

## TODO (next game-logic pass, refreshed)
- [x] Continue diplomacy AI lane on remaining shared generic behavior methods still unnamed in the same corridor (`FUN_005308b0`, `FUN_00530bb0`, `Cluster_TurnEventHint_00530200`).
- [ ] Re-check unresolved `FUN_005c1580` only if tied directly to turn-flow/message dispatch; otherwise keep deprioritized as UI-resource setup.
- [ ] Return to diplomacy turn-event core (`HandleDiplomacyTurnEventPacketByCode`) for case-level helper naming where event semantics are explicit.

## Continuation (2026-02-18, game-logic pass: final shared diplomacy-AI generic cleanup in foreign-minister lane)

### Additional renames applied (saved)
- `FUN_005308b0` -> `EvaluateLocalizedScoreThresholdPredicateForNationValue`
- `FUN_00530bb0` -> `QueueForeignMinisterActionCodesByNationStateAndCompatibility`
- `Cluster_TurnEventHint_00530200` -> `QueueTurnEventHintActionsByNationMetricsAndCompatibility`

### New thunk functions materialized + renamed
- `0x00406c3f` -> `thunk_EvaluateLocalizedScoreThresholdPredicateForNationValue`
- `0x00405f38` -> `thunk_QueueForeignMinisterActionCodesByNationStateAndCompatibility`
- `0x00403319` -> `thunk_QueueTurnEventHintActionsByNationMetricsAndCompatibility`

### Evidence notes
- `EvaluateLocalizedScoreThresholdPredicateForNationValue` is a bool predicate that computes mode/localization-dependent threshold checks and compares against a nation-linked score/value accessor lane.
- `QueueForeignMinisterActionCodesByNationStateAndCompatibility` emits action codes (`0x133`, `0x5f`, `0x4b`) from compatibility checks, nation-state matrix values, and minor-capability constraints.
- `QueueTurnEventHintActionsByNationMetricsAndCompatibility` emits multi-branch hint action codes (`0x12d`, `0x12e`, `0x12f`, `0x130`) using compatibility state, nation metrics, and eligibility filters.

## TODO (next game-logic pass, refreshed)
- [ ] Re-check unresolved `FUN_005c1580` only if tied directly to turn-flow/message dispatch; otherwise keep deprioritized as UI-resource setup.
- [ ] Return to diplomacy turn-event core (`HandleDiplomacyTurnEventPacketByCode`) for case-level helper naming where event semantics are explicit.

## Continuation (2026-02-18, game-logic pass: TMission base/factory extraction)

### Additional renames applied (saved)
- TMission base/factory lane:
  - `FUN_00534fb0` -> `GetTMissionTypeName`
  - `FUN_00535020` -> `ConstructTMission`
  - `FUN_00535050` -> `DeletingDestructTMission`
  - `FUN_00535080` -> `DestructTMission`
  - `FUN_005350a0` -> `InitializeMissionWithNationIdAndResetPathMarker`
  - `FUN_005350d0` -> `CreateMissionByKindAndContext`
- TNavyMission shared constructor/capability stubs:
  - `FUN_00535470` -> `ConstructTNavyMission`
  - `FUN_005354e0` -> `ReturnTrueMissionCapabilityStub`
  - `FUN_00535500` -> `ReturnFalseMissionCapabilityStub`

### New thunk functions materialized + renamed
- Added/renamed wrappers for the mission lane:
  - `0x0040542a` -> `thunk_GetTMissionTypeName`
  - `0x00406f05` -> `thunk_ConstructTMission`
  - `0x00401dde` -> `thunk_DeletingDestructTMission`
  - `0x00405a47` -> `thunk_DestructTMission`
  - `0x0040163b` -> `thunk_InitializeMissionWithNationIdAndResetPathMarker`
  - `0x00404e99` -> `thunk_CreateMissionByKindAndContext`
  - `0x004078ec` -> `thunk_ConstructTNavyMission`
  - `0x00406d1b` -> `thunk_ReturnTrueMissionCapabilityStub`
  - `0x00409340` -> `thunk_ReturnFalseMissionCapabilityStub`

### Evidence notes
- Type getter resolves class-string anchor `TMission`.
- `CreateMissionByKindAndContext` is a switch-based allocator/constructor dispatcher over mission kind and context arguments, invoking concrete mission constructors and post-init checks.
- `ConstructTNavyMission` writes `g_vtblTNavyMission` and initializes navy-mission state fields after base mission setup.

## TODO (next game-logic pass, refreshed)
- [ ] Continue mission lane low-hanging in same block (`0x00534c00..0x00534f90`) with behavior-backed names for default stubs and simple setters only.
- [ ] Re-check unresolved `FUN_005c1580` only if tied directly to turn-flow/message dispatch; otherwise keep deprioritized as UI-resource setup.
- [ ] Return to diplomacy turn-event core (`HandleDiplomacyTurnEventPacketByCode`) for case-level helper naming where event semantics are explicit.

## Continuation (2026-02-18, game-logic pass: TMission vtable slot-stub normalization)

### Additional renames applied (saved)
- Normalized TMission vtable slot stubs/setters in `0x00534c00..0x00534f90` using slot-based naming (non-speculative):
  - `ReturnFalseMissionVtableSlot28`
  - `ReturnZeroMissionVtableSlot2C`
  - `NoOpMissionVtableSlot30`
  - `SetMissionStateByte8To2`
  - `ResetMissionField0CToZero`
  - `NoOpMissionVtableSlot3C`
  - `InvokeMissionVtableMethods34_38_3C`
  - `NoOpMissionVtableSlot44`
  - `ReturnMissionPointerArgSlot48`
  - `ReturnFalseMissionVtableSlot4C`
  - `ReturnFalseMissionVtableSlot50`
  - `ReturnFalseMissionVtableSlot54`
  - `ReturnZeroMissionVtableSlot58`
  - `ReturnZeroMissionVtableSlot5C`
  - `ReturnFalseMissionVtableSlot60`
  - `ReturnFalseMissionVtableSlot64`
  - `ReturnMissionConstantFloatSlot68`
  - `ReturnMissionConstantFloatSlot6C`
  - `ReturnMissionConstantFloatSlot70`
  - `ReturnMissionConstantFloatSlot74`
  - `ReturnMissionConstantFloatSlot78`
  - `ReturnMissionConstantFloatSlot7C`
  - `NoOpMissionVtableSlot80Ret8`
  - `NoOpMissionVtableSlot84`
  - `NoOpMissionVtableSlot88Ret8`
  - `NoOpMissionVtableSlot8CRet8`
  - `NoOpMissionVtableSlot90Ret4`
  - `SetMissionField10FromArgSlot94`
  - `ReturnFalseMissionVtableSlot98`

### New thunk functions materialized + renamed
- Materialized and renamed corresponding thunk islands in the `0x0040xxxx` vtable-jump corridor for the above slot methods.
- This pass created function boundaries for previously raw jmp stubs and aligned names with slot targets.

### Evidence notes
- All renamed methods are trivial single-purpose stubs/setters (`RET`, constant return, field write, or call-chain trampoline), so slot-based naming is high-confidence and avoids speculative mission semantics.
- The slot mapping was verified directly from `TMission` vtable root (`0x0065a4e8`).

## TODO (next game-logic pass, refreshed)
- [x] Continue mission lane low-hanging in same block (`0x00534c00..0x00534f90`) with behavior-backed names for default stubs and simple setters only.
- [ ] Re-check unresolved `FUN_005c1580` only if tied directly to turn-flow/message dispatch; otherwise keep deprioritized as UI-resource setup.
- [ ] Return to diplomacy turn-event core (`HandleDiplomacyTurnEventPacketByCode`) for case-level helper naming where event semantics are explicit.

## Continuation (2026-02-18, game-logic pass: TSortByPriceList / TIndexAndRankList extraction)

### Additional renames applied (saved)
- TSortByPriceList family:
  - `FUN_00534680` -> `AllocateAndConstructTSortByPriceList`
  - `FUN_005346f0` -> `GetTSortByPriceListTypeName`
  - `FUN_00534710` -> `ConstructTSortByPriceList`
  - `FUN_00534740` -> `DeletingDestructTSortByPriceList`
  - `0x00534770` -> `DestructTSortByPriceList`
  - `FUN_005347b0` -> `CompareSortByPriceListEntriesByField2Ascending`
- TIndexAndRankList family:
  - `FUN_005347e0` -> `AllocateAndConstructTIndexAndRankList`
  - `FUN_00534850` -> `GetTIndexAndRankListTypeName`
  - `FUN_00534870` -> `ConstructTIndexAndRankList`
  - `FUN_005348a0` -> `DeletingDestructTIndexAndRankList`
  - `0x005348d0` -> `DestructTIndexAndRankList`
  - `FUN_00534910` -> `CompareIndexAndRankEntriesByField2Descending`

### New thunk functions materialized + renamed
- Added/renamed wrappers in the same list-helper corridor:
  - `0x00408bf7` -> `thunk_GetTSortByPriceListTypeName`
  - `0x00403242` -> `thunk_DeletingDestructTSortByPriceList`
  - `0x004023c9` -> `thunk_DestructTSortByPriceList`
  - `0x004013d9` -> `thunk_CompareSortByPriceListEntriesByField2Ascending`
  - `0x004084db` -> `thunk_GetTIndexAndRankListTypeName`
  - `0x004040b6` -> `thunk_DeletingDestructTIndexAndRankList`
  - `0x004069f1` -> `thunk_DestructTIndexAndRankList`
  - `0x004075e0` -> `thunk_CompareIndexAndRankEntriesByField2Descending`

### Evidence notes
- Type getters resolve direct class-string anchors (`TSortByPriceList`, `TIndexAndRankList`).
- Constructors/destructors follow standard `CObArray`-derived object patterns with class-specific vtable roots.
- Comparator helpers use deterministic signed-compare returns (`-1/1`) over field offset `+2`, with opposite ordering semantics between the two list types.

## TODO (next game-logic pass, refreshed)
- [ ] Continue diplomacy AI lane on remaining shared generic behavior methods still unnamed in the same corridor (`FUN_005308b0`, `FUN_00530bb0`, `Cluster_TurnEventHint_00530200`).
- [ ] Re-check unresolved `FUN_005c1580` only if tied directly to turn-flow/message dispatch; otherwise keep deprioritized as UI-resource setup.
- [ ] Return to diplomacy turn-event core (`HandleDiplomacyTurnEventPacketByCode`) for case-level helper naming where event semantics are explicit.

## Continuation (2026-02-18, non-map pass: runtime settings/protocol helper chain)

### Additional renames applied (saved)
- Settings wrappers:
  - `FUN_004154e0` -> `GetSettingValueFromSettingsSection`
  - `FUN_00415580` -> `SetSettingValueInSettingsSection`
- Runtime settings bridge:
  - `FUN_005e0290` -> `LoadSettingValueByKeyIntoOut`
  - `FUN_005e0260` -> `SaveSettingValueFromPointerByKey`
- Runtime protocol source lane:
  - `FUN_005e39a0` -> `ResetRuntimeProtocolOptionsAndRebuildSelectionSource`
  - `FUN_00508c50` -> `NormalizeRuntimeCredentialNameToken`
  - `FUN_005e34b0` -> `ReturnTrueRuntimeCredentialInitStub`
  - `FUN_005e3c00` -> `ReturnTrueRuntimeCredentialFinalizeStub`
- Runtime owner-release helper:
  - `FUN_0048a1b0` -> `ReleaseRuntimeSelectionOwnerAndDestroyObject`

### New thunk functions materialized + renamed
- Added/renamed wrappers tied to this chain:
  - `0x004014ce` -> `thunk_GetSettingValueFromSettingsSection`
  - `0x004017da` -> `thunk_SetSettingValueInSettingsSection`
  - `0x00402513` -> `thunk_LoadSettingValueByKeyIntoOut`
  - `0x0040451b` -> `thunk_SaveSettingValueFromPointerByKey`
  - `0x00409412` -> `thunk_ResetRuntimeProtocolOptionsAndRebuildSelectionSource`
  - `0x00402a2c` -> `thunk_NormalizeRuntimeCredentialNameToken`
  - `0x00402afe` -> `thunk_ReturnTrueRuntimeCredentialInitStub`
  - `0x004082d8` -> `thunk_ReturnTrueRuntimeCredentialFinalizeStub`
  - `0x00407d83` -> `thunk_ReleaseRuntimeSelectionOwnerAndDestroyObject`

### Evidence notes
- `ResetRuntimeProtocolOptionsAndRebuildSelectionSource` resolves provider tag `prot`, clears previously allocated option buffers (`DAT_006a5f14` lane), then rebuilds option source state.
- `LoadSettingValueByKeyIntoOut`/`SaveSettingValueFromPointerByKey` are directly paired by callers in the runtime-selection credential flow.
- `NormalizeRuntimeCredentialNameToken` rewrites provider text token handling leading marker/first-char policy before writing back through shared-string refs.
- Seeded non-map diplomacy/session callgraph re-scan now reports:
  - unresolved direct callees from seed set: `0`.

## TODO (next game-logic pass, refreshed)
- [ ] Keep avoiding map-action lanes; continue with non-map turn-flow/runtime helpers adjacent to this chain (event transport/session setup) and apply behavior-based names.
- [ ] Re-check unresolved `FUN_005c1580` only if tied directly to turn-flow/message dispatch; otherwise keep deprioritized as UI-resource setup.
- [ ] Optional: revisit route/UMapper class root around `0x00659920` and convert remaining vtable-root labels to class-extracted names once type string evidence is found.

## Continuation (2026-02-18, non-map follow-up: runtime cleanup and field helper lane)

### Additional renames applied (saved)
- Runtime cleanup/context release:
  - `FUN_0049e1a0` -> `ReleaseGlobalUiSystemsAndGameFlowState`
  - `FUN_004a0dc0` -> `ResetUiViewStateAndReleaseRuntimeSelectionOwner`
  - `FUN_005e51d0` -> `ReleaseRuntimeSelectionPeersAndResetOwner`
- Indexed credential slot helper:
  - `FUN_00581b20` -> `AssignNormalizedCredentialTokenToIndexedSlot`
  - `0x00405b14` -> `thunk_AssignNormalizedCredentialTokenToIndexedSlot`
- Small field-helper cluster:
  - `FUN_005811e0` -> `GetField30Value`
  - `FUN_00581200` -> `DecrementField30Value`
  - `FUN_00581240` -> `GetSumField34PlusField30`
  - `FUN_00581400` -> `InitializeOrLoadEntryArray14AndClampLimits`
  - `FUN_00581ae0` -> `SetSelectedIndex6AAndTriggerRefresh`
  - `FUN_00581bc0` -> `AssignSharedStringFromIndexedSlot7C`
- Additional helper requested in sequence:
  - `FUN_00582ed0` -> `ReadNextDwordSetField2CHighWordTimes4`
  - `0x004092be` -> `thunk_ReadNextDwordSetField2CHighWordTimes4`

### New thunk functions materialized + renamed
- Field-helper thunks aligned with renamed targets:
  - `0x00401b86` -> `thunk_GetField30Value`
  - `0x00407540` -> `thunk_DecrementField30Value`
  - `0x00406f46` -> `thunk_GetSumField34PlusField30`
  - `0x00408d0a` -> `thunk_InitializeOrLoadEntryArray14AndClampLimits`
  - `0x004067df` -> `thunk_SetSelectedIndex6AAndTriggerRefresh`
  - `0x0040664a` -> `thunk_AssignSharedStringFromIndexedSlot7C`

### Evidence notes
- `AssignNormalizedCredentialTokenToIndexedSlot` directly wraps token normalization (`NormalizeRuntimeCredentialNameToken`) then assigns shared-string output.
- `ReadNextDwordSetField2CHighWordTimes4` consumes one dword from a stream pointer and writes derived scaled value into field `+0x2C`; thunk wrapper at `0x004092be` now named.
- This subpass intentionally skipped map-action-heavy lanes (terrain/recruit/work-order paths) and stayed in runtime/session + small helper logic.

## TODO (next game-logic pass, refreshed)
- [ ] Continue non-map-only cleanup in adjacent runtime/transport/UI-context helpers; avoid map-order/terrain-action branches for now.
- [ ] Re-check unresolved `FUN_005c1580` only if tied directly to turn-flow/message dispatch; otherwise keep deprioritized as UI-resource setup.
- [ ] Optional: revisit route/UMapper class root around `0x00659920` and convert remaining vtable-root labels to class-extracted names once type string evidence is found.

## Continuation (2026-02-18, diplomacy game-logic cleanup: session-active nation helpers + turn-event packet creators)

### Additional renames applied (saved)
- Session-active nation + utility helpers:
  - `FUN_005e4280` -> `GetSessionActiveNationId`
  - `FUN_00405a3d` -> `thunk_GetSessionActiveNationId`
  - `FUN_005e42c0` -> `NotifyIfNationMatchesSessionActiveNation`
  - `0x00405682` -> `thunk_NotifyIfNationMatchesSessionActiveNation`
  - `FUN_005e8420` -> `MoveMemoryOverlapSafe`
  - `DAT_006a5fc0` -> `g_sessionActiveNationId`
- Diplomacy runtime/control helpers:
  - `FUN_00542b10` -> `ShutdownRuntimeSelectionAndPersistPlayerName`
  - `FUN_00544cd0` -> `ApplyEncodedDeltaPayloadToBufferByMode`
  - `FUN_00544e70` -> `InitializeProtocolOptionControlFromProvider`
  - `FUN_00545110` -> `InitializeRuntimeSelectionCredentialsFromProviderAndConnect`
  - `FUN_00545480` -> `AssignStringAtB4FromB0AndResetState40`
  - `FUN_00544630` -> `ResetDiplomacyRuntimeSelectionAndSetModeNada`
  - `FUN_00549280` -> `AppendNodeToTurnEventLinkedListAt6C`
  - `FUN_00549240` -> `TouchSessionActiveNationId`
  - `FUN_005424b0` -> `AllocateAndConstructTurnEventPacket_Vtbl0065bff0`
  - `FUN_005425d0` -> `AllocateAndInitConfigDefaultsObjectF8`
- Turn-event packet creator lane (event-code anchored names):
  - `FUN_005493c0` -> `CreateAndSendTurnEvent11_MapOffsetAndFlags`
  - `FUN_005494b0` -> `CreateAndSendTurnEvent12_TwoShorts`
  - `FUN_00549540` -> `CreateAndSendTurnEvent13_NationAndNineDwords`
  - `FUN_005495e0` -> `CreateAndSendTurnEvent20_ShortAndTwoBytes`
  - `FUN_00549680` -> `CreateAndSendTurnEvent21_ThreeBytes`
  - `FUN_00549720` -> `CreateAndSendTurnEvent22_ByteAndShort`
  - `FUN_005498d0` -> `CreateAndSendTurnEvent1B_FiveShortsAndDword`
  - `FUN_005499b0` -> `CreateAndSendTurnEvent1C_BoolAndSixShorts`
  - `FUN_0054aa10` -> `CreateAndSendTurnEvent0C_Text256AndTwoFlags`
  - `FUN_0054d3d0` -> `CreateAndSendTurnEvent2D_TableRowShortArray`
  - `FUN_00549c60` -> `SerializeOrderDataIntoTurnEventByTag`
  - `FUN_0054a500` -> `PublishTerrainDescriptorAndNotifyOrderListeners`
  - `FUN_0054a5e0` -> `PublishNationDescriptorAndNotifyOrderListeners`
  - `FUN_0054a6d0` -> `CreateMilitaryRecruitOrdersForSelectedTerrain`
  - `FUN_0054a840` -> `CreateCivilianWorkOrdersForSelectedNations`

### New thunk functions materialized + renamed
- Added/normalized matching thunk wrappers for the above lane, including:
  - `0x00403f62`, `0x004059b1`, `0x00408341`, `0x00408eb3`
  - `0x00407f72`, `0x004048d6`, `0x00405bd7`, `0x004072ac`, `0x004070f4`
  - `0x004037c9`, `0x0040290f`, `0x00409787`, `0x00403e13`, `0x004091a1`, `0x0040196f`, `0x00405c2c`
  - plus previously added diplomacy helper thunks `0x00405cb8`, `0x00402446`

### Evidence notes
- `GetNationStatusCodeForSlotOrActiveNation` and `FindActiveNationSlotIndexInGameFlowList` both consume the fallback getter now named `GetSessionActiveNationId`, validating `g_sessionActiveNationId` usage in diplomacy status paths.
- `ApplyEncodedDeltaPayloadToBufferByMode` has explicit mode-byte behavior at `+0x21`:
  - mode `0`: raw memcpy-style copy
  - mode `1`: indexed byte writes (`index:u16, value:u8`)
  - mode `2`: indexed word writes (`index:u16, value:u16`)
  - mode `3`: indexed dword writes (`index:u16, value:u32`)
- Event creator functions in `0x005493c0..0x0054d3d0` all build `time`-tag packet headers and call `EnqueueOrSendTurnEventPacketToNation`, so event-code anchored naming is high-confidence.
- Residual generic symbol scan in diplomacy range `0x00541000..0x0054e000` now reports `remaining 0`.

## TODO (next game-logic pass, refreshed)
- [ ] Continue into adjacent turn-flow logic outside diplomacy control lane (e.g. `0x0054e000+`) and apply the same event-code-first naming for packet creators/dispatch helpers.
- [ ] Re-check unresolved `FUN_005c1580` only if tied directly to turn-flow/message dispatch; otherwise keep deprioritized as UI-resource setup.
- [ ] Optional: revisit route/UMapper class root around `0x00659920` and convert remaining vtable-root labels to class-extracted names once type string evidence is found.

## Continuation (2026-02-18, low-hanging corridor cleanup: route-marker + foreign-minister slot variants + navy mission stubs)

### Additional renames applied (saved)
- Route/UMapper helper lane:
  - `FUN_0052e310` -> `ReallocateRouteRecordBufferByCountStride18`
  - `FUN_0052e350` -> `RebuildUMapperRouteRecordsAndActiveMapRects`
  - `FUN_0052e7b0` -> `AllocateRouteNodeStateBufferByCount`
  - `FUN_0052e840` -> `NormalizeRouteNodeMarkerValuesAndReportChanges`
  - `FUN_0052e890` -> `MarkRouteNodePendingAndActivateUnvisitedNeighbors`
  - `FUN_0052e900` -> `PropagateRouteNodeMarkersFromDeferredNodes`
  - `FUN_0052e990` -> `AreRoutePointPairsEqual`
- Shared foreign-minister slot handlers and variant overrides:
  - `FUN_0052f570` -> `RebuildForeignMinisterPreferenceTop4IdsFromWeights`
  - `FUN_0052f940` -> `RunForeignMinisterVtableSlot90Base`
  - `FUN_0052f9d0` -> `RunForeignMinisterVtableSlot94Shared`
  - `FUN_0052fba0` -> `RunForeignMinisterAmountDispatchShared`
  - `FUN_0052fcc0` -> `ResetForeignMinisterVtableSlot9CSharedState`
  - `Cluster_Vcall_48_4C_68_00531550` -> `RunForeignMinisterVtableSlot90TedVariant`
  - `Cluster_UiPageGrid244C6888_00531e50` -> `RunForeignMinisterVtableSlot90BillVariant`
  - `Cluster_UiPageGrid244C6888_00532c60` -> `RunForeignMinisterPolicySlot28VariantA`
  - `FUN_00532f70` -> `RunForeignMinisterPolicySlot30VariantA`
  - `Cluster_Vcall_48_4C_68_00533380` -> `RunForeignMinisterPolicySlot28VariantB`
  - `Cluster_UiPageGrid244C6888_00533b10` -> `RunForeignMinisterPolicySlot28VariantC`
  - `Cluster_UiPageGrid244C6888_00534190` -> `RunForeignMinisterVtableSlot90ArmsVariant`
- Navy mission vtable stub overrides:
  - `FUN_00535520` -> `ReturnZeroMissionSlot58NavyOverride`
  - `FUN_00535540` -> `ReturnArgMissionSlot5CNavyOverride`

### New thunk functions materialized + renamed
- Route/UMapper thunks:
  - `0x004052cc` -> `thunk_ReallocateRouteRecordBufferByCountStride18`
  - `0x0040356c` -> `thunk_RebuildUMapperRouteRecordsAndActiveMapRects`
  - `0x00402c5c` -> `thunk_AllocateRouteNodeStateBufferByCount`
  - `0x00404fde` -> `thunk_NormalizeRouteNodeMarkerValuesAndReportChanges`
  - `0x004060e6` -> `thunk_MarkRouteNodePendingAndActivateUnvisitedNeighbors`
  - `0x004010e1` -> `thunk_PropagateRouteNodeMarkersFromDeferredNodes`
  - `0x00402aef` -> `thunk_AreRoutePointPairsEqual`
- Foreign-minister slot/variant thunks:
  - `0x00402f36` -> `thunk_RebuildForeignMinisterPreferenceTop4IdsFromWeights`
  - `0x004095f2` -> `thunk_RunForeignMinisterVtableSlot90Base`
  - `0x00403e9a` -> `thunk_RunForeignMinisterVtableSlot94Shared`
  - `0x00403a80` -> `thunk_RunForeignMinisterAmountDispatchShared`
  - `0x0040172b` -> `thunk_ResetForeignMinisterVtableSlot9CSharedState`
  - `0x00407cc5` -> `thunk_RunForeignMinisterVtableSlot90TedVariant`
  - `0x004084cc` -> `thunk_RunForeignMinisterVtableSlot90BillVariant`
  - `0x004051b9` -> `thunk_RunForeignMinisterPolicySlot28VariantA`
  - `0x004048ef` -> `thunk_RunForeignMinisterPolicySlot30VariantA`
  - `0x0040690b` -> `thunk_RunForeignMinisterPolicySlot28VariantB`
  - `0x0040718a` -> `thunk_RunForeignMinisterPolicySlot28VariantC`
  - `0x004065be` -> `thunk_RunForeignMinisterVtableSlot90ArmsVariant`
- Navy mission thunks:
  - `0x004058bc` -> `thunk_ReturnZeroMissionSlot58NavyOverride`
  - `0x00407e1e` -> `thunk_ReturnArgMissionSlot5CNavyOverride`

### Evidence notes
- The full unresolved set in `0x0052e000..0x00535550` is now cleared (`remaining 0` for names matching `FUN_*`/`Cluster_*` in that range).
- Slot-based naming for the diplomacy variant cluster is anchored to vtable offsets:
  - base foreign minister table `0x00659cb0` (`+0x90/+0x94/+0x9c`),
  - concrete minister variants (`0x00659d70`, `0x00659e30`, `0x0065a188`) and policy tables (`0x00659fb0`, `0x0065a070`, `0x0065a130`) for `+0x28/+0x30`.
- `0x0052e350` references `UMapper.cpp` assert context and rebuilds route/rect lists via `CRect` writes into active map state, so it was named conservatively around rebuild behavior.

## TODO (next game-logic pass, refreshed)
- [ ] Continue game-logic renaming outside this corridor by following turn-flow/event dispatch branches (`HandleDiplomacyTurnEventPacketByCode`) and naming helper cases only when event semantics are explicit.
- [ ] Identify the class/type root for the route/UMapper table anchored around `0x00659920` (first-slot type getter candidate still unnamed), then fold current route helper names under that class once confirmed.
- [ ] Re-check unresolved `FUN_005c1580` only if tied directly to turn-flow/message dispatch; otherwise keep deprioritized as UI-resource setup.

## Continuation (2026-02-18, game-logic pass: shared dispatch helper cleanup)

### Additional renames applied (saved)
- `FUN_00530b30` -> `DispatchAction210ToFirstEligibleNationIfIdle`
- `0x00407c02` -> `thunk_DispatchAction210ToFirstEligibleNationIfIdle` (new thunk function materialized)

### Evidence notes
- Function exits early when object method `+0x20c` reports active/busy state.
- Otherwise scans nation slots, applies eligibility and callback gate checks (`+0x70`), and dispatches `+0x210` to the first passing slot.

## TODO (next game-logic pass, refreshed)
- [ ] Continue diplomacy AI lane on remaining shared generic behavior methods still unnamed in the same corridor (`FUN_005308b0`, `FUN_00530bb0`, `Cluster_TurnEventHint_00530200`).
- [ ] Re-check unresolved `FUN_005c1580` only if tied directly to turn-flow/message dispatch; otherwise keep deprioritized as UI-resource setup.
- [ ] Return to diplomacy turn-event core (`HandleDiplomacyTurnEventPacketByCode`) for case-level helper naming where event semantics are explicit.

## Continuation (2026-02-18, game-logic pass: resolved remaining 0x00659920 lane generics)

### Additional renames applied (saved)
- Remaining unresolved functions in the `0x00659920` callback class lane (`0x00526b00..0x0052a900`) were renamed with behavior-backed names:
  - `FUN_00528c10` -> `GetNeighborTileIndexOnMap108x60`
  - `FUN_005293d0` -> `RandomizeRegionTemplateBanksForMismatchedNeighborClasses`
  - `FUN_00529960` -> `RotateMapColumnsByPeakCityTileDensity`
  - `FUN_00529d90` -> `ComputeAverageTileIndexForClassIdWithWrapBias`
  - `FUN_0052a0a0` -> `CompactCityRegionIdsInTileData`
  - `FUN_0052a160` -> `GenerateCityRegionIdsBySeedAndNeighborPropagation`
  - `FUN_0052a670` -> `GetCityRegionIdAtTileIndex`
  - `FUN_0052a6e0` -> `WrapExtendedMapXCoordinateInPlace`

### New thunk functions normalized
- Matching thunk wrappers renamed to target-backed names:
  - `0x004084ae` -> `thunk_GetNeighborTileIndexOnMap108x60`
  - `0x00401ece` -> `thunk_RandomizeRegionTemplateBanksForMismatchedNeighborClasses`
  - `0x00406d4d` -> `thunk_RotateMapColumnsByPeakCityTileDensity`
  - `0x00408152` -> `thunk_GenerateCityRegionIdsBySeedAndNeighborPropagation`
  - `0x00402a68` -> `thunk_GetCityRegionIdAtTileIndex`
  - `0x00401541` -> `thunk_WrapExtendedMapXCoordinateInPlace`

### Ghidra comments added
- Added concise function comments for all eight renamed non-thunk functions to capture:
  - hex-neighbor index behavior with wrap/parity,
  - randomized template-bank swapping on neighbor-class mismatch,
  - city-density-based column rotation,
  - class-id centroid computation with wrap bias,
  - contiguous class-id compaction,
  - seed+propagation region-id generation,
  - tile-level region-id accessor,
  - extended X coordinate wrap normalization.

### Evidence notes
- Ref/caller validation for this lane:
  - `GetNeighborTileIndexOnMap108x60` and `GetCityRegionIdAtTileIndex` are used by `BuildCityRegionBorderOverlaySegments`.
  - `RandomizeRegionTemplateBanksForMismatchedNeighborClasses` is called from `RebuildCoarseCellNeighborTransitionState`.
  - `GenerateCityRegionIdsBySeedAndNeighborPropagation` is called from `ReindexType5CellsAndRebuildRegionOverlays`.
  - `WrapExtendedMapXCoordinateInPlace` is used in map-border/segment geometry path (`FUN_0052b9b0`).
- Post-pass verification: unresolved `FUN_*`/`Cluster_*` in `0x00526b00..0x0052a900` is now `0`.

## TODO (next game-logic pass, refreshed)
- [ ] Continue in the same map-logic lane and rename `FUN_00525a30` (map-generation orchestrator with tuning-string parser) plus obvious helper thunks.
- [ ] Decode and rename `FUN_0052b9b0` (city-border segment scan/selection path) using the now-named coordinate wrap and route-pair helpers.
- [ ] Revisit class extraction around `g_vtblCityRegionGenerationCallbacks` (`0x00659920`) once a constructor/type-string anchor is identified.

## Continuation (2026-02-18, game-logic pass: map generation startup low-hanging)

### Additional renames applied (saved)
- `FUN_00525a30` -> `GenerateMapFromTuningStringAndApplyScenarioOverrides`
- `0x004037b0` -> `thunk_GenerateMapFromTuningStringAndApplyScenarioOverrides`
- `FUN_0050ec90` -> `BuildOrLoadGlobalMapStateForSession`
- materialized + renamed missing thunk stub:
  - `0x00401f7d` -> `thunk_BuildOrLoadGlobalMapStateForSession`

### Ghidra comments added
- Added function comments for:
  - `GenerateMapFromTuningStringAndApplyScenarioOverrides`
  - `BuildOrLoadGlobalMapStateForSession`

### Evidence notes
- `GenerateMapFromTuningStringAndApplyScenarioOverrides`:
  - parses tuning tokens (`@^>` gate and case variants) into generation weights/knobs,
  - loops generation attempts via helper passes,
  - recenters map via `RotateMapColumnsByPeakCityTileDensity`,
  - applies scenario-name string overrides (e.g. Congo/Mirkwood/Yucatan checks) to post-generation terrain classes.
- `BuildOrLoadGlobalMapStateForSession`:
  - allocates/constructs the map-state object,
  - follows load-vs-generate branch,
  - invokes map generation path through the renamed thunk,
  - rebuilds route records and refreshes runtime/UI map views before returning success/failure.

## TODO (next game-logic pass, refreshed)
- [ ] Decode and rename `FUN_0052b9b0` (city-border segment scan/selection path) now that `WrapExtendedMapXCoordinateInPlace` and `GetCityRegionIdAtTileIndex` are named.
- [ ] Continue map-generation helper cleanup around `0x00526710/0x00526760/0x005267f0` and promote behavior-backed names only.
- [ ] Revisit class extraction around `g_vtblCityRegionGenerationCallbacks` (`0x00659920`) once a constructor/type-string anchor is identified.

## Continuation (2026-02-18, game-logic pass: map/overlay low-hanging rename waves)

### Additional renames applied (saved)
- Map-generation helper gate trio:
  - `FUN_00526710` -> `ValidateAllColumnsHaveAssignedRegionClass`
  - `FUN_00526760` -> `ValidateTerrainClassAdjacencyCoverageMask`
  - `FUN_005267f0` -> `ValidateSeedCandidateExistsForEachTerrainClass`
  - thunks normalized:
    - `0x00402536` -> `thunk_ValidateAllColumnsHaveAssignedRegionClass`
    - `0x00404d45` -> `thunk_ValidateTerrainClassAdjacencyCoverageMask`
    - `0x00406091` -> `thunk_ValidateSeedCandidateExistsForEachTerrainClass`

- TMapMaker object/class low-hanging:
  - `FUN_00525950` -> `GetTMapMakerRuntimeClassDescriptor`
  - `FUN_00525970` -> `ConstructTMapMaker`
  - `FUN_00525990` -> `DeleteTMapMaker`
  - `FUN_005259c0` -> `DestructTMapMaker`
  - thunks normalized:
    - `0x00402f77` -> `thunk_ConstructTMapMaker`
    - `0x0040225c` -> `thunk_DestructTMapMaker`

- Overlay span/quad container helper batch:
  - `FUN_0052b1e0` -> `InitializeOverlaySpanRecordSorted`
  - `FUN_0052b3e0` -> `ReserveOverlaySpanRecordArray18Capacity`
  - `FUN_0052b460` -> `GetOrCreateOverlaySpanRecordArray18Entry`
  - `FUN_0052b500` -> `DetachAndResetOverlaySpanRecordArray18Buffer`
  - `FUN_0052bef0` -> `ExtractWrappedEndpointFromSpanRecordBySide`
  - `FUN_0052c000` -> `SelectSpanEndpointXByThreshold`
  - `FUN_0052c030` -> `GetOverlaySpanRecordByIndex`
  - `FUN_0052c0a0` -> `AppendOverlayQuadRecord`
  - `FUN_0052c990` -> `ConvertTileIndexToOverlayCoord216BySide`
  - `FUN_0052ca00` -> `DetachAndResetOverlayQuadRecordArrayBuffer`
  - `FUN_0052ca20` -> `EmitOverlaySegmentFromTileEdgeSorted`
  - `FUN_0052d030` -> `ComputeWrappedOverlayCoordDeltaMetric`
  - `FUN_0052d0d0` -> `ReserveOverlayQuadRecordArrayCapacity`
  - `FUN_0052d150` -> `GetOrCreateOverlayQuadRecordByIndex`
  - matching thunk normalization applied for each direct thunk site (`0x00407efa`, `0x0040100f`, `0x00405b0a`, `0x00405cd1`, `0x00408cab`, `0x00402aa9`, `0x0040169f`, `0x00402275`, `0x00407a63`, `0x004068d9`, `0x00401087`, `0x00409408`, `0x0040974b`).

- Remaining high-confidence map/overlay logic helpers:
  - `FUN_0052ab00` -> `RecomputeOverlaySegmentEndpointsAndAngle`
  - `FUN_0052b220` -> `InitializeOverlaySegmentFromTwoMapCoords`
  - `FUN_0052b9b0` -> `AssignCityRegionIdsFromOverlayScanlineIntersections`
  - `FUN_0052cae0` -> `BuildOverlaySpanRecordsFromQuadBorderLinks`
  - `FUN_0052d4b0` -> `PropagateNegativeRegionLabelsByNeighborClass`
  - `FUN_0052d6b0` -> `RelabelNegativeRegionMarkersContiguously`
  - thunks normalized:
    - `0x004030e4` -> `thunk_InitializeOverlaySegmentFromTwoMapCoords`
    - `0x00401a55` -> `thunk_BuildOverlaySpanRecordsFromQuadBorderLinks`

### Ghidra comments added
- Added behavior comments to all newly named high-confidence non-thunk functions in the above batches (generation gate trio, TMapMaker ctor/dtor lane, overlay container helpers, and scanline/label propagation helpers).

### Evidence notes
- `BuildOverlaySpanRecordsFromQuadBorderLinks` is called by `ReindexType5CellsAndRebuildRegionOverlays` immediately after `BuildCityRegionBorderOverlaySegments`, confirming it as a border-link/span rebuild stage.
- `AssignCityRegionIdsFromOverlayScanlineIntersections` consumes span records and writes city-region class ids back into map tiles (`tile+0x04 = id + 0x17`) by scanline intersection selection.
- `PropagateNegativeRegionLabelsByNeighborClass` and `RelabelNegativeRegionMarkersContiguously` match the unresolved-label propagation/compaction phase used by region-id cleanup logic.

## TODO (next game-logic pass, refreshed)
- [ ] Resolve the final unresolved mini-corridor in `0x00525000..0x00525800`:
  - `FUN_005250a0`
  - `FUN_005252d0`
  - `FUN_005254a0`
  - `FUN_00525670`
  - `FUN_00525730`
- [ ] Rename `FUN_00512440` + `thunk_FUN_00512440` (projection helper) and fold `FUN_00525730` to that name lane once call intent is finalized.
- [ ] Revisit class extraction around `g_vtblCityRegionGenerationCallbacks` (`0x00659920`) once a constructor/type-string anchor is identified.

## Continuation (2026-02-18, class extraction pass: TMapMaker)

### TMapMaker class extraction applied (saved)
- Materialized missing vtable thunk slots and renamed:
  - `0x00406b72` -> `thunk_GetTMapMakerRuntimeClassDescriptor`
  - `0x00402158` -> `thunk_DeleteTMapMaker`
  - `0x00403396` -> `thunk_SmoothCityRegionOwnershipByNeighborSampling`
- Labeled class anchors:
  - `0x006598f8` -> `g_vtblTMapMaker`
  - `0x006598a8` -> `g_runtimeClass_TMapMaker`
  - `0x00659920` -> `g_vtblTMapMaker_CityRegionGenerationCallbacks`
- Added data comments at `g_vtblTMapMaker` and `g_runtimeClass_TMapMaker`.

### Namespace/class ownership extraction
- Created namespace: `TMapMaker`.
- Moved confirmed methods into `TMapMaker` namespace (`60` functions), including:
  - ctor/dtor/runtime class lane,
  - map-generation orchestrator and generation phases,
  - city-region id generation/compaction/smoothing,
  - overlay span/quad build and scanline assignment helpers.

### Evidence notes
- `g_vtblTMapMaker` slot walk confirms ownership of the previously decoded `0x00659920` callback lane.
- New thunk at `0x00403396` directly forwards to `SmoothCityRegionOwnershipByNeighborSampling`, which fills the previously unknown vtable slot at `g_vtblTMapMaker + 0x44`.

## TODO (next game-logic pass, refreshed)
- [ ] Finish the last unresolved helper mini-corridor in this lane:
  - `FUN_005250a0`
  - `FUN_005252d0`
  - `FUN_005254a0`
  - `FUN_00525670`
  - `FUN_00525730`
- [ ] Rename projection helper `FUN_00512440` + `thunk_FUN_00512440`, then fold `FUN_00525730` wrapper naming accordingly.
- [ ] Keep class extraction conservative for unresolved copy-kernel helpers until callsite evidence pins exact semantics.

## Continuation (2026-02-18, cleanup pass: final TMapMaker helper corridor + projection/key chain)

### Final unresolved TMapMaker mini-corridor resolved (saved)
- Resolved all remaining generic helpers in `0x00525000..0x00525800`:
  - `FUN_005250a0` -> `CopyDiamondMaskBlockKernel`
  - `FUN_005252d0` -> `CopyDiagonalMaskNarrowingBlockKernel`
  - `FUN_005254a0` -> `CopyDiagonalMaskWideningBlockKernel`
  - `FUN_00525670` -> `Copy64x64TileBlockWithStrideAdjustment`
  - `FUN_00525730` -> `ForwardProjectTileIndexToWrappedScreenOffsetByScale`
- Renamed projection helper lane:
  - `FUN_00512440` -> `ProjectTileIndexToWrappedScreenOffsetByScale`
- Materialized and renamed missing thunk wrappers:
  - `0x0040984f` -> `thunk_CopyDiamondMaskBlockKernel`
  - `0x0040648d` -> `thunk_CopyDiagonalMaskNarrowingBlockKernel`
  - `0x0040958e` -> `thunk_CopyDiagonalMaskWideningBlockKernel`
  - `0x00405812` -> `thunk_Copy64x64TileBlockWithStrideAdjustment`
  - `0x00402db5` -> `thunk_ForwardProjectTileIndexToWrappedScreenOffsetByScale`
  - `0x004056a5` -> `thunk_ProjectTileIndexToWrappedScreenOffsetByScale`

### Additional nearby chain cleanup (saved)
- Renamed the small link/context + key helper chain around `0x005121d0`:
  - `FUN_005121d0` -> `IsNodeTypeLinkUnavailableAndNoActiveMapActionContext`
  - `FUN_00517f80` -> `CollectSecondDegreeLinksMatchingNodeType`
  - `FUN_00564570` -> `FindMapActionContextContainingNodeByIndex`
  - `FUN_005122b0` -> `IsShiftKeyDown`
  - `FUN_005122d0` -> `IsAltKeyDown`
  - `FUN_005125a0` -> `SplitTileIndexToRowAndColumn`
- Materialized and renamed missing thunks:
  - `0x004093c7` -> `thunk_IsNodeTypeLinkUnavailableAndNoActiveMapActionContext`
  - `0x00405cbd` -> `thunk_IsShiftKeyDown`
  - `0x00403008` -> `thunk_IsAltKeyDown`
  - `0x00404313` -> `thunk_CollectSecondDegreeLinksMatchingNodeType`
  - `0x004066b3` -> `thunk_FindMapActionContextContainingNodeByIndex`
  - `0x00406c1c` -> `thunk_SplitTileIndexToRowAndColumn`

### Namespace updates
- Moved additional TMapMaker-related methods into `TMapMaker` namespace:
  - `ProjectTileIndexToWrappedScreenOffsetByScale`
  - `ForwardProjectTileIndexToWrappedScreenOffsetByScale`
  - copy-kernel helpers (`CopyDiamondMaskBlockKernel`, `CopyDiagonalMaskNarrowingBlockKernel`, `CopyDiagonalMaskWideningBlockKernel`, `Copy64x64TileBlockWithStrideAdjustment`)
  - `SplitTileIndexToRowAndColumn`

### Verification
- Post-pass generic scan:
  - `0x00525000..0x00525800`: `remaining 0`
  - `0x00512000..0x00512600`: `remaining 0`

## TODO (next game-logic pass, refreshed)
- [ ] Continue low-hanging cleanup for adjacent map-action and map-render helper lanes that still have isolated `FUN_*` names (outside the now-clean TMapMaker helper corridor).
- [ ] Backfill function signatures/parameter names for the newly named TMapMaker projection/copy kernels where arg roles are now stable (stride/source/dest/projection origin/scale).
- [ ] Keep class extraction conservative for non-TMapMaker lanes until constructor/vtable evidence is explicit.

## Continuation (2026-02-18, civilian actions focus: tile-improvement cursor/sprite mapping)

### Neo4j query findings (civilian improvement/action sprites)
- Improvement-capable civilian units (from `BUILDS_IMPROVEMENT`):
  - Engineer -> Fortification, Port, Rail Depot, Rail Line
  - Driller -> Oil Derrick
  - Miner -> Mine
  - Farmer -> Farm/Orchard/Plantation
  - Rancher -> Ranch/Sheep
  - Forester -> Hardwood Forest
- Civilian/map-order cursor resources confirmed:
  - 1001/raw 8 = Prospecting Cursor
  - 1002/raw 9 = Build Railway Horizontal Cursor
  - 1003/raw 10 = Build Improvement Cursor
  - 1004/raw 11 = Move Civilian Cursor
  - 1011/raw 18 = Busy Civilian Rescind Orders Cursor
  - 1018/raw 26 = Build Railway Diagonal Slash Cursor
  - 1019/raw 27 = Build Railway Diagonal Backslash Cursor
  - 1025/raw 32 = Developer Buy Tile Cursor
- Civilian command-panel bitmap IDs (Neo4j + function mappings):
  - 1199 (Next Unit), 1203 (No orders this turn), 1209 (Disband Civilian), 1211 (Sleep)
  - Civilian Report dialog background: 3012

### Ghidra updates applied (saved)
- Thunk normalization in civilian cursor-token lane:
  - `0x004043db` -> `thunk_LookupCivilianMapCursorTokenByStateIndex`
  - `0x00404b38` -> `thunk_LookupCivilianTileOrderCursorTokenByActionIndex`
  - `0x00401546` -> `thunk_ComputeCivilianMapCursorStateIndex`
  - `0x00406e83` -> `thunk_ComputeMapCursorStateIndex`
- Cursor-token table labels:
  - `0x00695668` -> `g_awMapCursorTokenByStateIndex`
  - `0x00695680` -> `g_awCivilianMapCursorTokenByStateIndex`
  - `0x00696678` -> `g_awCivilianTileOrderCursorTokenByActionIndex`
- Added behavior comments at:
  - `LookupCivilianMapCursorTokenByStateIndex` (`0x004a4aa0`)
  - `LookupCivilianTileOrderCursorTokenByActionIndex` (`0x004d2930`)
  - `ResolveCivilianTileOrderActionCode` (`0x004d2960`)
  - `UpdateMapCursorForTileAndAction` (`0x005958b0`)
  - plus PRE comments at the three cursor-token table addresses above.

### Additional nearby low-hanging cleanup (saved)
- Renamed helper chain around civilian/map selection checks:
  - `FUN_005121d0` -> `IsNodeTypeLinkUnavailableAndNoActiveMapActionContext`
  - `FUN_00517f80` -> `CollectSecondDegreeLinksMatchingNodeType`
  - `FUN_00564570` -> `FindMapActionContextContainingNodeByIndex`
  - `FUN_005122b0` -> `IsShiftKeyDown`
  - `FUN_005122d0` -> `IsAltKeyDown`
  - `FUN_005125a0` -> `SplitTileIndexToRowAndColumn`
  - with corresponding thunk normalization (`0x004093c7`, `0x00405cbd`, `0x00403008`, `0x00404313`, `0x004066b3`, `0x00406c1c`).

### Neo4j high-level sync
- Added high-level claim node:
  - `claim_civilian_cursor_token_tables_20260218`
- Claim links civilian cursor token-table behavior/action mapping to:
  - functions `0x005958b0`, `0x004d2930`, `0x004a4aa0`, `0x004d2960`
  - cursor group IDs `{1001,1002,1003,1004,1011,1018,1019,1025}`.

## TODO (next civilian-actions pass)
- [ ] Decode/annotate the immediate dispatcher that consumes `ResolveCivilianTileOrderActionCode` output and verify each action code path (`4..7/8/9/10/11`) against exact order packet/event builder calls.
- [ ] Promote key civilian cursor/token functions to cleaner prototypes with named parameters (tile index, click mode, action code, cursor token).
- [ ] If needed, split `g_awCivilianTileOrderCursorTokenByActionIndex` into an explicit typed array in Ghidra to lock first 12 active action slots.

## Continuation (2026-02-18, civilian action execution pass: improvements/rails)

### Neo4j query refresh (sprite IDs used by civilian tile actions)
- Confirmed cursor resource IDs for civilian improvement/action flow:
  - `1001` prospect, `1002` rail horizontal, `1003` build improvement, `1004` move/select civilian
  - `1011` busy/rescind report, `1018` rail diagonal `/`, `1019` rail diagonal `\\`

### Dispatcher decode and branch validation (saved)
- Verified full dispatcher chain for civilian tile clicks:
  - `HandleCivilianTileOrderAction` (`0x004d26d0`)
  - `ResolveCivilianTileOrderActionCode` (`0x004d2960`)
  - `HandleEngineerConstructionAction` (`0x004d3a60`)
  - `QueueCivilianWorkOrderWithCostCheck` (`0x004d3310`)
  - `PromptAndQueueEngineerRailOrder` (`0x004d3610`)
  - `HandleCivilianReportDecision` (`0x004d3070`)
- Confirmed action-code routing:
  - `2` select civilian, `3` direct assign/move
  - `4..7` engineer build/rail branch
  - `8` immediate order type `8`
  - `9` work-order queue with cost gate
  - `10` report/rescind path
  - `11` prompted rail-order dialog path

### Low-hanging type/comment cleanup (saved)
- Set `CanAssignCivilianOrderToTile` (`0x004d2f60`) return type from `undefined1` to `bool`.
- Added refreshed function comments for:
  - `ResolveCivilianTileOrderActionCode` (`0x004d2960`)
  - `HandleCivilianTileOrderAction` (`0x004d26d0`)
  - `HandleEngineerConstructionAction` (`0x004d3a60`)
- Typed `g_awCivilianTileOrderCursorTokenByActionIndex` at `0x00696678` as `word[12]`.
- Added PRE comment with explicit first-12 mapping:
  - `[0]=0, [1]=1008, [2]=0, [3]=1004, [4]=1003, [5]=1002, [6]=1018, [7]=1019, [8]=1001, [9]=1003, [10]=1011, [11]=1025`.

## TODO (next civilian-actions pass, refreshed)
- [ ] Identify/rename the function behind `g_pUiRuntimeContext` vfunc `+0xdc` used by `HandleEngineerConstructionAction` (returns `'rail'/'port'/'fort'` action tag).
- [ ] Lift civilian order-type constants in report/refund logic into named semantics (`5/6/7/10/12/13`) with short comments at callsites.
- [ ] Decode what action code `8` corresponds to in gameplay terms (likely unit-class specific special action) and map it to a named handler comment.

## Continuation (2026-02-18, civilian action pass: developer buy-tile lane correction)

### Key correction discovered (saved)
- Action code `11` in `ResolveCivilianTileOrderActionCode` maps to cursor `1025` (Developer Buy Tile), so the old `EngineerRail` naming in this lane was misleading.
- Assembly-level validation in `0x004d3610` confirmed order type `0x0d` is queued on confirm (`vfunc +0x34` with immediate `0x0d`) and cost is deducted immediately.

### Renames applied (saved)
- `0x00518b40`: `CalculateEngineerRailBuildCost` -> `CalculateDeveloperTilePurchaseCost`
- `0x004028b5`: `thunk_CalculateEngineerRailBuildCost` -> `thunk_CalculateDeveloperTilePurchaseCost`
- `0x004d3610`: `PromptAndQueueEngineerRailOrder` -> `PromptAndQueueDeveloperTilePurchaseOrder`
- `0x00403332`: `thunk_PromptAndQueueEngineerRailOrder` -> `thunk_PromptAndQueueDeveloperTilePurchaseOrder`
- `0x004d4740`: `FUN_004d4740` -> `ResolveCompetingDeveloperTilePurchaseOrders`
- `0x00404705`: `thunk_FUN_004d4740` -> `thunk_ResolveCompetingDeveloperTilePurchaseOrders`

### Comment and semantics sync (saved)
- Updated function comments for:
  - `HandleCivilianTileOrderAction` (`0x004d26d0`) to reflect action `11` as developer tile-purchase flow.
  - `ResolveCivilianTileOrderActionCode` (`0x004d2960`) action map (`11 -> 1025` developer buy tile).
  - `HandleCivilianReportDecision` (`0x004d3070`) order type `13` refund path wording.
  - `CalculateDeveloperTilePurchaseCost` (`0x00518b40`) cost model summary.
  - `PromptAndQueueDeveloperTilePurchaseOrder` (`0x004d3610`) prompt/queue summary.
  - `ResolveCompetingDeveloperTilePurchaseOrders` (`0x004d4740`) multi-order conflict resolution summary.

### Neo4j high-level sync
- Added claim:
  - `claim_civilian_action11_developer_tile_purchase_20260218`
- Claim states that action code `11` corresponds to cursor `1025` and dispatches the order type `13` developer tile-purchase lane.
- Linked to functions:
  - `0x004d2960`, `0x004d26d0`, `0x004d3610`, `0x00518b40`, `0x004d3070`, `0x004d4740`

## TODO (next civilian-actions pass, refreshed #2)
- [ ] Identify/rename the function behind `g_pUiRuntimeContext` vfunc `+0xdc` used by engineer same-tile build option selection (`'rail'/'port'/'fort'` tags).
- [ ] Lift remaining order-type constants into named semantics directly at order-issue callsites (`+0x34`): especially `5/6/7/8/10/12/13`.
- [ ] Decode action code `8` fully (cursor `1001` prospecting lane) and rename the immediate order-type-8 branch accordingly.

## Continuation (2026-02-18, civilian actions: vtable +0xDC helper resolution)

### TurnEventState / UiRuntimeContext vtable anchor
- Confirmed `ConstructGlobalTurnEventState` (`0x005d5060`) writes vtable pointer `0x0066f120` into `g_pUiRuntimeContext` instances.
- Confirmed slot `+0xDC` in `0x0066f120` points to thunk `0x004011a9` -> target `0x005dd0a0`.

### Renames applied (saved)
- `0x005dd0a0`:
  - `HandleTurnEventDialogFactorySlotDC` -> `ExecuteUiFactoryModalDialogAndReturnResultTag`
- `0x004011a9`:
  - `thunk_HandleTurnEventDialogFactorySlotDC` -> `thunk_ExecuteUiFactoryModalDialogAndReturnResultTag`

### Behavioral note
- `ExecuteUiFactoryModalDialogAndReturnResultTag` runs a UI factory transaction on the active view-manager dialog and returns the committed result tag.
- This is the exact vfunc lane used by the engineer same-tile build-option flow that yields `'rail'/'port'/'fort'` tag values consumed in `HandleEngineerConstructionAction`.

## TODO (next civilian-actions pass, refreshed #3)
- [ ] Lift remaining order-type constants into named semantics directly at order-issue callsites (`+0x34`): especially `5/6/7/8/10/12/13`.
- [ ] Decode action code `8` fully (cursor `1001` prospecting lane) and rename the immediate order-type-8 branch accordingly.
- [ ] Continue low-hanging civilian-game-logic cleanup around class-7 developer purchase AI/planning functions (`FUN_004c2120` and adjacent helpers) where semantics are now partially known.

## Continuation (2026-02-18, civilian actions: action-8 prospecting lane)

### Evidence chain completed
- `ResolveCivilianTileOrderActionCode` (`0x004d2960`) returns action code `8` on the class-id branch (`class 1` path) and maps to cursor `1001` (prospecting).
- `HandleCivilianTileOrderAction` (`0x004d26d0`) action-8 branch issues order type `8` via civilian-order vfunc `+0x34`, links target tile via `+0x30`, and plays SFX `0x232E`.
- `ApplyCompletedCivWorkOrderToMapState` (`0x004d4390`) confirms order type `8` completion behavior:
  - sets owner-visibility bit on tile
  - checks `CheckTileProspectingDiscoveryCandidate`
  - sets report message `0x232F` when discovery candidate path is valid for human nation flow.

### Renames/comments applied (saved)
- `0x004d39d0`: `FUN_004d39d0` -> `QueueProspectingOrderAndPlayFeedback`
  - return type set to `bool`
  - behavior comment added (queue order type `8`, SFX `0x232E`, short UI pump loop).
- Updated comments for:
  - `HandleCivilianTileOrderAction` (`0x004d26d0`)
  - `ResolveCivilianTileOrderActionCode` (`0x004d2960`)
  - `ApplyCompletedCivWorkOrderToMapState` (`0x004d4390`)
  to align action/cursor/order semantics with proven prospecting flow.

### Neo4j high-level sync
- Added claim:
  - `claim_civilian_action8_prospecting_order_20260218`
- Claim links action `8` <-> cursor `1001` <-> order type `8` completion semantics (visibility update + discovery message `0x232F`) to:
  - functions `0x004d2960`, `0x004d26d0`, `0x004d39d0`, `0x004d4390`, `0x0040375b`.

## TODO (next civilian-actions pass, refreshed #4)
- [ ] Lift remaining order-type constants into named semantics directly at order-issue callsites (`+0x34`): especially `5/6/7/10/12/13` (action-8 now resolved).
- [ ] Continue low-hanging civilian-game-logic cleanup around developer purchase AI/planning functions (`FUN_004c2120` and neighbors) using newly stabilized order-type/cursor semantics.
- [ ] Verify whether `QueueProspectingOrderAndPlayFeedback` (`0x004d39d0`) is an unreferenced duplicate helper or reachable via a missing thunk/function boundary; materialize/rename thunk if discovered.

## Continuation (2026-02-18, civilian logic: prospecting planner/thunk cleanup)

### Additional low-hanging renames (saved)
- `0x004c2120`:
  - `FUN_004c2120` -> `AutoAssignProspectingOrdersByTileHeuristics`
  - rationale: function scores candidate tiles with `CheckTileProspectingDiscoveryCandidate` and issues order type `8` via civilian order vfunc.
- `0x00405e2f`:
  - materialized missing no-function JMP wrapper as
  - `thunk_AutoAssignProspectingOrdersByTileHeuristics`
  - this now restores a clean call edge to `0x004c2120`.

### Comment refinement (saved)
- Updated `HandleEngineerConstructionAction` (`0x004d3a60`) comment to include inferred order-type mapping:
  - same-tile `'rail'` -> order type `6` (rail depot), `'port'` -> `7`, `'fort'` -> `12`
  - adjacent-tile rail section -> order type `5`.
- Updated `HandleCivilianReportDecision` (`0x004d3070`) comment with consistent refund mapping for `5/6/7/10/12/13`.

### Neo4j high-level sync
- Added claim:
  - `claim_auto_assign_prospecting_orders_20260218`
- Claim states `AutoAssignProspectingOrdersByTileHeuristics` appears to issue order type `8` prospecting assignments via heuristic tile scoring.
- Linked claim to cursor:
  - `group_cursor_id = 1001` (Prospecting Cursor).

## TODO (next civilian-actions pass, refreshed #5)
- [ ] Lift any remaining ambiguous order-type constants directly at order-issue callsites (`+0x34`) and convert to stable semantic comments where unresolved.
- [ ] Continue cleanup around developer-purchase/prospecting AI planning neighbors near `AutoAssignProspectingOrdersByTileHeuristics` (`0x004c2120`) and `ResolveCompetingDeveloperTilePurchaseOrders` (`0x004d4740`).
- [ ] Validate whether `QueueProspectingOrderAndPlayFeedback` (`0x004d39d0`) is dead duplicate vs reachable helper in another dispatch lane.

## Continuation (2026-02-18, civilian logic: land-sale/prospecting helper corridor)

### Low-hanging renames (saved)
- Prospecting candidate insert helper:
  - `0x004be000`: `FUN_004be000` -> `InsertScoredTileCandidateWithRandomTieBreak`
  - `0x00401fff`: `thunk_FUN_004be000` -> `thunk_InsertScoredTileCandidateWithRandomTieBreak`
- Land-sale payload helper (`TLandSaleEvent` lane):
  - `0x004e6710`: `FUN_004e6710` -> `InitializeLandSaleEventPayloadTileAndNation`
  - `0x0040791e`: `thunk_FUN_004e6710` -> `thunk_InitializeLandSaleEventPayloadTileAndNation`
- Land-sale event class-name helper:
  - `0x004e66f0`: `FUN_004e66f0` -> `GetLandSaleEventClassNamePointer`
  - `0x0040508d`: `thunk_FUN_004e66f0` -> `thunk_GetLandSaleEventClassNamePointer`
- Ring-priority map builder used by land-sale strategy tables:
  - `0x004ecbb0`: `FUN_004ecbb0` -> `BuildTileRingPriorityMapForNationTileList`
  - materialized no-function JMP wrapper:
    - `0x004071d0` -> `thunk_BuildTileRingPriorityMapForNationTileList`

### Land-sale event destructor lane (saved)
- `0x004d49d0`: `FUN_004d49d0` -> `DestructLandSaleEventToBase`
- `0x00408544`: `thunk_FUN_004d49d0` -> `thunk_DestructLandSaleEventToBase`
- `0x004d49a0`: `FUN_004d49a0` -> `DeleteLandSaleEvent`
- `0x00408ca1`: `thunk_FUN_004d49a0` -> `thunk_DeleteLandSaleEvent`

### Signature/comment cleanup (saved)
- `BuildTileRingPriorityMapForNationTileList` + thunk return type set to `byte *`.
- `AutoAssignProspectingOrdersByTileHeuristics` return type set to `void`.
- Added behavior comments to:
  - `InsertScoredTileCandidateWithRandomTieBreak`
  - `InitializeLandSaleEventPayloadTileAndNation`
  - `BuildTileRingPriorityMapForNationTileList`
  - `DestructLandSaleEventToBase`
  - `DeleteLandSaleEvent`

## TODO (next civilian-actions pass, refreshed #6)
- [ ] Investigate/rename `thunk_FUN_004d6b70` (called by `ShowCountryOrderTransferNotification`) after confirming exact string-slot formatting semantics.
- [ ] Keep pushing low-hanging renames in the land-sale/prospecting lane around `ResolveCompetingDeveloperTilePurchaseOrders` and adjacent helper callbacks.
- [ ] Validate whether `QueueProspectingOrderAndPlayFeedback` (`0x004d39d0`) is dead duplicate vs reachable helper in another dispatch lane.

## Continuation (2026-02-18, civilian logic: land-sale callback cleanup + orphan check)

### Additional renames (saved)
- Land-sale event helper/destructor lane:
  - `0x004d49d0`: `FUN_004d49d0` -> `DestructLandSaleEventToBase`
  - `0x00408544`: `thunk_FUN_004d49d0` -> `thunk_DestructLandSaleEventToBase`
  - `0x004d49a0`: `FUN_004d49a0` -> `DeleteLandSaleEvent`
  - `0x00408ca1`: `thunk_FUN_004d49a0` -> `thunk_DeleteLandSaleEvent`
- String-shared copy wrapper used by transfer notifications and other flows:
  - `0x004d6b70`: `FUN_004d6b70` -> `AssignStringSharedRefFromPointer`
  - `0x00407072`: `thunk_FUN_004d6b70` -> `thunk_AssignStringSharedRefFromPointer`
- Thunk normalization:
  - `0x00401307`: `ShowCountryOrderTransferNotification` -> `thunk_ShowCountryOrderTransferNotification`
    (real target remains `0x004e6740`).

### Signature/comment cleanup (saved)
- `BuildTileRingPriorityMapForNationTileList` (`0x004ecbb0`) return type set to `byte *` (matches allocated byte score-map usage).
- `AutoAssignProspectingOrdersByTileHeuristics` (`0x004c2120`) return type set to `void`.
- Added comments for:
  - `DestructLandSaleEventToBase`
  - `DeleteLandSaleEvent`
  - `AssignStringSharedRefFromPointer`

### QueueProspectingOrderAndPlayFeedback reachability result
- Per `.text` raw instruction/data scan and reference-manager check:
  - `0x004d39d0` has `0` references and no embedded literal pointer occurrences.
- Added explicit function comment marking it as likely orphan/dead duplicate helper of action-8 logic currently inlined in `HandleCivilianTileOrderAction`.

## TODO (next civilian-actions pass, refreshed #7)
- [ ] Continue low-hanging renames in the land-sale/prospecting lane around `ShowCountryOrderTransferNotification` and nearby formatting helpers (only where semantics are clear).
- [ ] Look for additional no-function thunk wrappers in this lane (like `0x004071d0`) and materialize/rename when directly referenced from data tables.
- [ ] Keep focus on game-logic naming/signature cleanup; avoid speculative UI-layer overreach.

## Continuation (2026-02-18, civilian logic: land-sale notification lane refinement)

### Renames applied (saved)
- Land-sale notification override:
  - `0x004e6740`: `ShowCountryOrderTransferNotification` -> `ShowLandSaleTransferNotification`
  - `0x00401307`: `thunk_ShowCountryOrderTransferNotification` -> `thunk_ShowLandSaleTransferNotification`
- Rationale:
  - same lane is tied to `TLandSaleEvent` (`GetLandSaleEventClassNamePointer`) and payload tag `'land'`.
  - function formats old/new terrain owner tokens and dispatches localized transfer notice.

### Reachability validation result retained
- `QueueProspectingOrderAndPlayFeedback` (`0x004d39d0`) remains marked as likely orphan/dead duplicate:
  - no code/data refs from reference manager
  - no literal pointer occurrences in `.text` scan
  - behavior duplicates the action-8 branch logic already in `HandleCivilianTileOrderAction`.

## TODO (next civilian-actions pass, refreshed #8)
- [ ] Continue low-hanging renames for nearby land-sale string-formatting helpers only when role is direct and reusable (avoid speculative template-token naming).
- [ ] Check for other data-referenced no-function JMP thunks in this corridor and materialize as needed.
- [ ] Keep game-logic-first focus: prioritize order/event state transitions and AI decision helpers over UI container internals.

## Continuation (2026-02-18, civilian logic: second prospecting auto-assign method)

### Renames applied (saved)
- `0x004c2a30`:
  - `FUN_004c2a30` -> `AutoAssignProspectingOrdersFromSeedTileNeighbors`
- `0x00408de6`:
  - materialized no-function JMP wrapper and named
  - `thunk_AutoAssignProspectingOrdersFromSeedTileNeighbors`

### Why this is safe
- `0x004c2a30` directly calls `CheckTileProspectingDiscoveryCandidate` and performs neighbor-based gating/scoring over a seed tile list before invoking assignment callback flow.
- `0x00408de6` is table-referenced data stub (multiple data refs in `0x00650978` family) and unconditionally jumps to `0x004c2a30`, matching standard thunk pattern in this binary.

### Signature/comment cleanup
- `AutoAssignProspectingOrdersFromSeedTileNeighbors` return type set to `void`.
- `thunk_AutoAssignProspectingOrdersFromSeedTileNeighbors` return type set to `void`.
- Added behavior comment to `AutoAssignProspectingOrdersFromSeedTileNeighbors` emphasizing seed-neighbor scan + assignment callback semantics.

### Post-pass validation
- In `0x004c0000..0x004f2000`, there are no remaining `FUN_*` functions directly tied to the cleaned prospecting/land-sale lane helpers:
  - `CheckTileProspectingDiscoveryCandidate`
  - `AutoAssignProspectingOrdersByTileHeuristics`
  - `AutoAssignProspectingOrdersFromSeedTileNeighbors`
  - `BuildTileRingPriorityMapForNationTileList`
  - `ResolveCompetingDeveloperTilePurchaseOrders`
  - `ShowLandSaleTransferNotification`
  - `InitializeLandSaleEventPayloadTileAndNation`

## TODO (next civilian-actions pass, refreshed #9)
- [ ] Continue low-hanging renames in adjacent event/AI helper tables around the `0x00650978` method-pointer family where behavior is directly recoverable.
- [ ] Keep class extraction conservative: only promote table families to class/namespace names when ctor/dtor/runtime-class evidence is explicit.
- [ ] Revisit broader civilian order-queue manager callbacks (`vfunc +0xb4` style sites) to lock down assignment semantics without speculative naming.

## Continuation (2026-02-18, civilian logic: neighbor primitive + table-linked method cleanup)

### Renames applied (saved)
- Neighbor primitive used by prospecting seed scan:
  - `0x00512cc0`: `FUN_00512cc0` -> `GetWrappedHexNeighborTileIndexByDirection`
  - `0x0040246e`: `thunk_FUN_00512cc0` -> `thunk_GetWrappedHexNeighborTileIndexByDirection`
- Additional table-linked method in prospecting corridor:
  - `0x004c2a30`: `FUN_004c2a30` -> `AutoAssignProspectingOrdersFromSeedTileNeighbors`
  - `0x00408de6`: materialized and named `thunk_AutoAssignProspectingOrdersFromSeedTileNeighbors`

### Why this is safe
- `GetWrappedHexNeighborTileIndexByDirection`:
  - takes `(tileIndex, direction)`,
  - normalizes direction into `0..5`,
  - applies row-parity offset tables,
  - clamps/wraps against map width/height (`108x60` logic),
  - returns `-1` on invalid/out-of-range final index.
- `AutoAssignProspectingOrdersFromSeedTileNeighbors`:
  - directly calls `CheckTileProspectingDiscoveryCandidate`,
  - walks neighbor tiles via the above primitive,
  - applies owner/terrain/resource gating before assignment callback flow.

### Signature/comment notes
- `AutoAssignProspectingOrdersFromSeedTileNeighbors` return type set to `void`.
- Thunk return type aligned to `void`.
- Added behavior comments for both methods.

## TODO (next civilian-actions pass, refreshed #10)
- [ ] Continue low-hanging renames in adjacent event/AI helper tables around the `0x00650978` method-pointer family where behavior is directly recoverable.
- [ ] Revisit broader civilian order-queue manager callbacks (`vfunc +0xb4` style sites) to lock down assignment semantics without speculative naming.
- [ ] Keep class extraction conservative: only promote table families to class/namespace names when ctor/dtor/runtime-class evidence is explicit.

## Continuation (2026-02-19, civilian class dehardcoding: miner/farmer/forester anchors)

### Goal of this pass
- Dehardcode productive civilian class semantics (especially Miner/Farmer/Forester) from implicit constants into explicit named comments and safe renames.

### Evidence stabilized
- University recruit-row builder and selection flow now used as class-id anchor:
  - `BuildUniversityRecruitmentRows` (`0x00475f84`) uses `civ*` tags (`0x63697630 + index`) with known bitmap IDs.
  - `SelectUniversityRecruitmentEntry` (`0x004cb320`) uses selected row index directly for recruit-entry slot mapping (`+0x22` base).
- Anchored class mapping:
  - `0` Miner (`civ0`, bitmap `9920`/`0x26C0`)
  - `1` Prospector (`civ1`, bitmap `9922`/`0x26C2`)
  - `2` Farmer (`civ2`, bitmap `9924`/`0x26C4`)
  - `3` Forester (`civ3`, bitmap `9926`/`0x26C6`)
  - `4` Engineer (`civ4`, bitmap `9928`/`0x26C8`)
  - `5` Rancher (`civ5`, bitmap `9930`/`0x26CA`)
  - `7` Developer
  - `8` Driller (`civ8`, bitmap `9936`/`0x26D0`)

### Renames applied (saved)
- `0x004cb8a0`:
  - `FUN_004cb8a0` -> `HandleUniversityRecruitmentSelectionAndStepCommand`
- `0x00406aa5`:
  - materialized missing JMP thunk and named
  - `thunk_HandleUniversityRecruitmentSelectionAndStepCommand`

### Game-logic dehardcoding comments applied (saved)
- Added explicit civilian class-id mapping note to:
  - `ResolveCivilianTileOrderActionCode` (`0x004d2960`)
  - `CanAssignCivilianOrderToTile` (`0x004d2f60`)
  - `QueueCivilianWorkOrderWithCostCheck` (`0x004d3310`)
  - `HandleCivilianReportDecision` (`0x004d3070`)
  - `ApplyCompletedCivWorkOrderToMapState` (`0x004d4390`)
- Added specific `classId == 0 || classId == 8` clarification (Miner/Driller shared mining-mode branch) to:
  - `QueueCivilianWorkOrderWithCostCheck` (`0x004d3310`)
  - `HandleCivilianReportDecision` (`0x004d3070`)
  - `ApplyCompletedCivWorkOrderToMapState` (`0x004d4390`)

### Why this is low-risk
- No speculative behavior names were added in core simulation paths; changes are limited to one UI handler rename/thunk materialization and explicit comments tied to already-proven class/tag/icon anchors.
- Productive-lane behavior remains unchanged (action `9` -> order type `10`), now with explicit class semantics attached.

## TODO (next civilian class dehardcoding pass)
- [ ] Promote an explicit `ECivilianClassId` enum in key signatures/locals where variable role is already stable (start with `ResolveCivilianTileOrderActionCode`, `CanAssignCivilianOrderToTile`, `QueueCivilianWorkOrderWithCostCheck`).
- [ ] Find and rename the class-id-to-target-profile table usage in `RenderCivilianTargetProfilePanel` (`0x005903c0`) now that Miner/Farmer/Forester classes are anchored.
- [ ] Continue low-hanging order-type `10` path cleanup by replacing remaining implicit class checks with class-named comments at branch sites.

## Continuation (2026-02-19, enum + target-profile panel dehardcoding pass)

### Scope
- Continued civilian class dehardcoding with explicit enum/type work and low-risk function/data naming in the civilian target-profile panel lane.

### Enum/type dehardcoding (saved)
- Added enum datatype:
  - `ECivilianClassId` (`/Imperialism/Enums`)
  - values:
    - `0` Miner
    - `1` Prospector
    - `2` Farmer
    - `3` Forester
    - `4` Engineer
    - `5` Rancher
    - `7` Developer
    - `8` Driller
- Added struct datatype:
  - `TCivilianTargetProfilePanelContext` (`/Imperialism/Structs`)
  - key fields:
    - `+0x60` `eSelectedCivilianClassId : ECivilianClassId`
    - `+0x62` owner nation id
    - `+0x64..+0x6c` target-profile slot counters
- Applied signature improvement:
  - `RenderCivilianTargetProfilePanel` (`0x005903c0`) param0 typed as `TCivilianTargetProfilePanelContext *`.

### Low-hanging renames in panel lane (saved)
- `0x0058f550`: `FUN_0058f550` -> `RefreshCivilianTargetLegendBySelectedClass`
- `0x0058f7b0`: `FUN_0058f7b0` -> `RenderCivilianTargetLegendVariantA`
- `0x0058fec0`: `FUN_0058fec0` -> `RenderCivilianTargetLegendVariantB`
- Materialized/renamed thunks:
  - `0x00401fd7` -> `thunk_RefreshCivilianTargetLegendBySelectedClass`
  - `0x00407db5` -> `thunk_RenderCivilianTargetLegendVariantA`
  - `0x004030ad` -> `thunk_RenderCivilianTargetLegendVariantB`
  - `0x004042f5` -> `thunk_RenderCivilianTargetProfilePanel`

### Data table dehardcoding (saved)
- Typed and documented class-indexed tables:
  - `0x00698f58`: `g_anTargetTileProfileByCivilianClassAndSlot` as `short[45]`
  - `0x00698fe0`: `g_awCivilianTargetProfileVisibleSlotCountByClass` as `short[9]`
  - `0x00698fca`: `g_awCivilianCapabilityIconOffsetYPairBySlot` as `short[8]`
  - `0x00662b98`: `g_aiCivilianCapabilityRequirementIdByClassSlot` as `sdword[36]`
- Added PRE comments describing each table layout and class-index semantics.

### Comment propagation (saved)
- Added `ECivilianClassId` anchor comments to:
  - `UpdateCivilianOrderTargetTileCountsForOwnerNation` (`0x0058f3c0`)
  - `RenderCivilianTargetProfilePanel` (`0x005903c0`)
  - `RefreshCivilianTargetLegendBySelectedClass` (`0x0058f550`)
  - plus previously cleaned civilian order functions (`0x004d2960`, `0x004d3310`, `0x004d3070`, `0x004d4390`).

### Neo4j sync (high-level)
- Added/updated claims:
  - `claim_civilian_class_id_mapping_and_enum_anchor_20260219`
  - `claim_ecivilianclassid_enum_and_target_profile_panel_dehardcoded_20260219`
- Added concept node link:
  - `concept_civilian_target_profile_panel`
- Stored function-address and data-symbol lists on the enum/panel claim for traceability.

## TODO (next dehardcoding pass)
- [ ] Replace residual raw class-id branches in civilian order logic with enum-anchored variable/type names where Ghidra variable storage allows stable edits.
- [ ] Decode `RenderCivilianTargetLegendVariantA/B` semantics enough to rename from VariantA/B to behavior names (if evidence is direct).
- [ ] Apply `TCivilianTargetProfilePanelContext` typing to additional methods in this lane where call signatures are stable.

## Continuation (2026-02-19, enum pass follow-up: legend helpers + typed tables)

### Additional dehardcoding completed
- Confirmed and preserved enum typing on panel renderer signature:
  - `RenderCivilianTargetProfilePanel` (`0x005903c0`) keeps param0 type `TCivilianTargetProfilePanelContext *`.
- Renamed conservative legend helpers/thunks in the same lane:
  - `RefreshCivilianTargetLegendBySelectedClass` (`0x0058f550`)
  - `RenderCivilianTargetLegendVariantA` (`0x0058f7b0`)
  - `RenderCivilianTargetLegendVariantB` (`0x0058fec0`)
  - `thunk_RefreshCivilianTargetLegendBySelectedClass` (`0x00401fd7`)
  - `thunk_RenderCivilianTargetLegendVariantA` (`0x00407db5`)
  - `thunk_RenderCivilianTargetLegendVariantB` (`0x004030ad`)
  - `thunk_RenderCivilianTargetProfilePanel` (`0x004042f5`)
- Added behavior comments to the three legend helpers plus the panel renderer for table/enum usage.

### Typed-table status (retained)
- `g_anTargetTileProfileByCivilianClassAndSlot` -> `short[45]`
- `g_awCivilianTargetProfileVisibleSlotCountByClass` -> `short[9]`
- `g_awCivilianCapabilityIconOffsetYPairBySlot` -> `short[8]`
- `g_aiCivilianCapabilityRequirementIdByClassSlot` -> `sdword[36]`

### Constraint discovered (documented)
- Ghidra auto-parameters cannot be directly retagged (`InvalidInputException: Auto-parameter may not be modified`), so `UpdateCivilianOrderTargetTileCountsForOwnerNation` auto-`this` typing must be improved via broader function-signature/conv rewrite, not direct param edit.

### Neo4j sync update
- Updated claim:
  - `claim_ecivilianclassid_enum_and_target_profile_panel_dehardcoded_20260219`
- Added renamed-function list and refreshed statement to reflect enum + struct + legend helper dehardcoding.

## TODO (next dehardcoding pass, refreshed)
- [ ] Promote `ECivilianClassId` into more signatures by rewriting selected calling conventions/signatures where auto-`this` blocks direct param type edits.
- [ ] Resolve VariantA/VariantB to semantic names once class-specific dispatch evidence is explicit.
- [ ] Continue replacing remaining raw class-id comparisons in civilian order logic with enum-oriented naming/comments.

## Continuation (2026-02-19, dehardcoding pass: action/order enums + order-state struct)

### What was dehardcoded
- Added enum datatypes:
  - `ECivilianTileActionCode` (action dispatch values `0..11`, including engineer/prospect/report/developer branches)
  - `ECivilianWorkOrderType` (order semantics including `5/6/7/8/10/12/13`)
- Added struct datatype:
  - `TCivilianOrderState` (`/Imperialism/Structs`), with key typed fields:
    - `+0x04` `eCivilianClassId`
    - `+0x06` `nCurrentTileIndex`
    - `+0x08` `eCurrentWorkOrderType`
    - `+0x18` `nOwnerNationId`
    - `+0x26` `wQueuedReportMessageId`

### Signature propagation (saved)
- `ResolveCivilianTileOrderActionCode` (`0x004d2960`) return type -> `ECivilianTileActionCode`
- `HandleCivilianReportDecision` (`0x004d3070`) explicit order param -> `TCivilianOrderState *`
- `ApplyCompletedCivWorkOrderToMapState` (`0x004d4390`) param -> `TCivilianOrderState *`
- `UpdateCivilianOrderTargetTileCountsForOwnerNation` (`0x0058f3c0`) explicit order param -> `TCivilianOrderState *`

### Low-hanging function cleanup near map-interaction manager (saved)
- `0x004d2050`: `FUN_004d2050` -> `InitializeCivilianMapInteractionManagerVtable`
- `0x004092e1`: `thunk_FUN_004d2050` -> `thunk_InitializeCivilianMapInteractionManagerVtable`
- `0x004d20a0`: `FUN_004d20a0` -> `InitializeCivilianMapInteractionManagerBaseVtable`
- `0x00402f18`: `thunk_FUN_004d20a0` -> `thunk_InitializeCivilianMapInteractionManagerBaseVtable`
- `0x004d20c0`: `FUN_004d20c0` -> `NoOpCivilianMapInteractionManagerVirtualHook`
- `0x0040744b`: `thunk_FUN_004d20c0` -> `thunk_NoOpCivilianMapInteractionManagerVirtualHook`
- `0x004d2070`: `DestroyCivilianMapManager` -> `DeleteCivilianMapInteractionManager`

### Cursor token table typing pass (saved)
- Reapplied explicit array typing/comments:
  - `g_awCivilianTileOrderCursorTokenByActionIndex` (`0x00696678`) as `unsigned short[12]`, documented as `ECivilianTileActionCode` indexed cursor group IDs.
  - `g_awCivilianMapCursorTokenByStateIndex` (`0x00695680`) as `unsigned short[32]`, documented as state-index cursor token table.

### Neo4j high-level sync
- Added claim:
  - `claim_civilian_action_order_enums_and_orderstate_struct_20260219`
- Added concept link:
  - `concept_civilian_order_state`

## TODO (next dehardcoding pass, refreshed)
- [ ] Push `ECivilianWorkOrderType` into more local variable/type contexts in order queue/commit functions where Ghidra storage permits direct variable typing.
- [ ] Replace `RenderCivilianTargetLegendVariantA/B` names with behavior names after class-branch evidence is fully decoded.
- [ ] Continue class extraction opportunities when constructor/destructor pairs around civilian map interaction manager become explicit enough.

## Continuation (2026-02-19, signature normalization follow-up)

### Signature cleanup completed (saved)
- Normalized inferred-but-untyped signatures in civilian interaction lane:
  - `LookupCivilianTileOrderCursorTokenByActionIndex` (`0x004d2930`)
    - `__thiscall`, return `ushort`, params `short nTileIndex, short nInputHint`
  - `InitializeCivilianMapInteractionManagerVtable` (`0x004d2050`)
    - `__thiscall void(this)`
  - `InitializeCivilianMapInteractionManagerBaseVtable` (`0x004d20a0`)
    - `__thiscall void(this)`
  - `NoOpCivilianMapInteractionManagerVirtualHook` (`0x004d20c0`)
    - `__thiscall void(this)`
  - `DeleteCivilianMapInteractionManager` (`0x004d2070`)
    - `__thiscall`, return `void*`, param `byte bFreeHeapMemory`

### Why this matters
- Removes residual `unknown/params=0` metadata in this lane, making decompiler output stable and easier for next class-extraction/struct-typing passes.

### Neo4j sync update
- Updated claim `claim_civilian_action_order_enums_and_orderstate_struct_20260219` with the new function-rename/signature cleanup list.

## TODO (next pass, refined)
- [ ] Start class extraction attempt around CivilianMapInteractionManager using the now-clean ctor/base-vtable/delete trio (`0x004d2050`, `0x004d20a0`, `0x004d2070`).
- [ ] Continue enum-oriented cleanup in order queue paths: replace remaining magic numbers in comments/locals where direct variable typing is possible.
- [ ] Decode legend variant dispatch (`RenderCivilianTargetLegendVariantA/B`) enough to replace variant names with semantic names.

## Continuation (2026-02-20, map logic low-hanging: hotkey + military-power lane)

### Renames/comments applied and saved (direct pyghidra)
- Hotkey W selection-reset handler:
  - `0x004d49f0`: `FUN_004d49f0` -> `HandleMapHotkeyW_ResetSelectedActionableObjects`
  - `0x00402d74`: `thunk_FUN_004d49f0` -> `thunk_HandleMapHotkeyW_ResetSelectedActionableObjects`
  - Added function comment documenting exact behavior:
    - iterates active-nation selection entries,
    - for type IDs `2/3/4` calls virtual slot `+0x34` with `(0,0)`,
    - then conditionally cycles selection through `CycleMapInteractionSelectionAfterHandledClick`.
- Military power score/classification helpers:
  - `0x004d8430`: `FUN_004d8430` -> `ComputeSelectedMilitaryPowerScore`
  - `0x00402e32`: `thunk_FUN_004d8430` -> `thunk_ComputeSelectedMilitaryPowerScore`
  - `0x004d84b0`: `FUN_004d84b0` -> `ClassifyNationMilitaryPowerBandAgainstGlobalMean`
  - `0x0040132f`: `thunk_FUN_004d84b0` -> `thunk_ClassifyNationMilitaryPowerBandAgainstGlobalMean`
  - Added comments:
    - score helper sums per-entry weights from `DAT_00695cd4`,
    - classifier computes a `0..4` band via global mean/stddev across eligible nations with nation-base + selection contribution.

### Evidence anchors used for safety
- `HandleMapScreenHotkeyDispatch` (`0x00595130`) case `0x57/0x77` (`W/w`) calls thunk at `0x00402d74` with active nation context.
- `ComputeSelectedMilitaryPowerScore` is called from already named logic:
  - `EvaluateLocalizedScoreThresholdPredicateForNationValue` (`0x005308b0`)
  - `RecomputeNationOrderPriorityMetrics` (`0x0053fe30`)
  - `ShowPeriodicNationComparisonAdvisoryIfNeeded` (`0x00501be0`)
  - `CommitCityRecruitmentOrderDelta` (`0x004b73b0`)

### Deliberate deferral
- Did not rename iterator primitives at `0x00487ef0/0x00487f20/0x00487f40` yet.
  - They are heavily reused across many systems; call-convention/structure semantics are clear enough for use, but naming them narrowly right now would be risky without one more struct pass.

## TODO (next game-logic pass, refreshed)
- [ ] Type/rename the shared iterator-state struct used by `0x00487ef0/0x00487f20/0x00487f40`, then rename those helpers once name is generic and correct.
- [ ] Continue game-logic renames around callers of `ComputeSelectedMilitaryPowerScore` (`0x005308b0`, `0x0053fe30`, `0x00501be0`, `0x004b73b0`) focusing on low-hanging threshold/classification helpers.
- [ ] Revisit `HandleMapHotkeyW_ResetSelectedActionableObjects` signature once stable class type for `0x006a43dc` manager is extracted.

## Continuation (2026-02-20, game-logic lane continuation: order-priority helpers)

### Additional renames/comments applied and saved
- Shared linked-list cursor helper trio (widely reused):
  - `0x00487ef0` -> `InitializeLinkedListCursorFromOwnerHead`
  - `0x00401118` -> `thunk_InitializeLinkedListCursorFromOwnerHead`
  - `0x00487f20` -> `LinkedListCursorHasCurrent`
  - `0x00403620` -> `thunk_LinkedListCursorHasCurrent`
  - `0x00487f40` -> `AdvanceLinkedListCursor`
  - `0x00406d20` -> `thunk_AdvanceLinkedListCursor`
  - Added concise comments for each helper describing cursor-field behavior.
- Nation order-priority helper cluster used by `RecomputeNationOrderPriorityMetrics`:
  - `0x005505c0` -> `GetNavyPrimaryOrderListHead`
  - `0x0040793c` -> `thunk_GetNavyPrimaryOrderListHead`
  - `0x005505a0` -> `GetNavyOrderNormalizationBaseByNationType`
  - `0x004063e3` -> `thunk_GetNavyOrderNormalizationBaseByNationType`
  - `0x0054ff00` -> `ComputeNavyOrderPriorityContributionPercentByCategory`
  - `0x0040605f` -> `thunk_ComputeNavyOrderPriorityContributionPercentByCategory`
  - `0x0053cc10` -> `AccumulateUnitOrderPriorityVectorContribution`
  - `0x004072fc` -> `thunk_AccumulateUnitOrderPriorityVectorContribution`
  - Added comments to the four non-thunk functions documenting vector/category semantics.

### Signature hygiene (return types only, saved)
- `LinkedListCursorHasCurrent` (`0x00487f20`): return `bool`
- `ComputeSelectedMilitaryPowerScore` (`0x004d8430`): return `int`
- `ClassifyNationMilitaryPowerBandAgainstGlobalMean` (`0x004d84b0`): return `int`
- `ComputeNavyOrderPriorityContributionPercentByCategory` (`0x0054ff00`): return `uint`
- `GetNavyPrimaryOrderListHead` (`0x005505c0`): return `void *`

### Evidence anchors for this batch
- `RecomputeNationOrderPriorityMetrics` (`0x0053fe30`) directly:
  - iterates navy order list (`iVar6 = ...; iVar6 = *(int *)(iVar6 + 0x24)`),
  - requests per-order category contributions for categories `0..3`,
  - accumulates selected-unit contribution vectors through `0x0053cc10`.

## TODO (next game-logic pass, refreshed again)
- [ ] Improve parameter/calling-convention typing for the renamed cursor helper trio once iterator-state struct layout is formalized.
- [ ] Continue low-hanging renames in `ShowPeriodicNationComparisonAdvisoryIfNeeded` / `EvaluateLocalizedScoreThresholdPredicateForNationValue` around remaining unresolved predicates (`0x004e0770`, `0x00517c30`) after one more evidence pass.
- [ ] Revisit `HandleMapHotkeyW_ResetSelectedActionableObjects` to set stable signature (`this + activeNationId`) when the owning manager class is extracted.

## Continuation (2026-02-20, game-logic lane: recruitment spawn search)

### Renames/comments applied and saved
- Recruitment spawn tile search helpers:
  - `0x00514c80`: `FUN_00514c80` -> `FindReachableRecruitSpawnTileWithVisitedReset`
  - `0x00408251`: `thunk_FUN_00514c80` -> `thunk_FindReachableRecruitSpawnTileWithVisitedReset`
  - `0x00514cd0`: `FUN_00514cd0` -> `FindReachableRecruitSpawnTileRecursive`
  - `0x0040146a`: `thunk_FUN_00514cd0` -> `thunk_FindReachableRecruitSpawnTileRecursive`
- Added comments describing:
  - full visited-flag reset pass before search (`0x00514c80`),
  - recursive hex-neighbor flood/search with owner+blocking checks returning first valid tile or `-1` (`0x00514cd0`).

### Signature hygiene
- `FindReachableRecruitSpawnTileRecursive` (`0x00514cd0`) return type set to `short` (tile index / `-1` sentinel).

### Evidence anchors
- `CommitCityRecruitmentOrderDelta` (`0x004b73b0`) references this lane through thunk at `0x00408251`.
- `FindReachableRecruitSpawnTileWithVisitedReset` calls recursive helper and seeds it with:
  - start tile (`param_2`),
  - owner-like class/id byte from tile record,
  - mode flag (`param_3`), matching recursive constraint checks.

## TODO (next game-logic pass, refreshed once more)
- [ ] Continue narrowing unresolved scoring predicates in advisory/threshold lane (`0x004e0770`, `0x00517c30`) with one extra caller-context sweep before renaming.
- [ ] Improve parameter typing for `FindReachableRecruitSpawnTileWithVisitedReset` / `FindReachableRecruitSpawnTileRecursive` once tile/state structs are extracted.
- [ ] Revisit `HandleMapHotkeyW_ResetSelectedActionableObjects` signature (`this + activeNationId`) after manager-class extraction.

## Continuation (2026-02-20, advisory/runtime getter cleanup pass)

### Renames/comments applied and saved
- `0x004e0740`: `FUN_004e0740` -> `GetNationRuntimeCityBuildingProductionValueBySlot`
  - Comment: wrapper over `GetCityBuildingProductionValueBySlot` using nation runtime substate at `+0x894`.
- `0x004e0770`: `FUN_004e0770` -> `ComputeNationRuntimeAdvisoryMetricCase6`
  - `0x00401aaf`: `thunk_FUN_004e0770` -> `thunk_ComputeNationRuntimeAdvisoryMetricCase6`
  - Comment: metric extractor used by periodic nation-comparison advisory case-6 threshold checks.
- `0x004e06d0`: `FUN_004e06d0` -> `SumNationRuntimeFiveBucketValue44`
  - Comment: sums `+0x44` values across five runtime bucket pointers (`+0x104/+0x108/+0x10c/+0x110/+0x114`) in nation runtime substate (`+0x894`).

### Why these names are still conservative
- The `+0x894` substate is used very widely across city/diplomacy/turn systems.
- Kept names behavior-based and avoided overfitting to one gameplay interpretation until struct extraction provides stable semantic field names.

## TODO (next game-logic pass, refreshed yet again)
- [ ] Resolve/rename `0x00517c30` using one more caller-context pass; keep it behavior-based unless terrain-graph semantics become explicit.
- [ ] Improve parameter typing for recruitment spawn search helpers (`0x00514c80`, `0x00514cd0`) after tile/state struct extraction.
- [ ] Revisit `HandleMapHotkeyW_ResetSelectedActionableObjects` signature (`this + activeNationId`) once manager class extraction is stable.

## Continuation (2026-02-20, advisory/compatibility lane completed)

### Compatibility predicate dehardcoding
- Assembly-level decode confirmed `0x00517c30` is a `ret 0x8` boolean predicate with:
  - `ECX` object context (`0x006a43d4` callsite),
  - two stack args (source index + target code),
  - graph/list scan behavior over nation-linked descriptor records.
- Applied rename/comment/return-type:
  - `0x00517c30`: `FUN_00517c30` -> `IsNationCodeLinkedInNationGraph` (return `bool`)
  - `0x004090c5`: `thunk_FUN_00517c30` -> `thunk_IsNationCodeLinkedInNationGraph`

### Turn-hint helper pair cleanup
- `0x004ee540`: `FUN_004ee540` -> `ConstructObArrayWithVtable654D38`
  - `0x004066db`: `thunk_FUN_004ee540` -> `thunk_ConstructObArrayWithVtable654D38`
- `0x004ee5c0`: `FUN_004ee5c0` -> `InitializeObArrayVtable654D38ModeField`
  - `0x00406901`: `thunk_FUN_004ee5c0` -> `thunk_InitializeObArrayVtable654D38ModeField`
- Added comments noting vtable anchor (`0x654d38`) and the explicit `+0x14 = 4` mode literal.

### Coverage status
- `QueueTurnEventHintActionsByNationMetricsAndCompatibility` now has zero `FUN_` unresolved direct callees.
- Previously targeted lane functions are now fully cleaned of direct `FUN_` call edges:
  - `CommitCityRecruitmentOrderDelta`
  - `RecomputeNationOrderPriorityMetrics`
  - `ShowPeriodicNationComparisonAdvisoryIfNeeded`
  - `EvaluateLocalizedScoreThresholdPredicateForNationValue`
  - `QueueTurnEventHintActionsByNationMetricsAndCompatibility`

## TODO (next game-logic pass, refreshed)
- [ ] Improve parameter typing for `HandleMapHotkeyW_ResetSelectedActionableObjects` (`this + activeNationId`) and for shared linked-list cursor helpers once iterator struct layout is formalized.
- [ ] Extract/label the `+0x894` nation runtime sub-struct fields to replace current behavior-based getter names with semantic field names.
- [ ] Continue low-hanging game-logic around adjacent advisory/diplomacy metric handlers (`0x004e0fe0`, `0x004e1170`, `0x004e1300`, `0x004e1490`, `0x004e1f40`, `0x004e7cc0`, `0x004e7ec0`).

## Continuation (2026-02-20, diplomacy advisory dispatch-table structural pass)

### Advisory handler cluster renamed (targets + thunk islands)
- Metric/action handlers (comments added):
  - `0x004e0fe0` -> `ComputeAdvisoryMetric23CNormalizedBySelectionAndPeers`
  - `0x004e1170` -> `ComputeAdvisoryMatrixRatio23CByTargetSlot`
  - `0x004e1300` -> `ComputeAdvisoryMetric240NormalizedBySelectionAndPeers`
  - `0x004e1490` -> `ComputeAdvisoryMatrixRatio240ByTargetSlot`
  - `0x004e1f40` -> `ComputeAdvisoryPeerAdjustedNationMetricRatio`
  - `0x004e7cc0` -> `ExecuteAdvisoryCaseActionType1ForEligibleNations`
  - `0x004e7ec0` -> `ExecuteAdvisoryCaseActionType2OrQueueFallback`
- Materialized and renamed thunk-island entries:
  - `0x00407617`, `0x004074c3`, `0x00407a6d`, `0x004045de`, `0x00409101`, `0x004062f8`, `0x00403efe`
  - all now mapped as `thunk_*` names to the handlers above.

### Dispatch table labels added
- Created labels:
  - `0x006542d0` -> `g_apfnDiplomacyAdvisoryHandlerDispatchTable`
  - `0x00654300` -> `g_apfnDiplomacyAdvisoryActionHandlerSubtable`
  - variants:
    - `0x00653b80` -> `g_apfnDiplomacyAdvisoryHandlerDispatchTableVariantA`
    - `0x0065b620` -> `g_apfnDiplomacyAdvisoryHandlerDispatchTableVariantB`
    - `0x0065b970` -> `g_apfnDiplomacyAdvisoryHandlerDispatchTableVariantC`
    - `0x0065bcc8` -> `g_apfnDiplomacyAdvisoryHandlerDispatchTableVariantD`
    - `0x0065b2c0` -> `g_apfnDiplomacyAdvisoryHandlerDispatchTableVariantE`

### Case-indexed cleanup for previously generic handlers
- Renamed with explicit case anchors (comments note case index and table source):
  - `0x004e0c10` -> `ComputeAdvisoryHandlerCase00Metric`
  - `0x004e0d80` -> `ComputeAdvisoryHandlerCase01Metric`
  - `0x004e0e70` -> `ComputeAdvisoryHandlerCase02Metric`
  - `0x004e1620` -> `ComputeAdvisoryHandlerCase07Metric`
  - `0x004e1750` -> `ComputeAdvisoryHandlerCase08Metric`
  - `0x004e1910` -> `ComputeAdvisoryHandlerCase09Metric`
  - `0x004e1a40` -> `ComputeAdvisoryHandlerCase10Metric`
  - `0x004e8040` -> `ExecuteAdvisoryHandlerCase11`
  - `0x004e9a50` -> `ExecuteAdvisoryHandlerCase16`
- Materialized/renamed corresponding thunk entries:
  - `0x0040956b`, `0x004011f4`, `0x00401a05`, `0x00401aaa`, `0x00407b2b`, `0x00406929`, `0x00404e3f`, `0x00409331`, `0x004086c5`.

### Additional action-lane low-hanging renames
- `0x004e1c20` -> `TryValidateProposalAndQueueInterNationEvent1C`
- `0x004e9ed0` -> `QueueWarTransitionFromAdvisoryAction`
- `0x004ea300` -> `MarkNationPortZoneAndLinkedTilesForActionFlag`
- `0x004e2630` -> `ApplyMinorNationCapabilityActionType6`
- `0x004e2720` -> `ApplyMinorNationCapabilityActionType4`
- plus thunk entries:
  - `0x00405439`, `0x00408bcf`, `0x00406235`, `0x00403706`, `0x00406e3d`.

### Entry-18/tracked-entry cleanup
- `0x004eb0d0` -> `PruneInvalidTrackedEntriesAndNotifyOwner` (commented)
- `0x00407568` -> `thunk_PruneInvalidTrackedEntriesAndNotifyOwner`
- `0x004ebea0` -> `thunk_PruneInvalidTrackedEntriesAndNotifyOwner_Dispatch`
- dispatch-table entry thunk:
  - `0x00405565` -> `thunk_PruneInvalidTrackedEntriesAndNotifyOwner_DispatchTableEntry`
- remaining table thunks completed:
  - `0x00402b0d` -> `thunk_ReleaseAllTrackedObjectsFromList89C`
  - `0x00406492` -> `thunk_ReleaseTrackedObjectsByMapOwnerAndUnassignedEntries`

### Coverage result
- `g_apfnDiplomacyAdvisoryHandlerDispatchTable` entries `0..23` now resolve to named functions/thunks.
- Verification pass reports `unresolved_count = 0` for `FUN_*/thunk_FUN_*` within this 24-entry dispatch set.

## TODO (next game-logic pass, post-dispatch cleanup)
- [ ] Improve signatures/parameter names for case-based advisory handlers (especially case `11` and `16`) once argument roles are decoded from top-level callers.
- [ ] Extract/label the `+0x894` nation-runtime sub-struct field groups to replace case/helper names with domain semantics.
- [ ] Continue low-hanging non-UI game logic near this lane: `FUN_004eae70` caller chain and adjacent turn-state handlers for more behavior names.

## Continuation (2026-02-20, diplomacy advisory tables completed across all variants)

### Additional dehardcoding and naming
- Renamed advisory pre-replan pass:
  - `0x004eae70`: `FUN_004eae70` -> `RefreshTrackedEntriesAndReplanAiDevelopment`
  - Added comment explaining: initialize/update entries, per-entry refresh callbacks, prune invalid entries, then replan AI development.

### Case 13/14 action prompt handlers renamed
- `0x004e1d50` -> `ExecuteAdvisoryPromptAndApplyActionType1` (return typed `bool`)
- `0x004e1e40` -> `ExecuteAdvisoryPromptAndApplyActionType2OrFallback` (return typed `bool`)
- Thunks:
  - `0x00403c15` -> `thunk_ExecuteAdvisoryPromptAndApplyActionType1` (`bool`)
  - `0x00402bda` -> `thunk_ExecuteAdvisoryPromptAndApplyActionType2OrFallback` (`bool`)

### Variant-table helper/stub cleanup
- Target/helper renames:
  - `0x004e1c00` -> `ReturnFalseNoOpAdvisoryHandler` (`bool`)
  - `0x004e25c0` -> `ResetNationDiplomacySlotsAndMarkRelatedNations`
  - `0x004e27b0` -> `DispatchNationDiplomacySlotActionByMode`
  - `0x004e1f20` -> `NoOpAdvisoryHandlerReturn` (materialized from single `RET`)
  - `0x00541a20` -> `NoOpGreatPowerCommandHandlerRet4` (materialized from `RET 4`)
- Thunk/materialization + rename pass:
  - `0x00405826` -> `thunk_ReturnFalseNoOpAdvisoryHandler`
  - `0x00406c9e` -> `thunk_ResetNationDiplomacySlotsAndMarkRelatedNations`
  - `0x0040487c` -> `thunk_DispatchNationDiplomacySlotActionByMode`
  - `0x00407e8c` -> `thunk_NoOpAdvisoryHandlerReturn`
  - `0x00408067` -> `thunk_NoOpGreatPowerCommandHandlerRet4`
  - `0x004061ea` -> `thunk_HandleHostGreatPowerLostStateAndNotifyOrEndSession`
  - `0x00406edd` -> `thunk_ApplyClientGreatPowerCommand69AndEmitTurnEvent1E`
  - `0x00408279` -> `thunk_ApplyClientGreatPowerCommand61AndEmitTurnEvent1E`
  - `0x004052a4` -> `thunk_EmitTurnEvent1DCommand69ForCurrentNationSlot`
  - `0x00405240` -> `thunk_EmitTurnEvent1DCommand61ForCurrentNationSlot`

### Coverage milestone
- Verified all 24 entries resolve to named functions/thunks in each advisory dispatch table variant:
  - `0x006542d0`
  - `0x00653b80`
  - `0x0065b620`
  - `0x0065b970`
  - `0x0065bcc8`
  - `0x0065b2c0`
- Verification status: `total_unresolved = 0` (`FUN_*`/`thunk_FUN_*`/missing across these sets).

## TODO (next game-logic pass, refreshed after full table coverage)
- [ ] Decode high-value case handlers `ExecuteAdvisoryHandlerCase11` (`0x004e8040`) and `ExecuteAdvisoryHandlerCase16` (`0x004e9a50`) enough to replace case names with semantic action names.
- [ ] Improve signatures/parameter names for case-based advisory handlers (especially `0x004e0c10`, `0x004e1620`, `0x004e1750`, `0x004e1910`, `0x004e1a40`) now that dispatch mappings are stable.
- [ ] Start structured extraction of nation runtime sub-struct at `+0x894` to convert behavior names into identity-based field/type names.

## Continuation (2026-02-20, tracked-entry replan helper dehardcoding)

### Renames/comments applied and saved
- Replan helper subpasses renamed from generic `FUN_*`:
  - `0x004eb6b0`: `FUN_004eb6b0` -> `UpdateTrackedEntryEligibilityByClassMaskAndRatio`
  - `0x004eb8b0`: `FUN_004eb8b0` -> `AssignTrackedEntryActionsByProfileToOrdersOrUnits`
  - `0x00535940`: `FUN_00535940` -> `FindFirstTrackedHandlerMatchingModeAndShortKey`
  - `0x004eafa0`: `FUN_004eafa0` -> `SeedTrackedEntryAssignmentsFromEligibleUnits`
- Matching thunk wrappers renamed:
  - `0x0040745a` -> `thunk_UpdateTrackedEntryEligibilityByClassMaskAndRatio`
  - `0x00409633` -> `thunk_AssignTrackedEntryActionsByProfileToOrdersOrUnits`
  - `0x00408e86` -> `thunk_FindFirstTrackedHandlerMatchingModeAndShortKey`
- Materialized missing thunk function and renamed:
  - `0x00407577` (new function created at JMP island) -> `thunk_RefreshTrackedEntriesAndReplanAiDevelopment`

### Signature hygiene
- Set `void` return type for:
  - `UpdateTrackedEntryEligibilityByClassMaskAndRatio`
  - `thunk_UpdateTrackedEntryEligibilityByClassMaskAndRatio`
  - `AssignTrackedEntryActionsByProfileToOrdersOrUnits`
  - `thunk_AssignTrackedEntryActionsByProfileToOrdersOrUnits`
  - `SeedTrackedEntryAssignmentsFromEligibleUnits`
  - `thunk_RefreshTrackedEntriesAndReplanAiDevelopment`
- Set `void *` return type for:
  - `FindFirstTrackedHandlerMatchingModeAndShortKey`
  - `thunk_FindFirstTrackedHandlerMatchingModeAndShortKey`

### Why these names are safe
- `UpdateTrackedEntryEligibilityByClassMaskAndRatio`:
  - two-pass scan over tracked entries,
  - class-mask gating from byte `+0x11`,
  - ratio threshold compare through vfunc `+0x6c`,
  - suppression toggle through vfunc `+0x94` with inverted boolean.
- `AssignTrackedEntryActionsByProfileToOrdersOrUnits`:
  - resets per-entry transient state (vfunc `+0x98`),
  - computes normalized profile vectors from vfunc `+0x2c`,
  - attempts navy-order matching first (vfunc `+0x7c` + assign via `+0x84`),
  - falls back to unit-target matching (vfunc `+0x78` + assign via `+0x80`).
- `FindFirstTrackedHandlerMatchingModeAndShortKey`:
  - list-scan helper that runs pre-check (`+0xc`) and predicate (`+0x4c`) and returns first matching handler pointer.
- `SeedTrackedEntryAssignmentsFromEligibleUnits`:
  - runs movement-class-0 filtering and seeds handler linkage via `FindFirstTrackedHandlerMatchingModeAndShortKey` + vfunc `+0x80`.

### Integration result
- `RefreshTrackedEntriesAndReplanAiDevelopment` now decompiles with named call chain:
  - `thunk_PruneInvalidTrackedEntriesAndNotifyOwner`
  - `thunk_UpdateTrackedEntryEligibilityByClassMaskAndRatio`
  - `thunk_AssignTrackedEntryActionsByProfileToOrdersOrUnits`
  - `thunk_PlanAiDevelopmentActionsFromResourcePools`

## TODO (next game-logic pass, refreshed)
- [ ] Continue in same lane: decode and rename next helper(s) adjacent to replan flow (start with `0x005742b0` via thunk island `0x00407572`) using the same behavior-first naming style.
- [ ] Decode/rename one of the unresolved targets in the nearby thunk island (`0x00430bf0`, `0x00487b60`, `0x00430b00`) if direct behavior is obvious; otherwise skip and move to next easy pass.
- [ ] Revisit `FindFirstTrackedHandlerMatchingModeAndShortKey` parameters once one additional caller cluster is decoded, then set meaningful param names/types if stable.

## Continuation (2026-02-20, advisory map-action game-logic pass)

### Scope decision
- Checked TODO-adjacent thunk target `0x005742b0` (via `0x00407572`): this lane is UI/DC clipping/paint setup (region/DC operations), not game-logic.
- Skipped it per current priority (game logic first), then moved to advisory case logic around case `11` and `16`.

### Renames/comments applied and saved
- Advisory case handlers:
  - `0x004e8040`: `ExecuteAdvisoryHandlerCase11` -> `EvaluateAdvisoryCase11TriggerByPeerAdjustedNationMetrics`
  - `0x00409331`: `thunk_ExecuteAdvisoryHandlerCase11` -> `thunk_EvaluateAdvisoryCase11TriggerByPeerAdjustedNationMetrics`
  - `0x004e9a50`: `ExecuteAdvisoryHandlerCase16` -> `SelectAndQueueAdvisoryMapMissionsCase16`
  - `0x004086c5`: `thunk_ExecuteAdvisoryHandlerCase16` -> `thunk_SelectAndQueueAdvisoryMapMissionsCase16`
- Case-16 helper cluster:
  - `0x004e8540`: `FUN_004e8540` -> `QueueDiplomacyMissionFromAdvisorySelectionAndMarkState`
  - `0x004014a6`: `thunk_FUN_004e8540` -> `thunk_QueueDiplomacyMissionFromAdvisorySelectionAndMarkState`
  - `0x004e8c50`: `FUN_004e8c50` -> `ComputeAdvisoryMapNodeCompositeScoreByMode`
  - `0x004099e9`: `thunk_FUN_004e8c50` -> `thunk_ComputeAdvisoryMapNodeCompositeScoreByMode`
  - `0x004e9060`: `FUN_004e9060` -> `ComputeMapActionContextCompositeScoreForNation`
  - `0x00406915`: `thunk_FUN_004e9060` -> `thunk_ComputeMapActionContextCompositeScoreForNation`
  - `0x00517dd0`: `FUN_00517dd0` -> `HasDirectOrFallbackLinkedNodeType`
  - `0x004023b5`: `thunk_FUN_00517dd0` -> `thunk_HasDirectOrFallbackLinkedNodeType`
  - `0x00518090`: `FUN_00518090` -> `CollectSecondDegreeLinksWithMinorNationFallback`
  - `0x00403a7b`: `thunk_FUN_00518090` -> `thunk_CollectSecondDegreeLinksWithMinorNationFallback`
  - `0x0055f4d0`: `FUN_0055f4d0` -> `ContainsPointerArrayEntryMatchingByteKey`
  - `0x0040408e`: `thunk_FUN_0055f4d0` -> `thunk_ContainsPointerArrayEntryMatchingByteKey`

### Added behavior comments
- Added concise function comments to:
  - `EvaluateAdvisoryCase11TriggerByPeerAdjustedNationMetrics`
  - `SelectAndQueueAdvisoryMapMissionsCase16`
  - `QueueDiplomacyMissionFromAdvisorySelectionAndMarkState`
  - `ComputeAdvisoryMapNodeCompositeScoreByMode`
  - `ComputeMapActionContextCompositeScoreForNation`
  - `HasDirectOrFallbackLinkedNodeType`
  - `CollectSecondDegreeLinksWithMinorNationFallback`
  - `ContainsPointerArrayEntryMatchingByteKey`

### Coverage result for this slice
- Verified direct callsites inside:
  - `EvaluateAdvisoryCase11TriggerByPeerAdjustedNationMetrics`
  - `SelectAndQueueAdvisoryMapMissionsCase16`
- Remaining direct `FUN_*`/`thunk_FUN_*` callees in both: `0`.

## TODO (next game-logic pass, refreshed)
- [ ] Continue map/diplomacy game-logic by decoding `thunk_FindMapActionContextContainingNodeByIndex` target and related context-list helpers to replace remaining context-selection ambiguity with semantic names.
- [ ] Revisit function prototypes for the newly renamed case-16 helper cluster (especially `QueueDiplomacyMissionFromAdvisorySelectionAndMarkState` and `ComputeAdvisoryMapNodeCompositeScoreByMode`) once one more caller layer is decoded.
- [ ] If map-action lane stalls, pivot back to tracked-entry replan neighbor helpers around `RefreshTrackedEntriesAndReplanAiDevelopment` and grab next easy non-UI rename batch.

## Continuation (2026-02-20, map-action context lookup follow-up)

### Result
- Audited `thunk_FindMapActionContextContainingNodeByIndex` (`0x004066b3`) target (`0x00564570`).
- Target is already semantically named/commented as `FindMapActionContextContainingNodeByIndex`.
- No rename needed in this micro-pass; behavior remains: iterate `g_pMapActionContextListHead`, return first context containing node record pointer (`globalMapState + nodeIndex*0xa8`), else `0`.

## TODO (next game-logic pass, refined)
- [ ] Decode/rename unresolved callers around `FindMapActionContextContainingNodeByIndex` (map-action context selection producers/consumers) rather than the lookup itself.
- [ ] Improve prototypes for the case-16 helper cluster where argument roles are now clearer (mission type/node/context ids) without overfitting uncertain fields.
- [ ] If this lane slows down, switch back to tracked-entry replan neighbors for another easy non-UI batch.

## Continuation (2026-02-20, case-16 map-action helper extraction)

### Renames/comments applied and saved
- Case-16 candidate-state builder + thunk:
  - `0x004e92b0`: `Cluster_MapHint_004e92b0` -> `PopulateCase16AdvisoryMapNodeCandidateState`
  - `0x00402e5f`: `Cluster_MapHint_004e92b0` -> `thunk_PopulateCase16AdvisoryMapNodeCandidateState`
- Local CObArray helper pair used by candidate-state builder:
  - `0x004d6590`: `FUN_004d6590` -> `ConstructObArrayWithVtable653810`
  - `0x00409372`: `thunk_FUN_004d6590` -> `thunk_ConstructObArrayWithVtable653810`
  - `0x004d6610`: `FUN_004d6610` -> `InitializeObArrayVtable653810ModeField`
  - `0x00405b50`: `thunk_FUN_004d6610` -> `thunk_InitializeObArrayVtable653810ModeField`
- Context/link predicates and lookup typing:
  - Kept `IsNodeTypeLinkUnavailableAndNoActiveMapActionContext`, set return type to `bool` (+ thunk at `0x004093c7`)
  - Kept `FindMapActionContextContainingNodeByIndex`, set return type to `void *` (+ thunk at `0x004066b3`)

### Additional helper extraction in same scoring lane
- Shared case-metric score factor helper:
  - `0x004e8750`: `FUN_004e8750` -> `ComputeAdvisoryMapNodeScoreFactorByCaseMetric`
  - `0x00401ad2`: `thunk_FUN_004e8750` -> `thunk_ComputeAdvisoryMapNodeScoreFactorByCaseMetric`
- Navy-order accumulation helpers:
  - `0x004e0460`: `FUN_004e0460` -> `SumNavyOrderPriorityForNationAndNodeType`
  - `0x0040716c`: `thunk_FUN_004e0460` -> `thunk_SumNavyOrderPriorityForNationAndNodeType`
  - `0x004e04b0`: `FUN_004e04b0` -> `SumNavyOrderPriorityForNation`
  - `0x0040440d`: `thunk_FUN_004e04b0` -> `thunk_SumNavyOrderPriorityForNation`
- Map-action context value helpers:
  - `0x0055f140`: `FUN_0055f140` -> `ComputeMapActionContextNodeValueAverage`
  - `0x00401172`: `thunk_FUN_0055f140` -> `thunk_ComputeMapActionContextNodeValueAverage`
  - `0x00564530`: `FUN_00564530` -> `ComputeGlobalMapActionContextNodeValueAverage`
  - `0x00404f07`: `thunk_FUN_00564530` -> `thunk_ComputeGlobalMapActionContextNodeValueAverage`
- Weighted-link score mini-cluster:
  - `0x004a5aa0`: `FUN_004a5aa0` -> `ComputeWeightedNeighborLinkScoreForNodeIndex`
  - `0x0040226b`: `thunk_FUN_004a5aa0` -> `thunk_ComputeWeightedNeighborLinkScoreForNodeIndex`
  - `0x004d8390`: `FUN_004d8390` -> `ComputeWeightedNeighborLinkScoreForNode`
  - `0x00406271`: `thunk_FUN_004d8390` -> `thunk_ComputeWeightedNeighborLinkScoreForNode`
  - `0x004d83c0`: `FUN_004d83c0` -> `SumWeightedNeighborLinkScoreForLinkedNodes`
  - `0x00408ef9`: `thunk_FUN_004d83c0` -> `thunk_SumWeightedNeighborLinkScoreForLinkedNodes`

### Signature hygiene applied
- `void`:
  - `SelectAndQueueAdvisoryMapMissionsCase16` (+ thunk)
  - `PopulateCase16AdvisoryMapNodeCandidateState` (+ thunk)
  - `QueueDiplomacyMissionFromAdvisorySelectionAndMarkState` (+ thunk)
  - `InitializeObArrayVtable653810ModeField` (+ thunk)
- `float`:
  - `ComputeAdvisoryMapNodeScoreFactorByCaseMetric` (+ thunk)
  - `ComputeAdvisoryMapNodeCompositeScoreByMode` (+ thunk)
  - `ComputeMapActionContextCompositeScoreForNation` (+ thunk)
- `bool`:
  - `IsNodeTypeLinkUnavailableAndNoActiveMapActionContext` (+ thunk)
  - `HasDirectOrFallbackLinkedNodeType` (+ thunk)
  - `ContainsPointerArrayEntryMatchingByteKey` (+ thunk)
- `int`/`uint`:
  - `CollectSecondDegreeLinksWithMinorNationFallback` (+ thunk) -> `int`
  - `SumNavyOrderPriorityForNationAndNodeType` (+ thunk) -> `int`
  - `SumNavyOrderPriorityForNation` (+ thunk) -> `int`
  - `ComputeGlobalMapActionContextNodeValueAverage` (+ thunk) -> `int`
  - `ComputeMapActionContextNodeValueAverage` (+ thunk) -> `uint`
  - weighted-link helper cluster (`ComputeWeightedNeighborLinkScore...`) -> `int`
- `void *`:
  - `ConstructObArrayWithVtable653810` (+ thunk)
  - `FindMapActionContextContainingNodeByIndex` (+ thunk)

### Coverage status after this pass
- Verified key case-16 lane functions have zero direct unresolved call edges (`FUN_*` / `thunk_FUN_*` / missing):
  - `SelectAndQueueAdvisoryMapMissionsCase16`
  - `PopulateCase16AdvisoryMapNodeCandidateState`
  - `ComputeAdvisoryMapNodeCompositeScoreByMode`
  - `ComputeAdvisoryMapNodeScoreFactorByCaseMetric`

## TODO (next game-logic pass, refreshed)
- [ ] Decode and rename `thunk_GetField30Value` target in the case-metric helper denominator path (likely global eligible-count style metric) if evidence is direct.
- [ ] Improve parameter names/prototypes in the case-16 cluster (`mission type`, `node index`, `context pointer`, `nation slot`) now that helper names are stabilized.
- [ ] Continue adjacent non-UI map/diplomacy logic by following callers of `ComputeMapActionContextNodeValueAverage` and `ComputeGlobalMapActionContextNodeValueAverage` for next easy behavior-based renames.

## Continuation (2026-02-20, ambitious case-16 mission-factory terminology correction)

### Neo4j-assisted context alignment (high-level only)
- Queried Neo4j diplomacy/process concepts (`DiplomaticAction`, `ProcessStep`) to avoid naming drift.
- Result: kept high-level framing as advisory/AI process, but corrected local lane naming from misleading "diplomacy mission" wording to "map-action mission" object factory semantics.

### Core rename correction (saved)
- Field getter in score denominator path:
  - `0x005811e0`: `GetField30Value` -> `GetInt32Field30`
  - `0x00401b86`: `thunk_GetField30Value` -> `thunk_GetInt32Field30`
- Mission factory lane:
  - `0x005350d0`: `CreateMissionByKindAndContext` -> `CreateMissionObjectByKindAndNodeContext`
  - `0x00404e99`: `thunk_CreateMissionByKindAndContext` -> `thunk_CreateMissionObjectByKindAndNodeContext`
  - `0x004e8540`: `QueueDiplomacyMissionFromAdvisorySelectionAndMarkState` -> `QueueMapActionMissionFromCandidateAndMarkState`
  - `0x004014a6`: thunk renamed accordingly
- Mission-constructor branches (factory sub-lane):
  - `0x0053c0a0` -> `ConstructTArmyMissionWithNodeKey` (+ thunk `0x004064a1`)
  - `0x0053d780` -> `ConstructArmyMissionVariantAdf8` (+ thunk `0x00405c8b`)
  - `0x0053f2d0` -> `ConstructArmyMissionVariantAec0WithOptionalBeachhead` (+ thunk `0x004082bf`)
  - `0x00539a20` -> `ConstructMissionVariantAab0ForPortContext` (+ thunk `0x0040322e`)
  - `0x0053ab50` -> `ConstructBlockadePortMissionForContext` (+ thunk `0x004071a3`)
- Residual helper in factory switch:
  - `0x0053eff0` -> `ClearMissionStateByte11`
  - `0x004038aa` -> `thunk_ClearMissionStateByte11`

### Adjacent caller-lane extraction (saved)
- Port-zone context scoring methods calling map-action context average helpers:
  - `0x005387f0` -> `RecomputeAndClearMissionScoreUsingPortZoneContextAverage`
  - `0x00408f67` -> `thunk_RecomputeAndClearMissionScoreUsingPortZoneContextAverage`
  - `0x00539290` -> `ComputeMissionScoreUsingPortZoneContextAverage`
  - `0x0040787e` -> `thunk_ComputeMissionScoreUsingPortZoneContextAverage` (materialized)
  - `0x00539ca0` -> `ComputeNationScaledMissionScoreUsingPrimaryPortContextAverage`
  - `0x004037ec` -> `thunk_ComputeNationScaledMissionScoreUsingPrimaryPortContextAverage` (materialized)
  - `0x0053ace0` -> `RecomputeAndClearMissionScoreUsingPortZoneContextAverageVariantB`
  - `0x00407ced` -> `thunk_RecomputeAndClearMissionScoreUsingPortZoneContextAverageVariantB` (materialized)
- Small owner-code accessor used in the above:
  - `0x00561b90` -> `GetPortZoneOwnerNationCodeFromMissionField48`
  - `0x00403585` -> `thunk_GetPortZoneOwnerNationCodeFromMissionField48`

### Signature hygiene in this pass
- `GetInt32Field30` (+ thunk): return `int`
- `CreateMissionObjectByKindAndNodeContext` (+ thunk): return `void *`
- Mission-constructor branch helpers (+ thunks): return `void *`
- `ClearMissionStateByte11` (+ thunk): return `void`
- Port-zone score recomputation methods (+ thunks): return `void`
- `GetPortZoneOwnerNationCodeFromMissionField48` (+ thunk): return `short`

### Coverage status (post-pass verification)
- Zero direct unresolved (`FUN_*`/`thunk_FUN_*`/missing) in:
  - `SelectAndQueueAdvisoryMapMissionsCase16`
  - `PopulateCase16AdvisoryMapNodeCandidateState`
  - `QueueMapActionMissionFromCandidateAndMarkState`
  - `CreateMissionObjectByKindAndNodeContext`
  - `ComputeAdvisoryMapNodeCompositeScoreByMode`
  - `ComputeAdvisoryMapNodeScoreFactorByCaseMetric`
- Also cleared direct unresolved edges in the newly renamed port-zone score mini-cluster.

### Neo4j high-level update
- Added/updated concept:
  - `Concept{id:'concept_case16_map_action_mission_selection'}`
- Linked 6 key functions via `[:IMPLEMENTS]` with source `ghidra_pass_2026-02-20`:
  - `0x004e9a50`, `0x004e92b0`, `0x004e8c50`, `0x004e8750`, `0x004e8540`, `0x005350d0`

## TODO (next game-logic pass, refreshed)
- [ ] Decode missionKind semantics (`0..5`) in `CreateMissionObjectByKindAndNodeContext` by tracing mission class vtables (`0x65adf8`, `0x65aec0`, `0x65aab0`, `0x65a740`, `0x65a5a8`) to replace variant-style names with identity names.
- [ ] Apply parameter names/prototypes for the case-16 chain (`missionKind`, `nodeIndex`, `contextPtr`, `auxKey`) now that factory behavior is stable.
- [ ] Continue from callers of `ConstructArmyMissionVariantAdf8` / `ConstructArmyMissionVariantAec0WithOptionalBeachhead` for next high-confidence mission-logic renames.

## Continuation (2026-02-20, ambitious mission-class semantic upgrade from class-name getters)

### Scope
- Continued in the case-16 map-action mission factory lane.
- Goal for this pass: replace address-based mission-variant naming with identity-based class names using direct evidence from slot-0 class-name getter strings.

### Direct evidence used
- Slot-0 methods return pointers to class-name string pointers:
  - `0x00538780` -> `0x6979b0` -> `"TControlSeaZoneMission"`
  - `0x005399b0` -> `0x6979c8` -> `"TEscortMission"`
  - `0x0053bb20` -> `0x697a10` -> `"TScatteredShipsMission"`
  - `0x0053d710` -> `0x697a40` -> `"TAttackProvinceMission"`
  - `0x0053f260` -> `0x697a70` -> `"TInvadeMission"`
- Allocation + vtable-install factories confirmed by constructor patterns:
  - `Create*` functions allocate (`AllocateWithFallbackHandler`), call base constructor, then install class vtable.

### Renames applied and saved (Ghidra)
- Class-object factories:
  - `0x005386c0`: `FUN_005386c0` -> `CreateTControlSeaZoneMission`
  - `0x00539840`: `FUN_00539840` -> `CreateTEscortMission`
  - `0x0053ba60`: `FUN_0053ba60` -> `CreateTScatteredShipsMission`
  - `0x0053d670`: `FUN_0053d670` -> `CreateTAttackProvinceMission`
  - `0x0053f080`: `FUN_0053f080` -> `CreateTInvadeMission`
- Class-name getters (slot 0) + thunks:
  - `GetControlSeaZoneMissionClassName` (`0x00538780`) + thunk `0x00402e2d`
  - `GetEscortMissionClassName` (`0x005399b0`) + thunk `0x004027a2`
  - `GetScatteredShipsMissionClassName` (`0x0053bb20`) + thunk `0x004015cd`
  - `GetAttackProvinceMissionClassName` (`0x0053d710`) + thunk `0x00401e10`
  - `GetInvadeMissionClassName` (`0x0053f260`) + thunk `0x0040984a`
- Class-specific vtable slot methods + thunks:
  - `TControlSeaZoneMission_VtblSlot04` (`0x005355f0`) + thunk `0x004030a3`
  - `TEscortMission_VtblSlot04` (`0x00539960`) + thunk `0x004094a3`
  - `TScatteredShipsMission_VtblSlot04` (`0x005356a0`) + thunk `0x00403e86`
  - `TAttackProvinceMission_VtblSlot04` (`0x0053d7c0`) + thunk `0x00406e6a`
  - `TInvadeMission_VtblSlot04` (`0x0053f3c0`) + thunk `0x00406488`
  - `TAttackProvinceMission_VtblSlot14` (`0x0053d810`) + thunk `0x00405ef7`
  - `TInvadeMission_VtblSlot14` (`0x0053f640`) + thunk `0x00405f65`
  - `TAttackProvinceMission_VtblSlot18` (`0x0053d850`) + thunk `0x00404926`
  - `TInvadeMission_VtblSlot18` (`0x0053f690`) + thunk `0x00406a96`
  - `TAttackProvinceMission_VtblSlot1C` (`0x0053d890`) + thunk `0x00408599`
  - `TInvadeMission_VtblSlot1C` (`0x0053f410`) + thunk `0x00401505`
- Constructor naming cleanup tied to class identity:
  - `0x00539a20`: `ConstructMissionVariantAab0ForPortContext` -> `ConstructTEscortMissionForPortContext`
  - `0x0040322e`: thunk renamed accordingly
  - `0x0053d780`: `ConstructArmyMissionVariantAdf8` -> `ConstructTAttackProvinceMission`
  - `0x00405c8b`: thunk renamed accordingly
  - `0x0053f2d0`: `ConstructArmyMissionVariantAec0WithOptionalBeachhead` -> `ConstructTInvadeMissionWithOptionalBeachhead`
  - `0x004082bf`: thunk renamed accordingly

### Vtable label renames (data)
- `0x0065a740`: `g_vtblMissionVariantA740` -> `g_vtblTControlSeaZoneMission`
- `0x0065aab0`: `g_vtblMissionVariantAab0` -> `g_vtblTEscortMission`
- `0x0065a5a8`: `g_vtblMissionVariantA5a8` -> `g_vtblTScatteredShipsMission`
- `0x0065adf8`: `g_vtblMissionVariantAdf8` -> `g_vtblTAttackProvinceMission`
- `0x0065aec0`: `g_vtblMissionVariantAec0` -> `g_vtblTInvadeMission`

### Additional low-hanging structural cleanup
- Materialized missing thunk function at `0x00401000` (jmp island) and named:
  - `thunk_CreateTEscortMission` -> `JMP 0x00539840`

### Signature/comment hygiene
- Set return type to `void *` for create/construct factories where allocation/constructor pattern is explicit:
  - `CreateTControlSeaZoneMission`, `CreateTEscortMission`, `CreateTScatteredShipsMission`, `CreateTAttackProvinceMission`, `CreateTInvadeMission`
  - `ConstructTEscortMissionForPortContext`, `ConstructTAttackProvinceMission`, `ConstructTInvadeMissionWithOptionalBeachhead`
- Added concise comments to the core factory and class-creation functions:
  - `CreateMissionObjectByKindAndNodeContext`
  - `CreateTControlSeaZoneMission`, `CreateTEscortMission`, `CreateTScatteredShipsMission`, `CreateTAttackProvinceMission`, `CreateTInvadeMission`

### Verification
- Re-checked unresolved direct call edges for key lane functions:
  - `CreateMissionObjectByKindAndNodeContext`
  - all five `CreateT*Mission` functions
- Result: direct unresolved (`FUN_*`/`thunk_FUN_*`/missing) = `0` for this slice.

### Neo4j (high-level only)
- Added concept + claim for mission class taxonomy and missionKind mapping:
  - `Concept{id:'concept_map_action_mission_class_taxonomy'}`
  - `Claim{id:'claim_map_action_mission_kind_to_class_mapping_2026_02_20'}`
- Linked key functions via `(:Function)-[:IMPLEMENTS]->(:Claim)` for:
  - `0x005350d0`, `0x005386c0`, `0x00539840`, `0x0053ba60`, `0x0053d670`, `0x0053f080`

## TODO (next game-logic pass, refreshed)
- [ ] Decode missionKind `3` branch fallback split in `CreateMissionObjectByKindAndNodeContext` to name the non-escort `TMission` fallback path explicitly.
- [ ] Decode/rename class-specific behavior slots beyond slot04/14/18/1C where still generic in mission classes (prioritize `TControlSeaZoneMission` and `TEscortMission`).
- [ ] Continue from callers/users of `CreateTAttackProvinceMission` and `CreateTInvadeMission` to identify concrete world-map action semantics (attack vs invade decision points).
- [ ] If easy, materialize additional thunk-island entries adjacent to `0x00401000` when they are direct single-jump wrappers to already named game-logic functions.

## Continuation (2026-02-20, missionKind branch refinement)

### Result
- Closed the pending ambiguity in missionKind `3` branch of `CreateMissionObjectByKindAndNodeContext`.
- Confirmed fallback class is `TControlSeaZoneMission` (explicit vtable install `g_vtblTControlSeaZoneMission`), not generic `TMission`.

### Refined conditional mapping (factory `0x005350d0`)
- `kind 0`: `contextPtr != 0` -> `TControlSeaZoneMission`, else -> `TAttackProvinceMission`
- `kind 1`: `TAttackProvinceMission`
- `kind 2`: `auxKey == 0` -> `TControlSeaZoneMission`, else -> `TInvadeMission`
- `kind 3`: `contextPtr == FindFirstPortZoneContextByNation(...)` -> `TEscortMission`, else -> `TControlSeaZoneMission`
- `kind 4`: `TBlockadePortMission`
- `kind 5`: `TScatteredShipsMission`

### Saved updates
- Updated function comment on `CreateMissionObjectByKindAndNodeContext` with full conditional mapping.
- Updated Neo4j claim statement (`claim_map_action_mission_kind_to_class_mapping_2026_02_20`) to the refined conditional map.

## TODO (next game-logic pass, refined)
- [ ] Rename/annotate branch-input parameters in `CreateMissionObjectByKindAndNodeContext` (`missionKind`, `contextPtr`, `auxKey`) once one stable caller confirms stack slot roles.
- [ ] Continue from callers/users of `CreateTAttackProvinceMission` and `CreateTInvadeMission` to recover concrete decision semantics for attack vs invade selection.
- [ ] Decode `TControlSeaZoneMission_VtblSlot04` / `TEscortMission_VtblSlot04` behavior to replace slot names with semantic names if behavior is direct.

## Continuation (2026-02-20, mission destructor lane low-hanging renames)

### Scope
- Focused on slot-04 mission-class methods after class identity extraction.
- Pattern is consistent scalar-deleting-destructor flow:
  - call class-specific reset helper,
  - conditional free via `FreeHeapBufferIfNotNull` when delete-flag bit0 is set,
  - return `this`.

### Renames applied and saved
- Class destructors (former slot-04 names):
  - `DestroyTControlSeaZoneMission` (`0x005355f0`) + thunk `0x004030a3`
  - `DestroyTEscortMission` (`0x00539960`) + thunk `0x004094a3`
  - `DestroyTScatteredShipsMission` (`0x005356a0`) + thunk `0x00403e86`
  - `DestroyTAttackProvinceMission` (`0x0053d7c0`) + thunk `0x00406e6a`
  - `DestroyTInvadeMission` (`0x0053f3c0`) + thunk `0x00406488`
  - `DestroyTNavyMission` (`0x00535560`) + thunk `0x00402531` (materialized)
  - `DestroyTBlockadePortMission` (`0x0053aa90`) + thunk `0x00401fdc` (materialized)
  - `DestroyTArmyMission` (`0x0053c1d0`) + thunk `0x00406d7f` (materialized)
- Reset helpers that install sentinel vtable (`0x66fec4`) before delete path:
  - `ResetTControlSeaZoneMissionToSentinelVtable` (`0x00535620`) + thunk `0x00405e84`
  - `ResetTEscortMissionToSentinelVtable` (`0x00539990`) + thunk `0x00401a23`
  - `ResetTScatteredShipsMissionToSentinelVtable` (`0x005356d0`) + thunk `0x00402a31`
  - `ResetTAttackProvinceMissionToSentinelVtable` (`0x0053d7f0`) + thunk `0x00405e6b`
  - `ResetTInvadeMissionToSentinelVtable` (`0x0053f3f0`) + thunk `0x004022fc`
  - `ResetTNavyMissionToSentinelVtable` (`0x00535590`) + thunk `0x004044da`
  - `ResetTBlockadePortMissionToSentinelVtable` (`0x0053aac0`) + thunk `0x00401ac3`
  - `ResetTArmyMissionToSentinelVtable` (`0x0053c200`) + thunk `0x00407b94`

### Signature/comment hygiene
- Set return type `void *` for all `Destroy*Mission` functions and their thunks.
- Set return type `void` for all `Reset*ToSentinelVtable` functions and thunks.
- Added concise comments on key mission-class destructors to document scalar-deleting-destructor behavior.

### Verification
- Spot-checked all renamed addresses and signatures; names now resolve consistently in vtable slot-04 families and associated reset thunks.

### Neo4j policy
- No Neo4j sync for this pass (low-level naming hygiene only; no new high-level concept).

## TODO (next game-logic pass, refreshed)
- [ ] Continue attack/invade decision semantics by tracing callers of `CreateTAttackProvinceMission` and `CreateTInvadeMission`.
- [ ] Decode `TControlSeaZoneMission_VtblSlot14/18/...` behavior (and escort equivalents) and replace residual slot names when behavior is direct.
- [ ] Rename and type one stable caller of `CreateMissionObjectByKindAndNodeContext` to lock parameter roles (`missionKind`, `contextPtr`, `auxKey`) from callsite evidence.

## Continuation (2026-02-20, mission serialization/deserialization lane)

### Scope
- Continued game-logic extraction in mission-class vtable slots previously labelled as numeric slots.
- Focused on slot14/slot18 behavior for army/attack/invade classes.

### Renames applied and saved
- Base mission stream I/O:
  - `SerializeTMission` (`0x00535820`) + thunk `0x0040245a`
  - `DeserializeTMission` (`0x005358a0`) + thunk `0x00405ec5`
- Army mission stream I/O:
  - `SerializeTArmyMission` (`0x0053c2b0`) + thunk `0x00407ec8`
  - `DeserializeTArmyMission` (`0x0053c3d0`) + thunk `0x00407653`
- Attack mission stream I/O:
  - `SerializeTAttackProvinceMission` (`0x0053d810`) + thunk `0x00405ef7`
  - `DeserializeTAttackProvinceMission` (`0x0053d850`) + thunk `0x00404926`
- Invade mission stream I/O:
  - `SerializeTInvadeMission` (`0x0053f640`) + thunk `0x00405f65`
  - `DeserializeTInvadeMission` (`0x0053f690`) + thunk `0x00406a96`
- Linked-list index helper used by army mission serialization:
  - `FindOneBasedNodeIndexByValueInLinkedList` (`0x00487e10`) + thunk `0x004062e4`

### Behavior evidence summary
- `SerializeTMission` / `DeserializeTMission` use stream callback vfuncs (`+0x78` write / `+0x3c` read) with version guards.
- `SerializeTArmyMission` / `DeserializeTArmyMission` extend base mission serialization with extra state and linked payload list handling.
- `SerializeTAttackProvinceMission` / `DeserializeTAttackProvinceMission` serialize/deserialize mission-specific 16-bit fields at `+0x30/+0x32` on top of army mission base.
- `SerializeTInvadeMission` / `DeserializeTInvadeMission` do the same and additionally process optional beachhead mission child state (`+0x34`), including reconstruction in deserialize path.

### Signature/comment hygiene
- Set return type `void` for all serialize/deserialize functions and their thunks in this lane.
- Added concise function comments for mission serialization methods.
- Set `int` return type and comment for `FindOneBasedNodeIndexByValueInLinkedList`.

### Verification
- Unresolved direct callees (`FUN_*` / `thunk_FUN_*` / missing) reduced to `0` for:
  - `SerializeTArmyMission`
  - `DeserializeTArmyMission`
  - `SerializeTAttackProvinceMission`
  - `DeserializeTAttackProvinceMission`
  - `SerializeTInvadeMission`
  - `DeserializeTInvadeMission`

### Neo4j (high-level)
- Added concept + claim for mission persistence pipeline:
  - `Concept{id:'concept_map_action_mission_serialization'}`
  - `Claim{id:'claim_mission_serialization_methods_2026_02_20'}`
- Linked key functions via `(:Function)-[:IMPLEMENTS]->(:Claim)`:
  - `0x00535820`, `0x005358a0`, `0x0053c2b0`, `0x0053c3d0`, `0x0053f640`, `0x0053f690`

## TODO (next game-logic pass, refreshed)
- [ ] Decode and name reader/writer stream interface methods behind callback offsets (`+0x3c`, `+0x4c`, `+0x78`, `+0x88`) in mission serialization callers.
- [ ] Continue attack vs invade selection semantics by tracing callsites feeding constructor args (`+0x30/+0x32/+0x34`) in case-16 mission selection path.
- [ ] Resolve remaining generic helper names in invade deserialize branch around beachhead reconstruction if still ambiguous.

## Continuation (2026-02-20, embedded .cpp source-path research)

### Goal
- Investigate embedded `.cpp` file-name strings in `Imperialism.exe` and determine whether they are actionable code anchors.

### Artifacts generated
- `exports/cpp_string_research_20260220.json`
- `exports/cpp_string_research_20260220.md`
- `exports/cpp_string_function_map_20260220.json`
- `exports/cpp_string_function_map_20260220.md`
- `exports/cpp_string_indirect_refs_20260220.json`
- `exports/cpp_string_indirect_refs_20260220.md`

### Findings
- Detected `51` embedded `.cpp` path strings (mostly `D:\Ambit\...`).
- Direct code xrefs exist for a subset; top anchors by distinct functions:
  - `D:\Ambit\Cross\UCityViews.cpp` (`13` functions)
  - `D:\Ambit\McAppUI.cpp` (`13` functions)
  - `D:\Ambit\Cross\UDisplayMgr.cpp` (`4` functions)
  - `D:\Ambit\DirectPlay.cpp` (`3` functions)
- Diplomacy-specific anchor detected:
  - `D:\Ambit\DiplomacyDialogs.cpp` at `0x00694cc0` with direct code ref from `FUN_0047f3e0` (`PUSH file, line 0x3d`).
- Critical classification result:
  - All `57` functions that directly reference `.cpp` strings call the same assert/report routine at `0x004057a4`.
  - This indicates direct `.cpp` xrefs are assertion/debug guard wrappers, not core business logic implementations.
- For the remaining `.cpp` strings with `0` direct function refs (e.g., `UTradeViews.cpp`, `UDiplomacyViews.cpp`, `UArmyViews.cpp`), no robust non-executable pointer-table code path was recovered in this pass; they appear as passive string-pool remnants unless reached via currently unmodeled indirection.

### Practical takeaway for RE workflow
- `.cpp` strings are still useful as domain hints, but direct references should be treated as assert-context anchors.
- Prioritize finding real logic via callers around asserted condition checks rather than naming the assert wrappers themselves as feature entry points.

## TODO (added from this pass)
- [ ] Optional: rename assert-wrapper cluster using neutral `Assert...` naming convention (low-risk hygiene), but keep separate from gameplay logic naming passes.
- [ ] For diplomacy/trade domains, use `.cpp` names as contextual hints only and continue tracing non-assert callers for actual behavior entry points.

## Continuation (2026-02-20, Neo4j sync for embedded .cpp anchor research)

### What was synced to Neo4j
- Added concept:
  - `concept_embedded_cpp_assert_anchors`
- Added claims:
  - `claim_embedded_cpp_paths_count_2026_02_20` (51 embedded `.cpp` paths)
  - `claim_embedded_cpp_refs_assert_wrapper_pattern_2026_02_20` (all 57 direct `.cpp`-ref functions call `0x004057a4`)
  - `claim_diplomacydialogs_cpp_anchor_2026_02_20` (`DiplomacyDialogs.cpp` anchor at `0x00694cc0`, line hint 61 in `0x0047f3e0`)
- Added/updated function nodes linked to those claims:
  - `0x004057a4` `thunk_TemporarilyClearAndRestoreUiInvalidationFlag`
  - `0x0047f3e0` `FUN_0047f3e0`
- Added report source documents and evidence nodes:
  - `source_cpp_string_research_20260220`
  - `source_cpp_string_function_map_20260220`
  - `source_cpp_string_indirect_refs_20260220`
- Added top embedded path anchors as `SourceDocument` nodes (`type='embedded_cpp_path'`) with ref counts and linked them to the concept:
  - `UCityViews.cpp`, `McAppUI.cpp`, `UDisplayMgr.cpp`, `DirectPlay.cpp`, `UMapper.cpp`, `QuickDraw.cpp`, `WAssetMgr.cpp`, `WNetMgr.cpp`, `DiplomacyDialogs.cpp`

### RE workflow implication
- `.cpp` paths are valid subsystem breadcrumbs but direct xrefs are assert wrappers.
- Practical usage: pivot from each wrapper to its callers/thunk islands to locate real logic functions.

## Continuation (2026-02-20, `.cpp`-driven assert-anchor exploitation pass)

### What was done
- Used embedded `.cpp` source-path anchors to extract tiny assert-wrapper functions and rename them with file+line semantics.
- Scope-limited to high-confidence wrappers:
  - small bodies (<=14 instructions),
  - direct call to common assert/report routine `0x004057a4`,
  - explicit `PUSH line` + `PUSH file` pattern.

### Renames applied and saved (Ghidra)
- `AssertDiplomacyDialogsLine61` (`0x0047f3e0`)
- `AssertDirectPlayLine111` (`0x0047fb20`)
- `AssertDirectPlayLine118` (`0x0047fb50`)
- `AssertMcAppStreamLine304` (`0x00488b10`)
- `AssertMcAppStreamLine596` (`0x00488e00`)
- `AssertMcAppUILine1914` (`0x0048c7a0`)
- `AssertMcAppUILine2358` (`0x0048d8d0`)
- `AssertMcAppUILine2554` (`0x0048dce0`)
- `AssertMcAppUILine2756` (`0x0048e1e0`)
- `AssertMcAppUILine2777` (`0x0048e210`)
- `AssertMcAppUILine2798` (`0x0048e240`)
- `AssertMcAppUILine2815` (`0x0048e270`)
- `AssertUAmbitLine1335` (`0x0049ee70`)
- `AssertUDisplayMgrLine471` (`0x004fec20`)
- `AssertUDisplayMgrLine495` (`0x004fec50`)
- `AssertUDisplayMgrLine730` (`0x004ff1c0`)
- Additional pivot function:
  - `FUN_005003a0` -> `AssertUGameWindowLines634And639`

### Thunk materialization / call-graph improvements
- Materialized and named jump-thunk stubs to assertion helpers (15 created in this pass).
- Additional explicit thunk created:
  - `thunk_AssertUGameWindowLines634And639` (`0x00406db1`) -> `JMP 0x005003a0`.

### Type/comment hygiene
- Set return type `void` for the renamed assert helpers.
- Added concise comments with source-path/line anchor context on these wrappers.

### Practical reverse-engineering value from `.cpp` names
- This pass turns raw source-path strings into named anchor points that are now searchable and traversable in call graph.
- Immediate confirmed pivot:
  - `AssertUGameWindowLines634And639` performs UGameWindow assertions and calls `AssertMcAppUILine2358`, giving a concrete cross-file relationship (`UGameWindow.cpp` <-> `McAppUI.cpp`).

### Neo4j sync (high-level)
- Added claim: `claim_cpp_assert_wrapper_cluster_named_2026_02_20` under `concept_embedded_cpp_assert_anchors`.
- Linked named wrapper cluster functions (17 nodes, including thunk `0x00406db1`) via `[:IMPLEMENTS]`.

## TODO (next pass from these anchors)
- [ ] For each assert-anchor function, recover non-wrapper upstream callers by disassembling/materializing nearest undefined call-site islands (where refs originate outside functions).
- [ ] Prioritize anchors from game-facing files (`UDisplayMgr.cpp`, `UGameWindow.cpp`, `UCityViews.cpp`) and rename first non-assert parent functions once behavior is clear.
- [ ] Optionally normalize legacy assert names (`AssertQuickDrawFlag6A1DC8NonZero`, `AssertQuickDrawFlag6A1DCCNonZero`) into the same file+line scheme if line constants are recoverable.

## Continuation (2026-02-20, game-logic pass: navy mission common + blockade serialization lane)

### Scope
- Returned to non-UI mission game-logic and cleaned up low-hanging shared serialization/deserialization helpers.
- Targeted functions with direct evidence from vtable ownership and read/write callback behavior.

### Renames applied and saved
- Shared navy-mission common methods:
  - `MissionCommon_VtblSlot14` (`0x00536530`) -> `SerializeTNavyMissionCommon`
  - `thunk_MissionCommon_VtblSlot14` (`0x00406c76`) -> `thunk_SerializeTNavyMissionCommon`
  - `MissionCommon_VtblSlot18` (`0x00536650`) -> `DeserializeTNavyMissionCommon`
  - `thunk_MissionCommon_VtblSlot18` (`0x00404d3b`) -> `thunk_DeserializeTNavyMissionCommon`
- Blockade mission specializations:
  - `FUN_0053ac60` -> `SerializeTBlockadePortMission`
  - `FUN_0053aca0` -> `DeserializeTBlockadePortMission`
- Additional game-logic helpers in same mission corridor:
  - `FUN_0053d630` -> `ReturnMissionIfMovementClassMatchesTargetTile`
  - `FUN_005356f0` -> `ReturnTrueForArmyMissionCapabilityFlag`
  - `FUN_00535710` -> `ReturnMissionSelfPointer`
  - `FUN_00535730` -> `ReturnZeroForArmyMissionCapabilityFlag`
  - `FUN_0053ceb0` -> `ComputeArmyMissionCompositionAlignmentScore`
  - `FUN_0053d3e0` -> `ComputeArmyMissionDotProductScore`
  - `FUN_0053d420` -> `ComputeArmyMissionScoreDeltaAgainstCurrentSelection`

### Evidence anchors
- `Serialize/DeserializeTNavyMissionCommon` are shared by:
  - `g_vtblTNavyMission`
  - `g_vtblTControlSeaZoneMission`
  - `g_vtblTEscortMission`
  - `g_vtblTScatteredShipsMission`
  - `g_vtblTBeachheadMission`
- `Serialize/DeserializeTBlockadePortMission` are the blockade-specific slot implementations layered over the navy common serializer/deserializer and include mission-specific field handling (`+0x3c`).

### Signature/comment hygiene
- Return types set:
  - `void`: `SerializeTNavyMissionCommon`, `DeserializeTNavyMissionCommon`, `SerializeTBlockadePortMission`, `DeserializeTBlockadePortMission`
  - `bool`: `ReturnTrueForArmyMissionCapabilityFlag`
  - `int`: `ReturnZeroForArmyMissionCapabilityFlag`
- Added concise comments to the renamed shared/common functions and scoring helpers.
- Attempted parameter renaming (`this`, stream pointer) for serializer/deserializer functions, but these currently expose `0` formal parameters in Ghidra's locked signature model in this database, so no parameter-name edits were possible in this pass.

### Persistence
- Saved program after rename batch and after signature cleanup batch.

## TODO (next game-logic pass, refreshed)
- [ ] Continue `TInvadeMission` lane (`0x0053f4e0`, `0x0053f580`, `0x0053f610`, `0x0053f780`, `0x0053f7d0`, `0x0053f800`) and promote names only when each behavior is directly provable from decomp/callers.
- [ ] Materialize and name missing tiny thunk functions used as vtable entries around `g_vtblTArmyMission`/`g_vtblTInvadeMission` (for example `0x00401794`, `0x00406019`, `0x00403b02`, `0x004090f7`, `0x00404e4e`, `0x004098fe`, `0x004041e2`) to improve call-graph readability.
- [ ] Revisit serializer/deserializer parameter modeling once calling-convention/parameter recovery is unlocked (currently zero-parameter signatures in this lane).

## Continuation (2026-02-20, game-logic pass: `TInvadeMission` slot cleanup + thunk materialization)

### Scope
- Continued directly on the TODO invade lane and focused on high-confidence, behavior-backed renames.
- Mapped unresolved targets through `g_vtblTInvadeMission` entries and then renamed the concrete implementations.

### Renames applied and saved
- `FUN_0053f4e0` -> `EvaluateInvadeMissionBeachheadAndQueueEligibleUnits`
- `FUN_0053f580` -> `InitializeInvadeMissionFromNationAndTargetTile`
- `FUN_0053f5f0` -> `SetInvadeMissionKindTag2`
- `FUN_0053f610` -> `UpdateInvadeMissionAndBeachheadChildState`
- `FUN_0053f780` -> `RefreshInvadeMissionBeachheadNodeAndMaybeRepath`
- `FUN_0053f7d0` -> `AdvanceInvadeMissionCompositeHandlers`
- `FUN_0053f800` -> `ComputeInvadeMissionPriorityScore`

### Thunk materialization and naming
- Created missing jump-thunk functions and named them:
  - `0x00402225` -> `thunk_EvaluateInvadeMissionBeachheadAndQueueEligibleUnits`
  - `0x0040330a` -> `thunk_InitializeInvadeMissionFromNationAndTargetTile`
  - `0x00404016` -> `thunk_SetInvadeMissionKindTag2`
  - `0x00403503` -> `thunk_UpdateInvadeMissionAndBeachheadChildState`

### Signature/comment hygiene
- Return types updated:
  - `bool`: `EvaluateInvadeMissionBeachheadAndQueueEligibleUnits` and its thunk
  - `void`: the other renamed invade helpers and created thunks in this pass
- Added concise plate comments on all renamed invade helpers describing the direct observed behavior.

### Evidence highlights
- `EvaluateInvadeMissionBeachheadAndQueueEligibleUnits` is wired from `g_vtblTInvadeMission + 0x98` and gates on beachhead-child readiness before unit-eligibility queueing.
- `InitializeInvadeMissionFromNationAndTargetTile` and `SetInvadeMissionKindTag2` are consecutive invade vtable entries (`+0x30` / `+0x34`) and align with mission state/tag initialization.
- `ComputeInvadeMissionPriorityScore` is a large scoring function combining linked-list unit/resource contributions and city-selection heuristics.

### Neo4j policy
- No Neo4j update in this pass (low-level symbol hygiene only).

## TODO (next game-logic pass, refreshed)
- [ ] Continue the remaining `TInvadeMission` helper window after priority scoring (`0x0053faa0`, `0x0053fac0`, `0x0053fb60`, `0x0053fb90`, `0x0053fbc0`, `0x0053fc10`, `0x0053fdc0`, `0x0053fe10`) with the same behavior-first naming discipline.
- [ ] Materialize and name remaining tiny thunk entries still missing in related army/mission vtable lanes (`0x00401794`, `0x00406019`, `0x00403b02`, `0x004090f7`, `0x00404e4e`, `0x004098fe`, `0x004041e2`).
- [ ] Revisit stream/calling-convention parameter modeling for serializer/deserializer functions once parameter recovery is available (still showing zero formal parameters in this database for several locked functions).

## Continuation (2026-02-20, game-logic pass: army/mission thunk materialization completed)

### Scope
- Closed the low-hanging thunk-materialization TODO for mission/army vtable entries.
- Created missing function boundaries for one-instruction JMP stubs and normalized names to `thunk_*`.

### Created and renamed thunk functions
- `0x00401794` -> `thunk_ReturnMissionIfMovementClassMatchesTargetTile`
- `0x00406019` -> `thunk_ReturnTrueForArmyMissionCapabilityFlag`
- `0x00403b02` -> `thunk_ReturnMissionSelfPointer`
- `0x004090f7` -> `thunk_ReturnZeroForArmyMissionCapabilityFlag`
- `0x00404e4e` -> `thunk_ComputeArmyMissionCompositionAlignmentScore`
- `0x004098fe` -> `thunk_ComputeArmyMissionDotProductScore`
- `0x004041e2` -> `thunk_ComputeArmyMissionScoreDeltaAgainstCurrentSelection`
- `0x00404813` -> `thunk_DeserializeTBlockadePortMission`

### Result
- Mission/army vtable-call readability improved (no-function gaps removed for this thunk set).
- Call-graph traversal for these slots now lands on named thunk/function pairs instead of unlabeled islands.

### Persistence
- Saved program after materialization/rename batch.

## TODO (next game-logic pass, refreshed)
- [ ] Continue the remaining `TInvadeMission` helper window after priority scoring (`0x0053faa0`, `0x0053fac0`, `0x0053fb60`, `0x0053fb90`, `0x0053fbc0`, `0x0053fc10`, `0x0053fdc0`, `0x0053fe10`) with the same behavior-first naming discipline.
- [x] Materialize and name remaining tiny thunk entries still missing in related army/mission vtable lanes (`0x00401794`, `0x00406019`, `0x00403b02`, `0x004090f7`, `0x00404e4e`, `0x004098fe`, `0x004041e2`).
- [ ] Revisit stream/calling-convention parameter modeling for serializer/deserializer functions once parameter recovery is available (still showing zero formal parameters in this database for several locked functions).

## Continuation (2026-02-20, game-logic pass: invade helper window `0x0053faa0..0x0053fe10`)

### Renames applied and saved
- `FUN_0053faa0` -> `ReturnTrueForInvadeMissionCapabilityFlag`
- `FUN_0053fac0` -> `ComputeInvadeMissionWeightedScoreDelta`
- `FUN_0053fb60` -> `ComputeInvadeMissionBeachheadScoreIfEnabled`
- `FUN_0053fb90` -> `SetInvadeMissionBeachheadDisabledFlag`
- `FUN_0053fbc0` -> `HandleInvadeMissionActionOnTargetViaBeachhead`
- `FUN_0053fc10` -> `BuildInvadeMissionUnitPriorityVectorAndScore`
- `FUN_0053fdc0` -> `TryResolveInvadeMissionTargetTerrainClass`
- `FUN_0053fe10` -> `ResetInvadeMissionTargetTerrainClassAndRefresh`

### Thunk materialization and naming
- Created and named:
  - `0x00407ed7` -> `thunk_ReturnTrueForInvadeMissionCapabilityFlag`
  - `0x0040443f` -> `thunk_ComputeInvadeMissionWeightedScoreDelta`
  - `0x00405632` -> `thunk_ComputeInvadeMissionBeachheadScoreIfEnabled`
  - `0x004061f4` -> `thunk_SetInvadeMissionBeachheadDisabledFlag`
  - `0x00409782` -> `thunk_HandleInvadeMissionActionOnTargetViaBeachhead`
  - `0x00405c9f` -> `thunk_BuildInvadeMissionUnitPriorityVectorAndScore`
  - `0x004017f3` -> `thunk_TryResolveInvadeMissionTargetTerrainClass`
  - `0x00407667` -> `thunk_ResetInvadeMissionTargetTerrainClassAndRefresh`

### Signature/comment hygiene
- Set return type `bool` for:
  - `ReturnTrueForInvadeMissionCapabilityFlag`
  - `HandleInvadeMissionActionOnTargetViaBeachhead`
  - `TryResolveInvadeMissionTargetTerrainClass`
  - and their corresponding thunks.
- Added concise comments for all 8 renamed helper functions.

## Continuation (2026-02-20, game-logic pass: final generic cleanup in `0x0053f000..0x0053f240`)

### Renames applied and saved
- `FUN_0053f010` -> `HandleInvadeMissionActionType3ForTargetTile`
- `FUN_0053f040` -> `ReturnInvadeMissionIfMovementClassMatchesTargetTile`
- `FUN_0053f120` -> `GetInvadeMissionBeachheadChild`
- `FUN_0053f140` -> `ReturnTrueForInvadeMissionCapabilityFlagAlt`
- `FUN_0053f160` -> `ForwardInvadeMissionArgToBeachheadSlot90`
- `FUN_0053f190` -> `ForwardInvadeMissionArgsToBeachheadSlot84`
- `FUN_0053f1c0` -> `ForwardInvadeMissionArgsToBeachheadSlot8C`
- `FUN_0053f1f0` -> `ComputeInvadeMissionCompositeScoreWithBeachhead`
- `FUN_0053f240` -> `ReturnFalseForInvadeMissionCapabilityFlag`

### Thunk materialization and naming
- Created and named:
  - `0x004028ba` -> `thunk_HandleInvadeMissionActionType3ForTargetTile`
  - `0x00401b68` -> `thunk_ReturnInvadeMissionIfMovementClassMatchesTargetTile`
  - `0x00406587` -> `thunk_GetInvadeMissionBeachheadChild`
  - `0x004075f9` -> `thunk_ReturnTrueForInvadeMissionCapabilityFlagAlt`
  - `0x00402ce3` -> `thunk_ForwardInvadeMissionArgToBeachheadSlot90`
  - `0x00408c7e` -> `thunk_ForwardInvadeMissionArgsToBeachheadSlot84`
  - `0x00404db3` -> `thunk_ForwardInvadeMissionArgsToBeachheadSlot8C`
  - `0x00406a32` -> `thunk_ComputeInvadeMissionCompositeScoreWithBeachhead`
  - `0x004040a2` -> `thunk_ReturnFalseForInvadeMissionCapabilityFlag`

### Signature/comment hygiene
- Set return type `bool` for:
  - `HandleInvadeMissionActionType3ForTargetTile`
  - `ReturnTrueForInvadeMissionCapabilityFlagAlt`
  - `ReturnFalseForInvadeMissionCapabilityFlag`
  - and their corresponding thunks.
- Added concise comments for all 9 renamed helper functions.

### Verification
- Re-scan result for range `0x0053f000..0x00540000`:
  - remaining generic names matching `FUN_*`/`thunk_FUN_*` = `0`.

### Neo4j policy
- No Neo4j update for these passes (low-level symbol/thunk cleanup only).

## TODO (next game-logic pass, refreshed)
- [x] Continue the remaining `TInvadeMission` helper window after priority scoring (`0x0053faa0`, `0x0053fac0`, `0x0053fb60`, `0x0053fb90`, `0x0053fbc0`, `0x0053fc10`, `0x0053fdc0`, `0x0053fe10`) with the same behavior-first naming discipline.
- [x] Materialize and name remaining tiny thunk entries still missing in related army/mission vtable lanes (`0x00401794`, `0x00406019`, `0x00403b02`, `0x004090f7`, `0x00404e4e`, `0x004098fe`, `0x004041e2`).
- [ ] Revisit stream/calling-convention parameter modeling for serializer/deserializer functions once parameter recovery is available (still showing zero formal parameters in this database for several locked functions).
- [ ] Continue next non-UI mission lane immediately adjacent to this cleaned block (start at `0x0053e500..0x0053ef00` for remaining generic mission/AI helpers).

## Continuation (2026-02-20, game-logic pass: defend-province mission lane `0x0053e000..0x0053ef00`)

### Scope
- Executed the queued adjacent non-UI mission pass and focused on the `TDefendProvinceMission` cluster.
- Applied only behavior-backed names; materialized related one-jump thunk stubs for call-graph readability.

### Renames applied and saved (core functions)
- `FUN_0053e050` -> `TryValidateOrRetargetDefendProvinceMissionTarget`
- `FUN_0053e180` -> `SetDefendProvinceMissionStateFlag8ToPending`
- `FUN_0053e1a0` -> `ComputeDefendProvinceMissionTerrainAdjacencyScoreFromTile30`
- `FUN_0053e290` -> `PopulateDefendProvinceMissionResourceWeightsFromTargetProvince`
- `FUN_0053e500` -> `ComputeDefendProvinceMissionScoreWithEarlyThreatGate`
- `FUN_0053e570` -> `InitializeDefendProvinceMissionMovementClassFromTargetProvince`
- `FUN_0053e5b0` -> `HandleDefendProvinceMissionActionType01ForTargetTile`
- `FUN_0053e5f0` -> `CreateTDefendProvinceMission`
- `FUN_0053e6e0` -> `ComputeDefendProvinceMissionCrossNationSupportVectorScore`
- `FUN_0053ea70` -> `ComputeDefendProvinceMissionLocalSupportVectorScore`
- `FUN_0053ebe0` -> `CleanupDefendProvinceMissionAndReleaseChildContext`
- `FUN_0053ecc0` -> `UpdateDefendProvinceMissionStateByNationTargetMatch`
- `FUN_0053ed00` -> `ComputeDefendProvinceMissionTerrainAdjacencyScoreFromTile14`
- `FUN_0053edf0` -> `PopulateDefendProvinceMissionResourceWeightsByDiplomacyContext`

### Thunk normalization/materialization
- Renamed existing thunks:
  - `0x004057fe` -> `thunk_TryValidateOrRetargetDefendProvinceMissionTarget`
  - `0x004042d7` -> `thunk_PopulateDefendProvinceMissionResourceWeightsFromTargetProvince`
  - `0x00401a32` -> `thunk_ComputeDefendProvinceMissionCrossNationSupportVectorScore`
  - `0x0040857b` -> `thunk_ComputeDefendProvinceMissionLocalSupportVectorScore`
- Created + named missing thunk stubs:
  - `0x00406c8f` -> `thunk_SetDefendProvinceMissionStateFlag8ToPending`
  - `0x004037bf` -> `thunk_ComputeDefendProvinceMissionTerrainAdjacencyScoreFromTile30`
  - `0x0040211c` -> `thunk_ComputeDefendProvinceMissionScoreWithEarlyThreatGate`
  - `0x0040558d` -> `thunk_InitializeDefendProvinceMissionMovementClassFromTargetProvince`
  - `0x004076d5` -> `thunk_HandleDefendProvinceMissionActionType01ForTargetTile`
  - `0x00402c75` -> `thunk_CleanupDefendProvinceMissionAndReleaseChildContext`
  - `0x00403ea9` -> `thunk_UpdateDefendProvinceMissionStateByNationTargetMatch`
  - `0x00408f9e` -> `thunk_ComputeDefendProvinceMissionTerrainAdjacencyScoreFromTile14`
  - `0x00407a8b` -> `thunk_PopulateDefendProvinceMissionResourceWeightsByDiplomacyContext`

### Signature/comment hygiene
- Set return type `bool` for:
  - `HandleDefendProvinceMissionActionType01ForTargetTile`
  - `thunk_HandleDefendProvinceMissionActionType01ForTargetTile`
- Added concise plate comments for all 14 renamed core functions in this pass.

### Verification
- Re-scan result for `0x0053e000..0x0053ef00`:
  - remaining generic names matching `FUN_*`/`thunk_FUN_*` = `0`.
- Re-scan result for wider `0x0053e000..0x0053ffff`:
  - remaining generic names matching `FUN_*`/`thunk_FUN_*` = `0`.

### Neo4j policy
- No Neo4j update for this pass (low-level rename/thunk hygiene only).

## TODO (next game-logic pass, refreshed)
- [x] Continue next non-UI mission lane immediately adjacent to this cleaned block (start at `0x0053e500..0x0053ef00` for remaining generic mission/AI helpers).
- [ ] Revisit stream/calling-convention parameter modeling for serializer/deserializer functions once parameter recovery is available (still showing zero formal parameters in this database for several locked functions).
- [ ] Continue low-hanging non-UI mission logic in adjacent corridor `0x0053d000..0x0053e000` (prioritize easy wrappers/thunks first, then behavior-backed renames).

## Continuation (2026-02-20, game-logic pass: attack/army mission lane `0x0053d000..0x0053e000`)

### Scope
- Continued immediately into the next adjacent non-UI mission corridor and took the highest-confidence, vtable-backed low-hanging renames.
- Covered shared army scoring helpers plus attack-province mission capability/cleanup/target-refresh logic.

### Renames applied and saved
- Shared army scoring helper lane:
  - `FUN_0053d020` -> `ComputeArmyMissionScoreDeltaWithCandidateUnit`
  - `thunk_FUN_0053d020` (`0x004031f2`) -> `thunk_ComputeArmyMissionScoreDeltaWithCandidateUnit`
  - `FUN_0053d200` -> `ComputeArmyMissionScoreDeltaWithScaledCandidateUnit`
  - `thunk_FUN_0053d200` (`0x00406686`) -> `thunk_ComputeArmyMissionScoreDeltaWithScaledCandidateUnit`
  - `FUN_0053d4a0` -> `ComputeArmyMissionCandidateVectorDistanceScore`
  - `thunk_FUN_0053d4a0` (`0x00402b5d`) -> `thunk_ComputeArmyMissionCandidateVectorDistanceScore`
- Attack province mission lane:
  - `FUN_0053d6f0` -> `ReturnFalseForAttackProvinceMissionCapabilityFlag`
  - `0x00404eee` (materialized) -> `thunk_ReturnFalseForAttackProvinceMissionCapabilityFlag`
  - `TAttackProvinceMission_VtblSlot1C` (`0x0053d890`) -> `CleanupTAttackProvinceMissionAndReleaseChildContext`
  - `thunk_TAttackProvinceMission_VtblSlot1C` (`0x00408599`) -> `thunk_CleanupTAttackProvinceMissionAndReleaseChildContext`
  - `FUN_0053d950` -> `EvaluateAttackProvinceMissionAndQueueEligibleUnits`
  - `0x004094fd` (materialized) -> `thunk_EvaluateAttackProvinceMissionAndQueueEligibleUnits`
  - `FUN_0053db60` -> `TryResolveAttackProvinceMissionTargetTerrainClass`
  - `thunk_FUN_0053db60` (`0x00408427`) -> `thunk_TryResolveAttackProvinceMissionTargetTerrainClass`
  - `FUN_0053de00` -> `RefreshAttackProvinceMissionTargetAndMaybeQueueUnits`
  - `thunk_FUN_0053de00` (`0x004028c9`) -> `thunk_RefreshAttackProvinceMissionTargetAndMaybeQueueUnits`

### Signature/comment hygiene
- Set return type `bool` for:
  - `ReturnFalseForAttackProvinceMissionCapabilityFlag`
  - `thunk_ReturnFalseForAttackProvinceMissionCapabilityFlag`
  - `EvaluateAttackProvinceMissionAndQueueEligibleUnits`
  - `thunk_EvaluateAttackProvinceMissionAndQueueEligibleUnits`
- Added concise plate comments for renamed core functions in this lane.

### Evidence anchors
- `ReturnFalseForAttackProvinceMissionCapabilityFlag` is vtable-owned by `g_vtblTAttackProvinceMission` (slot offset `+0x64`).
- `TryResolveAttackProvinceMissionTargetTerrainClass` is vtable-owned by `g_vtblTAttackProvinceMission` (slot offset `+0xA0`) and directly reused by invade terrain-resolution path.
- `RefreshAttackProvinceMissionTargetAndMaybeQueueUnits` is vtable-owned by `g_vtblTAttackProvinceMission` (slot offset `+0x44`) and called from invade-beachhead refresh path.
- `ComputeArmyMissionCandidateVectorDistanceScore` remains shared between `g_vtblTArmyMission` and `g_vtblTDefendProvinceMission`.

### Verification
- Re-scan result for `0x0053d000..0x0053e000`:
  - remaining names matching `FUN_*`/`thunk_FUN_*`/`*VtblSlot*` = `0`.

### Neo4j policy
- No Neo4j sync for this pass (low-level rename/thunk cleanup only).

## TODO (next game-logic pass, refreshed)
- [x] Continue low-hanging non-UI mission logic in adjacent corridor `0x0053d000..0x0053e000` (prioritize easy wrappers/thunks first, then behavior-backed renames).
- [ ] Revisit stream/calling-convention parameter modeling for serializer/deserializer functions once parameter recovery is available (still showing zero formal parameters in this database for several locked functions).
- [ ] Continue to the next adjacent non-UI mission corridor (`0x0053c000..0x0053d000`) and clear remaining easy generic helpers with the same low-hanging-first policy.

## Continuation (2026-02-20, game-logic pass: attack/army corridor `0x0053d000..0x0053e000`, follow-up)

### Renames applied and saved
- `ComputeArmyMissionScoreDeltaWithCandidateUnit` + thunk (`0x0053d020`, `0x004031f2`)
- `ComputeArmyMissionScoreDeltaWithScaledCandidateUnit` + thunk (`0x0053d200`, `0x00406686`)
- `ComputeArmyMissionCandidateVectorDistanceScore` + thunk (`0x0053d4a0`, `0x00402b5d`)
- `ReturnFalseForAttackProvinceMissionCapabilityFlag` + thunk (`0x0053d6f0`, `0x00404eee`)
- `CleanupTAttackProvinceMissionAndReleaseChildContext` + thunk (`0x0053d890`, `0x00408599`)
- `EvaluateAttackProvinceMissionAndQueueEligibleUnits` + thunk (`0x0053d950`, `0x004094fd`)
- `TryResolveAttackProvinceMissionTargetTerrainClass` + thunk (`0x0053db60`, `0x00408427`)
- `RefreshAttackProvinceMissionTargetAndMaybeQueueUnits` + thunk (`0x0053de00`, `0x004028c9`)

### Materialization and signature updates
- Materialized missing thunk functions at `0x00404eee` and `0x004094fd`.
- Set return type `bool` for:
  - `ReturnFalseForAttackProvinceMissionCapabilityFlag` + thunk
  - `EvaluateAttackProvinceMissionAndQueueEligibleUnits` + thunk

### Evidence notes
- `ReturnFalseForAttackProvinceMissionCapabilityFlag`, `TryResolveAttackProvinceMissionTargetTerrainClass`, and `RefreshAttackProvinceMissionTargetAndMaybeQueueUnits` are vtable-owned by `g_vtblTAttackProvinceMission` (offsets `+0x64`, `+0xA0`, `+0x44` respectively).
- `ComputeArmyMissionCandidateVectorDistanceScore` remains shared between `g_vtblTArmyMission` and `g_vtblTDefendProvinceMission`.

## Continuation (2026-02-20, game-logic pass: shared mission-helper corridor `0x0053c000..0x0053d000`)

### Renames applied and saved
- `FUN_0053c1b0` -> `ReturnFalseForArmyAttackInvadeCapabilityFlag`
- `FUN_0053c220` -> `CleanupTArmyMissionAndReleaseChildContext`
- `FUN_0053c4f0` -> `EvaluateMissionAndQueueEligibleUnitsByMovementClass`
- `FUN_0053c570` -> `AttachMissionAsOwnerAndNotifyIfRequested`
- `FUN_0053c5e0` -> `ReleaseMissionOwnerLinkAtOffset40`
- `FUN_0053c620` -> `BuildMissionPriorityVectorAndReturnTotal`
- `FUN_0053c950` -> `PropagateTargetTileToLinkedUnitsIfDifferent`
- `FUN_0053c9d0` -> `AccumulateMissionUnitPriorityVectorWithOptionalFilter`
- `FUN_0053cac0` -> `ComputeMissionPrioritySimilarityScoreForFilter`
- `FUN_0053cb50` -> `AccumulateMissionUnitPriorityContributionWithScaleMode`
- `FUN_0053cda0` -> `AccumulateMissionUnitPriorityVector`

### Thunk normalization/materialization
- Materialized and renamed:
  - `0x00408b84` -> `thunk_ReturnFalseForArmyAttackInvadeCapabilityFlag`
  - `0x00405d35` -> `thunk_CleanupTArmyMissionAndReleaseChildContext`
  - `0x0040763f` -> `thunk_EvaluateMissionAndQueueEligibleUnitsByMovementClass`
  - `0x00402130` -> `thunk_AttachMissionAsOwnerAndNotifyIfRequested`
  - `0x00401f8c` -> `thunk_ReleaseMissionOwnerLinkAtOffset40`
  - `0x00407e87` -> `thunk_BuildMissionPriorityVectorAndReturnTotal`
- Renamed existing stubs:
  - `0x00403779` -> `thunk_PropagateTargetTileToLinkedUnitsIfDifferent`
  - `0x004090a7` -> `thunk_AccumulateMissionUnitPriorityVectorWithOptionalFilter`

### Signature/comment hygiene
- Set return type `bool` for:
  - `ReturnFalseForArmyAttackInvadeCapabilityFlag` + thunk
  - `EvaluateMissionAndQueueEligibleUnitsByMovementClass` + thunk
- Added concise comments for all renamed core helpers in this pass.

### Verification
- Re-scan result for `0x0053d000..0x0053e000`:
  - remaining names matching `FUN_*`/`thunk_FUN_*`/`*VtblSlot*` = `0`.
- Re-scan result for `0x0053c000..0x0053d000`:
  - remaining names matching `FUN_*`/`thunk_FUN_*`/`*VtblSlot*` = `0`.

### Neo4j policy
- No Neo4j updates in these passes (low-level symbol/thunk cleanup only).

## TODO (next game-logic pass, refreshed)
- [x] Continue to the next adjacent non-UI mission corridor (`0x0053c000..0x0053d000`) and clear remaining easy generic helpers with the same low-hanging-first policy.
- [ ] Revisit stream/calling-convention parameter modeling for serializer/deserializer functions once parameter recovery is available (still showing zero formal parameters in this database for several locked functions).
- [ ] Continue low-hanging mission-logic cleanup in the next adjacent corridor (`0x0053b000..0x0053c000`) with the same wrapper-first, behavior-backed naming style.

## Continuation (2026-02-20, game-logic pass: scattered/blockade mission lane `0x0053b000..0x0053c000`)

### Scope
- Continued one corridor earlier with low-hanging-first strategy, focusing on `TScatteredShipsMission` and nearby blockade action-gate helpers.
- Used vtable ownership and direct slot behavior to avoid speculative naming.

### Renames applied and saved (first batch)
- `FUN_0053ba10` -> `HandleBlockadePortMissionActionType4ForTargetPort`
- `FUN_0053bb90` -> `ResetScatteredShipsMissionStateAndScoreDefault`
- `FUN_0053bbb0` -> `RunScatteredShipsMissionStateUpdatePipeline`
- `FUN_0053bbe0` -> `ReturnMissionArgPassthrough`
- `FUN_0053bc00` -> `SetScatteredShipsMissionStateByte8To3`
- `FUN_0053bc20` -> `ResetScatteredShipsMissionScoreField0C`
- `FUN_0053bc40` -> `PopulateScatteredShipsMissionResourceWeightsFromNationNavyPressure`
- `FUN_0053bcc0` -> `HandleScatteredShipsMissionActionType5WithNoTarget`
- `FUN_0053bdd0` -> `SelectMapActionContextAndPromoteMissionOrderChain`
- `FUN_0053bf90` -> `ReturnFalseForScatteredShipsMissionCapabilityFlag`

### Thunk materialization and naming
- Created and renamed:
  - `0x00407fe0` -> `thunk_HandleBlockadePortMissionActionType4ForTargetPort`
  - `0x0040326f` -> `thunk_RunScatteredShipsMissionStateUpdatePipeline`
  - `0x004056f0` -> `thunk_ReturnMissionArgPassthrough`
  - `0x00402360` -> `thunk_SetScatteredShipsMissionStateByte8To3`
  - `0x00408b11` -> `thunk_ResetScatteredShipsMissionScoreField0C`
  - `0x004070db` -> `thunk_PopulateScatteredShipsMissionResourceWeightsFromNationNavyPressure`
  - `0x00406816` -> `thunk_HandleScatteredShipsMissionActionType5WithNoTarget`
  - `0x0040420f` -> `thunk_SelectMapActionContextAndPromoteMissionOrderChain`
  - `0x004012cb` -> `thunk_ReturnFalseForScatteredShipsMissionCapabilityFlag`
- Renamed existing thunk:
  - `0x00406677` -> `thunk_ResetScatteredShipsMissionStateAndScoreDefault`

### Signature/comment hygiene
- Set return type `bool` for:
  - `HandleBlockadePortMissionActionType4ForTargetPort` + thunk
  - `HandleScatteredShipsMissionActionType5WithNoTarget` + thunk
  - `ReturnFalseForScatteredShipsMissionCapabilityFlag` + thunk
- Added concise plate comments to all renamed core functions in this batch.

### Renames applied and saved (second batch: remaining 3 heavy helpers)
- `FUN_0053b350` -> `ComputeMissionNavyOrderDistributionScoreForPortOwnerOrAllies`
- `FUN_0053b800` -> `ComputeNavyOrderDistributionScoreForNation`
- `FUN_0053bfb0` -> `AllocateAndConstructTArmyMissionWithNodeKey`
- Added concise comments on each of the three functions.

### Evidence notes
- Vtable mapping confirms these methods are directly in `g_vtblTScatteredShipsMission` / `g_vtblTBlockadePortMission` slots (not random helpers).
- `ComputeMissionNavyOrderDistributionScoreForPortOwnerOrAllies` shows explicit fallback:
  - if mission port-owner code is invalid, iterates allied nations and takes best navy-order distribution score.

### Verification
- Re-scan result for `0x0053b000..0x0053c000`:
  - remaining names matching `FUN_*`/`thunk_FUN_*`/`*VtblSlot*` = `0`.

### Neo4j policy
- No Neo4j updates in this pass (low-level rename/thunk cleanup only).

## TODO (next game-logic pass, refreshed)
- [x] Continue low-hanging mission-logic cleanup in the next adjacent corridor (`0x0053b000..0x0053c000`) with the same wrapper-first, behavior-backed naming style.
- [ ] Revisit stream/calling-convention parameter modeling for serializer/deserializer functions once parameter recovery is available (still showing zero formal parameters in this database for several locked functions).
- [ ] Continue to next adjacent non-UI mission corridor (`0x0053a000..0x0053b000`) and clear easy wrappers/thunks first, then behavior-backed names.

## Continuation (2026-02-20, game-logic pass: beachhead/blockade corridor `0x0053a000..0x0053b000`)

### Scope
- Continued adjacent mission lane cleanup with low-hanging-first discipline.
- Focused on `TBeachheadMission` + `TBlockadePortMission` constructor/state/action-gate helpers and corresponding thunk islands.

### Renames applied and saved (core functions)
- `FUN_0053a250` -> `HandleBeachheadMissionActionType0Or3ForTargetPort`
- `FUN_0053a290` -> `ResetBeachheadMissionChildFlagsAndDispatchField5Context`
- `FUN_0053a2d0` -> `CreateTBeachheadMission`
- `FUN_0053a390` -> `ReturnFalseForBeachheadMissionCapabilityFlagA`
- `FUN_0053a3b0` -> `ReturnFalseForBeachheadMissionCapabilityFlagB`
- `FUN_0053a3d0` -> `DestroyTBeachheadMission`
- `FUN_0053a400` -> `ResetTBeachheadMissionToSentinelVtable`
- `FUN_0053a490` -> `ConstructTBeachheadMissionWithNodeAndParent`
- `FUN_0053a500` -> `PopulateBeachheadMissionResourceWeightsFromNavyContext`
- `FUN_0053a7b0` -> `HandleBlockadePortMissionActionType2ForBeachheadTarget`
- `FUN_0053a920` -> `GetBlockadePortMissionBeachheadChild`
- `FUN_0053a940` -> `ClearBlockadePortMissionChildOrderLinksIfReady`
- `FUN_0053a990` -> `CreateTBlockadePortMission`
- `FUN_0053aa50` -> `ReturnFalseForBlockadePortMissionCapabilityFlagA`
- `FUN_0053aa70` -> `ReturnFalseForBlockadePortMissionCapabilityFlagB`
- `FUN_0053adf0` -> `ValidateBlockadePortMissionContextAndRefreshChild`
- `FUN_0053ae90` -> `SetBlockadePortMissionStateByte8To3`
- `FUN_0053aeb0` -> `PopulateBlockadePortMissionResourceWeightsFromNavyContext`

### Thunk materialization and naming
- Created and renamed:
  - `0x00407c39` -> `thunk_HandleBeachheadMissionActionType0Or3ForTargetPort`
  - `0x00402b21` -> `thunk_ResetBeachheadMissionChildFlagsAndDispatchField5Context`
  - `0x0040526d` -> `thunk_ReturnFalseForBeachheadMissionCapabilityFlagA`
  - `0x00403ec2` -> `thunk_ReturnFalseForBeachheadMissionCapabilityFlagB`
  - `0x00402ee6` -> `thunk_DestroyTBeachheadMission`
  - `0x00402a9f` -> `thunk_PopulateBeachheadMissionResourceWeightsFromNavyContext`
  - `0x004059fc` -> `thunk_HandleBlockadePortMissionActionType2ForBeachheadTarget`
  - `0x00405d62` -> `thunk_GetBlockadePortMissionBeachheadChild`
  - `0x004099da` -> `thunk_ClearBlockadePortMissionChildOrderLinksIfReady`
  - `0x004096a6` -> `thunk_ReturnFalseForBlockadePortMissionCapabilityFlagA`
  - `0x00406064` -> `thunk_ReturnFalseForBlockadePortMissionCapabilityFlagB`
  - `0x004024b9` -> `thunk_ValidateBlockadePortMissionContextAndRefreshChild`
  - `0x004027fc` -> `thunk_SetBlockadePortMissionStateByte8To3`
  - `0x00403567` -> `thunk_PopulateBlockadePortMissionResourceWeightsFromNavyContext`
- Renamed existing thunk:
  - `0x00404cc3` -> `thunk_ResetTBeachheadMissionToSentinelVtable`

### Signature/comment hygiene
- Set return type `bool` for:
  - `HandleBeachheadMissionActionType0Or3ForTargetPort` + thunk
  - `ReturnFalseForBeachheadMissionCapabilityFlagA/B` + thunks
  - `HandleBlockadePortMissionActionType2ForBeachheadTarget` + thunk
  - `ClearBlockadePortMissionChildOrderLinksIfReady` + thunk
  - `ReturnFalseForBlockadePortMissionCapabilityFlagA/B` + thunks
- Added concise plate comments for renamed core functions where behavior is non-obvious.

### Verification
- Re-scan result for `0x0053a000..0x0053b000`:
  - remaining names matching `FUN_*`/`thunk_FUN_*`/`*VtblSlot*` = `0`.

### Neo4j policy
- No Neo4j updates in this pass (low-level symbol/thunk cleanup only).

## TODO (next game-logic pass, refreshed)
- [x] Continue to next adjacent non-UI mission corridor (`0x0053a000..0x0053b000`) and clear easy wrappers/thunks first, then behavior-backed names.
- [ ] Revisit stream/calling-convention parameter modeling for serializer/deserializer functions once parameter recovery is available (still showing zero formal parameters in this database for several locked functions).
- [ ] Continue to next adjacent non-UI mission corridor (`0x00539000..0x0053a000`) and repeat low-hanging wrapper-first cleanup.

## Continuation (2026-02-20, game-logic pass: control-sea-zone / escort corridor `0x00539000..0x0053a000`)

### Scope
- Continued adjacent mission-logic cleanup with the same low-hanging-first strategy.
- This lane split across `TControlSeaZoneMission` and `TEscortMission` vtable methods and nearby thunk islands.

### Renames applied and saved
- `FUN_005393a0` -> `PopulateControlSeaZoneMissionResourceWeightsFromAlliedNavyPressure`
- `FUN_00539600` -> `HandleControlSeaZoneMissionActionType0Or3ForTargetPort`
- `FUN_00539780` -> `ResolveAndCacheMissionPortZoneContextForNationTarget`
- `FUN_00539900` -> `ReturnEscortMissionArgPassthrough`
- `FUN_00539920` -> `ReturnTrueForEscortMissionCapabilityFlagA`
- `FUN_00539940` -> `ReturnFalseForEscortMissionCapabilityFlagB`
- `FUN_00539a70` -> `ResetEscortMissionDispatchFlagAndCopyTargetContextId`
- `FUN_00539a90` -> `ComputeNavyOrderDistributionSimilarityScoreForNation`
- `FUN_00539e70` -> `PopulateEscortMissionResourceWeightsFromEligibleNationNavyPressure`

### Thunk materialization and naming
- Created and renamed:
  - `0x004011c2` -> `thunk_PopulateControlSeaZoneMissionResourceWeightsFromAlliedNavyPressure`
  - `0x00407f68` -> `thunk_HandleControlSeaZoneMissionActionType0Or3ForTargetPort`
  - `0x00405722` -> `thunk_ResolveAndCacheMissionPortZoneContextForNationTarget`
  - `0x00405c04` -> `thunk_ReturnEscortMissionArgPassthrough`
  - `0x004094c1` -> `thunk_ReturnTrueForEscortMissionCapabilityFlagA`
  - `0x00408f1c` -> `thunk_ReturnFalseForEscortMissionCapabilityFlagB`
  - `0x00401f1e` -> `thunk_ResetEscortMissionDispatchFlagAndCopyTargetContextId`
  - `0x004022d4` -> `thunk_PopulateEscortMissionResourceWeightsFromEligibleNationNavyPressure`

### Signature/comment hygiene
- Set return type `bool` for:
  - `HandleControlSeaZoneMissionActionType0Or3ForTargetPort` + thunk
  - `ReturnTrueForEscortMissionCapabilityFlagA` + thunk
  - `ReturnFalseForEscortMissionCapabilityFlagB` + thunk
- Added concise plate comments to the non-obvious score/weight/context methods.

### Evidence anchors
- `0x0065a740` (`g_vtblTControlSeaZoneMission`) contains direct data refs to:
  - `thunk_PopulateControlSeaZoneMissionResourceWeightsFromAlliedNavyPressure` (`+0x3c`)
  - `thunk_HandleControlSeaZoneMissionActionType0Or3ForTargetPort` (`+0x4c`)
  - `thunk_ResolveAndCacheMissionPortZoneContextForNationTarget` (`+0xa0`)
- `0x0065aab0` (`g_vtblTEscortMission`) contains direct data refs to:
  - `thunk_ResetEscortMissionDispatchFlagAndCopyTargetContextId` (`+0x30`)
  - `thunk_PopulateEscortMissionResourceWeightsFromEligibleNationNavyPressure` (`+0x3c`)
  - `thunk_ReturnEscortMissionArgPassthrough` (`+0x48`)
  - `thunk_ReturnFalseForEscortMissionCapabilityFlagB` (`+0x60`)
  - `thunk_ReturnTrueForEscortMissionCapabilityFlagA` (`+0x64`)
- `ResolveAndCacheMissionPortZoneContextForNationTarget` is reused by multiple nearby mission vtables (`0x0065a7e0`, `0x0065ac28`, `0x0065ad00`), so it was named generically (not class-specific).

### Verification
- Re-scan result for `0x00539000..0x0053a000`:
  - remaining names matching `FUN_*`/`thunk_FUN_*`/`*VtblSlot*` = `0`.

### Persistence note
- In direct `pyghidra` batch mode, explicit `program.save(...)` currently reports `Unable to lock due to active transaction` (transaction label shows `Batch Processing`), but reopen verification confirms the rename changes are persisted in the project database.

### Neo4j policy
- No Neo4j update for this pass (low-level symbol/thunk cleanup only).

## TODO (next game-logic pass, refreshed)
- [x] Continue to next adjacent non-UI mission corridor (`0x00539000..0x0053a000`) and repeat low-hanging wrapper-first cleanup.
- [ ] Revisit stream/calling-convention parameter modeling for serializer/deserializer functions once parameter recovery is available (still showing zero formal parameters in this database for several locked functions).
- [ ] Continue low-hanging mission-logic cleanup in the next adjacent corridor (`0x00538000..0x00539000`) with wrapper-first, behavior-backed naming.

## Continuation (2026-02-20, game-logic pass: mission scoring/control-sea-zone helper corridor `0x00538000..0x00539000`)

### Scope
- Continued into the next adjacent non-UI lane and focused on high-confidence scoring/validation/state helpers tied to `TControlSeaZoneMission` behavior.
- Kept naming behavior-based where direct vtable/class anchoring was weak.

### Renames applied and saved
- `FUN_00538120` -> `ComputeMissionOrderMatchScoreWithCandidateNavyOrder`
- `FUN_005383f0` -> `ComputeMissionOrderMatchScoreWithScaledCandidateNavyOrder`
- `FUN_00538900` -> `ValidateMissionTerrainCoverageAndRefreshTargetContext`
- `FUN_005389f0` -> `ComputeNavyOrderDistributionSimilarityScoreWithDiplomacyFilter`
- `FUN_00538bf0` -> `ComputeNavyOrderDistributionSimilarityScoreForExactSourceNation`
- `FUN_00538dd0` -> `ComputeNavyOrderDistributionSimilarityScoreForMissionNation`
- `FUN_00538fe0` -> `UpdateControlSeaZoneMissionStateFromTargetNavySimilarity`

### Thunk materialization and naming
- Created and renamed:
  - `0x004031e8` -> `thunk_ValidateMissionTerrainCoverageAndRefreshTargetContext`
  - `0x00409a57` -> `thunk_UpdateControlSeaZoneMissionStateFromTargetNavySimilarity`
- Renamed existing:
  - `0x0040638e` -> `thunk_ComputeNavyOrderDistributionSimilarityScoreWithDiplomacyFilter`
  - `0x0040824c` -> `thunk_ComputeNavyOrderDistributionSimilarityScoreForExactSourceNation`

### Comment hygiene
- Added concise plate comments for all seven renamed core helpers in this pass.

### Evidence notes
- `ValidateMissionTerrainCoverageAndRefreshTargetContext`:
  - scans terrain descriptors and compatibility/array-membership predicates,
  - refreshes stale target context through mission vtable `+0xA0` callback path.
- `UpdateControlSeaZoneMissionStateFromTargetNavySimilarity`:
  - computes target distribution similarity and writes mission state byte `+0x8` to `1` or `2`.
- `ComputeMissionOrderMatchScoreWithCandidateNavyOrder` / scaled variant:
  - compare candidate navy-order category vector against mission desired weights (`+0x2c` region).

### Verification
- Re-scan result for `0x00538000..0x00539000`:
  - remaining names matching `FUN_*`/`thunk_FUN_*`/`*VtblSlot*` = `0`.

### Neo4j policy
- No Neo4j update for this pass (low-level symbol/thunk cleanup only).

## TODO (next game-logic pass, refreshed)
- [x] Continue low-hanging mission-logic cleanup in the next adjacent corridor (`0x00538000..0x00539000`) with wrapper-first, behavior-backed naming.
- [ ] Revisit stream/calling-convention parameter modeling for serializer/deserializer functions once parameter recovery is available (still showing zero formal parameters in this database for several locked functions).
- [ ] Continue to the next adjacent mission corridor (`0x00537000..0x00538000`) and clear easy wrapper/thunk-backed game-logic helpers first.

## Continuation (2026-02-20, game-logic pass: mission-order prioritizer/scoring corridor `0x00537000..0x00538000`)

### Scope
- Continued immediately into the next adjacent mission-logic lane.
- Prioritized the clear mission-order vector/scoring helpers and deferred two decompiler-storage-problem functions that are not low-hanging.

### Renames applied and saved (core functions)
- `FUN_005371d0` -> `ConsolidateMissionOrderEntriesByTargetAndQueue`
- `FUN_00537270` -> `ComputeMissionOrderMatchDeltaWithCandidateNavyOrder`
- `FUN_00537610` -> `ComputeMissionOrderPenaltyForCandidateAgainstTargetProfile`
- `FUN_005378c0` -> `ComputeMissionWeightDotProductWithBaselineProfile`
- `FUN_00537900` -> `BuildNavyOrderCategoryVectorForNationWithExclusion`
- `FUN_00537c60` -> `AccumulateNavyOrderCategoryVectorWithScale`
- `FUN_00537d40` -> `BuildMissionQueuedOrderCategoryVector`
- `FUN_00537eb0` -> `ComputeMissionQueuedOrderSimilarityForTargetNation`
- `FUN_00537f40` -> `ComputeMissionQueuedOrderSimilarityWithFloorAdjustedCandidateVector`

### Thunk materialization and naming
- Created and renamed:
  - `0x004026c1` -> `thunk_ConsolidateMissionOrderEntriesByTargetAndQueue`
  - `0x0040891d` -> `thunk_ComputeMissionOrderMatchDeltaWithCandidateNavyOrder`
  - `0x0040565a` -> `thunk_ComputeMissionOrderPenaltyForCandidateAgainstTargetProfile`
  - `0x00404a61` -> `thunk_ComputeMissionWeightDotProductWithBaselineProfile`
  - `0x00402518` -> `thunk_ComputeMissionQueuedOrderSimilarityWithFloorAdjustedCandidateVector`
- Renamed existing:
  - `0x004016b8` -> `thunk_BuildNavyOrderCategoryVectorForNationWithExclusion`
  - `0x00405272` -> `thunk_AccumulateNavyOrderCategoryVectorWithScale`

### Comment hygiene
- Added concise plate comments for all nine renamed core helpers.

### Verification
- Re-scan result for `0x00537000..0x00538000`:
  - remaining names matching `FUN_*`/`thunk_FUN_*`/`*VtblSlot*` = `2`
  - residuals:
    - `FUN_005370f0`
    - `FUN_0053714f`
- These two are deferred because decomp still shows heavy register-storage artifacts (`unaff_*`) and are not low-hanging without storage/cc cleanup.

### Neo4j policy
- No Neo4j update for this pass (low-level symbol/thunk cleanup only).

## TODO (next game-logic pass, refreshed)
- [x] Continue to the next adjacent mission corridor (`0x00537000..0x00538000`) and clear easy wrapper/thunk-backed game-logic helpers first.
- [ ] Revisit stream/calling-convention parameter modeling for serializer/deserializer functions once parameter recovery is available (still showing zero formal parameters in this database for several locked functions).
- [ ] Revisit deferred non-low-hanging functions in this lane after storage cleanup:
  - `FUN_005370f0`
  - `FUN_0053714f`
- [ ] Continue to the next adjacent mission corridor (`0x00536000..0x00537000`) for another low-hanging wrapper-first pass.

## Continuation (2026-02-20, game-logic pass: mission base/order helper corridor `0x00536000..0x00537000`)

### Scope
- Completed the next adjacent corridor with low-hanging-first renames.
- Focused on base `TMission` helper methods, linked-order ownership operations, and queue/category aggregation helpers.

### Renames applied and saved
- `FUN_00536090` -> `CompareMissionOrderEntriesByPriorityScore`
- `FUN_005362c0` -> `ComputeDistributionSimilarityScoreFromVectorAndReferenceProfile`
- `FUN_00536390` -> `CreateTNavyMission`
- `MissionCommon_VtblSlot1C` -> `CleanupTMissionAndReleaseOwnedOrders`
- `FUN_00536740` -> `ClearMissionQueuedOrderLinksAndOwnerPointers`
- `FUN_00536780` -> `AttachMissionOrderAsQueuedChildAndNotify`
- `FUN_005367d0` -> `DetachMissionOrderChildAndClearPrimaryIfMatch`
- `FUN_00536810` -> `ClearMissionSecondaryOrderIfMatch`
- `FUN_00536840` -> `BuildMissionQueuedOrderCategoryWeightsAndReturnTotal`
- `FUN_00536b30` -> `UpdateMissionOrderSelectionStateByNationSimilarityThresholds`
- `FUN_00536fa0` -> `RefreshMissionPortZoneContextForNation`
- `FUN_00536fc0` -> `EnsureMissionCurrentTargetContextIsValid`

### Thunk materialization and naming
- Created and renamed:
  - `0x004089b8` -> `thunk_ClearMissionQueuedOrderLinksAndOwnerPointers`
  - `0x0040530d` -> `thunk_AttachMissionOrderAsQueuedChildAndNotify`
  - `0x00401898` -> `thunk_DetachMissionOrderChildAndClearPrimaryIfMatch`
  - `0x00405b91` -> `thunk_ClearMissionSecondaryOrderIfMatch`
  - `0x00404efd` -> `thunk_BuildMissionQueuedOrderCategoryWeightsAndReturnTotal`
  - `0x004051b4` -> `thunk_UpdateMissionOrderSelectionStateByNationSimilarityThresholds`
  - `0x00408c10` -> `thunk_RefreshMissionPortZoneContextForNation`
  - `0x00402810` -> `thunk_EnsureMissionCurrentTargetContextIsValid`
- Renamed existing:
  - `0x004027e3` -> `thunk_ComputeDistributionSimilarityScoreFromVectorAndReferenceProfile`
  - `0x004098c2` -> `thunk_CleanupTMissionAndReleaseOwnedOrders`

### Evidence notes
- `CreateTNavyMission` matches existing class constructors (`CreateTControlSeaZoneMission`, `CreateTEscortMission`) pattern exactly:
  - alloc `0x3C`,
  - `ConstructTMission`,
  - zero shared fields,
  - set vtable to `g_vtblTNavyMission`.
- `thunk_RefreshMissionPortZoneContextForNation` is reused across multiple navy-mission families (`g_vtblTNavyMission` and `g_vtblTEscortMission` slot `+0xA0`), so naming stayed generic.

### Verification
- Re-scan result for `0x00536000..0x00537000`:
  - remaining names matching `FUN_*`/`thunk_FUN_*`/`*VtblSlot*` = `0`.

### Neo4j policy
- No Neo4j update for this pass (low-level symbol/thunk cleanup only).

## Continuation (2026-02-20, game-logic pass: mission stub/comparator lane `0x00535000..0x00536000`)

### Scope
- Continued into adjacent helper lane and resolved tiny boolean stubs, target-id propagators, map compatibility check, and comparator helper.
- Included corresponding thunk islands and easy return-type cleanup.

### Renames applied and saved
- `FUN_005355b0` -> `ReturnTrueForControlSeaZoneMissionCapabilityFlagA`
- `FUN_005355d0` -> `ReturnFalseForControlSeaZoneMissionCapabilityFlagB`
- `FUN_00535640` -> `ReturnTrueForScatteredShipsMissionCapabilityFlagA`
- `FUN_00535660` -> `ReturnTrueForScatteredShipsMissionCapabilityFlagB`
- `FUN_00535680` -> `ReturnTrueForScatteredShipsMissionSlot20`
- `FUN_00535750` -> `GetMissionTargetContextIdFromField14`
- `FUN_00535770` -> `PropagateMissionTargetContextIdToLinkedUnits`
- `FUN_00535790` -> `ReturnTrueForDefendProvinceMissionCapabilityFlagA`
- `FUN_005357b0` -> `ReturnTrueForDefendProvinceMissionCapabilityFlagB`
- `FUN_005357d0` -> `DestroyTDefendProvinceMission`
- `FUN_00535800` -> `ResetTDefendProvinceMissionToSentinelVtable`
- `FUN_005359e0` -> `IsMapTileCompatibleWithCurrentTerrainOrActionContext`
- `FUN_00535f80` -> `CompareMissionOrderEntriesByMovementClassThenEfficiency`

### Thunk materialization and naming
- Created and renamed:
  - `0x0040967e` -> `thunk_ReturnTrueForControlSeaZoneMissionCapabilityFlagA`
  - `0x00401cfd` -> `thunk_ReturnFalseForControlSeaZoneMissionCapabilityFlagB`
  - `0x00406645` -> `thunk_ReturnTrueForScatteredShipsMissionCapabilityFlagA`
  - `0x0040925f` -> `thunk_ReturnTrueForScatteredShipsMissionCapabilityFlagB`
  - `0x0040434a` -> `thunk_ReturnTrueForScatteredShipsMissionSlot20`
  - `0x00401ba9` -> `thunk_GetMissionTargetContextIdFromField14`
  - `0x00405f0b` -> `thunk_PropagateMissionTargetContextIdToLinkedUnits`
  - `0x0040831e` -> `thunk_ReturnTrueForDefendProvinceMissionCapabilityFlagA`
  - `0x0040943f` -> `thunk_ReturnTrueForDefendProvinceMissionCapabilityFlagB`
  - `0x0040438b` -> `thunk_DestroyTDefendProvinceMission`
  - `0x0040448a` -> `thunk_CompareMissionOrderEntriesByMovementClassThenEfficiency`
- Renamed existing:
  - `0x00408cf6` -> `thunk_ResetTDefendProvinceMissionToSentinelVtable`
  - `0x004016d6` -> `thunk_IsMapTileCompatibleWithCurrentTerrainOrActionContext`

### Signature/comment hygiene
- Set return type `bool` for easy 0/1 stub methods and their thunks:
  - control-sea-zone/scattered/defend capability stubs,
  - map-tile compatibility helper.
- Added concise comments for non-obvious helpers/destructor/comparator paths.

### Verification
- Re-scan result for `0x00535000..0x00536000`:
  - remaining names matching `FUN_*`/`thunk_FUN_*`/`*VtblSlot*` = `0`.

### Neo4j policy
- No Neo4j update for this pass (low-level symbol/thunk cleanup only).

## Continuation (2026-02-20, cleanup pass: invade mission residual)

### Renames applied and saved
- `TInvadeMission_VtblSlot1C` (`0x0053f410`) -> `CleanupTInvadeMissionAndReleaseOwnedOrders`
- `thunk_TInvadeMission_VtblSlot1C` (`0x00401505`) -> `thunk_CleanupTInvadeMissionAndReleaseOwnedOrders`

### Verification
- Re-scan result for `0x0053f000..0x00540000`:
  - remaining names matching `FUN_*`/`thunk_FUN_*`/`*VtblSlot*` = `0`.

## TODO (next game-logic pass, refreshed)
- [ ] Revisit stream/calling-convention parameter modeling for serializer/deserializer functions once parameter recovery is available (still showing zero formal parameters in this database for several locked functions).
- [ ] Revisit deferred non-low-hanging functions after storage cleanup:
  - `FUN_005370f0`
  - `FUN_0053714f`
- [ ] Continue low-hanging sweep beyond this corridor while preserving game-logic priority.

## Continuation (2026-02-20, follow-up: resolved deferred range-queue helpers `0x00537000..0x00538000`)

### Renames applied and saved
- `FUN_005370f0` -> `QueueMissionOrderEntriesAcrossSelectionRange`
- `FUN_0053714f` -> `QueueMissionOrderEntryAndPropagateSelectionRange`

### Notes
- These still have decompiler storage artifacts (`unaff_*`), but control flow and called helpers are now sufficiently clear for behavior-based naming.
- Added comments explicitly noting the artifact risk and intended behavior.

## Corridor Status Snapshot (2026-02-20)
- Verified clean (no `FUN_*` / `thunk_FUN_*` / `*VtblSlot*`) across:
  - `0x00535000..0x00536000`
  - `0x00536000..0x00537000`
  - `0x00537000..0x00538000`
  - `0x00538000..0x00539000`
  - `0x00539000..0x0053a000`
  - `0x0053a000..0x0053f000`
  - `0x0053f000..0x00540000`

## TODO (next game-logic pass, refreshed)
- [ ] Revisit stream/calling-convention parameter modeling for serializer/deserializer functions once parameter recovery is available (still showing zero formal parameters in this database for several locked functions).
- [ ] Continue low-hanging game-logic sweep in a new corridor outside `0x00535000..0x00540000` (avoid UI-heavy areas where possible).

## Triage Note (2026-02-20, next corridor selection)
- Quick reconnaissance on `0x00500000..0x00501000` shows mostly UI/object-framework code paths (`TDlgWindow` type-name getter, `THelpMgr`, dialog slot handlers, UI window resource entry ctor/dtor patterns).
- Decision: deprioritized this lane for now to preserve game-logic focus.

## Continuation (2026-02-20, game-logic pass: task-force/navy-order lane `0x00552000..0x00557000`)

### Scope
- Continued in the already-partially-cleaned map-order/task-force corridor.
- Finished the remaining `FUN_*` helpers in this lane, including stream serialization/deserialization and prune/lifecycle helpers.
- Materialized one missing thunk wrapper function at `0x0040283d` (raw JMP island) for consistent naming.

### Renames applied and saved
- `FUN_00552b90` -> `SerializeTaskForceToBinaryStream`
- `FUN_00552d10` -> `DeserializeTaskForceFromBinaryStreamAndRefreshMarkers`
- `FUN_00555090` -> `PruneNavyOrderIfUnserviceableOrNoChildren`
- `FUN_00554b20` -> `BuildTaskForceOrderBreakdownSummaryText`
- `FUN_00554c90` -> `BuildTaskForceSelectionOverlayLabelText`
- `FUN_00554e70` -> `BuildNavyOrderStatusLineText`
- `FUN_005551d0` -> `BuildTaskForcePrimaryObjectiveDescriptionText`

### Thunk materialization and naming
- Created and named:
  - `0x0040283d` -> `thunk_SerializeTaskForceToBinaryStream`
- Renamed existing:
  - `0x00407004` -> `thunk_DeserializeTaskForceFromBinaryStreamAndRefreshMarkers`
  - `0x004063b1` -> `thunk_PruneNavyOrderIfUnserviceableOrNoChildren`
  - `0x00405655` -> `thunk_BuildTaskForceOrderBreakdownSummaryText`
  - `0x00406b7c` -> `thunk_BuildTaskForceSelectionOverlayLabelText`
  - `0x004062b7` -> `thunk_BuildTaskForcePrimaryObjectiveDescriptionText`

### Notes
- `SerializeTaskForceToBinaryStream` and `DeserializeTaskForceFromBinaryStreamAndRefreshMarkers` are high-confidence stream methods (virtual stream interface usage in both paths, with complementary read/write behaviors).
- Added concise function comments on the newly named serialization/prune/text-builder helpers where behavior was not obvious from name alone.

### Verification
- Re-scan result for `0x00552000..0x00557000`:
  - remaining names matching `FUN_*`/`thunk_FUN_*`/`*VtblSlot*` = `0`.

### Neo4j policy
- No Neo4j update for this pass (low-level symbol/thunk cleanup only).

## TODO (next game-logic pass, refreshed)
- [ ] Continue in adjacent non-UI map-action lane and prioritize civilian/build/improvement execution paths over string/UI formatters.
- [ ] Revisit stream/calling-convention parameter modeling for task-force serializers/deserializers if parameter recovery improves.
- [ ] Keep extracting constructor/destructor-backed class slices when clear ownership/lifecycle patterns are present.

## Continuation (2026-02-20, game-logic pass: `TZone` / map-action context slice `0x0055e600..0x0055f700`)

### Scope
- Identified a coherent class-like cluster anchored by class-name getter returning `TZone`.
- Renamed constructor/lifecycle, stream IO, pointer-array membership helpers, and status-selection helper.
- Renamed matching thunk wrappers and set obvious boolean return types for pure flag methods.

### Renames applied and saved
- `FUN_0055e660` -> `CreateTZone`
- `FUN_0055e6e0` -> `GetZoneClassName`
- `FUN_0055e700` -> `ConstructTZoneAndLinkIntoGlobalMapActionContextList`
- `FUN_0055e820` -> `ReturnTrueForZoneCapabilityFlagA`
- `FUN_0055e840` -> `ReturnFalseForZoneCapabilityFlagB`
- `FUN_0055e860` -> `ReturnFalseForZoneCapabilityFlagC`
- `FUN_0055e880` -> `ReturnFalseForZoneCapabilityFlagD`
- `FUN_0055e8a0` -> `ReturnFalseForZoneCapabilityFlagE`
- `FUN_0055e8c0` -> `HasZoneActiveChildCount`
- `FUN_0055e8e0` -> `GetOrAppendUniqueZonePointerInPrimaryArray`
- `FUN_0055e9c0` -> `GetOrAppendUniqueZonePointerInSecondaryArray`
- `FUN_0055ead0` -> `AppendZonePointerToPrimaryArray`
- `FUN_0055eba0` -> `AppendZonePointerToSecondaryArray`
- `FUN_0055ec60` -> `RemoveZoneFromGlobalListAndRelease`
- `FUN_0055ed20` -> `DeserializeZoneFromBinaryStream`
- `FUN_0055eff0` -> `SerializeZoneToBinaryStream`
- `FUN_0055f070` -> `AssignZoneDisplayNameToOutputRef`
- `FUN_0055f090` -> `AssignZoneDisplayNameAliasToOutputRef`
- `FUN_0055f100` -> `FindMapActionContextByNodeId`
- `FUN_0055f300` -> `DispatchMapActionContextCallbackViaField24`
- `FUN_0055f440` -> `ContainsCityStatePointerInZoneArrayByCityIndex`
- `FUN_0055f540` -> `IsZoneMaskOrArrayEntryPresentForKey`
- `FUN_0055f5c0` -> `GenerateZoneStatusCodeIfUnset`

### Thunk renames
- `0x0040405c` -> `thunk_ConstructTZoneAndLinkIntoGlobalMapActionContextList`
- `0x0040466f` -> `thunk_DeserializeZoneFromBinaryStream`
- `0x004024c3` -> `thunk_FindMapActionContextByNodeId`
- `0x0040145b` -> `thunk_DispatchMapActionContextCallbackViaField24`
- `0x00402752` -> `thunk_ContainsCityStatePointerInZoneArrayByCityIndex`
- `0x00404895` -> `thunk_IsZoneMaskOrArrayEntryPresentForKey`
- `0x00401055` -> `thunk_GenerateZoneStatusCodeIfUnset`

### Notes
- Added comments for constructor/list-unlink/stream helpers and key membership/status functions to capture behavior.
- Set bool return type for pure flag helpers:
  - `ReturnTrueForZoneCapabilityFlagA`
  - `ReturnFalseForZoneCapabilityFlagB/C/D/E`
  - `HasZoneActiveChildCount`

### Verification
- Re-scan result for `0x0055e600..0x0055f700`:
  - remaining names matching `FUN_*`/`thunk_FUN_*`/`*VtblSlot*` = `0`.

## Continuation (2026-02-20, low-hanging pass: `TNewsMgr` helper slice `0x0055b600..0x0055bc20`)

### Renames applied and saved
- `FUN_0055b6a0` -> `DestroyTNewsMgr`
- `FUN_0055b6d0` -> `ResetTNewsMgrToSentinelVtable`
- `FUN_0055b6f0` -> `GetNewsMgrClassName`
- `FUN_0055b820` -> `DestroyTNewsMgrAndReleaseHeadlineEntries`
- `FUN_0055b8a0` -> `DeserializeNewsMgrNoOpSlot18`
- `FUN_0055b8c0` -> `SerializeNewsMgrNoOpSlot14`
- `FUN_0055bbf0` -> `GetNewsMgrEntryArrayBaseAtOffset2C`

### Thunk renames
- `0x004093f4` -> `thunk_ResetTNewsMgrToSentinelVtable`
- `0x00408dbe` -> `thunk_GetNewsMgrEntryArrayBaseAtOffset2C`

### Notes
- Added comment on `DestroyTNewsMgrAndReleaseHeadlineEntries` documenting embedded headline/resource release behavior before instance teardown.

### Verification
- Re-scan result for `0x0055b600..0x0055bc20`:
  - remaining names matching `FUN_*`/`thunk_FUN_*`/`*VtblSlot*` = `0`.

### Neo4j policy
- No Neo4j update for these passes (low-level symbol/thunk cleanup only).

## TODO (next game-logic pass, refreshed)
- [ ] Continue from the same global lane into adjacent non-UI map-action/civilian-execution code (`0x0055f700+`) and avoid text-formatting clusters unless needed for control-flow understanding.
- [ ] Revisit stream/calling-convention parameter modeling for zone/task-force serializers if parameter recovery improves.
- [ ] Keep extracting constructor/destructor-backed class slices when direct ownership/lifecycle evidence is present.

## Continuation (2026-02-20, game-logic pass: `TPortZone` / port-context lane `0x00561600..0x00562240`)

### Scope
- Completed a coherent `TPortZone` class slice:
  - capability flags,
  - ctor/dtor/reset paths,
  - stream serialize/deserialize pair,
  - diplomacy/interaction checks,
  - nearest-valid-tile resolver,
  - manager reset/purge helpers.
- Materialized missing JMP-island thunks in `0x0040xxxx` and renamed them consistently.

### Renames applied and saved
- `FUN_00561660` -> `ReturnTrueForPortZoneCapabilityFlagA`
- `FUN_00561680` -> `ReturnTrueForPortZoneCapabilityFlagB`
- `FUN_005616a0` -> `ReturnFalseForPortZoneCapabilityFlagC`
- `FUN_005616c0` -> `DestroyTPortZone`
- `FUN_005616f0` -> `ResetTPortZoneToSentinelVtableAndReleaseResources`
- `FUN_005617d0` -> `GetTPortZoneClassName`
- `FUN_005617f0` -> `DeserializeTPortZoneFromBinaryStream`
- `FUN_00561820` -> `SerializeTPortZoneToBinaryStream`
- `FUN_005618b0` -> `RefreshTPortZoneDisplayNameFromLocalization`
- `FUN_005619e0` -> `ResolvePortZoneOwnerContextAndDispatch`
- `FUN_00561a70` -> `DestroyTPortZoneAndClearOverlayMarkers`
- `FUN_00561b10` -> `IsPortZoneOwnerNationEqual`
- `FUN_00561b50` -> `NotifyDiplomacyManagerForPortZoneOwnerNation`
- `FUN_00561dc0` -> `CanPortZoneInteractWithNationUnderDiplomacyRules`
- `FUN_00561e40` -> `FindNearestValidPortZoneOrCityContextTile`
- `FUN_005620c0` -> `ReallocatePortZoneContextArrayBuffer`
- `FUN_00562140` -> `DestroyTPortZoneManager`
- `FUN_00562170` -> `ResetTPortZoneManagerToSentinelVtable`
- `FUN_00562190` -> `GetTPortZoneManagerClassName`
- `FUN_005621b0` -> `ResetPortZoneGlobalContextCounters`
- `FUN_005621e0` -> `DestroyTPortZoneManagerAndPurgePortZones`

### Additional rename in adjacent lane
- `FUN_0055d1e0` -> `GetTNewspaperViewTypeNamePointer`

### Thunk materialization and naming
- Created and renamed:
  - `0x00401078` -> `thunk_DestroyTPortZone`
  - `0x004011f9` -> `thunk_GetTPortZoneClassName`
  - `0x00401b04` -> `thunk_ReturnTrueForPortZoneCapabilityFlagA`
  - `0x00401bc2` -> `thunk_DestroyTPortZoneManager`
  - `0x00401abe` -> `thunk_GetTPortZoneManagerClassName`
  - `0x00401b6d` -> `thunk_FindNearestValidPortZoneOrCityContextTile`
  - `0x00409327` -> `thunk_DestroyTPortZoneAndClearOverlayMarkers`
  - `0x00409791` -> `thunk_IsPortZoneOwnerNationEqual`
  - `0x00405c13` -> `thunk_CanPortZoneInteractWithNationUnderDiplomacyRules`
  - `0x00404287` -> `thunk_NotifyDiplomacyManagerForPortZoneOwnerNation`
  - `0x004032b5` -> `thunk_SerializeTPortZoneToBinaryStream`
  - `0x004022bb` -> `thunk_GetTNewspaperViewTypeNamePointer`
- Renamed existing:
  - `0x00401465` -> `thunk_ResetTPortZoneToSentinelVtableAndReleaseResources`
  - `0x00401212` -> `thunk_DeserializeTPortZoneFromBinaryStream`
  - `0x00402cb1` -> `thunk_RefreshTPortZoneDisplayNameFromLocalization`
  - `0x004041c9` -> `thunk_ReallocatePortZoneContextArrayBuffer`
  - `0x00407fbd` -> `thunk_ResetTPortZoneManagerToSentinelVtable`
  - `0x004043d1` -> `thunk_ResetPortZoneGlobalContextCounters`

### Signature/comment hygiene
- Set return type `bool` for:
  - `ReturnTrueForPortZoneCapabilityFlagA`
  - `ReturnTrueForPortZoneCapabilityFlagB`
  - `ReturnFalseForPortZoneCapabilityFlagC`
  - `IsPortZoneOwnerNationEqual`
  - `CanPortZoneInteractWithNationUnderDiplomacyRules`
- Added comments to non-obvious logic paths (resource release, diplomacy gate checks, nearest-valid-tile search, manager purge loop).

### Verification
- Re-scan result for `0x00561600..0x00562240`:
  - remaining names matching `FUN_*`/`thunk_FUN_*`/`*VtblSlot*` = `0`.

## Continuation (2026-02-20, game-logic pass: navy-order/map-context helpers in `0x00557000..0x00564000`)

### Renames applied and saved (batch A)
- `FUN_00557170` -> `ComputeAggregateWeightedChildCostForMatchingType5NavyOrders`
- `FUN_00557210` -> `RemoveOrdersByNationFromPrimarySecondaryAndTaskForceLists`
- `FUN_00557320` -> `BuildNavyOrderPromptTextByLocalizationMode`
- `FUN_005573f0` -> `CreateNavySecondaryOrderEntryAndDeduplicateDisplayName`
- `FUN_00563220` -> `RegenerateAllMapActionContextStatusCodes`
- `FUN_00563300` -> `GetMapActionContextEntryByNationCodeOffset17`
- `FUN_00563330` -> `GetMapActionContextEntryByIndex`

### Thunks renamed (batch A)
- `0x00403ef9` -> `thunk_ComputeAggregateWeightedChildCostForMatchingType5NavyOrders`
- `0x004059f7` -> `thunk_RemoveOrdersByNationFromPrimarySecondaryAndTaskForceLists`
- `0x0040395e` -> `thunk_BuildNavyOrderPromptTextByLocalizationMode`
- `0x00408f21` -> `thunk_RegenerateAllMapActionContextStatusCodes`
- `0x00402b03` -> `thunk_GetMapActionContextEntryByNationCodeOffset17`
- `0x0040165e` -> `thunk_GetMapActionContextEntryByIndex`

### Renames applied and saved (batch B)
- `FUN_00557e10` -> `UpdateType7NavyOrderChildSelectionByChanceThreshold`
- `FUN_00558860` -> `EnsureDwordPointerArraySlotAndReturnPointer`
- `FUN_0055fae0` -> `ResizePointerArrayCapacityByRequestedCount`
- `FUN_00560470` -> `AdvanceSpiralSearchStateAndStepHexCoordinates`
- `FUN_00560970` -> `GetMapOrderContextPointerForNationAndTarget`
- `FUN_00560e20` -> `ResetMapActionContextActivityAndNationFlags`
- `FUN_00561300` -> `ResizePointerArrayCapacityByRequestedCountAlt`
- `FUN_00561400` -> `BuildNationBitmaskForActiveType3Or4OrdersIncludingNation`
- `FUN_00561490` -> `BuildNationBitmaskForActiveType3Or4Orders`
- `FUN_00561510` -> `HasDiplomaticallyRelatedNationInActiveType3Or4OrderMask`
- `FUN_005615e0` -> `CreateTPortZone`
- `FUN_005627a0` -> `ReleaseTPortZoneOwnedResourcesAndUnlinkFromGlobalList`
- `FUN_00562880` -> `DestroyTPortZoneArrayWithOptionalElementDestruct`

### Thunks renamed/materialized (batch B)
- Created and renamed:
  - `0x00407fb8` -> `thunk_DestroyTPortZoneArrayWithOptionalElementDestruct`
- Renamed existing:
  - `0x004080f3` -> `thunk_EnsureDwordPointerArraySlotAndReturnPointer`
  - `0x004089a9` -> `thunk_ResizePointerArrayCapacityByRequestedCount`
  - `0x004090a2` -> `thunk_AdvanceSpiralSearchStateAndStepHexCoordinates`
  - `0x00401299` -> `thunk_GetMapOrderContextPointerForNationAndTarget`
  - `0x004011e0` -> `thunk_ResetMapActionContextActivityAndNationFlags`
  - `0x00408b6b` -> `thunk_ResizePointerArrayCapacityByRequestedCountAlt`
  - `0x00406e29` -> `thunk_HasDiplomaticallyRelatedNationInActiveType3Or4OrderMask`

### Additional adjacent renames
- `FUN_0055d160` -> `CreateTNewspaperView`
- `FUN_0055e360` -> `StepHexTileIndexByDirectionWithWrapRules`
- `FUN_0055e550` -> `StepHexRowColByDirectionWithWrapRules`
- `0x00403968` -> `thunk_StepHexTileIndexByDirectionWithWrapRules`
- `0x0040678f` -> `thunk_StepHexRowColByDirectionWithWrapRules`

### Signature/comment hygiene
- Set return type `bool` for:
  - `StepHexRowColByDirectionWithWrapRules`
  - `HasDiplomaticallyRelatedNationInActiveType3Or4OrderMask`
- Added comments for non-obvious helpers (spiral-step state machine, order-mask builders, context-reset loops, optional deep array destruction, status-regeneration behavior).

### Verification snapshot
- Broad range `0x00557000..0x00564000` generic count progression:
  - before this continuation: `75`
  - after first sub-pass: `53`
  - after next sub-passes: `43`
  - current: `30`

### Neo4j policy
- No Neo4j update for this continuation (low-level symbol/thunk cleanup only).

## TODO (next game-logic pass, refreshed)
- [ ] Continue reducing remaining `0x00557000..0x00564000` generics, prioritizing non-UI logic (`0x0055f780`, `0x00560150`, `0x00562340`, `0x00562f20`).
- [ ] Defer UI-heavy localized string assemblers unless needed for control-flow anchoring (`0x0055da80`, `0x0055dcd0`, `0x0055de90`).
- [ ] Revisit stream/calling-convention parameter modeling where signatures remain storage-locked.

## Continuation (2026-02-21, low-hanging cleanup: final generics in `0x00557000..0x00564000`)

### Scope
- Closed the last generic names in this range by targeting:
  - two larger interaction/outcome routines (`0x00557f10`, `0x00558960`),
  - two tiny alternating-search helpers used through JMP-island entries (`0x0055fe60`, `0x0055fef0`).
- Kept names behavior-oriented and non-speculative.

### Renames applied and saved
- `FUN_00557f10` -> `SelectEligibleMapOrderInteractionForNationAndContext`
- `FUN_00558960` -> `ProcessNationMapOrderInteractionsAndApplyOutcomes`
- `FUN_0055fe60` -> `FindNearestActiveSeaContextTileFromOffset216`
- `FUN_0055fef0` -> `FindNearestActiveSeaContextTileFromCurrentTile`

### Thunk materialization and renames
- Created and renamed missing JMP-island functions:
  - `0x00406208` -> `thunk_FindNearestActiveSeaContextTileFromOffset216`
  - `0x00405f5b` -> `thunk_FindNearestActiveSeaContextTileFromCurrentTile`
- Renamed existing thunk wrappers:
  - `0x004045d9` -> `thunk_SelectEligibleMapOrderInteractionForNationAndContext`
  - `0x0040977d` -> `thunk_ProcessNationMapOrderInteractionsAndApplyOutcomes`

### Signature/comment hygiene
- Return types updated:
  - `SelectEligibleMapOrderInteractionForNationAndContext` -> `bool`
  - `FindNearestActiveSeaContextTileFromOffset216` -> `short`
  - `FindNearestActiveSeaContextTileFromCurrentTile` -> `short`
- Added function comments for all four renamed routines to preserve intent and avoid re-analysis churn.

### Verification
- Re-scan result for `0x00557000..0x00564000`:
  - remaining names matching `FUN_*`/`thunk_FUN_*` = `0`.

### Neo4j policy
- No Neo4j update for this pass (low-level symbol/thunk/type cleanup only).

## TODO (next game-logic pass, refreshed)
- [ ] Move to next adjacent game-logic lane outside this now-clean band (`0x00564000+`) and repeat low-hanging naming + thunk materialization.
- [ ] Prioritize routines with direct state/economy/map mutation over UI-localized text builders.
- [ ] Keep extracting constructor/destructor-backed class slices when ownership/lifecycle evidence is explicit.

## Continuation (2026-02-21, low-hanging helper pass: map-order interaction support routines)

### Scope
- Focused on directly observed helper callees from:
  - `SelectEligibleMapOrderInteractionForNationAndContext`
  - `ProcessNationMapOrderInteractionsAndApplyOutcomes`
  - `SetMapActionContextTargetTileAndRefreshMarkers`
- Chose only behavior-evident helpers (callback iteration, short-counter accumulation, tile-byte update/notify, interaction payload dispatch, label formatting, heuristic scoring).

### Renames applied and saved
- `FUN_00412600` -> `InvokeCallbackForRecordRangeWithStride`
- `FUN_004ddcf0` -> `AddShortDeltaToNationCounterAtOffset198`
- `FUN_00515e00` -> `SetMapTileStateByteAndNotifyObserver`
- `FUN_00550aa0` -> `ComputeMapOrderEntryHeuristicScore`
- `FUN_004a6e80` -> `DispatchMapInteractionPayloadAndResetWorkingFields`
- `FUN_00550c20` -> `FormatLocalizedCommodityCountLabelByIndex`

### Thunk renames
- `0x004025d1` -> `thunk_InvokeCallbackForRecordRangeWithStride`
- `0x004018bb` -> `thunk_AddShortDeltaToNationCounterAtOffset198`
- `0x0040107d` -> `thunk_SetMapTileStateByteAndNotifyObserver`
- `0x0040735b` -> `thunk_ComputeMapOrderEntryHeuristicScore`
- `0x00408f30` -> `thunk_DispatchMapInteractionPayloadAndResetWorkingFields`
- `0x004062ee` -> `thunk_FormatLocalizedCommodityCountLabelByIndex`

### Signature/comment hygiene
- Return type updated:
  - `ComputeMapOrderEntryHeuristicScore` -> `short`
- Added comments for all renamed non-thunk helpers to capture intent and reduce future re-analysis.

### Verification
- Confirmed all renamed addresses and thunks persisted in Ghidra save.

### Neo4j policy
- No Neo4j update for this pass (low-level rename/thunk/comment maintenance only).

## TODO (next game-logic pass, refreshed)
- [ ] Continue with nearby interaction-weight helpers still generic (`0x004b4290`, `0x004b4310`, `0x004b4390`) and only rename when score/weight semantics are explicit.
- [ ] Advance into `0x00564000+` by selecting one tight class/vtable slice at a time instead of broad-range sweep.
- [ ] Keep prioritizing logic that mutates nation/map/order state over formatting-only routines.

## Continuation (2026-02-21, game-logic pass: resource-weight and allocation helper cluster)

### Scope
- Completed the previously queued interaction-weight helper trio and their accessor dependencies.
- All renames were based on direct decomp behavior (weighted averages, random constrained allocation, descriptor lookups).

### Renames applied and saved
- `FUN_00550d80` -> `GetResourceTypeRandomDrawBlockFlag`
- `FUN_00550ed0` -> `GetResourceDescriptorWeightWord1ByType`
- `FUN_004b4290` -> `ComputeAverageWeightWord1TimesTenFromResourceCounts`
- `FUN_004b4310` -> `ComputeAverageWeightWord0TimesTenFromResourceCounts`
- `FUN_004b4390` -> `AllocateRandomResourceCountsWithinWeightBudget`
- `FUN_00550670` -> `SelectPreferredMapOrderEntryByPriorityRules`

### Thunk renames
- `0x00408ed6` -> `thunk_GetResourceTypeRandomDrawBlockFlag`
- `0x004035ee` -> `thunk_GetResourceDescriptorWeightWord1ByType`
- `0x00403472` -> `thunk_ComputeAverageWeightWord1TimesTenFromResourceCounts`
- `0x00408184` -> `thunk_ComputeAverageWeightWord0TimesTenFromResourceCounts`
- `0x00402ecd` -> `thunk_AllocateRandomResourceCountsWithinWeightBudget`
- `0x004076fd` -> `thunk_SelectPreferredMapOrderEntryByPriorityRules`

### Signature/comment hygiene
- Return types set:
  - `GetResourceTypeRandomDrawBlockFlag` -> `short`
  - `GetResourceDescriptorWeightWord0ByType` -> `short`
  - `GetResourceDescriptorWeightWord1ByType` -> `short`
- Added comments for all renamed non-thunk helpers in this cluster.

### Verification
- Verified all renamed addresses persisted and resolve by new names in Ghidra.

### Neo4j policy
- No Neo4j update (low-level symbol/typing cleanup only).

## Continuation (2026-02-21, game-logic follow-up: representative terrain tile helper)

### Renames applied and saved
- `FUN_005178f0` -> `ComputeRepresentativeTileIndexForTerrainTypeWithWrapBias`
- `0x00405344` -> `thunk_ComputeRepresentativeTileIndexForTerrainTypeWithWrapBias`

### Signature/comment hygiene
- Return type updates:
  - `ComputeRepresentativeTileIndexForTerrainTypeWithWrapBias` -> `ushort`
  - `ComputeAverageWeightWord1TimesTenFromResourceCounts` -> `int`
  - `ComputeAverageWeightWord0TimesTenFromResourceCounts` -> `int`
  - `AllocateRandomResourceCountsWithinWeightBudget` -> `int`
  - `SelectPreferredMapOrderEntryByPriorityRules` -> `int`
- Added behavior comment to `ComputeRepresentativeTileIndexForTerrainTypeWithWrapBias`.

### Verification
- Verified function/thunk names and return types:
  - `0x005178f0`, `0x00405344`, `0x004b4290`, `0x004b4310`, `0x004b4390`, `0x00550670`, `0x00550d80`, `0x00550ed0`.

## TODO (next game-logic pass, refreshed)
- [ ] Continue in `0x00564000+` but focus on non-UI state mutators (defer `TMilitaryPageView`/`TNavyRoster` UI lifecycle cluster unless needed for a logic dependency).
- [ ] Decode and rename the remaining map-order state helpers that feed `ProcessNationMapOrderInteractionsAndApplyOutcomes`.
- [ ] Keep constructor/destructor extraction only when class identity is explicit from type-name string + vtable + lifecycle trio.

## Continuation (2026-02-21, additional progress in same session)

### Resource-weight helper cluster completed
- Renamed:
  - `FUN_00550d80` -> `GetResourceTypeRandomDrawBlockFlag`
  - `FUN_00550ed0` -> `GetResourceDescriptorWeightWord1ByType`
  - `FUN_004b4290` -> `ComputeAverageWeightWord1TimesTenFromResourceCounts`
  - `FUN_004b4310` -> `ComputeAverageWeightWord0TimesTenFromResourceCounts`
  - `FUN_004b4390` -> `AllocateRandomResourceCountsWithinWeightBudget`
  - `FUN_00550670` -> `SelectPreferredMapOrderEntryByPriorityRules`
- Thunks:
  - `0x00408ed6` -> `thunk_GetResourceTypeRandomDrawBlockFlag`
  - `0x004035ee` -> `thunk_GetResourceDescriptorWeightWord1ByType`
  - `0x00403472` -> `thunk_ComputeAverageWeightWord1TimesTenFromResourceCounts`
  - `0x00408184` -> `thunk_ComputeAverageWeightWord0TimesTenFromResourceCounts`
  - `0x00402ecd` -> `thunk_AllocateRandomResourceCountsWithinWeightBudget`
  - `0x004076fd` -> `thunk_SelectPreferredMapOrderEntryByPriorityRules`
- Return types updated:
  - `GetResourceTypeRandomDrawBlockFlag` -> `short`
  - `GetResourceDescriptorWeightWord0ByType` -> `short`
  - `GetResourceDescriptorWeightWord1ByType` -> `short`
- Added comments on all non-thunk helpers in this cluster.

### Terrain representative helper renamed
- `FUN_005178f0` -> `ComputeRepresentativeTileIndexForTerrainTypeWithWrapBias`
- `0x00405344` -> `thunk_ComputeRepresentativeTileIndexForTerrainTypeWithWrapBias`
- Return type: `ushort`
- Added behavior comment documenting averaging + wrap-bias + fallback behavior.

### Navy task-force selection pair renamed
- `FUN_00564400` -> `HandleNavyOrderNodeRemovalAndSelectionRefresh`
- `FUN_00564600` -> `EnsureSelectedTaskForceForOrderOwnerAndRefresh`
- Thunks:
  - `0x00404c28` -> `thunk_HandleNavyOrderNodeRemovalAndSelectionRefresh`
  - `0x0040928c` -> `thunk_EnsureSelectedTaskForceForOrderOwnerAndRefresh`
- Return types:
  - `HandleNavyOrderNodeRemovalAndSelectionRefresh` -> `void`
  - `EnsureSelectedTaskForceForOrderOwnerAndRefresh` -> `int`
- Added comments to both functions.

### Verification
- Verified persisted names/types in Ghidra for:
  - `0x00564400`, `0x00404c28`, `0x00564600`, `0x0040928c`,
  - `0x005178f0`, `0x00405344`,
  - `0x004b4290`, `0x004b4310`, `0x004b4390`,
  - `0x00550670`, `0x00550d80`, `0x00550ed0`.

### Neo4j policy
- No Neo4j update (low-level rename/type/comment cleanup only).

## TODO (next game-logic pass, refreshed)
- [ ] Continue from `EnsureSelectedTaskForceForOrderOwnerAndRefresh` callers/callees and finish nearby order-state mutators before touching view constructors.
- [ ] Identify and rename one additional non-UI `0x00564xxx` mutator cluster (selection/order transitions) with thunk alignment.
- [ ] Keep deferring `TMilitaryPageView`/`TNavyRoster` pure lifecycle/UI methods unless they gate logic paths.

## Continuation (2026-02-21, game-logic pass: navy primary/secondary order list management cluster)

### Scope
- Pivoted to functions referencing:
  - `g_pNavyPrimaryOrderList`
  - `g_pNavySecondaryOrderList`
- Prioritized concrete order-list logic (index lookup, node lookup, node create/link/unlink, selection rebind, preferred-child recomputation) and deferred UI page-view construction paths.

### Renames applied and saved (cluster batch 1)
- `FUN_00550610` -> `GetNavyPrimaryOrderListIndexOfNode`
- `FUN_00550640` -> `GetNavyPrimaryOrderNodeByIndex`
- `FUN_005512d0` -> `CreateNavySecondaryOrderNodeWithSentinelNation`
- `FUN_00551430` -> `ConstructAndLinkNavySecondaryOrderNode`
- `FUN_005515d0` -> `DestroyAndUnlinkNavySecondaryOrderNode`
- `FUN_00551670` -> `SerializeNavyOrderSelectionStateToStream`
- `FUN_00551700` -> `DeserializeNavyOrderSelectionStateFromStream`
- `FUN_00551850` -> `SelectNavyPrimaryOrderByNationAndRecomputePreferredChild`

### Thunk renames (cluster batch 1)
- `0x00408e81` -> `thunk_GetNavyPrimaryOrderListIndexOfNode`
- `0x0040254a` -> `thunk_GetNavyPrimaryOrderNodeByIndex`
- `0x004093db` -> `thunk_ConstructAndLinkNavySecondaryOrderNode`
- `0x00404e0d` -> `thunk_DestroyAndUnlinkNavySecondaryOrderNode`
- `0x004092dc` -> `thunk_DeserializeNavyOrderSelectionStateFromStream`
- `0x0040472d` -> `thunk_SelectNavyPrimaryOrderByNationAndRecomputePreferredChild`

### Additional rename in same lane
- `FUN_00551a00` -> `AccumulateRandomizedNavyOrderResourceDeltasByNationAndOwner`
- `0x0040523b` -> `thunk_AccumulateRandomizedNavyOrderResourceDeltasByNationAndOwner`

### Signature/comment hygiene
- Return types updated:
  - `GetNavyPrimaryOrderListIndexOfNode` -> `int`
  - `GetNavyPrimaryOrderNodeByIndex` -> `void *`
  - `CreateNavySecondaryOrderNodeWithSentinelNation` -> `void *`
  - `ConstructAndLinkNavySecondaryOrderNode` -> `void *`
  - `DestroyAndUnlinkNavySecondaryOrderNode` -> `void`
  - `SerializeNavyOrderSelectionStateToStream` -> `void`
  - `DeserializeNavyOrderSelectionStateFromStream` -> `void`
  - `SelectNavyPrimaryOrderByNationAndRecomputePreferredChild` -> `void`
  - `AccumulateRandomizedNavyOrderResourceDeltasByNationAndOwner` -> `short`
- Added comments for non-obvious helper behavior in this cluster (list index/node lookup, node lifecycle/linking, selection-state stream operations, and randomized delta accumulation).

### Verification
- Verified names/types persisted for:
  - `0x00550610`, `0x00408e81`,
  - `0x00550640`, `0x0040254a`,
  - `0x005512d0`,
  - `0x00551430`, `0x004093db`,
  - `0x005515d0`, `0x00404e0d`,
  - `0x00551670`,
  - `0x00551700`, `0x004092dc`,
  - `0x00551850`, `0x0040472d`,
  - `0x00551a00`, `0x0040523b`.

### Neo4j policy
- No Neo4j update (low-level rename/type/comment cleanup only).

## TODO (next game-logic pass, refreshed)
- [ ] Continue in same navy-order lane with remaining primary-list generics (`0x0054f500`, `0x0054f640`, `0x0054f8e0`, `0x0054fbf0`) before jumping to UI-centric classes.
- [ ] Improve prototype/calling-convention quality where parameter storage becomes stable (currently several helpers remain `unknown` CC despite good names/types).
- [ ] Keep de-prioritizing `TMilitaryPageView`/`TNavyRoster` constructor/destructor/UI-lifecycle methods unless they gate order mutation logic.

## Continuation (2026-02-21, game-logic pass: navy primary-order node lifecycle subcluster)

### Renames applied and saved
- `FUN_0054f500` -> `ConstructAndLinkNavyPrimaryOrderNode`
- `FUN_0054f640` -> `DestroyAndUnlinkNavyPrimaryOrderNode`
- `FUN_0054f8e0` -> `CreateNavyPrimaryOrderNodeAndAssignDisplayName`
- `FUN_0054fbf0` -> `RegenerateNavyPrimaryOrderDisplayNameUntilUnique`

### Thunk renames
- `0x00406ff0` -> `thunk_ConstructAndLinkNavyPrimaryOrderNode`
- `0x004093bd` -> `thunk_CreateNavyPrimaryOrderNodeAndAssignDisplayName`
- `0x00402fe0` -> `thunk_RegenerateNavyPrimaryOrderDisplayNameUntilUnique`

### Signature/comment hygiene
- Return types updated:
  - `ConstructAndLinkNavyPrimaryOrderNode` -> `void *`
  - `DestroyAndUnlinkNavyPrimaryOrderNode` -> `void`
  - `CreateNavyPrimaryOrderNodeAndAssignDisplayName` -> `void *`
  - `RegenerateNavyPrimaryOrderDisplayNameUntilUnique` -> `void`
  - matching thunk return types aligned.
- Added comments describing node lifecycle and unique-name regeneration behavior.

## Continuation (2026-02-21, lane verification)

### Navy list reference verification
- Re-scanned all function references to:
  - `g_pNavyPrimaryOrderList`
  - `g_pNavySecondaryOrderList`
- Result:
  - `total_ref_functions = 34`
  - `generic_ref_functions = 0` (`FUN_*`/`thunk_FUN_*` absent in this anchor lane).

### Neo4j policy
- No Neo4j update (low-level symbol/type/comment cleanup only).

## TODO (next game-logic pass, refreshed)
- [ ] Move to the next non-UI anchor lane adjacent to navy order mutation flow (e.g., functions consuming task-force outcomes rather than list/node maintenance).
- [ ] Keep improving signatures only where parameter storage is stable enough to avoid speculative prototypes.
- [ ] Continue avoiding UI page/view constructor clusters unless they directly gate game-state mutations.

## Continuation (2026-02-21, game-logic pass: navy lane cleanup in `0x0054f000..0x00552000`)

### Batch 3 renames (low-hanging lifecycle/accessor set)
- `FUN_0054f460` -> `CreateNavyPrimaryOrderNode`
- `FUN_0054f4e0` -> `GetTShipTypeName`
- `FUN_0054f5c0` -> `DestructTShipAndFreeIfOwned`
- `FUN_0054f5f0` -> `DestructTShip`
- `FUN_0054fab0` -> `SerializeNavyPrimaryOrderNodeToStream`
- `FUN_0054fb50` -> `DeserializeNavyPrimaryOrderNodeFromStream`
- `FUN_00550970` -> `GetIndustryActionCostWeightByResourceType`
- `FUN_00550db0` -> `GetResourceDescriptorWord0CByType`
- `FUN_00550de0` -> `GetResourceDescriptorWord10ByType`
- `FUN_00550e10` -> `GetResourceDescriptorWord14ByType`
- `FUN_00550e40` -> `GetResourceDescriptorWord18ByType`
- `FUN_00550ea0` -> `GetResourceDescriptorWord20ByType`
- `FUN_00551410` -> `GetTAdmiralTypeName`
- `FUN_00551550` -> `DestructTAdmiralAndFreeIfOwned`
- `FUN_00551580` -> `DestructTAdmiral`
- `FUN_005519d0` -> `FindCumulativeWeightBucketIndex`

### Batch 3 thunk renames
- `0x00401faa` -> `thunk_DestructTShip`
- `0x004019dd` -> `thunk_GetIndustryActionCostWeightByResourceType`
- `0x0040180c` -> `thunk_GetResourceDescriptorWord0CByType`
- `0x00405a60` -> `thunk_GetResourceDescriptorWord10ByType`
- `0x00407df1` -> `thunk_GetResourceDescriptorWord14ByType`
- `0x004072a2` -> `thunk_GetResourceDescriptorWord18ByType`
- `0x00405e9d` -> `thunk_GetResourceDescriptorWord20ByType`
- `0x004051cd` -> `thunk_DestructTAdmiral`
- `0x00403017` -> `thunk_FindCumulativeWeightBucketIndex`

### Batch 4 renames (remaining small/medium generic helpers)
- `FUN_0054fee0` -> `GetNavyContextPointerFromGlobalTableByIndex`
- `FUN_00550510` -> `GetOrderNodeDescriptorWord20ByResourceType`
- `FUN_00550550` -> `ComputeOrderNodeDistanceQuotientByDescriptorWord24`
- `FUN_00550820` -> `GetOrderNodeDescriptorWord0CByResourceType`
- `FUN_00550840` -> `ComputeOrderNodeDerivedScoreFromQuantityAndWord18`
- `FUN_005509c0` -> `PruneOrPromoteOrderNodeWhenChildCostDepleted`
- `FUN_00550b60` -> `ComputeOrderNodeCompositeEconomicScore`
- `FUN_00550f30` -> `GetResourceDescriptorWord08ByTypeOffset`
- `FUN_00550f60` -> `InvokeOrderNodeOwnerVfunc38`
- `FUN_00550f80` -> `DecrementOrderNodeRequiredCount`
- `FUN_00551100` -> `ReassignOrderNodeNationAndRebindParentCounters`

### Batch 4 thunk renames
- `0x0040185c` -> `thunk_GetNavyContextPointerFromGlobalTableByIndex`
- `0x00408c56` -> `thunk_GetOrderNodeDescriptorWord20ByResourceType`
- `0x00401807` -> `thunk_ComputeOrderNodeDistanceQuotientByDescriptorWord24`
- `0x004083aa` -> `thunk_GetOrderNodeDescriptorWord0CByResourceType`
- `0x00404269` -> `thunk_ComputeOrderNodeDerivedScoreFromQuantityAndWord18`
- `0x004026d0` -> `thunk_PruneOrPromoteOrderNodeWhenChildCostDepleted`
- `0x004085b2` -> `thunk_ComputeOrderNodeCompositeEconomicScore`
- `0x0040965b` -> `thunk_GetResourceDescriptorWord08ByTypeOffset`
- `0x00407c75` -> `thunk_InvokeOrderNodeOwnerVfunc38`
- `0x00404ade` -> `thunk_DecrementOrderNodeRequiredCount`
- `0x00401c26` -> `thunk_ReassignOrderNodeNationAndRebindParentCounters`

### Signature/comment hygiene
- Return types aligned for accessors and mutators (short/int/void/pointer as appropriate), including thunk wrappers where useful.
- Added focused comments for non-obvious formulas and state-mutation helpers:
  - distance quotient,
  - derived score,
  - child-cost prune/promote behavior,
  - composite economic score,
  - nation reassignment with parent counter rebind.
- Corrected return-type mistake during pass:
  - `FindCumulativeWeightBucketIndex` / thunk set to `int` (not `void`).

### Verification
- Re-scan for `0x0054f000..0x00552000`:
  - remaining generic functions = `1`
  - remaining generic: `0x00551be0`.

### Neo4j policy
- No Neo4j update (low-level rename/type/comment cleanup only).

## TODO (next game-logic pass, refreshed)
- [ ] Analyze and rename `0x00551be0` (the only remaining generic in `0x0054f000..0x00552000`) with a phased approach (top-level behavior, then helper names).
- [ ] After `0x00551be0`, move to the next adjacent non-UI mutation lane and repeat low-hanging cleanup.
- [ ] Keep signatures conservative where parameter storage remains unstable/unknown.

## Continuation (2026-02-21, game-logic pass: navy summary + engineer/map-action low-hanging)

### Completed: `0x00551be0` navy summary helper (previous single remaining generic in `0x0054f000..0x00552000`)
- `FUN_00551be0` -> `BuildNavyOrderResourceDeltaSummaryText`
- `0x004073a1` -> `thunk_BuildNavyOrderResourceDeltaSummaryText`
- Return types aligned to `void`.
- Added comment documenting behavior:
  - aggregates randomized per-resource navy-order deltas,
  - formats localized per-resource/total phrasing,
  - emits final shared-string summary used by map-context dialog flow.

### Verification checkpoint
- Re-scan of `0x0054f000..0x00552000` now reports:
  - remaining `FUN_*`/`thunk_FUN_*` = `0`.

### Continued adjacent map-action lane (`0x005658d0` cluster) with low-hanging semantic names
- `FUN_005658d0` -> `HandleEngineerOrderDialogCheckOrNameCommandAndForward`
- `FUN_00565a40` -> `RunEngineerOrderNameEditDialogAndApply`
- `0x004092ff` -> `thunk_RunEngineerOrderNameEditDialogAndApply`
- `FUN_005661d0` -> `ComputeEngineerPlacementTileAndOwnershipStateFromCursor`
- `FUN_00565d20` -> `ComputeWrappedIsometricScreenOffsetFromTile`
- `0x00404241` -> `thunk_ComputeWrappedIsometricScreenOffsetFromTile`

### Signature/comment hygiene
- Return types aligned to `void` for all renamed functions above.
- Added plate comments on non-obvious behavior for:
  - `HandleEngineerOrderDialogCheckOrNameCommandAndForward`
  - `RunEngineerOrderNameEditDialogAndApply`
  - `ComputeEngineerPlacementTileAndOwnershipStateFromCursor`
  - `ComputeWrappedIsometricScreenOffsetFromTile`

### Verification
- Verified persisted names/signatures for:
  - `0x00551be0`, `0x004073a1`,
  - `0x005658d0`, `0x00565a40`, `0x004092ff`,
  - `0x005661d0`, `0x00565d20`, `0x00404241`.
- Re-scan of `0x00562000..0x00568000`:
  - remaining `FUN_*`/`thunk_FUN_*` = `33` (still substantial, mostly same cluster).

### Neo4j policy
- No Neo4j update (low-level rename/type/comment cleanup only).

## TODO (next game-logic pass, refreshed)
- [ ] Continue in `0x00562000..0x00568000`, prioritizing non-UI map-action/order-state logic and skipping pure dialog/resource-entry constructors.
- [ ] Focus next on the `0x00564860..0x005654e0` residual generics and peel off only high-confidence behavioral renames.
- [ ] Improve easy function signatures/parameter names only where argument roles are stable from decomp + callsite evidence.

## Continuation (2026-02-21, game-logic pass: map-order command routing + sea-access gating + trade init)

### Map-order command/selection helpers renamed and documented
- `FUN_005962a0` -> `HandleMapTileClickSetOrderContextAndDispatchEvent79`
- `FUN_00569550` -> `HandleMapOrderPanelCommandTagsAndSelectionCycling`
- `FUN_00598e10` -> `RunNavyPrimaryOrderCreationDialogAndApplyResults`

### Sea-access diplomatic gating helper renamed
- `FUN_00513ca0` -> `HasReachableSeaTileOutsideActiveType3Or4DiplomaticMask`
- `0x00403b52` -> `thunk_HasReachableSeaTileOutsideActiveType3Or4DiplomaticMask`
- Return type aligned to `bool` on both function + thunk.

### Trade-screen logic helper renamed
- `FUN_00588b70` -> `SyncTradeCommoditySelectionWithActiveNationAndInitControls`
- Return type aligned to `void`.

### Signature/comment hygiene
- Added comments to all newly renamed non-thunk functions in this pass, with behavior-focused summaries:
  - map-tile click context rebinding + event dispatch,
  - map-order panel command-tag handling (owner/defend/done/next/bomb) and selection cycling,
  - navy primary-order dialog materialization and apply flow,
  - sea-tile reachability predicate under active diplomacy mask,
  - trade commodity slot sync + control initialization.

### Verification
- Verified persisted names/signatures for:
  - `0x005962a0`, `0x00569550`, `0x00598e10`,
  - `0x00513ca0`, `0x00403b52`,
  - `0x00588b70`.
- Generated quick candidate list for further game-logic triage:
  - `tmp_decomp/cluster_next_a/generic_logic_candidates.txt`

### Neo4j policy
- No Neo4j update (low-level rename/type/comment cleanup only).

## TODO (next game-logic pass, refreshed)
- [ ] Continue from `tmp_decomp/cluster_next_a/generic_logic_candidates.txt` top-ranked map/mission/order candidates and keep skipping pure UI paint/resource-entry constructors.
- [ ] In the `0x00562000..0x00568000` corridor, prioritize remaining command/selection/state-mutator helpers over draw/invalidate handlers.
- [ ] Tighten easy prototypes/parameter names for renamed game-logic functions when callsite storage is stable.

## Continuation (2026-02-21, game-logic pass: task-force pruning + order deserialization + tactical queueing + trade control)

### Task-force/order-state helpers renamed
- `FUN_0059edd0` -> `DecrementRequiredCountsForTaskForceOrderChildrenAndPruneHead`
- `FUN_0059eea0` -> `AddOrderNodeToHeadAndReassignNationCounters`
- `FUN_005a5b70` -> `ResolveNavyOrderChainsForTurnPhase`
- `FUN_005a6330` -> `GetOrderNodeDescriptorWord0CAsIntByResourceType`

### Civilian/military/navy order deserialization helpers renamed
- `FUN_00598d70` -> `CreateCivilianWorkOrderAndRegisterSelection`
- `FUN_00582630` -> `DeserializeAndCreateCivilianWorkOrderFromStream`
- `FUN_005824c0` -> `DeserializeAndCreateMilitaryRecruitOrdersFromStream`
- `FUN_00582720` -> `DeserializeAndCreateNavyPrimaryOrdersFromStream`

### Tactical move/queue helpers renamed
- `FUN_005a1bd0` -> `MoveTacticalUnitAndQueueEvent232AIfNoAdjacentReachableTarget`
- `FUN_005a5c50` -> `MoveTacticalUnitAndQueueEvent232AOnBlockedEngagementState`

### City capability + trade control helpers renamed
- `FUN_0050a6a0` -> `RefreshCityCapabilityUiHandlesForActiveNation`
- `0x00404804` -> `thunk_RefreshCityCapabilityUiHandlesForActiveNation`
- `FUN_00589260` -> `InitializeTradeBarsFromSelectedCommodityControl`
- `FUN_005897b0` -> `SelectTradeCommodityPresetBySummaryTagAndInitControls`
- `FUN_0058a610` -> `SelectTradeSpecialCommodityAndInitializeControls`
- `FUN_0058abf0` -> `SelectTradeSpecialCommodityAndRecomputeBarLimits`

### Signature/comment hygiene
- Added behavior comments for all newly renamed non-thunk functions above.
- Return types aligned:
  - most helpers -> `void`
  - `GetOrderNodeDescriptorWord0CAsIntByResourceType` -> `int`
  - `DeserializeAndCreateNavyPrimaryOrdersFromStream` -> `void *`

### Verification
- Verified persisted names/signatures for all addresses listed above.
- Candidate backlog check (`tmp_decomp/cluster_next_a/generic_logic_candidates.txt`):
  - remaining generic entries in that candidate file reduced to `120`.

### Neo4j policy
- No Neo4j update (low-level rename/type/comment cleanup only).

## TODO (next game-logic pass, refreshed)
- [ ] Continue candidate-file top block with map/tactical/order logic first (`0x00597340`, `0x00596a80`, `0x0059de30`, `0x0059e110`) and keep deferring pure UI paint/resource wrappers.
- [ ] Revisit `0x0051bff0` / `0x00518d90` for map-order pathfinding/order-compatibility logic naming.
- [ ] Apply easy parameter/prototype cleanup for the newly renamed order-deserialization helpers where stream-field roles are stable.

## Continuation (2026-02-21, game-logic pass: map-overlay command routing + tactical target heuristics + directional overlays)

### Map-overlay/tactical heuristic helpers renamed
- `FUN_00597340` -> `HandleMapOverlayDialogCommandTagsAndForward`
- `FUN_00596a80` -> `InitializeMapOverlayDialogControlsAndSelectionState`
- `FUN_0059de30` -> `ComputeTacticalActionScoreFromThreatAndReachability`
- `FUN_0059e110` -> `SelectBestTacticalTargetTileByActionHeuristics`
- `0x00408c92` -> `thunk_SelectBestTacticalTargetTileByActionHeuristics`

### Map overlay projection helpers renamed
- `FUN_00518d90` -> `MarkDirectionalMapOverlayFlagsForNationOrders`
- `0x00407b30` -> `thunk_MarkDirectionalMapOverlayFlagsForNationOrders`
- `FUN_0051bff0` -> `InitializeMapInteractionMode4BoundsAndCursorControls`

### Signature/comment hygiene
- Added behavior comments for all newly renamed non-thunk functions above.
- Return types aligned:
  - `ComputeTacticalActionScoreFromThreatAndReachability` -> `int`
  - `SelectBestTacticalTargetTileByActionHeuristics` (+ thunk) -> `int`
  - others in this pass -> `void`

### Verification
- Verified persisted names/signatures for:
  - `0x00597340`, `0x00596a80`, `0x0059de30`, `0x0059e110`, `0x00408c92`,
  - `0x00518d90`, `0x00407b30`, `0x0051bff0`.
- Candidate backlog check (`tmp_decomp/cluster_next_a/generic_logic_candidates.txt`):
  - remaining generic entries reduced to `114`.

### Neo4j policy
- No Neo4j update (low-level rename/type/comment cleanup only).

## TODO (next game-logic pass, refreshed)
- [ ] Continue with remaining map/tactical logic candidates before UI wrappers: `0x00593f20`, `0x005dd450`, `0x0058e1c0`, `0x005a1d70`.
- [ ] Keep skipping MFC/resource-handle internals (`0x0060xxxx`, `0x0061xxxx`) unless they directly gate game-state logic.
- [ ] Incrementally improve stable parameter names in the newly renamed tactical scoring helpers.

## Continuation (2026-02-21, game-logic pass: tactical/map-order lanes from refreshed non-UI candidates)

### Map overlay + tactical heuristic lane renamed
- `FUN_00597340` -> `HandleMapOverlayDialogCommandTagsAndForward`
- `FUN_00596a80` -> `InitializeMapOverlayDialogControlsAndSelectionState`
- `FUN_0059de30` -> `ComputeTacticalActionScoreFromThreatAndReachability`
- `FUN_0059e110` -> `SelectBestTacticalTargetTileByActionHeuristics`
- `0x00408c92` -> `thunk_SelectBestTacticalTargetTileByActionHeuristics`
- `FUN_00518d90` -> `MarkDirectionalMapOverlayFlagsForNationOrders`
- `0x00407b30` -> `thunk_MarkDirectionalMapOverlayFlagsForNationOrders`
- `FUN_0051bff0` -> `InitializeMapInteractionMode4BoundsAndCursorControls`

### Map-order / tactical command routing helpers renamed
- `FUN_00593f20` -> `InitializeNationRecipientSelectionDialogAndScores`
- `FUN_005dd450` -> `RunMapOrderPageSelectionDialogAndApplyResult`
- `0x00407f95` -> `thunk_RunMapOrderPageSelectionDialogAndApplyResult`
- `FUN_0058e1c0` -> `HandleMapContextActionArmyRatioAndModeCommands`
- `FUN_005a1d70` -> `HasValidTacticalFollowupTargetForCurrentAction`
- `0x00404a43` -> `thunk_HasValidTacticalFollowupTargetForCurrentAction`

### Scenario/global-map context lane renamed
- `FUN_00518540` -> `LoadScenarioMapStateFromTableResource`
- `0x00404fb6` -> `thunk_LoadScenarioMapStateFromTableResource`
- `FUN_0057c9a0` -> `RecreateActiveMapContextAndInitializeGlobalMapState`
- `0x004082ba` -> `thunk_RecreateActiveMapContextAndInitializeGlobalMapState`
- `FUN_00582fa0` -> `DeserializeAndAssignMapActionContextNameByNodeId`

### Nation metrics / production counters lane renamed
- `FUN_005b7570` -> `IncrementProductionDerivedCountersWithTurnParityRules`
- `FUN_005b97c0` -> `RunNationUpdatePassesAndResetTransitionFlags`
- `FUN_005b98d0` -> `BuildNationMetricBucketsAndWeightedTrendScores`

### Tactical action execution lane renamed
- `FUN_005a8550` -> `HandleTacticalInputCommandKeyAndTagDispatch`
- `FUN_005a8660` -> `DispatchTacticalActionFromHoverHexUnderCursor`
- `FUN_005a3640` -> `ExecuteTacticalDigActionAndConsumeUnitActionPoints`
- `FUN_005a1ca0` -> `ExecuteTacticalActionAndQueueEventIfNoAdjacentValidTarget`
- `FUN_005a5bc0` -> `ExecuteTacticalActionAndQueueEventIfSupportUnavailable`
- `FUN_005a51e0` -> `HandleTacticalDeployClickAndAdvanceSelection`
- `FUN_005a3810` -> `ComputeRallyStrengthAndQueueTacticalRallyCommand`

### Signature/comment hygiene
- Added behavior comments for all newly renamed non-thunk helpers listed above.
- Return type updates in this pass:
  - `ComputeTacticalActionScoreFromThreatAndReachability` -> `int`
  - `SelectBestTacticalTargetTileByActionHeuristics` (+ thunk) -> `int`
  - `HasValidTacticalFollowupTargetForCurrentAction` (+ thunk) -> `bool`
  - `LoadScenarioMapStateFromTableResource` (+ thunk) -> `bool`
  - `HandleTacticalDeployClickAndAdvanceSelection` -> `void *`
  - others renamed in this pass -> `void`

### Candidate tracking
- Generated refreshed non-UI candidate list:
  - `tmp_decomp/cluster_next_a/non_ui_logic_candidates_refresh.txt`
- Prior candidate backlog (`tmp_decomp/cluster_next_a/generic_logic_candidates.txt`) now down to:
  - `remaining generic entries = 101`

### Neo4j policy
- No Neo4j update (low-level rename/type/comment cleanup only).

## TODO (next game-logic pass, refreshed)
- [ ] Continue top unresolved entries in `tmp_decomp/cluster_next_a/non_ui_logic_candidates_refresh.txt`, prioritizing tactical/map-order logic (`0x005a24a0`, `0x005a3210`, `0x005a34d0`, `0x005a6560`).
- [ ] Keep excluding MFC/internal utility-heavy `0x0060xxxx/0x0061xxxx` unless directly tied to gameplay state.
- [ ] Tighten parameter names in tactical scoring/dispatch helpers where variable roles are stable from callsite evidence.

## Continuation (2026-02-21, cpp-anchor decode pass: USetupScreens.cpp + McAppUI.cpp)

### Source-anchor driven decode and renames
- `FUN_005769c0` -> `HandleSetupScreensCommandOkayCancelAndForward`
  - Anchor: `D:\\Ambit\\Cross\\USetupScreens.cpp`
  - Why safe: function explicitly checks command tags `cncl` / `okay`, executes setup-flow actions (`ResetGameFlowStateAndPostTurnEvent5DC`, `ValidateGameFlowNameAndSelectionContext`), then forwards to shared city-dialog toggle handler.
- `FUN_0048a7c0` -> `AllocateUiResourceEntryHeaderCopyFromSource`
  - Anchor: `D:\\Ambit\\McAppUI.cpp`
  - Why safe: allocates fixed `0x20` object, copies selected header fields from source (`+4,+8,+C,+1C`), assigns base vtable `0x006497a0`, returns pointer-or-null.
- `thunk_FUN_0048a7c0` (`0x00406aff`) -> `thunk_AllocateUiResourceEntryHeaderCopyFromSource`
  - Why safe: direct jump thunk to `0x0048a7c0`.
- `FUN_0048a100` -> `InitializeUiResourceEntryBaseHeaderDefaults`
  - Why safe: deterministic zero/default initialization of base header range/state fields and base vtable assignment.

### Signature/comment hygiene
- Added concise function comments documenting behavior and cpp provenance for all four addresses above.
- No speculative class extraction yet from this pass; kept names behavior-based.

### Verification
- Verified persisted names/comments at:
  - `0x005769c0`, `0x0048a7c0`, `0x00406aff`, `0x0048a100`.
- Saved program after transaction (`cpp anchor rename pass: setup screens + mcappui helpers`).

### Neo4j policy
- No Neo4j update (low-level rename/comment pass only).

## TODO (next pass, cpp-anchor driven)
- [ ] Decode `D:\\Ambit\\DiplomacyDialogs.cpp` nearby flow around `AssertDiplomacyDialogsLine61` to recover a non-assert diplomacy behavior function for naming.
- [ ] Continue `McAppUI.cpp` class lane around `0x0048bd30` (derived vtable `0x00649858`) and identify constructor/copy semantics for potential class extraction seed.
- [ ] Return to game-logic-first candidate file after one more cpp-anchor seed (`tmp_decomp/cluster_next_a/non_ui_logic_candidates_refresh.txt`).

## Continuation (2026-02-21, cpp-anchor decode expansion: network setup-picture cluster)

### Additional renames from `USetupScreens.cpp`-adjacent cluster
- `FUN_00576900` -> `AllocateTNetSelectPictureInstance`
- `FUN_00576980` -> `GetTNetSelectPictureClassNamePtr`
- `FUN_005769a0` -> `DestructTNetSelectPictureBaseState`
- `HandleSetupScreensCommandOkayCancelAndForward` -> `HandleTNetSelectPictureCommandOkayCancelAndForward`
- `FUN_00576aa0` -> `AllocateTNetGameSelectPictureInstance`
- `FUN_00576b20` -> `DestructTNetGameSelectPictureAndMaybeFree`
- `FUN_00576b70` -> `GetTNetGameSelectPictureClassNamePtr`
- `FUN_00576b90` -> `InitializeRuntimeSelectionCredentialsFromProvider`
- `FUN_00576bc0` -> `HandleTNetGameSelectPictureCommandHostJoinCancelAndForward`

### Why this is safe
- Same local address cluster (`0x00576900`..`0x00576bc0`) with clearly paired class-name tokens:
  - `TNetSelectPicture`
  - `TNetGameSelectPicture`
- Command handlers are explicit tag-based flows:
  - `cncl`/`okay` for net-select
  - `cncl`/`host`/`join` for net-game-select
- Constructors/allocators are straightforward fixed-size allocate + base constructor + vtable assignment patterns.

### Signature/comment hygiene
- Added concise behavior comments to each renamed function above.
- Kept types conservative; no speculative struct/class type propagation in this pass.

### Verification
- Verified persisted names in database at:
  - `0x00576900`, `0x00576980`, `0x005769a0`, `0x005769c0`,
  - `0x00576aa0`, `0x00576b20`, `0x00576b70`, `0x00576b90`, `0x00576bc0`.
- Program saved after transaction (`cpp anchor net-setup picture cluster rename pass`).

### Neo4j policy
- No Neo4j update (low-level function naming/comments only).

## TODO (next pass, refreshed)
- [ ] Continue cpp-seed for `McAppUI.cpp` around `0x0048bd30` / `0x00649858` to recover reusable class extraction seed (constructor + ownership/list semantics).
- [ ] Re-open diplomacy via non-assert call chains (not `AssertDiplomacyDialogsLine61` thunk lane, which is too shallow).
- [ ] Pivot back to game-logic candidate queue after one more cpp-seeded class lane pass.

## Continuation (2026-02-21, cpp-anchor decode expansion: TSetupRandomMapPicture cluster)

### Additional renames from `USetupScreens.cpp` neighborhood
- `FUN_00576ca0` -> `AllocateTSetupRandomMapPictureInstance`
- `FUN_00576d60` -> `GetTSetupRandomMapPictureClassNamePtr`
- `FUN_00576d80` -> `ConstructTSetupRandomMapPictureBaseState`
- `0x00409061` -> `thunk_ConstructTSetupRandomMapPictureBaseState`
- `FUN_00576e30` -> `DestructTSetupRandomMapPictureBaseState`
- `0x00402d88` -> `thunk_DestructTSetupRandomMapPictureBaseState`
- `FUN_00576e00` -> `DestructTSetupRandomMapPictureAndMaybeFree`
- `FUN_00576fe0` -> `RefreshSetupRandomMapCountryControlIfApplicable`
- `0x004023b0` -> `thunk_RefreshSetupRandomMapCountryControlIfApplicable`
- `Cluster_TurnEventHint_00577030` -> `InitializeSetupRandomMapPictureDialogFromGameContext`

### Why this is safe
- Same contiguous setup-screen cluster (`0x00576ca0`..`0x00577030`) with explicit class token:
  - `PTR_s_TSetupRandomMapPicture_006619e0`
- Constructor/allocator signatures are standard allocate + shared base init + vtable install.
- Destructor path is explicit shared-string release + shared city-dialog base destructor (+ conditional free wrapper).
- Dialog init (`0x00577030`) visibly builds random-map setup UI state (difficulty/random/history/country controls) from current game/global-map context.

### Signature/comment hygiene
- Added concise behavior comments for each renamed function in this batch.
- Kept types conservative; no speculative structure propagation.

### Verification
- Verified persisted names for all 10 renamed addresses above.
- Saved program after transaction (`cpp anchor random-map setup picture rename pass`).

### Neo4j policy
- No Neo4j update (low-level rename/comment pass only).

## TODO (next pass, refreshed again)
- [ ] Continue `McAppUI.cpp` class lane around `0x0048bd30` / `0x00649858` (copy-constructor + child-list clone semantics) as class extraction seed.
- [ ] Find non-assert diplomacy behavior entry points by walking outward from diplomacy UI command handlers rather than assertion thunks.
- [ ] Resume game-logic-first candidate queue after one more cpp-seeded class-lane rename.

## Continuation (2026-02-21, cpp-anchor class-seed follow-up: McAppUI copy/clone lane)

### Additional renames (class extraction groundwork)
- `FUN_0048bd30` -> `CopyCityDialogStateFromSourceAndCloneChildLinks`
- `0x004017ad` -> `thunk_CopyCityDialogStateFromSourceAndCloneChildLinks`

### Why this is safe
- `CloneEngineerDialogStateToNewInstance` allocates a new instance and immediately forwards into this routine, establishing clone/copy semantics.
- Function body clearly:
  - copies base state fields from source object,
  - rebinds destination ownership pointers,
  - clones/queues child link nodes under destination list container.
- Wrapper at `0x004017ad` is direct jump-thunk to this function.

### Signature/comment hygiene
- Added concise behavior comments documenting copy + child-list cloning semantics.
- No speculative type propagation in this pass.

### Verification
- Verified persisted names:
  - `0x0048bd30` -> `CopyCityDialogStateFromSourceAndCloneChildLinks`
  - `0x004017ad` -> `thunk_CopyCityDialogStateFromSourceAndCloneChildLinks`
- Program saved after transaction (`mcappui class-seed copy-ctor rename`).

### Neo4j policy
- No Neo4j update (low-level rename/comment pass only).

## TODO (next pass, refreshed)
- [ ] Continue outward from `CloneEngineerDialogStateToNewInstance` (`0x0048bfd0`) to name one more concrete constructor/allocator pair for this class family.
- [ ] Re-enter game-logic-first queue (`tmp_decomp/cluster_next_a/non_ui_logic_candidates_refresh.txt`) after one additional class-family low-hanging rename.
- [ ] Revisit diplomacy via command handlers (not assert anchors) once a solid non-assert entry is identified.

## Continuation (2026-02-21, cpp-anchor expansion: UMap.cpp initializer lane)

### Additional renames from `UMap.cpp` source anchor
- `FUN_0050e901` -> `InitializeUMapPrimaryTileRecordDefaultsAndEnsureAuxBuffer`
- `FUN_0050ea56` -> `InitializeUMapAuxEntryDefaultsAndSharedNameFields`

### Why this is safe
- Both functions are directly anchored by `D:\\Ambit\\Cross\\UMap.cpp`.
- Bodies are clear bulk-initializer loops writing sentinel/default values across fixed-size record arrays.
- First function additionally ensures and initializes an auxiliary backing buffer before default fill.
- Second function resets per-entry shared-string/name fields during auxiliary-array initialization.

### Signature/comment hygiene
- Added concise behavior comments emphasizing initializer semantics and conservative naming.
- Kept signatures unchanged (`void`) due decompiler register-recovery noise in these routines.

### Verification
- Verified persisted names:
  - `0x0050e901` -> `InitializeUMapPrimaryTileRecordDefaultsAndEnsureAuxBuffer`
  - `0x0050ea56` -> `InitializeUMapAuxEntryDefaultsAndSharedNameFields`
- Program saved after transaction (`umap cpp-anchor initializer renames`).

### Neo4j policy
- No Neo4j update (low-level rename/comment pass only).

## TODO (next pass, refreshed again)
- [ ] Continue class-seed naming outward from `CloneEngineerDialogStateToNewInstance` (`0x0048bfd0`) with one more concrete constructor/allocator pair.
- [ ] Pivot back to game-logic-first queue (`tmp_decomp/cluster_next_a/non_ui_logic_candidates_refresh.txt`) immediately after that.
- [ ] Find a non-assert diplomacy command handler entry (outside assertion thunks) and apply one safe behavior rename.

## Continuation (2026-02-21, cpp-anchor expansion: IncludeView.cpp / McWindow.cpp / WAssetMgr.cpp)

### Additional renames from other cpp anchors
- `FUN_004833b0` -> `ReinitializeIncludeViewMainPaneAndRedrawWindow`
- `FUN_004838b0` -> `HandleIncludeViewPointerUpdateAndNotifyChildren`
- `FUN_00493470` -> `CreateMcWindowFromDescriptorAndShow`
- `0x00402bd0` -> `thunk_CreateMcWindowFromDescriptorAndShow`
- `FUN_005e0460` -> `DispatchWAssetMgrPeriodicCallbackAndStopInactiveTimerSlot`
- `0x004037e7` -> `thunk_DispatchWAssetMgrPeriodicCallbackAndStopInactiveTimerSlot`

### Why this is safe
- `IncludeView.cpp` pair:
  - first function rebinds/refreshes main-pane context (`'main'` tag), rebuilds state, invalidates and redraws host window.
  - second function forwards pointer/motion updates to child/controller and updates tracked pointer state.
- `McWindow.cpp` function is a straightforward style/rect-driven window creation flow (`AdjustWindowRectEx`, create hook, `SetWindowPos`, `BringWindowToTop`).
- `WAssetMgr.cpp` function dispatches callback for timer slots (`0xA000..0xA009`) and kills/clears timer slot state when callback indicates stop.
- Both thunk renames are direct wrapper renames.

### Signature/comment hygiene
- Added concise behavior comments to all six renamed functions.
- Kept signatures/types unchanged due partial register-recovery noise in `IncludeView.cpp` decompilation.

### Verification
- Verified persisted names at:
  - `0x004833b0`, `0x004838b0`, `0x00493470`, `0x00402bd0`, `0x005e0460`, `0x004037e7`.
- Saved program after transaction (`cpp-anchor decode batch includeview/mcwindow/wassetmgr`).

### Neo4j policy
- No Neo4j update (low-level rename/comment pass only).

## TODO (next pass, refreshed)
- [ ] Continue with another cpp-anchor module still carrying generic functions (candidate next: `McAppStream.cpp` around `0x00488b10` / `0x00488e00`).
- [ ] Keep one low-hanging class-seed rename from `CloneEngineerDialogStateToNewInstance` lane when behavior is clear.
- [ ] Then pivot to game-logic-first candidate queue (`tmp_decomp/cluster_next_a/non_ui_logic_candidates_refresh.txt`).

## Continuation (2026-02-21, cpp-anchor expansion: class-name getters from indirect cpp neighborhoods)

### Additional renames (class-name getter helpers)
- `FUN_005ba700` -> `GetTradeScreenPictureClassNamePointer`
- `FUN_005a8330` -> `GetTacticalBattleViewClassNamePointer`
- `FUN_004f2c40` -> `GetMinisterViewClassNamePointer`
- `FUN_00509c80` -> `GetMacViewManagerClassNamePointer`
- `FUN_005aeb70` -> `GetTaskListClassNamePointer`

### Why this is safe
- Each function is a tiny accessor returning one static `PTR_s_*` class-name descriptor entry.
- String targets map directly to class tokens in cpp neighborhoods (`TTradeScreenPicture`, `TTacticalBattleView`, `TMinisterView`, `TMacViewMgr`, `TTaskList`).
- Naming is consistent with existing `GetTurnViewManagerClassNamePointer`.

### Verification
- Verified persisted names for all five addresses above.
- Saved program after transaction (`rename class-name getter helpers`).

### Neo4j policy
- No Neo4j update (low-level rename/comment pass only).

## Continuation (2026-02-21, indirect cpp-anchor expansion: diplomacy/trade view functions)

### Additional renames (recovered via cpp-path push sites in code)
- `FUN_004f2d10` -> `HandleDiplomacyBackOkayButtonsAndForwardMouseEvent`
- `FUN_004f4620` -> `InitializeDiplomacyMinisterActionControlsAndLabels`
- `0x004040ac` -> `thunk_InitializeDiplomacyMinisterActionControlsAndLabels`
- `FUN_004f8ff0` -> `InitializeDiplomacyAcceptRejectControlsAndPrompts`
- `Cluster_UiControlA4A8_1C8_1E4_005bea00` -> `InitializeTradeScreenControlsLabelsAndNationContext`

### Why this is safe
- These functions contain direct `PUSH`es of cpp file-path anchors:
  - `D:\\Ambit\\Cross\\UDiplomacyViews.cpp`
  - `D:\\Ambit\\Cross\\UTradeViews.cpp`
- Behavior is explicit from decomp/disassembly:
  - resolves tagged controls (`back`/`okay`, `acce`/`reje`, etc.),
  - initializes UI control groups and localized labels,
  - forwards or applies input/control-state handling.
- Thunk at `0x004040ac` is a direct wrapper.

### Signature/comment hygiene
- Added concise behavior comments on all five renamed functions above.
- Kept signatures conservative due decompiler noise in large UI-init routines.

### Verification
- Verified persisted names:
  - `0x004f2d10`, `0x004f4620`, `0x004040ac`, `0x004f8ff0`, `0x005bea00`.
- Saved program after transaction (`indirect cpp-anchor diplomacy/trade rename pass`).

### Neo4j policy
- No Neo4j update (low-level rename/comment pass only).

## TODO (next pass, refreshed again)
- [ ] Continue indirect cpp-anchor mining on high-density modules (`USmallViews.cpp`, `UViewMgr.cpp`) using pointer-site-in-code strategy.
- [ ] Add one more low-hanging rename in diplomacy range near existing named functions (`0x004f6170`, `0x004f6440`, `0x004f64c0`).
- [ ] Pivot back to game-logic-first candidate queue once another non-UI gameplay rename batch is completed.

## Continuation (2026-02-21, class extraction pass: vtbl 0x643A40 family + descriptor/vtable labels)

### Extracted class-family semantics (constructor/allocator/destructor + builder hub)
- `FUN_00453800` -> `ConstructUiClickablePictureResourceEntry_Vtbl643A40`
- `FUN_004caa50` -> `AllocateUiClickablePictureResourceEntry_Vtbl643A40`
- `FUN_00453830` -> `DestructUiClickablePictureResourceEntry_Vtbl643A40_AndMaybeFree`
- `Cluster_UiControlA4A8_1C8_1E4_0044fbc0` -> `BuildUiResourceTreeByTemplateIdAndBindScreenContext`

### Why this supports class extraction
- `0x00453800` and `0x004caa50` both assign vtable `0x00643A40` after running clickable-picture base constructor path.
- `0x00453830` is the matching destructor/free wrapper shape for the same object family.
- `0x0044fbc0` repeatedly allocates/registers UI entries by template id and constructs this class (`vtable 0x643A40`) as part of screen-context resource-tree build.

### New class data labels (to make class mapping explicit in symbol tree)
- Vtables:
  - `0x00643a40` -> `g_vtblUiClickablePictureResourceEntry_643A40`
  - `0x006440d8` -> `g_vtblTNetSelectPicture`
  - `0x00661fb0` -> `g_vtblTNetGameSelectPicture`
  - `0x006621e0` -> `g_vtblTSetupRandomMapPicture`
- Class descriptors:
  - `0x0066dba0` -> `g_pClassDescTTradeScreenPicture`
  - `0x0066a280` -> `g_pClassDescTTacticalBattleView`
  - `0x00654ed0` -> `g_pClassDescTMinisterView`
  - `0x00658610` -> `g_pClassDescTMacViewMgr`
  - `0x0066a8f8` -> `g_pClassDescTTaskList`
- Type-name strings:
  - `0x0069aa78` -> `g_szTypeNameTTradeScreenPicture`
  - `0x00699fdc` -> `g_szTypeNameTTacticalBattleView`
  - `0x00696ad0` -> `g_szTypeNameTMinisterView`
  - `0x00696d58` -> `g_szTypeNameTMacViewMgr`
  - `0x0069a018` -> `g_szTypeNameTTaskList`

### Verification
- Verified persisted function names for:
  - `0x0044fbc0`, `0x00453800`, `0x00453830`, `0x004caa50`
  - plus previous diplomacy/trade extraction: `0x004f2d10`, `0x004f4620`, `0x004f8ff0`, `0x005bea00`.
- Verified all new symbol labels exist at listed addresses.
- Program saved after transactions:
  - `class extraction pass for vtable 643a40 family`
  - `class extraction labels for known descriptors/vtables`

### Neo4j policy
- No Neo4j update (low-level rename/symbol extraction pass only).

## TODO (next pass, class-focused)
- [ ] Continue class extraction for diplomacy-view family by mapping vtables near `0x00655b68` / `0x00655fb0` to their ctor/dtor/allocator triplets.
- [ ] Use pointer-site-in-code approach on `USmallViews.cpp` / `UViewMgr.cpp` to recover additional class-name getters and template builders.
- [ ] After one more class-family extraction, switch back to non-UI gameplay logic queue (`tmp_decomp/cluster_next_a/non_ui_logic_candidates_refresh.txt`).

## Continuation (2026-02-21, class extraction pass: TDiplomacyMapView + TOffersPanelView)

### Class methods extracted/renamed
- `FUN_004f3b60` -> `GetTDiplomacyMapViewClassNamePointer`
- `ConstructPictureResourceEntry_Vtbl00655b68` (`0x004f3b80`) -> `ConstructTDiplomacyMapViewBaseState`
- `FUN_004f3cc0` -> `DestructTDiplomacyMapViewBaseState`
- `FUN_004f3c90` -> `DestructTDiplomacyMapViewAndMaybeFree`
- `FUN_004f8f50` -> `GetTOffersPanelViewClassNamePointer`
- `ConstructUiResourceEntry_Vtbl00655fb0` (`0x004f8f70`) -> `ConstructTOffersPanelViewBaseState`
- `FUN_004f8ec0` -> `AllocateTOffersPanelViewInstance`
- `FUN_004f8fa0` -> `DestructTOffersPanelViewAndMaybeFree`

### Vtable thunk entries functionized + renamed (were non-functionized thunk-island JMPs)
- `0x00407379` -> `thunk_GetTDiplomacyMapViewClassNamePointer`
- `0x00401442` -> `thunk_DestructTDiplomacyMapViewAndMaybeFree`
- `0x00402d1f` -> `thunk_GetTOffersPanelViewClassNamePointer`
- `0x00401712` -> `thunk_DestructTOffersPanelViewAndMaybeFree`

### New class labels
- `0x00655b68` -> `g_vtblTDiplomacyMapView`
- `0x00655fb0` -> `g_vtblTOffersPanelView`
- `0x00654f48` -> `g_pClassDescTDiplomacyMapView`
- `0x00654fc0` -> `g_pClassDescTOffersPanelView`

### Why this is safe
- Vtable slot 0 methods return explicit class descriptors:
  - `PTR_sTypeName_TDiplomacyMapView_00654f48`
  - `PTR_sTypeName_TOffersPanelView_00654fc0`
- Constructors directly install corresponding vtables:
  - `0x655B68` for diplomacy map view family
  - `0x655FB0` for offers panel family
- Destructor wrappers follow canonical `destruct + (flag&1 ? free : nofree)` pattern.
- Thunk-island entries are single `JMP` stubs and map 1:1 to the methods above.

### Verification
- Verified all renamed functions exist at the listed addresses.
- Verified new symbols exist at the four class/vtable descriptor addresses.
- Program saved after transaction: `class extraction TDiplomacyMapView and TOffersPanelView`.

### Neo4j policy
- No Neo4j update (low-level rename/symbol extraction pass only).

## TODO (next pass, refreshed)
- [ ] Continue class extraction on `USmallViews.cpp` pointer sites (`0x00584388`, `0x00584840`, ...), starting with one method family and matching class descriptor/vtable labels.
- [ ] Follow the new `TDiplomacyMapView` family around nearby virtual methods (`0x004f3e60`, `0x004f3e30`, `0x004f3d60`) for additional safe behavior names.
- [ ] After one more class-focused pass, switch to non-UI gameplay queue (`tmp_decomp/cluster_next_a/non_ui_logic_candidates_refresh.txt`).

## Continuation (2026-02-21, class extraction pass: USmallViews class clusters)

### Class families extracted (high-confidence create/get/construct/destruct quads)

#### `TDipDlgCluster`
- `0x00584040` -> `CreateTDipDlgClusterInstance`
- `0x005840c0` -> `GetTDipDlgClusterClassNamePointer`
- `0x005840e0` -> `ConstructTDipDlgClusterBaseState`
- `0x00584110` -> `DestructTDipDlgClusterAndMaybeFree`

#### `TTradePolicyCluster`
- `0x00584200` -> `CreateTTradePolicyClusterInstance`
- `0x00584280` -> `GetTTradePolicyClusterClassNamePointer`
- `0x005842a0` -> `ConstructTTradePolicyClusterBaseState`
- `0x005842d0` -> `DestructTTradePolicyClusterAndMaybeFree`

#### `TTradeOrderPicture`
- `0x005843e0` -> `CreateTTradeOrderPictureInstance`
- `0x00584460` -> `GetTTradeOrderPictureClassNamePointer`
- `0x00584480` -> `ConstructTTradeOrderPictureBaseState`
- `0x005844b0` -> `DestructTTradeOrderPictureAndMaybeFree`

#### `TToolBarCluster`
- `0x00584d80` -> `CreateTToolBarClusterInstance`
- `0x00584e00` -> `GetTToolBarClusterClassNamePointer`
- `0x00584e20` -> `ConstructTToolBarClusterBaseState`
- `0x00584e50` -> `DestructTToolBarClusterAndMaybeFree`

#### `TCivToolbar`
- `0x0058ea00` -> `CreateTCivToolbarInstance`
- `0x0058ea80` -> `GetTCivToolbarClassNamePointer`
- `0x0058eaa0` -> `ConstructTCivToolbarBaseState`
- `0x0058ead0` -> `DestructTCivToolbarAndMaybeFree`

#### `TCivReport`
- `0x00590b90` -> `CreateTCivReportInstance`
- `0x00590c10` -> `GetTCivReportClassNamePointer`
- `0x00590c30` -> `ConstructTCivReportBaseState`
- `0x00590c60` -> `DestructTCivReportAndMaybeFree`

#### `TArmyInfoView`
- `0x00591500` -> `CreateTArmyInfoViewInstance`
- `0x00591580` -> `GetTArmyInfoViewClassNamePointer`
- `0x005915a0` -> `ConstructTArmyInfoViewBaseState`
- `0x005915d0` -> `DestructTArmyInfoViewAndMaybeFree`

#### `TTransportPicture`
- `0x00591d90` -> `CreateTTransportPictureInstance`
- `0x00591e50` -> `GetTTransportPictureClassNamePointer`
- `0x00591e70` -> `ConstructTTransportPictureBaseState`
- `0x00591ec0` -> `DestructTTransportPictureAndMaybeFree`

#### `TWarningView`
- `0x00592860` -> `CreateTWarningViewInstance`
- `0x005928e0` -> `GetTWarningViewClassNamePointer`
- `0x00592900` -> `ConstructTWarningViewBaseState`
- `0x00592930` -> `DestructTWarningViewAndMaybeFree`

#### Consistency cleanup
- `0x00587090` renamed from `GetLiteralTypeName_TTradeCluster` to `GetTTradeClusterClassNamePointer`

### New class labels added

#### Class descriptors
- `0x00662e18` -> `g_pClassDescTDipDlgCluster`
- `0x00662e30` -> `g_pClassDescTTradePolicyCluster`
- `0x00662e48` -> `g_pClassDescTTradeOrderPicture`
- `0x00662ec0` -> `g_pClassDescTToolBarCluster`
- `0x00663100` -> `g_pClassDescTCivToolbar`
- `0x00663130` -> `g_pClassDescTCivReport`
- `0x00663148` -> `g_pClassDescTArmyInfoView`
- `0x00663160` -> `g_pClassDescTTransportPicture`
- `0x00663178` -> `g_pClassDescTWarningView`

#### Vtables
- `0x00663bb0` -> `g_vtblTDipDlgCluster`
- `0x00663de0` -> `g_vtblTTradePolicyCluster`
- `0x00664010` -> `g_vtblTTradeOrderPicture`
- `0x00664b00` -> `g_vtblTToolBarCluster`
- `0x00667f00` -> `g_vtblTCivToolbar`
- `0x00668128` -> `g_vtblTCivReport`
- `0x00668358` -> `g_vtblTArmyInfoView`
- `0x00668588` -> `g_vtblTTransportPicture`
- `0x006687b8` -> `g_vtblTWarningView`

#### Type-name strings
- `0x00699290` -> `g_szTypeNameTDipDlgCluster`
- `0x00699278` -> `g_szTypeNameTTradePolicyCluster`
- `0x00699260` -> `g_szTypeNameTTradeOrderPicture`
- `0x006991f8` -> `g_szTypeNameTToolBarCluster`
- `0x00699044` -> `g_szTypeNameTCivToolbar`
- `0x00698ea4` -> `g_szTypeNameTCivReport`
- `0x00698e94` -> `g_szTypeNameTArmyInfoView`
- `0x00698e7c` -> `g_szTypeNameTTransportPicture`
- `0x00698e6c` -> `g_szTypeNameTWarningView`

### Comments/signature hygiene
- Added function comments on all renamed class-descriptor getter functions (`GetT*ClassNamePointer`) noting they return class descriptor pointers.
- Kept signatures conservative in this pass; constructor/dtor roles are now explicit from names.

### Why this is safe
- Each getter is a 6-byte function returning a single class-descriptor pointer (`PTR_s_*`).
- Each class quad has canonical shape:
  - allocator (`AllocateWithFallbackHandler(size)`),
  - constructor (base ctor + vtable store),
  - destructor (`base dtor + conditional free`).
- Vtable labels were taken directly from constructor-assigned values.

### Persistence/verification
- Batch applied: `37` function renames, `27` labels, `10` function comments.
- Program saved: `class extraction batch: small views clusters` and follow-up save pass.
- Spot checks confirmed renamed getters/ctors and labels are present.

### Neo4j policy
- No Neo4j update (low-level rename/class extraction pass only).

## TODO (next pass)
- [ ] Continue the same quad-pattern extraction for adjacent `USmallViews` classes around `0x005846e0`, `0x00584890`, `0x00584a50`, `0x00584c40`.
- [ ] Recover one additional diplomacy class family beyond `TDipDlgCluster` in `0x00584f27` command/tag dispatch neighborhood.
- [ ] Pivot back to game-logic-first renames after one more class cluster pass.

## Continuation (2026-02-21, class extraction pass: button-family USmallViews clusters)

### Additional class families extracted (adjacent low-hanging quads)

#### `TBoycottButton`
- `0x005846e0` -> `CreateTBoycottButtonInstance`
- `0x00584760` -> `GetTBoycottButtonClassNamePointer`
- `0x00584780` -> `ConstructTBoycottButtonBaseState`
- `0x005847b0` -> `DestructTBoycottButtonAndMaybeFree`

#### `T2PictToggleButton`
- `0x00584890` -> `CreateT2PictToggleButtonInstance`
- `0x00584910` -> `GetT2PictToggleButtonClassNamePointer`
- `0x00584930` -> `ConstructT2PictToggleButtonBaseState`
- `0x00584960` -> `DestructT2PictToggleButtonAndMaybeFree`

#### `TCloseButton`
- `0x00584a50` -> `CreateTCloseButtonInstance`
- `0x00584ad0` -> `GetTCloseButtonClassNamePointer`
- `0x00584af0` -> `ConstructTCloseButtonBaseState`
- `0x00584b20` -> `DestructTCloseButtonAndMaybeFree`

#### `TCloseParentButton`
- `0x00584bb0` -> `CreateTCloseParentButtonInstance`
- `0x00584c40` -> `GetTCloseParentButtonClassNamePointer`
- `0x00584c60` -> `ConstructTCloseParentButtonBaseState`
- `0x00584ce0` -> `DestructTCloseParentButtonAndMaybeFree`

### New labels added

#### Class descriptors
- `0x00662e60` -> `g_pClassDescTBoycottButton`
- `0x00662e78` -> `g_pClassDescT2PictToggleButton`
- `0x00662e90` -> `g_pClassDescTCloseButton`
- `0x00662ea8` -> `g_pClassDescTCloseParentButton`

#### Vtables
- `0x00664238` -> `g_vtblTBoycottButton`
- `0x00664470` -> `g_vtblT2PictToggleButton`
- `0x006646a8` -> `g_vtblTCloseButton`
- `0x006648d8` -> `g_vtblTCloseParentButton`

#### Type-name strings
- `0x0069924c` -> `g_szTypeNameTBoycottButton`
- `0x00699234` -> `g_szTypeNameT2PictToggleButton`
- `0x00699224` -> `g_szTypeNameTCloseButton`
- `0x0069920c` -> `g_szTypeNameTCloseParentButton`

### Notes
- `ConstructTCloseParentButtonBaseState` briefly assigns an intermediate base vtable then final class vtable (`0x006648d8`); only final class vtable was labeled as class-specific.
- Added concise getter comments for the four new `GetT*ClassNamePointer` functions.

### Persistence/verification
- Batch applied: `16` function renames, `12` labels, `4` comments.
- Program saved: `class extraction batch: button family clusters`.
- Spot checks confirmed names/labels at representative addresses.

### Neo4j policy
- No Neo4j update (low-level rename/class extraction pass only).

## TODO (next pass, refreshed)
- [ ] Continue class-quad extraction forward from `0x0058f050` and `0x00593210` where remaining tiny getter-style functions exist.
- [ ] Extract one diplomacy-heavy class family by following `HandleCrossUSmallViewsCommandTagDispatch` (`0x00584f27`) dispatch targets.
- [ ] After next class batch, pivot back to game-logic renaming queue.

## Continuation (2026-02-21, class extraction pass: TCivDescription + TSoundPlayer)

### Extracted class methods

#### `TCivDescription`
- `0x0044a770` -> `ConstructTCivDescriptionBaseState`
- `0x0058f050` -> `CreateTCivDescriptionInstance`
- `0x0058f0f0` -> `GetTCivDescriptionClassNamePointer`

#### `TSoundPlayer`
- `0x005932b0` -> `CreateTSoundPlayerInstance`
- `0x00593350` -> `GetTSoundPlayerClassNamePointer`
- `0x00593370` -> `ConstructTSoundPlayerBaseState`
- `0x005933b0` -> `DestructTSoundPlayerAndMaybeFree`
- `0x005933e0` -> `DestructTSoundPlayerBaseState`

### New labels
- Class descriptors:
  - `0x00663118` -> `g_pClassDescTCivDescription`
  - `0x00668a18` -> `g_pClassDescTSoundPlayer`
- Vtables:
  - `0x006431b0` -> `g_vtblTCivDescription`
  - `0x00668a60` -> `g_vtblTSoundPlayer`
- Type-name strings:
  - `0x00699030` -> `g_szTypeNameTCivDescription`
  - `0x006993c4` -> `g_szTypeNameTSoundPlayer`

### Notes
- `TSoundPlayer` constructor/destructor shape is canonical (`construct base + vtable`, `destruct base + conditional free`).
- `TCivDescription` has clear constructor + allocator + class-descriptor getter; destructor override not yet isolated in this pass.

### Comments/signature hygiene
- Added getter comments for:
  - `GetTCivDescriptionClassNamePointer`
  - `GetTSoundPlayerClassNamePointer`

### Persistence/verification
- Batch applied: `8` function renames, `6` labels, `2` comments.
- Program saved: `class extraction batch: civ description + sound player`.
- Spot checks confirmed names/labels at all listed addresses.

### Neo4j policy
- No Neo4j update (low-level rename/class extraction pass only).

## TODO (next pass, refreshed)
- [ ] Isolate `TCivDescription` destructor override (if present) by following vtable `0x006431b0` entries and nearest thunk stubs.
- [ ] Continue class extraction from `HandleCrossUSmallViewsCommandTagDispatch` (`0x00584f27`) to recover diplomacy-heavy button/view families.
- [ ] Then pivot back to game-logic queue (turn flow/map action/civilian orders) per priority.

## Continuation (2026-02-21, class extraction pass: toolbar/amount-bar families)

### Large class-quad extraction (high-confidence, same pattern)
Applied across contiguous `0x585f70..0x58e3f0` region using the proven pattern:
- allocator/create (`AllocateWithFallbackHandler`),
- class-descriptor getter (6-byte `MOV EAX,desc; RET`),
- constructor (base ctor + final vtable store),
- destructor (`base dtor + conditional free`).

### Function renames (18 classes, 72 functions)
- `TRightLeftView`: `Create/Get/Construct/Destruct`
- `TUnitToolbarCluster`: `Create/Get/Construct/Destruct`
- `TStatusButton`: `Create/Get/Construct/Destruct`
- `TCityBarCluster`: `Create/Get/Construct/Destruct`
- `TProductionCluster`: `Create/Get/Construct/Destruct`
- `TClosePicture`: `Create/Get/Construct/Destruct`
- `TAmtBar`: `Create/Get/Construct/Destruct`
- `TIndustryAmtBar`: `Create/Get/Construct/Destruct`
- `TRailAmtBar`: `Create/Get/Construct/Destruct`
- `TShipAmtBar`: `Create/Get/Construct/Destruct`
- `TCivilianButton`: `Create/Get/Construct/Destruct`
- `THQButton`: `Create/Get/Construct/Destruct`
- `TPlacard`: `Create/Get/Construct/Destruct`
- `TArmyPlacard`: `Create/Get/Construct/Destruct`
- `TNumberedArrowButton`: `Create/Get/Construct/Destruct`
- `TCombatReportView`: `Create/Get/Construct/Destruct`
- `TArmyToolbar`: `Create/Get/Construct/Destruct`
- `TStratReportView`: `Create/Get/Construct/Destruct`

### Labels added in this batch (54)
Per class:
- `g_pClassDescT*` (descriptor),
- `g_vtblT*` (final class vtable),
- `g_szTypeNameT*` (type-name string).

### Comments
- Added getter comments on all 18 renamed `GetT*ClassNamePointer` functions.

### Persistence
- Batch results: `fn_ok=72`, `lbl_ok=54`, `comments=18`.
- Saved as: `class extraction batch: toolbar/amtbar families`.

## Continuation (2026-02-21, class extraction pass: arrows + status picture families)

### Extracted/renamed class methods
#### `TArrowsControl`
- `0x005838b0` -> `CreateTArrowsControlInstance`
- `0x00583950` -> `GetTArrowsControlClassNamePointer`
- `0x00583970` -> `ConstructTArrowsControlBaseState`
- `0x005839a0` -> `DestructTArrowsControlAndMaybeFree`

#### `TSidewaysArrow`
- `0x00583a90` -> `CreateTSidewaysArrowInstance`
- `0x00583b30` -> `GetTSidewaysArrowClassNamePointer`
- `0x00583b50` -> `ConstructTSidewaysArrowBaseState`
- `0x00583b80` -> `DestructTSidewaysArrowAndMaybeFree`

#### `TUpDownView`
- `0x00583c90` -> `CreateTUpDownViewInstance`
- `0x00583d30` -> `GetTUpDownViewClassNamePointer`
- `0x00583d50` -> `ConstructTUpDownViewBaseState`
- `0x00583d80` -> `DestructTUpDownViewAndMaybeFree`

#### `TStatusPicture` (partial family)
- `0x00593e80` -> `CreateTStatusPictureInstance`
- `0x00593f00` -> `GetTStatusPictureClassNamePointer`
- Note: constructor logic also appears in existing function `ConstructTurnEventMainPictureEntry_10CC` (`0x0043d840`) which assigns the same vtable (`0x00642268`).

### Labels added
- `TArrowsControl`:
  - `g_pClassDescTArrowsControl` @ `0x00662db8`
  - `g_vtblTArrowsControl` @ `0x00663318`
  - `g_szTypeNameTArrowsControl` @ `0x006992dc`
- `TSidewaysArrow`:
  - `g_pClassDescTSidewaysArrow` @ `0x00662dd0`
  - `g_vtblTSidewaysArrow` @ `0x00663540`
  - `g_szTypeNameTSidewaysArrow` @ `0x006992c8`
- `TUpDownView`:
  - `g_pClassDescTUpDownView` @ `0x00662de8`
  - `g_vtblTUpDownView` @ `0x00663770`
  - `g_szTypeNameTUpDownView` @ `0x006992b8`
- `TStatusPicture`:
  - `g_pClassDescTStatusPicture` @ `0x00668b90`
  - `g_vtblTStatusPicture` @ `0x00642268`
  - `g_szTypeNameTStatusPicture` @ `0x006993d4`

### Comments
- Added getter comments for:
  - `GetTArrowsControlClassNamePointer`
  - `GetTSidewaysArrowClassNamePointer`
  - `GetTUpDownViewClassNamePointer`
  - `GetTStatusPictureClassNamePointer`

### Persistence/verification
- Batch results: `fn_ok=14`, `lbl_ok=12`, `comments=4`.
- Saved as: `class extraction batch: arrows/status families`.
- Post-pass verification scan: no remaining `FUN_` 6-byte class-getter stubs in `0x00583000..0x00594000`.

### Neo4j policy
- No Neo4j update (low-level rename/class extraction pass only).

## TODO (next pass)
- [ ] Move class-extraction sweep to the next region outside `0x00583000..0x00594000` using the same safe getter/quad pattern.
- [ ] Investigate `TStatusPicture` full destructor path (if separate from shared turn-event picture destructor family).
- [ ] Resume game-logic-first queue after one more class sweep (map actions / civilian order processing).

## Continuation (2026-02-21, workflow improvement: reusable pyghidra scripts)

### Why
- Repeated inline terminal snippets were slowing down iteration and causing avoidable lock/retry friction.
- Added small `argv`-driven scripts for the exact repetitive loop (scan -> apply -> count).

### Added scripts
- `new_scripts/scan_class_getters_fun6.py`
  - Scans a function range for 6-byte class getter stubs (`MOV EAX,<desc>; RET`).
  - Outputs rows with inferred neighboring `create/ctor/dtor` addresses.
- `new_scripts/apply_class_quads_from_csv.py`
  - Applies `Create/Get/Construct/Destruct` renames + descriptor/type/vtable labels from CSV.
  - Adds getter comment `Returns class descriptor pointer for T*.`
- `new_scripts/count_re_progress.py`
  - Prints function rename counts and class symbol counts (`g_pClassDescT*`, `g_vtblT*`, `g_szTypeNameT*`).

### Smoke-check results
- `count_re_progress.py` confirmed current state:
  - `total_functions=10512`
  - `renamed_functions=5257`
  - `class_desc_count=44`, `vtbl_count=54`, `type_name_count=42`
- `scan_class_getters_fun6.py 0x583000 0x594000` returned `rows=0` (expected; that region was exhausted in prior pass).

## TODO (workflow)
- [ ] Use `scan_class_getters_fun6.py` on next ranges outside `0x583000..0x594000`.
- [ ] Feed curated CSV rows directly into `apply_class_quads_from_csv.py` for batch renames.
- [ ] Use `count_re_progress.py` for quick checkpoints instead of ad-hoc snippets.

## Continuation (2026-02-21, class extraction pass: `0x594000..0x5c2000`)

### Script-first workflow used
- Scan ranges with:
  - `new_scripts/scan_class_getters_fun6.py`
- Curate/apply in batches with:
  - `new_scripts/apply_class_quads_from_csv.py`
- Checkpoint with:
  - `new_scripts/count_re_progress.py`

### Batch A (curated full/partial quads from `0x594000..0x5a2000`)
Applied curated rows:
- `TWorldView` (full `Create/Get/Construct/Destruct`)
- `TMapUberPicture` (full quad)
- `TMiniMapView` (full quad)
- `TMapUberUberPicture` (partial: `Create/Get` + labels)

Result:
- `fn_ok=14`, `lbl_ok=12`, `comments=4`.

### Batch B (safe full quads from `0x5a2000..0x5c2000`)
Applied conservative filtered set (`16` classes) where inferred create/ctor/dtor remained `FUN_*` and size/profile looked constructor-like:
- `TNextMoveCommand`
- `TTechItemLine`
- `TMyNumberText`
- `TPictureNumberText`
- `TPictureText`
- `TDropShadowNumberText`
- `TDealList`
- `TNextTradeCommand`
- `TDealBookPicture`
- `TTradeOfferNationLine`
- `TTradeBidNationLine`
- `TOfferDeskPicture`
- `TDealLine`
- `TCommodityLine`
- `TTradeTotalsLine`
- `TTradeTotalsView`

Result:
- `fn_ok=64`, `lbl_ok=48`, `comments=16`.

### Batch C (getter-only low-risk pass for remaining rows in `0x594000..0x5c2000`)
- For all remaining `FUN_` class getter stubs in this range, applied only:
  - `GetT*ClassNamePointer` rename,
  - `g_pClassDescT*` label,
  - `g_szTypeNameT*` label,
  - getter comment.
- Explicitly did **not** rename inferred neighbor functions (to avoid clobbering gameplay logic in tactical/AI paths).

Result:
- `fn_ok=45`, `lbl_ok=90`, `comments=45`.

### Range completion check
- Re-scan `0x594000..0x5c2000` now returns `rows=0` (no remaining `FUN_` 6-byte class getters in that range).

### Progress snapshot after this pass
- `total_functions=10512`
- `renamed_functions=5388`
- `default_fun_or_thunk_fun=5124`
- `class_desc_count=109`
- `vtbl_count=74`
- `type_name_count=107`

### Neo4j policy
- No Neo4j update (low-level rename/class extraction pass only).

## TODO (next pass)
- [ ] Continue scan/apply class-getter workflow beyond `0x5c2000`.
- [ ] Revisit tactical player/battle families with targeted manual analysis before renaming non-getter neighbors.
- [ ] After next class sweep, pivot back to game-logic-first renaming (map actions/civilian orders/turn flow).

## Continuation (2026-02-21, class extraction sweep: `0x400000..0x610000`)

### Scope and method
- Used reusable scripts only (no MCP):
  - `scan_class_getters_fun6.py`
  - `apply_class_quads_from_csv.py`
  - `count_re_progress.py`
- Safety mode for broad regions:
  - bulk **getter-only** apply (`GetT*ClassNamePointer` + `g_pClassDescT*` + `g_szTypeNameT*`),
  - avoided renaming inferred neighbors unless manually curated.

### Sub-passes completed

#### 1) `0x5c2000..0x5e4000`
- Found/processed:
  - `TUnit` getter + class/typename labels (getter-only)
  - `TModalMessageCommand`, `TAssetMgr`, `TMovieView`, `TNetMgr` getters + labels (getter-only)
- Batch results:
  - first small apply: `fn_ok=1`, `lbl_ok=2`, `comments=1`
  - second getter-only apply: `fn_ok=4`, `lbl_ok=8`, `comments=4`

#### 2) `0x400000..0x583000` massive backlog
- Scans produced:
  - `142` rows (`0x400000..0x500000`)
  - `78` rows (`0x500000..0x583000`)
  - total `220` getter rows.
- Applied getter-only bulk:
  - `fn_ok=220`, `lbl_ok=440`, `comments=220`.

#### 3) `0x594000..0x5c2000` cleanup/curated work
- Earlier in this session:
  - curated full/partial quads for selected safe classes,
  - then getter-only for remaining families.
- Post-scan now shows no remaining getter stubs there.

### Completion check
- Re-scan `0x400000..0x610000` after bulk apply:
  - `rows=0` (no remaining `FUN_` 6-byte class getters in this broad range).

### Progress snapshot after this sweep
- `total_functions=10512`
- `renamed_functions=5614`
- `default_fun_or_thunk_fun=4898`
- `class_desc_count=334`
- `vtbl_count=74`
- `type_name_count=332`

### Notes
- `class_desc_count` and `type_name_count` now closely track each other due getter-only descriptor/type label sweep.
- `vtbl_count` intentionally lags (vtables were not bulk-labeled in safety mode for ambiguous families).

### Neo4j policy
- No Neo4j updates (low-level rename/class-label extraction only).

## TODO (next pass)
- [ ] Targeted vtable labeling pass for high-confidence classes (derive from constructor assignments where safe) to close `vtbl_count` gap.
- [ ] Resume game-logic-first renaming (civilian orders, map actions, turn flow) now that class-getter backlog is mostly exhausted.
- [ ] Manually audit tactical/player families before renaming non-getter neighbors.

## Continuation (2026-02-21, class extraction acceleration with reusable scripts)

### Range scans performed
- `0x594000..0x5a2000` -> `10` getter rows
- `0x5a2000..0x5b2000` -> `17` getter rows
- `0x5b2000..0x5c2000` -> `38` getter rows
- `0x5c2000..0x5d4000` -> `1` getter row (`TUnit`)
- `0x5d4000..0x5e4000` -> `4` getter rows
- `0x5e4000..0x610000` -> `0` rows
- `0x400000..0x500000` -> `142` getter rows
- `0x500000..0x583000` -> `78` getter rows

### Bulk getter-only pass (very low risk)
- Combined getter-only CSV for `0x400000..0x583000` (`220` rows) and applied:
  - `fn_ok=220`
  - `lbl_ok=440`
  - `comments=220`
- Additional getter-only applications in upper ranges:
  - `TUnit` single-row batch (`fn_ok=1`, `lbl_ok=2`, `comments=1`)
  - `0x5d4000..0x5e4000` getter-only batch (`fn_ok=4`, `lbl_ok=8`, `comments=4`)

### Strict ctor/dtor promotion pass (high-confidence only)
- Generated `tmp_decomp/getters_strict_ctor_dtor_candidates.csv` with strict semantic checks:
  - create function still `FUN_*`, has `AllocateWithFallbackHandler`, assigns vtable pointer,
  - ctor still `FUN_*`, assigns same final vtable pointer,
  - dtor still `FUN_*`, 30-byte shape with `FreeHeapBufferIfNotNull`.
- Strict set size: `56` classes.
- Applied via `apply_class_quads_from_csv.py`:
  - `rows=56`
  - `fn_ok=168` (create/ctor/dtor promoted)
  - `fn_skip=56` (getters already renamed in prior getter-only pass)
  - `lbl_ok=56` (new vtable labels)
  - `lbl_skip=112` (descriptor/type labels already present)
  - `comments=56`

### Verification snapshot
- Re-scan `0x400000..0x610000` getter stubs now returns `rows=0`.
- Latest progress count:
  - `total_functions=10512`
  - `renamed_functions=5813`
  - `default_fun_or_thunk_fun=4699`
  - `class_desc_count=334`
  - `vtbl_count=130`
  - `type_name_count=332`

### Notes
- This pass intentionally optimized for momentum and safety:
  - broad getter/descriptor/type-name dehardcoding first,
  - constructor/dtor renames only when constructor signature evidence was strong.
- Tactical/player and some manager families remain intentionally conservative where inferred neighbors already looked like gameplay/event logic.

### Neo4j policy
- No Neo4j updates (low-level rename/class extraction only).

## TODO (next pass)
- [ ] Manual class extraction for ambiguous tactical/player families where getter is known but neighbor functions are logic-heavy.
- [ ] Continue game-logic-first renaming now that class-getter backlog is essentially exhausted.
- [ ] Optional: derive additional `g_vtblT*` labels for getter-only families by constructor trace without renaming non-getter methods.

## Continuation (2026-02-21, game-logic-focused ctor/dtor promotion from named getters)

### What was done
- Built a neighbor-promotion candidate set from already-renamed getters (`GetT*ClassNamePointer`) and inferred adjacent create/ctor/dtor functions:
  - generated: `tmp_decomp/getter_neighbor_promotion_candidates.csv`
  - size: `97` candidate rows (`create=9`, `ctor=38`, `dtor=93` potential promotions)
- Curated a game-logic-heavy subset (orders/ministers/country/minor/diplomacy/map/sim/trade/player/tactical-related families):
  - generated: `tmp_decomp/getter_neighbor_promotion_game_logic.csv`
  - subset size: `40` rows
  - rename intents: `create=6`, `ctor=19`, `dtor=40` (`65` function renames)
- Applied batch:
  - command: `new_scripts/apply_class_quads_from_csv.py tmp_decomp/getter_neighbor_promotion_game_logic.csv`
  - result: `fn_ok=65`, `fn_skip=40`, `fn_fail=0`, `lbl_ok=25`, `lbl_skip=74`, `lbl_fail=0`, `comments=40`
- Added a follow-up micro-curation for `TProductionOrder` (ctor+dtor only; no create due boundary ambiguity):
  - generated: `tmp_decomp/getter_neighbor_promotion_orders_curated.csv`
  - apply result: `fn_ok=2`, `fn_skip=1`, `fn_fail=0`, `lbl_ok=1`, `lbl_skip=2`, `lbl_fail=0`, `comments=1`

### Why this is safe
- Promotions were restricted to inferred neighbors of existing class getters and required heuristic evidence (constructor-like vtable assignment and/or destructor-like cleanup/call patterns).
- Curated batch avoided broad UI-plumbing sweeps and targeted game-logic-relevant families.
- Ambiguous create-side boundary cases (like `TProductionOrder`) were handled conservatively by promoting ctor/dtor only.

### Progress snapshot
- `total_functions=10512`
- `renamed_functions=5896`
- `default_fun_or_thunk_fun=4616`
- `class_desc_count=337`
- `vtbl_count=150`
- `type_name_count=335`

### Neo4j policy
- No Neo4j updates for this pass (low-level class-function labeling only).

## TODO (next pass)
- [ ] Use `manual_text.txt` and Neo4j gameplay concepts to semantically rename newly-promoted manager/player/minister methods beyond ctor/dtor.
- [ ] Continue game-logic-first passes (map actions/civilian orders/turn flow), using class extraction only when it unlocks nearby logic names.
- [ ] Optionally promote another curated subset from `getter_neighbor_promotion_candidates.csv` after manual semantics checks.

## Continuation (2026-02-21, gameplay-focused class-neighbor promotion + script hardening)

### User guidance integrated
- Applied the workflow reminder:
  - use `manual_text.txt` / Neo4j for gameplay semantics when uncertain,
  - keep improving reusable scripts to avoid one-off inline friction.

### New reusable script added
- Added `new_scripts/generate_named_getter_neighbor_candidates.py`:
  - scans already-renamed getters (`GetT*ClassNamePointer`),
  - infers unresolved adjacent create/ctor/dtor candidates with lightweight heuristics,
  - emits CSV with descriptor/type/vtable fields for direct apply.
- Updated `AGENTS.md` with usage guidance for this script.

### Rename batches applied (saved)
1) Curated gameplay-heavy promotion set from named-getter candidates:
- Source CSV: `tmp_decomp/getter_neighbor_promotion_game_logic.csv` (`40` rows).
- Apply result:
  - `fn_ok=65`, `fn_skip=40`, `fn_fail=0`
  - `lbl_ok=25`, `lbl_skip=74`, `lbl_fail=0`
  - `comments=40`

2) Focused follow-up for `TProductionOrder` (ctor+dtor only):
- Source CSV: `tmp_decomp/getter_neighbor_promotion_orders_curated.csv` (`1` row).
- Apply result:
  - `fn_ok=2`, `fn_skip=1`, `fn_fail=0`
  - `lbl_ok=1`, `lbl_skip=2`, `lbl_fail=0`
  - `comments=1`

3) Small gameplay-leaning cleanup from fresh live candidates:
- Source CSV: `tmp_decomp/named_getter_neighbor_candidates_gameplay_small.csv` (`4` rows):
  - `TProvinceDesirabilityList`, `TSortedByRelationshipList`, `TFuzzySet`, `TTown`
- Apply result:
  - `fn_ok=5`, `fn_skip=4`, `fn_fail=0`
  - `lbl_ok=1`, `lbl_skip=8`, `lbl_fail=0`
  - `comments=4`

### Progress snapshot
- `total_functions=10512`
- `renamed_functions=5902`
- `default_fun_or_thunk_fun=4610`
- `class_desc_count=337`
- `vtbl_count=151`
- `type_name_count=335`

### Notes
- A stale full-triple subset re-apply was attempted once and correctly no-op’ed (`fn_ok=0`, only skips), then abandoned in favor of fresh live-candidate generation.
- Fresh candidate scan now shows mostly framework/UI-class leftovers; gameplay-relevant adjacent ctor/dtor low-hanging is significantly reduced.

### Neo4j policy
- No low-level rename sync to Neo4j for this pass.

## TODO (next pass)
- [ ] Use `manual_text.txt` / Neo4j to semantically rename internal methods under newly promoted gameplay classes (especially diplomacy/minister/trade/tactical managers) instead of only ctor/dtor lanes.
- [ ] Run targeted caller/callee sweeps from `TTradeMgr`, `TDiplomacyMgr`, `TTechMgr`, and tactical player classes to harvest next non-UI low-hanging behavior names.
- [ ] Keep class-neighbor promotions limited to curated gameplay subsets; skip framework/UI-heavy leftovers unless they unblock game logic.

## Continuation (2026-02-21, tactical game-logic low-hanging via reusable CSV renamer)

### Workflow upgrade (reusable scripts)
- Added `new_scripts/apply_function_renames_csv.py`:
  - applies address->name renames from CSV,
  - optionally writes function comments,
  - saves in one transaction.
- Updated `AGENTS.md` with usage for:
  - `generate_named_getter_neighbor_candidates.py`
  - `apply_function_renames_csv.py`

### Tactical caller/callee sweep (game-logic focused)
- Ran a targeted sweep from tactical/trade/diplomacy/tech manager anchors to isolate remaining `FUN_*` low-hanging functions.
- Identified a small tactical cluster with clear behavior from decomp (state-strip clear, weighted tile scoring, tile-state queue/reset, active-unit toggle/advance).

### Renames applied (saved)
- Source CSV: `tmp_decomp/tactical_state_low_hanging_renames.csv`
- Applied via: `new_scripts/apply_function_renames_csv.py`
- Result:
  - `rows=7`, `ok=7`, `skip=0`, `fail=0`, `comments=7`

Renamed functions:
- `FUN_0059d530` -> `SelectBestTacticalTileByWeightedHeuristics`
- `thunk_FUN_0059d530` (`0x004033e6`) -> `thunk_SelectBestTacticalTileByWeightedHeuristics`
- `FUN_005a3320` -> `ClearTacticalTileStateRunByStride`
- `FUN_005a3190` -> `MarkTacticalTileStateQueuedAndMaybeDispatchPacket`
- `FUN_005a3210` -> `AdvanceOrResetTacticalTileStateRunAndMaybeDispatchPacket`
- `FUN_005a6620` -> `HandleActiveTacticalUnitReadyToggleOrAdvanceTurn`
- `FUN_005a8be0` -> `AdjustTacticalUnitVerticalOffsetAndRefreshMarker`

### Progress snapshot
- `total_functions=10512`
- `renamed_functions=5909`
- `default_fun_or_thunk_fun=4603`
- `class_desc_count=337`
- `vtbl_count=151`
- `type_name_count=335`

### Neo4j policy
- No Neo4j updates in this pass (low-level tactical code renaming/comments only).

## TODO (next pass)
- [ ] Continue tactical lane from these anchors to rename immediate helper siblings (`0x0059d6e0`, `0x0059d940`, `0x0059dd40`, `0x0059e3e0`) with behavior-backed names.
- [ ] Use `manual_text.txt` tactical sections + Neo4j gameplay concepts when deciding terminology (e.g., readiness/action-point/event packet semantics).
- [ ] Keep using CSV-driven scripts for all non-trivial rename batches to reduce repeated inline code.

## Continuation (2026-02-21, tactical helper follow-up pass)

### Why
- The prior tactical batch exposed a tightly related set of helper functions used in target selection/reachability and auto-advance packet gating.
- Continued with the same reusable flow (`apply_function_renames_csv.py`) to avoid ad-hoc edits.

### Renames applied (saved)
- Source CSV: `tmp_decomp/tactical_state_followup_renames.csv`
- Apply result:
  - `rows=4`, `ok=4`, `skip=0`, `fail=0`, `comments=4`

Renamed:
- `FUN_0059d6e0` -> `EvaluateBestTacticalTargetAndReturnActionScore`
- `FUN_0059d940` -> `CountReachableTacticalTargetsInSelectionList`
- `FUN_0059dd40` -> `CountReachableCategory2TacticalTargetsInSelectionList`
- `FUN_0059e3e0` -> `UpdateTacticalAutoAdvanceStateAndMaybeQueuePacket`

### Progress snapshot
- `total_functions=10512`
- `renamed_functions=5913`
- `default_fun_or_thunk_fun=4599`
- `class_desc_count=337`
- `vtbl_count=151`
- `type_name_count=335`

### Neo4j policy
- No Neo4j updates for this pass (low-level tactical helper naming/comments only).

## TODO (next pass)
- [ ] Continue tactical low-hanging around remaining unresolved helpers in the same neighborhood (`0x0059e4f0`, `0x005a24a0`, `0x005a34d0`, `0x005acf90`) with behavior-backed names.
- [ ] Use manual terminology (`manual_text.txt`) for tactical command wording before broader packet/event rename sweeps.
- [ ] Keep all rename batches CSV-driven through `apply_function_renames_csv.py`.

## Continuation (2026-02-21, script-driven tactical + helper expansion)

### Reusable scripts added in this pass
- `new_scripts/generate_fun_callee_candidates.py`
  - finds unresolved `FUN_*` callees reachable from caller regex cluster.
- `new_scripts/generate_fun_caller_candidates.py`
  - finds unresolved `FUN_*` callers for named callee regex cluster.
- Updated `AGENTS.md` with usage and examples for both scripts.

### Tactical lane renames applied (saved)
Source CSV: `tmp_decomp/tactical_controller_lane_renames.csv`
- `FUN_0059e4f0` -> `RunTacticalAutoTurnControllerForActiveUnit`
- `FUN_005a1ee0` -> `EvaluateAndResolveTacticalActionAgainstTileOccupant`
- `FUN_005a24a0` -> `ApplyTacticalActionEffectsAndMaybeRemoveUnit`
- `thunk_FUN_005a24a0` (`0x00402770`) -> `thunk_ApplyTacticalActionEffectsAndMaybeRemoveUnit`
- `FUN_005a34d0` -> `ExecuteTacticalMineActionAndQueuePacket`
- `FUN_005acf90` -> `HandleArmyTacticalToolbarCommandTags`
- `FUN_005ad1b0` -> `HandleNavyTacticalToolbarModeAndCommandTags`

Apply result:
- `rows=7`, `ok=7`, `skip=0`, `fail=0`, `comments=7`

### Tactical unresolved verification
- Ran:
  - `generate_fun_callee_candidates.py` on tactical/player/controller regex cluster.
- Before helper rename:
  - only `FUN_00601f1d` remained.
- Renamed:
  - `FUN_00601f1d` -> `InitializeLinkedListSentinelNodeWithOwnerContext`
- After rename:
  - tactical callee candidate list for that regex cluster returned `0`.

### Additional low-hanging helper renames (time conversion path)
Derived from map/civilian candidate mining and decomp:
- `FUN_005edcc0` -> `ConvertBrokenDownLocalTimeToEpochSeconds`
- `FUN_005e7d60` -> `ConvertFileTimeToLocalEpochSeconds`
- `FUN_005e8ee0` -> `GetCurrentLocalEpochSecondsWithTimezoneCache`

Apply result:
- `rows=3`, `ok=3`, `skip=0`, `fail=0`, `comments=3`

### Progress snapshot
- `total_functions=10512`
- `renamed_functions=5924`
- `default_fun_or_thunk_fun=4588`
- `class_desc_count=337`
- `vtbl_count=151`
- `type_name_count=335`

### Neo4j policy
- No Neo4j updates for this pass (low-level rename and comment work only).

## TODO (next pass)
- [ ] Use `generate_fun_caller_candidates.py` on broader gameplay clusters (turn flow, civilian orders, map actions) to mine next `FUN_*` wrappers around already-named logic.
- [ ] Continue diplomacy/trade gameplay terms from named anchors, using `manual_text.txt` when semantic wording is ambiguous.
- [ ] Keep CSV-driven apply-only workflow (`apply_function_renames_csv.py`) for all rename batches.

## Continuation (2026-02-21, global script-mined helper pass)

### Mining results and direction
- Ran broad unresolved-callee mining from all non-`FUN_` callers:
  - `generate_fun_callee_candidates.py "^(?!FUN_|thunk_FUN_).+"`
  - output: `tmp_decomp/global_named_callers_fun_callee_candidates.csv`
  - candidates found: `182`
- Filtered for safe/high-confidence helpers and gameplay-adjacent shared utility first (low speculation).

### Additional tactical/controller renames applied (saved)
- Source CSV: `tmp_decomp/tactical_controller_lane_renames.csv`
- Applied:
  - `RunTacticalAutoTurnControllerForActiveUnit`
  - `EvaluateAndResolveTacticalActionAgainstTileOccupant`
  - `ApplyTacticalActionEffectsAndMaybeRemoveUnit`
  - `thunk_ApplyTacticalActionEffectsAndMaybeRemoveUnit`
  - `ExecuteTacticalMineActionAndQueuePacket`
  - `HandleArmyTacticalToolbarCommandTags`
  - `HandleNavyTacticalToolbarModeAndCommandTags`
- Result: `rows=7 ok=7 fail=0 comments=7`

### Shared linked-list helper promoted from tactical residual mining
- `FUN_00601f1d` -> `InitializeLinkedListSentinelNodeWithOwnerContext`
- Result: `rows=1 ok=1 fail=0 comments=1`
- Follow-up tactical unresolved-callee scan for current tactical regex cluster now returns `0`.

### Time conversion helper cluster (gameplay-adjacent utility) applied
- Source CSV: `tmp_decomp/time_conversion_helpers_renames.csv`
- Renamed:
  - `ConvertBrokenDownLocalTimeToEpochSeconds`
  - `ConvertFileTimeToLocalEpochSeconds`
  - `GetCurrentLocalEpochSecondsWithTimezoneCache`
- Result: `rows=3 ok=3 fail=0 comments=3`

### Linked-list utility cluster applied (high-confidence behavior)
- Source CSV: `tmp_decomp/list_utility_cluster_renames.csv`
- Renamed:
  - `ProbeStackPagesForLargeFrameAllocation`
  - `AllocateListNodeFromFreePoolAndLink`
  - `RecycleListNodeToFreePoolAndMaybeRemoveAll`
  - `RemoveHeadNodeAndReturnPayload`
  - `RemoveTailNodeAndReturnPayload`
  - `FindListNodeByKeyFromNodeOrHead`
  - `RemoveListNodeAndRecycle`
  - `InsertNodeBeforeAndSetPayload`
  - `InsertNodeAfterAndSetPayload`
- Result: `rows=9 ok=9 fail=0 comments=9`

### Progress snapshot
- `total_functions=10512`
- `renamed_functions=5933`
- `default_fun_or_thunk_fun=4579`
- `class_desc_count=337`
- `vtbl_count=151`
- `type_name_count=335`

### Neo4j policy
- No Neo4j updates for this pass (all changes are low-level code/helper naming and comments).

## TODO (next pass)
- [ ] Continue from `global_named_callers_fun_callee_candidates.csv` with curated gameplay-leaning rows first (avoid CRT/MFC internals unless they unblock logic).
- [ ] Use `manual_text.txt` / Neo4j wording checks for diplomacy/trade/tactical semantics before naming command-specific handlers.
- [ ] Keep CSV-driven mining/apply loop:
  - `generate_fun_callee_candidates.py` / `generate_fun_caller_candidates.py`
  - `apply_function_renames_csv.py`
