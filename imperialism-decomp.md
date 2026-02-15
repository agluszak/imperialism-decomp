# Imperialism Reverse Engineering Notes

## City Screen Building/Icon Mapping

### Slot ID to Building Type

Derived from city-screen code paths (`slotId + 0x35` enum indexing), render formulas, and extracted assets/string tables:

- `0` Textile Mill
- `1` Clothing Factory
- `2` Steel Mill
- `3` Metalworks
- `4` Lumber Mill
- `5` Furniture Factory
- `6` Oil Refinery
- `7` Shipyard
- `8` Armory
- `9` Trade School
- `10` University
- `11` Power Plant
- `12` Food Processing
- `13` Warehouse
- `14` Railyard
- `15` Capitol

### Render/Control Formulas

- Normal building render icon: `7000 + (level * 16) + slotId`
- Upgrading render icon: `7300 + (level * 16) + slotId`
- Click/control icon: `7100 + (level * 16) + slotId`
- City building entry index: `buildingEnum = slotId + 0x35`

### Known Special Cases

- Slot `11` (Power Plant) uses special icon path (`7011` / `7027`) instead of a full regular level chain.
- Late overlays in render path include IDs `7070` / `7071` (railyard/capitol related late-state visuals).

### Concrete IDs Present in Extracted Assets

- `0` Textile Mill: normal `7000, 7016, 7032, 7048`; upgrading `7316, 7332, 7348`
- `1` Clothing Factory: normal `7001, 7017, 7033, 7049`; upgrading `7317, 7333, 7349`
- `2` Steel Mill: normal `7002, 7018, 7034, 7050`; upgrading `7318, 7334, 7350`
- `3` Metalworks: normal `7003, 7019, 7035, 7051`; upgrading `7319, 7335, 7351`
- `4` Lumber Mill: normal `7004, 7020, 7036, 7052`; upgrading `7320, 7336, 7352`
- `5` Furniture Factory: normal `7005, 7021, 7037, 7053`; upgrading `7321, 7337, 7353`
- `6` Oil Refinery: normal `7006, 7022, 7038, 7054`; upgrading `7322, 7338, 7354`
- `7` Shipyard: normal `7023, 7039` (others missing in current extracted set)
- `8` Armory: normal `7024, 7040, 7056` (base missing)
- `9` Trade School: no `7000..7059` found in current extracted set
- `10` University: normal `7026, 7042, 7058` (`7058` = highest university upgrade)
- `11` Power Plant: normal `7011, 7027`
- `12` Food Processing: no `7000..7059` found in current extracted set
- `13` Warehouse: no `7000..7059` found in current extracted set
- `14` Railyard: normal `7030, 7046`
- `15` Capitol: normal `7031, 7047`

### City-Screen Slot Iteration/Display Order

From `g_anCityBuildingSlotOrder`:

`[12, 13, 7, 10, 14, 15, 9, 6, 11, 2, 3, 8, 0, 1, 4, 5]`

### Relevant Code Anchors

- `RenderCityBuildingIcons @ 0x004ba7b0`
  - Normal formula at `0x004ba9da`
  - Upgrading formula at `0x004ba9ce`
  - Power Plant special at `0x004ba995`
  - Enum index use (`slot + 0x35`) at `0x004ba958`
- `InitializeCityBuildingControlRegions @ 0x004ba3b0`
  - Control formula at `0x004ba537`
- `HandleCityBuildingHoverSelection @ 0x004bafa0`
  - Enum index use (`slot + 0x35`) at `0x004bb0ff`

## Notes on Persistence in Ghidra

This mapping is also documented directly in Ghidra:

- Plate comments updated for:
  - `RenderCityBuildingIcons`
  - `InitializeCityBuildingControlRegions`
  - `HandleCityBuildingHoverSelection`
- Disassembly comments added at key formula instructions listed above.


## City Logic Pass: Simple Production Buildings

Scope: generic factory/mill-style production dialog flow (excluding University, Armory, Shipyard specialized UIs).

### Core Flow (High Level)

1. City production controls are built for a selected building slot.
2. Clicking a simple building opens the generic production dialog.
3. Dialog rows/sliders are initialized (plus/minus + numeric fields).
4. Detail panel updates from current slot state (capacity/cost/status text and values).
5. On dialog action:
   - `OK` commits production delta.
   - non-`OK` path can clear pending production state.
6. Parent city view refreshes derived UI after apply/cancel.

### Key Functions and Anchors

- `BuildCityViewProductionControls @ 0x004d0810`
  - Builds per-slot production widgets and commodity icon rows.
- `OpenCityViewProductionDialog @ 0x004ce5a0`
  - Generic production popup for selected slot.
  - Building entry lookup uses `(slot + 0x35)`.
- `InitializeCityViewProductionRows @ 0x004c8390`
  - Initializes row controls (plus/minus/units display wiring).
- `RefreshCityViewProductionDetails @ 0x004cfbd0`
  - Recomputes detail panel for selected slot.
- `ApplyCityProductionDialogChanges @ 0x004cebb0`
  - Handles dialog result (`'okay'` commit path vs cancel/non-OK path).
- `GetCityBuildingProductionValueBySlot @ 0x004b4dc0`
  - Reads/derives per-slot production value.
  - Slot `15` uses special derived computation (not direct table read).

### Vtable/Thunk Notes

- `0x00652aa4` points to thunk `0x00402e23` -> `OpenCityViewProductionDialog`.
- `0x00652aa8` points to thunk `0x0040547a` -> `ApplyCityProductionDialogChanges`.

### Observed UI-Specific Behavior

- Generic dialog branch distinguishes slot `11` (Power Plant) for a distinct localized prompt variant.
- Dialog logic references control tags like `'okay'`, and row control tags associated with plus/minus semantics.


### Supporting UI Command Dispatcher

- `DispatchPictureResourceCommand @ 0x0048e850`
  - Generic picture-control command router used by production UI controls.
  - Routes events to owner callback and emits action IDs (`0x1F`, `0x20`, `0x21`, or control-specific ID), which feed city dialog behaviors.


## City Production State Storage (Confirmed)

### Backing Storage

- Per-city production orders are primarily stored in a slot-indexed short table at:
  - `cityState + 0x1DC` (23 entries)
- `GetCityBuildingProductionValueBySlot @ 0x004b4dc0` reads:
  - `*(short *)(cityState + 0x1DC + slotId*2)` for regular slots
  - Slot `15` uses a derived/special computation path

### Entry Lookup Layer

- Building entry pointers come from:
  - `cityState + 0xE4 + cityEntryIndex*4`
  - with `cityEntryIndex = slotId + 0x35`
- Dialog apply path (`ApplyCityProductionDialogChanges @ 0x004cebb0`) computes a delta and calls entry vfunc `+0x2C`.

### Command/Queue Update Path

- `InitializeCityProductionQueueCommand @ 0x005add90` initializes command payload fields:
  - `+0x04` city entry index
  - `+0x08` `pCityState`
  - `+0x0C` requested production amount
  - `+0x0E` queued flag
- `QueueCityProductionOrderCommand @ 0x005ae4b0` resolves the entry from `cityState + 0xE4`, builds a follow-up command, and submits it to queue vfunc `+0x30`.
- `ApplyProductionDistributionToCitySlots @ 0x005ae420` (labeled code block) iterates 23 slots and applies non-zero deltas through manager/city virtual calls (including city vfunc `+0x48`).

### Practical Conclusion

- The remembered "what to produce" state is city-owned and slot-indexed (primary table at `+0x1DC`).
- UI actions do not directly poke fields; they enqueue/apply via city-entry and command dispatch layers, which then update the city slot state.

### Direct Writers and Persistence Handlers (Code-Confirmed)

- `ApplyCityProductionSlotDelta @ 0x004b8dd0`
  - commits slot value to `city + 0x1DC + slot*2`
  - updates mirror/delta at `city + 0x1FC + slot*2`
- `ApplyCityProductionSlotDeltaSimple @ 0x004b9090`
  - same core write path (`+0x1DC`, `+0x1FC`) without one special branch
- `ApplyNetworkCityProductionSlotValue @ 0x005822c0`
  - network-driven write into `+0x1DC` and `+0x1FC`

- `DeserializeCityProductionState @ 0x004b30a0`
  - reads/restores production tables including `+0x1DC` and `+0x1FC`
- `SerializeCityProductionState @ 0x004b35d0`
  - writes/saves production tables including `+0x1DC` and `+0x1FC`

This confirms production orders are persisted in city state and survive save/load through explicit serialization of the slot tables.

## University UI Pass (2026-02-15)

### Newly Defined Functions

- `BuildUniversityDialogControls @ 0x00474ac5`
  - Base university dialog builder (background/stat/header layout).
- `BuildUniversityRecruitmentRows @ 0x00475f84`
  - Recruitment row builder for civilian hiring and level-specific row variants.

### Confirmed Bitmap IDs in Code

- `9900` (`0x26AC`) university background (`push 0x26ac` at `0x00474bd9`).
- `9920` (`0x26C0`) miner icon (`push 0x26c0` at `0x0047603f`).
- `9922` (`0x26C2`) prospector icon (`push 0x26c2` at `0x00476156`).
- `9924` (`0x26C4`) farmer icon (`push 0x26c4` at `0x00476862`).
- `9926` (`0x26C6`) forester icon (`push 0x26c6` at `0x00476f6c`).
- `9928` (`0x26C8`) engineer icon (`push 0x26c8` at `0x00477ac1`).
- `9930` (`0x26CA`) rancher icon (`push 0x26ca` at `0x00478195`).
- `9936` (`0x26D0`) driller icon (`push 0x26d0` at `0x00477b4b`).

### University Control Tag Families (Code-Observed)

- `civ*` (`civ0`, `civ1`, ...): row picture controls for civilian recruit blocks.
- `ucl*` (`ucl1`, `ucl3`, `ucl5`, `ucl8`, ...): university level/upgrade controls.
- `num*` (`num0`, `num1`, `num3`, `num4`, ...): numeric text/value controls for rows.
- `stat/fix*` controls are used for static labels and level/stat text fields.

### Notes

- The university dialog is built from repeated row-construction blocks using `thunk_RegisterUiResourceEntry`.
- The base builder and recruitment-row builder are currently separate blocks in the `0x00474ac5..0x004784ce` region and were previously undefined.

### Recruitment State / Persistence Anchors (Current)

- Selected university entry pointer in dialog state:
  - `pCityViewDialog + 0xA8` (set in `SelectUniversityRecruitmentEntry @ 0x004cb320`)
- Selected entry index:
  - `pCityViewDialog + 0xA4`
- Recruitment entry lookup:
  - `cityState + 0xE4 + (entryIndex + 0x22) * 4`
- Per-entry queued count field used by refresh:
  - `*(short *)(pRecruitEntry + 0x04)` (read in `RefreshUniversityRecruitmentDialog`)
- Resource requirement fields observed in UI refresh:
  - `pRecruitEntry + 0x50` (paper requirement)
  - `pRecruitEntry + 0x54` (money/resource requirement)
  - `pRecruitEntry + 0x56` (availability mode/divisor selector)

### Power Plant Special Path (Resolved)

- `ApplyCityViewBuildingOrderDialogResult @ 0x004ca8f0` has a slot `11` special case.
- Slot `11` is the **Power Plant** branch (not University recruitment commit).
- City-model virtual `vfunc + 0x60` resolves to:
  - `ThunkToggleCityPowerPlantUpgradeOrder @ 0x0040494e`
  - `ToggleCityPowerPlantUpgradeOrder @ 0x004b4d50`
- Behavior at `0x004b4d50`:
  - Enable path: deduct `5000` and set queued flag.
  - Disable path: refund `5000` and clear queued flag.

## OpenCityViewProductionDialog Legibility Pass (2026-02-15)

- Function kept as `OpenCityViewProductionDialog @ 0x004ce5a0` with cleaned prototype:
  - `void __thiscall OpenCityViewProductionDialog(int nBuildingSlotId, void* pResourceEntryCity, int dwDialogContextFlags)`
- Improved variable naming for key symbols (`pBuildingEntry`, `pCityStateCtx`, `pfnFindControlByTag`, etc.).
- Renamed globals used by this function:
  - `DAT_006a20f8 -> g_pLocalizationTable`
  - `DAT_0069430c -> g_szDecimalFormat`
- Added focused plate/decompiler/disassembly comments for slot lookup, localized text loads, queued-upgrade detection, and slot-11 special-case text selection.

## Order Delta Callback Resolution (2026-02-15)

- City-entry vtable `PTR_LAB_0064f8a0` resolves callback `+0x2C` to:
  - `ThunkApplyCityEntryOrderDeltaAndCosts @ 0x00404c5a`
  - `ApplyCityEntryOrderDeltaAndCosts @ 0x004b7210`

### What `ApplyCityEntryOrderDeltaAndCosts` Does

- Validates requested target amount (`0 <= target <= entryCap`).
- Computes `delta = target - current`.
- Applies resource deltas to city stock arrays (`city + 0xB6 + resourceIndex*2`):
  - primary resource (`entry + 0x4C`, multiplier `entry + 0x50`)
  - optional secondary resource (`entry + 0x4E`, multiplier `entry + 0x52`)
- Applies optional worker-group delta via manager callback when `entry + 0x56 != 0`.
- Deducts cash from city treasury:
  - `city->money -= entryCashCost * delta` where `entryCashCost` is `entry + 0x54`.

### Practical Meaning

- The same callback used by city dialogs (`ApplyCityProductionDialogChanges`, `ApplyCityViewBuildingOrderDialogResult`) is where order-side resource and money adjustments are applied.
- This is the key commit point for per-entry production/recruitment quantity changes.

### Entry Save/Load Sync

- City-entry vtable `PTR_LAB_0064f8a0` archive method resolves to:
  - `ThunkSyncCityEntryOrderStateWithArchive @ 0x00404589`
  - `SyncCityEntryOrderStateWithArchive @ 0x004b7920`
- Synced fields include:
  - `entry + 0x04` current order amount
  - `entry + 0x4C..0x56` requirement/resource/cost configuration used by apply callback
  - `entry + 0x58` status byte
- This confirms recruitment/production entry order state is persisted through archive sync, not only transient UI state.

## Map Order Dispatch Pass (2026-02-15)

### Core Dispatch Chain (Renamed)

- `HandleMapClickByInteractionMode @ 0x005964b0`
  - Top-level map click router by interaction mode (`this + 0x96`).
  - Thunk: `ThunkHandleMapClickByInteractionMode @ 0x00401073`.
- `TryHandleMapContextAction @ 0x0055a020`
  - First-stage tile action dispatch.
  - Thunk: `ThunkTryHandleMapContextAction @ 0x0040446c`.
- `GetMapContextActionCode @ 0x00559a70`
  - Computes action code from tile state (`tile + 0x16`).
  - Thunk: `ThunkGetMapContextActionCode @ 0x00407ee1`.
- `TryQueueMapOrderFromTileAction @ 0x0055a160`
  - Fallback path that writes command/target into active order entry and commits queue updates.
  - Thunk: `ThunkTryQueueMapOrderFromTileAction @ 0x004012ee`.
- `OpenMapEntryOrderDialog @ 0x00597f80`
  - Per-entry order dialog path used by action code `11`.
  - Thunk: `ThunkOpenMapEntryOrderDialog @ 0x00408247`.

### Action Code Mapping (From `GetMapContextActionCode`)

- Tile class `2..6` excluding `3` -> action `11` (entry-order dialog branch).
- Tile class `7..13` -> actions `2..8` (`class - 5`), with context entry cached in `DAT_006A3ED8`.
- Tile class `14..21` -> action `10` if current context matches, else `9`.
- Otherwise `0` (no context action).

### Active Entry / Commit Flow (Where Orders Are Remembered)

- Active map-order entry pointer:
  - `GetActiveMapOrderEntry @ 0x005979f0` returns `*(DAT_006A3FBC + 0x14)`.
  - `SetActiveMapOrderEntry @ 0x00597950` updates active pointer and refreshes panel.
- In `TryQueueMapOrderFromTileAction`, selected command is written into active entry:
  - `entry + 0x08` = command type (`piVar5[2]`)
  - `entry + 0x0C` = command target/context pointer (`piVar5[3]`)
- Commit helpers (renamed):
  - `RebuildMapOrderEntryChildren @ 0x00553f10`
  - `MoveMapOrderEntryToQueueHeadIfValid @ 0x00557080`
  - `FinalizeQueuedMapOrderEntry @ 0x005642e0`
- Global queue head used by commit/reorder:
  - `*(DAT_006A43E4 + 0x04)` (entry linked-list head)
  - Entry queue link fields used in commit path:
    - `entry + 0x28` previous
    - `entry + 0x2C` next

### Context Resolution Helpers

- `GetMapActionContextByTileIndex @ 0x005633b0`
  - Resolves per-tile context pointer (special branch for `TPortZone`-style contexts).
- `GetProvinceByTileIndex @ 0x00563360`
  - Resolves owning province pointer from tile.
- `GetMapContextActionLabelToken @ 0x00559e00`
  - Returns localized label token for current tile/action context.

## Order Persistence Deepening Pass (2026-02-15)

### Global Save/Load Anchors (Confirmed)

- `LoadGlobalSystemsFromSave @ 0x0049e6a0`
  - Deserializes core runtime managers via vfunc `+0x18`.
- `SaveGlobalSystemsToStream @ 0x0049eb30`
  - Serializes core runtime managers via vfunc `+0x14`.
- Both explicitly include:
  - `g_pActiveMapContextState @ 0x006A3FBC`
  - `g_pNavyOrderManager @ 0x006A43E4`

### Order Manager / Queue Globals (Renamed)

- `DAT_006A43E4 -> g_pNavyOrderManager`
- `DAT_006A3FBC -> g_pActiveMapContextState`
- `DAT_006A3EDC -> g_pNavyPrimaryOrderList`
- `DAT_006A3EBC -> g_pNavySecondaryOrderList`
- `DAT_006A4370 -> g_apNationStates`

### Queue Mutation Functions (Legibility Pass)

- `DeleteMapOrderEntryAndUnlink @ 0x00552930`
- `SetMapOrderType9AndQueue @ 0x00552f80`
- `SetMapOrderType3Or4AndQueue @ 0x005530f0`
- `PromoteMapOrderChainAndQueue @ 0x005533f0`
- `SetMapOrderType6AndQueue @ 0x005536c0`
- `SetMapOrderType5AndQueue @ 0x00553840`
- `ApplyMapOrderTypeAndQueue @ 0x005540b0`
- `RequeueMapOrderEntry @ 0x00554660`
- `CancelMapOrderEntryAndRestoreActive @ 0x005547d0`

These all operate on the same queue-head field at:
- `g_pNavyOrderManager + 0x04`

### Map Improvement Order Creation (Costs + Storage)

- `QueueMapImprovementOrderBit10 @ 0x005145b0`
  - If tile-order bit `0x10` is not set: allocates and enqueues an order object into nation queue.
  - Writes tile pending flag bit `0x10`.
  - If acting nation is player-controlled, deducts `2000` cash immediately.
- `QueueMapImprovementOrderBit04 @ 0x005147d0`
  - If tile-order bit `0x04` is not set: allocates and enqueues an order object into nation queue.
  - Writes tile pending flag bit `0x04`.
  - If acting nation is player-controlled, deducts `3000` cash immediately.

### Practical Implication

- For these two improvement-order paths, cash is deducted at order queue time (not deferred to completion), and pending state is persisted directly in tile flag bits (`0x04` / `0x10`) plus the nation-side queued order chain.

### Handler Table / Label Token Anchors

- `g_aMapImprovementOrderVtable @ 0x006588F0` contains map-improvement/order handlers.
  - Confirmed slots:
    - slot `5` -> `QueueMapImprovementOrderBit10`
    - slot `6` -> `QueueMapImprovementOrderBit04`
    - slot `7` -> `FUN_005149d0`
    - slot `8` -> `FUN_005143d0`
    - slot `9` -> `FUN_00514a20`
- `g_awMapContextActionLabelTokenByCommand @ 0x0065C2F0`
  - Used by `GetMapContextActionLabelToken` to map resolved command id -> localized action label token.
  - Observed command ids in queue path: `0x0C..0x10` (mapped through this token table).

### Command-ID Resolution (Queue Branches)

- `ResolveMapOrderCommandFromActionContext @ 0x00554300`
  - Uses action-context virtual predicates (`+0x34/+0x38/+0x40/+0x44`) and returns command id:
    - `0x0C`, `0x0D`, `0x0E`, `0x0F`, or fallback `0x01`.
- `ResolveMapOrderCommandFromProvinceContext @ 0x00554460`
  - Returns province command id `0x10` on success, otherwise fallback `0x01`.
- `TryQueueMapOrderFromTileAction @ 0x0055A160`
  - Handles resolved ids `0x0A`, `0x0C`, `0x0D`, `0x0E`, `0x0F`, `0x10`.
  - Queue write pattern:
    - `entry[2]` (decomp index) stores internal order type (`1/3/5/6` seen).
    - `entry[3]` stores target context pointer (tile-action or province context).

## Transport Flag / Engineer Order Mapping Pass (2026-02-15)

### Confirmed Bit Semantics (Code-Confirmed)

- `tileFlags bit 0x04` -> **port marker/pending**
  - `QueuePortConstructionOrder` sets this bit.
  - `SetTileTransportFlags` treats this as port-zone membership trigger.
  - `DumpAndResetMapScriptState` logs this as `port %d` and clears it.
- `tileFlags bit 0x10` -> **rail marker/pending**
  - `QueueRailConstructionOrder` sets this bit.
  - `DumpAndResetMapScriptState` logs this as `rail %d` and clears it.

### Function Renames Applied

- `QueueRailConstructionOrder @ 0x005145B0`
- `QueuePortConstructionOrder @ 0x005147D0`
- `SetTileTransportFlags @ 0x00513200`
- `EnsurePortZoneForTile @ 0x005635E0`
- `RemovePortZoneByTile @ 0x00564240`
- `FindPortZoneByTile @ 0x00561BF0`
- `GetFirstPortZone @ 0x00561C80`
- `GetNextPortZone @ 0x00561D40`
- `FindPortZoneBySelectedTile @ 0x005634A0`
- `DumpAndResetMapScriptState @ 0x00519140`

### Cost Mapping (Now Grounded to Rail/Port)

- `QueueRailConstructionOrder`:
  - deducts `2000` for player nation
  - sets bit `0x10`
- `QueuePortConstructionOrder`:
  - deducts `3000` for player nation
  - sets bit `0x04`

This aligns with manual guidance that ports cost more than depots/rail infrastructure.

### Additional Related Handlers (Still Partially Semantic)

- `FloodFillTileRegionMarker @ 0x005143D0`
- `SetProvinceCapitalTileFlagBit08 @ 0x005149D0`
- `SetTileTransportFlagsTo0x37AndRefreshNeighbors @ 0x00514A20`

These are now documented in Ghidra with behavior-focused comments; they appear to support transport hub / region propagation, but exact UI action naming (depot vs combined hub variants) remains to be finalized.

### Network-Side Sync Anchor

- `HandleNetworkPortConstructionOrder @ 0x004E5730`
  - Mirrors queued port construction from network/event input.
  - Uses same init mode as port queue path (`...b6cd0(..., mode=1, ...)`).
  - Applies `SetTileTransportFlags(tile, 0x15)` then enqueues into nation queue (`+0x898`).
  - This strongly suggests `0x15` is a combined transport state used after port-side construction sync.
