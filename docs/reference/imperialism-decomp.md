# Imperialism Reverse Engineering Notes

## Executable Startup Entrypoint (2026-02-16)

### Confirmed Process Entry Chain

- `entry @ 0x005e98b0`
  - PE/CRT startup: runtime init, command-line parsing, startup info handling.
  - Calls `CallMfcAppLifecycleEntry @ 0x005fa7c2`.
- `CallMfcAppLifecycleEntry @ 0x005fa7c2`
  - Thin wrapper to `DispatchMfcAppLifecycle @ 0x0060d3fc`.
- `DispatchMfcAppLifecycle @ 0x0060d3fc`
  - MFC app lifecycle dispatcher using application vtable slots:
    - `+0x8C` -> `InitializeMfcAppDocumentManager @ 0x00622572`
    - `+0x58` -> `InitializeImperialismApplicationInstance @ 0x00412dc0` (via thunk `0x00407e19`)
    - if init succeeds: `+0x5C` -> `RunImperialismThreadMainLoop @ 0x006055ae`
    - else: `+0x70` -> `ShutdownImperialismApplicationInstance @ 0x00413780` (via thunk `0x00407e14`)

### App Singleton Constructor / Vtable Anchor

- `ConstructImperialismApplicationSingleton @ 0x00412ac0`
  - Sets app object vtable to `PTR_LAB_0063e2d0`.
  - This vtable mapping resolves the lifecycle offsets used in `DispatchMfcAppLifecycle`.
- Global constructor bootstrap:
  - `InitializeImperialismAppSingletonGlobal @ 0x00412d40`
  - referenced in CRT init table (`0x00692344`)
  - constructs singleton at `DAT_006a1210`
  - registers `DestroyImperialismAppSingletonGlobal @ 0x00412d70`

### Main Loop Anchor

- `RunImperialismThreadMainLoop @ 0x006055ae`
  - delegates to `RunMfcThreadMessageLoopCore @ 0x006063cd`.
- `RunMfcThreadMessageLoopCore @ 0x006063cd`
  - executes idle callbacks + message pumping.
  - pump helper: `PumpMfcThreadMessage @ 0x0060694f`.

### First Startup Command Dispatch (`WM_COMMAND 100`)

- `InitializeImperialismApplicationInstance @ 0x00412dc0` posts:
  - `PostMessageA(mainWndHwnd, 0x111, 100, 0)`.
- Runtime class/message map anchors for main startup window class:
  - `TMacViewMgr_RuntimeClass @ 0x00648628` (class-name string: `TMacViewMgr`)
  - `TMacViewMgr_MessageMapDescriptor @ 0x00648640`
  - `TMacViewMgr_OnCommand100_MsgEntry @ 0x006487c8`
- Exact message-map entry decode at `0x006487c8`:
  - `nMessage=0x111`, `nCode=0`, `nID=100`, `nLastID=100`, `nSig=0x0C`, `pfn=0x0040132A`.
- Resolved handler chain:
  - `thunk_DispatchStartupCommand100ToAppSingleton @ 0x0040132a`
  - `-> DispatchStartupCommand100ToAppSingleton @ 0x00484fd0`
  - `-> thunk_HandleStartupCommand100 @ 0x004019fb`
  - `-> HandleStartupCommand100 @ 0x00413950`
  - `-> g_pLocalizationTable vfunc +0x4C`
  - `-> thunk_AdvanceGlobalTurnStateMachine @ 0x00403b0c`
  - `-> AdvanceGlobalTurnStateMachine @ 0x0057da70`.

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

## Strategic Map Order/Civilian Legibility Pass (2026-02-15)

### Newly Renamed Helpers

- `InitializeStrategicMapTileIconStateCache @ 0x0051CC60`
- `SelectNextValidMapOrderEntryFromCursor @ 0x00599770`
- `TrySelectNextValidMapOrderEntry @ 0x005998A0`
- `ResetMapInteractionToCivilianMode @ 0x005999F0`

### Order Entry Persistence Fields (Code-Confirmed)

From `TryQueueMapOrderFromTileAction @ 0x0055A160` and `RefreshMapOrderEntryPanel @ 0x00597810`:

- `entry + 0x08` (`entry[2]`): order type code written during queue selection (`1/3/5/6` observed).
- `entry + 0x0C` (`entry[3]`): action/province context pointer.
- `entry + 0x1E, +0x20, +0x22, +0x24`: four short slider/order values shown in panel controls (`0slc..3slc`).

This confirms the slider production/order values are remembered in the order entry object itself and restored whenever the entry is re-selected.

### Strategic Tile Icon Cache Initialization Table

`InitializeStrategicMapTileIconStateCache` seeds `tile[0x11]` from `tile[0x13]` via a local 15-entry map:

- index `0..14` -> `[-1, -1, 0, 20, 5, 17, 18, 1, -1, -1, -1, -1, -1, 2, -1]`

Related tile bytes:

- `tile + 0x11`: primary icon variant cache (consumed by `DrawStrategicMapUnitIcon`)
- `tile + 0x12`: secondary icon variant cache (`0xFF` means empty)
- `tile + 0x13`: source profile/index driving cache selection
- `tile + 0x17`: overlay-state selector used by `DrawStrategicMapUnitIconOverlay`

### Additional Icon Table (Slot Update Path)

`FUN_0051D970` (tile icon slot updater) uses a small mapping for `param_1[0x36C]`:

- `{22, 21, 6}` -> written to either `tile[0x11]` or `tile[0x12]`

This supports the hypothesis that selected/no-order variants are derived from base unit class indices through compact lookup maps rather than direct bitmap-id constants in one place.

### Important Split: Editor Tile-Cache Mutators vs Runtime Order Queue

Newly renamed and documented:

- `DispatchStrategicMapTileEditAction @ 0x0051CE60`
- `ApplyTileIconProfileFromEditorSelection @ 0x0051D4F0`
- `ApplyTileIconOverlayFromEditorSelection @ 0x0051D970`
- `ResetTileIconCacheFromProfile @ 0x0051DA60`

These functions directly write `tile+0x11/+0x12/+0x13` and refresh rendering, but they belong to a dedicated tile-edit action dispatcher path (selected action id at `this+0x368`), not the normal civilian order queue commit path.

In contrast, runtime order commit path remains:

- `TryQueueMapOrderFromTileAction @ 0x0055A160`
- `RebuildMapOrderEntryChildren @ 0x00553F10`
- `MoveMapOrderEntryToQueueHeadIfValid @ 0x00557080`
- `FinalizeQueuedMapOrderEntry @ 0x005642E0`

This path writes order-entry structure fields (`+0x08/+0x0C/+0x1E..+0x24`) rather than directly mutating tile icon cache bytes.

Further confirmation:

- `ThunkSetMapOrderType6AndQueue`
- `ThunkSetMapOrderType3Or4AndQueue`

Both queue helpers only update order-entry type/context and queue linkage before `ThunkFinalizeQueuedMapOrderEntry`; no direct tile cache writes (`+0x11/+0x12/+0x17`) were found in these paths.
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
  - Thunk: `Thunk_DispatchMapTileContextAction @ 0x0040446c`.
- `GetMapContextActionCode @ 0x00559a70`
  - Computes action code from tile state (`tile + 0x16`).
  - Thunk: `Thunk_ResolveMapTileContextActionCode @ 0x00407ee1`.
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

Current operation-index correlation in `g_apfnMapImprovementOperationHandlers`:

- op `7` -> `SetProvinceCapitalTileFlagBit08`
- op `8` -> `FloodFillTileRegionMarker`
- op `9` -> `SetTileTransportFlagsTo0x37AndRefreshNeighbors`

These are now documented in Ghidra with behavior-focused comments; they appear to support transport hub / region propagation, but exact UI action naming (depot vs combined hub variants) remains to be finalized.

### Network-Side Sync Anchor

- `HandleNetworkPortConstructionOrder @ 0x004E5730`
  - Mirrors queued port construction from network/event input.
  - Uses same init mode as port queue path (`...b6cd0(..., mode=1, ...)`).
  - Applies `SetTileTransportFlags(tile, 0x15)` then enqueues into nation queue (`+0x898`).
  - This strongly suggests `0x15` is a combined transport state used after port-side construction sync.

## Map Order UI Dispatch / Operation Tables (2026-02-15)

### New Global Labels Applied in Ghidra

- `g_apfnMapOrderUiDispatchHandlers @ 0x00653D00`
- `g_apfnMapOrderUiDispatchHandlersBackup @ 0x0065BE50`
- `g_apfnMapImprovementOperationHandlers @ 0x006588F0`
- `g_anMapActionClassToImprovementOpIndex @ 0x00658964`

### Action-Class to Improvement-Operation Index Table

Decoded from `g_anMapActionClassToImprovementOpIndex`:

- `3 -> 0`
- `4 -> 1`
- `7 -> 2`
- `8 -> 3`
- `9 -> 4`
- `11 -> 5`
- `12 -> 6`
- `13 -> 7`
- other entries in this range are `-1` (no mapped improvement op)

This table is consistent with the known operation table at `0x006588F0` where:
- op index `5` routes to `QueueRailConstructionOrder` (tile bit `0x10`, cost `2000`)
- op index `6` routes to `QueuePortConstructionOrder` (tile bit `0x04`, cost `3000`)

### Additional Operation Helpers Renamed

- `GetMapImprovementTierBucketOffset @ 0x005176E0`
- `GetMapImprovementSpriteBaseOffset @ 0x00517780`
- `ApplyMapImprovementSelectionState @ 0x00517710`
- `GetMapImprovementTileOffsetFromClass @ 0x005177D0`
- `GetMapImprovementTileSpriteOffset @ 0x005177F0`

These functions feed sprite/selection behavior used by improvement UI/order handling and are now plate-commented in Ghidra.

## Map Order Type Setters: Caller Mapping (2026-02-15)

Newly mapped orchestration functions that call type-specific queue setters:

- `ProcessMapOrderEntryContextMode @ 0x00536E40`
  - Branches on internal mode field (`entry + 0x28` in decomp indexing).
  - Queues:
    - `SetMapOrderType3Or4AndQueue(..., 0)`
    - `SetMapOrderType9AndQueue(...)`
    - vfunc route (`+0x9C`) for mode `2`.
- `ResolveAndQueuePortZoneMapOrder @ 0x00539640`
  - Builds a nation bitmask of valid port-zone contexts.
  - If active context is outside mask but matching zone exists: `SetMapOrderType6AndQueue`.
  - Else falls back to `SetMapOrderType3Or4AndQueue(..., 0)`.
- `TryQueueProvinceOrderFromContextMessage @ 0x0053A800`
  - On province predicate success (`manager vfunc +0x48`), queues:
    - `SetMapOrderType5AndQueue(entry, pProvince)`.

Supporting helpers renamed:

- `FindFirstPortZoneContextByNation @ 0x00563540`
- `RebuildMapOrderEntryChildrenForContext @ 0x00536D60`
- `SetMapOrderEntryChildFlags @ 0x00536F70`

Practical interpretation:

- Internal order types `3/6` are strongly tied to port-zone context selection/routing.
- Internal order type `5` is province-targeted and set from context-message flow.
- Type `9` remains an alternate queued mode used by `ProcessMapOrderEntryContextMode` branch `mode==1`.

## Mission Prioritizer Branch (Type-9 Clarification, 2026-02-15)

Additional reverse-engineering confirms a major subset of type-1/type-9 queue logic belongs to mission AI prioritization:

- `QueueMissionOrdersByPriorityForContext @ 0x00537090`
  - Selects highest-priority child node via weighted profile scoring.
  - For each selected chain node:
    - if `node->contextPtr == requestedContext`: `SetMapOrderType9AndQueue`
    - else: `PromoteMapOrderChainAndQueue` (type-1 path)
- `CalculateMissionOrderPriorityScore @ 0x005501B0`
- `GetOrCreateMissionOrderEntryForNode @ 0x005503A0`
- `FindMissionOrderNodeById @ 0x00552510`
- `GetMissionOrderBudgetByMode @ 0x00537060`

Mission class-name anchors found via vtable methods:

- `TDefendProvinceMission`
- `TNavyMission`
- `TBeachheadMission`
- `TBlockadePortMission`
- `TArmyMission`

Labeled mission-related vtables:

- `g_vtblMissionOrderPrioritizerDefendProvince @ 0x0065A650`
- `g_vtblMissionOrderPrioritizerNavy @ 0x0065A7E8`
- `g_vtblMissionOrderPrioritizerBeachhead @ 0x0065AB58`
- `g_vtblMissionOrderPrioritizerBlockadePort @ 0x0065AC30`
- `g_vtblMissionOrderPrioritizerArmy @ 0x0065AD08`
- `g_vtblTDefendProvinceMission @ 0x0065A680`
- `g_vtblTNavyMission @ 0x0065A818`
- `g_vtblTBeachheadMission @ 0x0065AB88`
- `g_vtblTBlockadePortMission @ 0x0065AC60`
- `g_vtblTArmyMission @ 0x0065AD38`

Interpretation update:

- `type9` is now strongly associated with mission-context match handling (AI mission prioritizer path), not a direct simple civilian-click command in the map UI.

## Map Interaction Post-Click Cycler + Context Dialog (2026-02-15)

New renames/documentation applied in Ghidra:

- `CycleMapInteractionSelectionAfterHandledClick @ 0x00597A80`
  - Former: `FUN_00597a80`
  - Called from `HandleMapClickByInteractionMode` after a click branch reports handled.
  - Cycles interaction submodes and reselects valid target/state:
    - mode 0: unit-style target path
    - mode 1: province/region path
    - mode 2: map-order-entry list traversal (`DAT_006A3FC8` chain)
    - fallback to neutral mode 3 when no candidate is found.

- `OpenMapContextActionDialogByType @ 0x00599090`
  - Former: `FUN_00599090`
  - Called only from `TryHandleMapContextAction` for action codes `2..8`.
  - Call-site assembly confirms 3 stack args plus manager `this` in ECX:
    - arg0: context pointer from `GetMapActionContextByTileIndex`
    - arg1: `actionCode - 2`
    - arg2: cached context (`DAT_006A3ED8`)
  - This is a dialog/text building path (localized tokens including `title`/`lab1..lab4`) used before/while committing map action context changes.

- Thunks renamed:
  - `ThunkCycleMapInteractionSelectionAfterHandledClick @ 0x00408B93`
  - `ThunkOpenMapContextActionDialogByType @ 0x004016A9`

### Refined Action-Class Mapping (from `GetMapContextActionCode`)

- tile class `2..6` except `3` -> action code `11` (entry-order dialog path)
- tile class `7..13` -> action code `2..8`, with context match cached in `DAT_006A3ED8`
- tile class `14..21` -> action code `10` if clicked context equals active context, otherwise `9`

This strengthens the model that `2..8` are context-action dialog branches, while queue writes/commit happen in `TryQueueMapOrderFromTileAction` (`entry[2]` / `entry[3]` + finalize).

### Additional Helper Renamed (Map Order Gating)

- `GetMinActionThresholdFromEntryChildren @ 0x00554A80`
  - Former: `FUN_00554a80`
  - Iterates entry child list (`entry + 0x10`) and returns minimum threshold from `DAT_00698124` over active children.
  - Returns `0` when no active child contributes.
  - Used in both `TryQueueMapOrderFromTileAction` and `GetMapContextActionLabelToken` as part of action gating.

## Strategic Map Tile Renderer Anchor (2026-02-15)

- Renamed `FUN_0051EB40` -> `RenderStrategicMapTileCell`.
- Confirmed inside this function:
  - Explicit blit from source rect `[left=400, right=420)` (width `0x14`) on sprite sheet `DAT_006A21A8[0x1A6]`.

Implication:
- The map renderer directly references icon-id `400` range assets in tile overlay rendering.
- This is a strong anchor for finishing the `400..426` mapping (normal / selected / no-orders civilian icon states).

## Legibility Pass: City Production Dialog (2026-02-15)

Applied readability-focused updates in Ghidra:

- `RenderCityViewProductionDialogMetrics @ 0x004C9150`
  - Former: `FUN_004c9150`.
  - Added full plate comment.
  - Updated prototype to named parameters.
  - Renamed key locals (commodity sprite id, metric values, clip-intersection flag, etc.).

- `OpenCityViewProductionDialog @ 0x004CE5A0`
  - Kept name, expanded plate comment to full Algorithm/Parameters/Returns structure.
  - Renamed core temporary locals for legibility:
    - `iVar2` -> `pDialogVtable`
    - `piVar1` -> `pFoundControl`
    - `pNameTextControl` -> `pBuildingNameTextControl`
    - `pTextControl` -> `pBuildingCostTextControl`
    - `pUiNode` -> `pBuildingCapacityTextControl`

Result:
- Decompiled city production path is now significantly easier to read and aligns with known slot/upgrade behavior.

## Map Civilian/Province Selection Helpers Renamed (2026-02-15)

Additional helper renames in the map click mode-cycler branch:

- `ClearCivilianSelectionHighlightsForNation @ 0x004D20E0`
- `SelectFirstAvailableCivilianForNation @ 0x004D2160`
- `SetActiveCivilianSelection @ 0x004D2C60`
- `ClearProvinceSelectionHighlightsForNation @ 0x004A46D0`
- `FindNextSelectableProvinceForNation @ 0x004A4760`
- `SetActiveProvinceSelection @ 0x004A45E0`

Interpretation:
- `CycleMapInteractionSelectionAfterHandledClick` mode `0` path is civilian-centric and uses the `0x004D20E0/0x004D2160/0x004D2C60` chain.
- Mode `1` path is province-centric and uses the `0x004A46D0/0x004A4760/0x004A45E0` chain.
- This cleanly separates civilian selection vs province selection before mode `2` map-order-entry traversal.

## Strategic Map Icon Draw Vtable Recovery (2026-02-15)

Recovered vtable entry targets behind `g_pStrategicMapViewSystem` virtual calls used in `RenderStrategicMapTileCell`:

- `DrawStrategicMapUnitIcon @ 0x0050DD40`
  - vtable slot `+0x80` (entry `g_vtblStrategicMapViewSystem_DrawUnitIcon @ 0x006586E0`)
  - Draws 20x24 icon with transparent color-key `0x10`.

- `DrawStrategicMapUnitIconOverlay @ 0x0050DF40`
  - vtable slot `+0x84` (entry `g_vtblStrategicMapViewSystem_DrawUnitIconOverlay @ 0x006586E4`)
  - Draws secondary overlay block (0x26 x 0x1A) with transparent key `0x10`.
  - Uses lookup table `g_anStrategicMapOverlaySourceRowByIconId @ 0x00696D20`.

- `CopySpriteSurfaceToStrideBuffer @ 0x0050D9E0`
  - low-level buffer copy helper in same rendering family.

Additional labels:
- `g_vtblStrategicMapViewSystem @ 0x00658660`
- `g_pStrategicMapViewSystem @ 0x006A21A8`
- thunk labels at dispatcher addresses:
  - `thunk_DrawStrategicMapUnitIcon @ 0x00403684`
  - `thunk_DrawStrategicMapUnitIconOverlay @ 0x00404D68`
  - `thunk_CopySpriteSurfaceToStrideBuffer @ 0x00409999`

Interpretation:
- `RenderStrategicMapTileCell` is now clearly wired to vfunc icon draw helpers, which explains why `400/409/418` states are only partially visible as direct constants in the parent function.

## Strategic Map Region/Order Legibility Pass (2026-02-15, continuation)

### Newly Renamed Functions

- `SmoothCityRegionOwnershipByNeighborSampling @ 0x00528E50`
  - Neighbor-sampling smoothing pass for city-region ownership classes.
- `BuildCityRegionBorderOverlaySegments @ 0x0052C1A0`
  - Emits overlay border segments where adjacent city-region IDs differ.
- `ReindexContiguousCityRegionIds @ 0x0052D1F0`
  - Propagates contiguous labels, then writes compact region IDs back to city tiles.
- `MergeSmallCityRegionsAndCompactIds @ 0x0052D750`
  - Merges undersized regions and rewrites region-link metadata.
- `UpdateMapOrderEntryTilePreviewSlot @ 0x00523170`
  - Assigns/updates preview slot, caches tile->slot mapping (`tile + 0x10`), and redraws preview atlas.
- `RenderMapOrderEntryTilePreview @ 0x00523640`
  - Draws tile preview with faction-sensitive overlay/icon behavior.
- `DrawHexNeighborConnectionMask @ 0x00522CF0`
  - Renders hex-edge connection strips from a bitmask + neighbor tile class checks.
- `ApplyTileTerrainIndexAndInvalidateAdjacency @ 0x0051DBA0`
  - Applies terrain index (`tile + 0x02`), clears adjacency cache bytes (`+0x0A/+0x0B`), and invalidates redraw.

### Confirmed Data Semantics from This Pass

- `tile + 0x04` (for city tiles `tile[0] == 0x05`) is reused as a city-region/cluster class during border/region generation.
  - Region IDs are represented as `tile[0x04] = regionId + 0x17` in region passes.
- `tile + 0x10` is used as a preview-slot cache index by `UpdateMapOrderEntryTilePreviewSlot`.
- Region-border overlay construction and region merging are separate from civilian order queue persistence.

### Runtime Icon-State Writer Status

- Still unresolved: direct non-editor runtime writer for `tile + 0x17` (overlay selector used by `RenderStrategicMapTileCell`/overlay draw path).
- Confirmed this pass:
  - editor/tile-edit dispatchers mutate icon cache fields (`+0x11/+0x12/+0x13`) and related bytes,
  - queue/order commit path still does not directly write `tile + 0x17`.

### Strategic Tile Cache Mutator Renames (same pass)

- `ApplyCityInfluenceTierAndInvalidateTileCaches @ 0x0051D060`
  - Updates city influence tier bytes (`tile+0x03/+0x04`) by city-id match and invalidates related caches.
- `InitializeStrategicMapCityInfluenceBuffers @ 0x0051D210`
  - Clears city influence working arrays and propagates neighbor-max influence tier for city tiles.
- `ApplyTileOrderOverlayMaskAndInvalidate @ 0x0051DB30`
  - Writes overlay/order mask at `tile+0x06` then triggers redraw invalidation.
- `PromoteTileToCityAndRefreshNeighbors @ 0x0051DC90`
  - City-type promotion/update pass touching city flags (`tile+0x1C`) and neighbor refresh callbacks.

These functions improve readability of the strategic-map cache pipeline and confirm more runtime writes for `+0x03/+0x04/+0x06/+0x07/+0x1C`, while the direct gameplay writer for `tile+0x17` remains to be identified.

## City Dialog Legibility Update (2026-02-15, continuation)

### OpenCityViewProductionDialog cleanup

Function: `OpenCityViewProductionDialog @ 0x004CE5A0`

- Prototype normalized to:
  - `void __thiscall OpenCityViewProductionDialog(void* this, int nBuildingSlotId, void* pCityState, int nDialogContextFlags)`
- Variable names improved for readability in key dialog flow:
  - `pUiControlByTag`, `pUiControlMatch`, `pfnFindControlByTagHash`, `pNameTextControl`, `pCostTextControl`, `pCapacityTextControl`, `pfnFormatProductionValue`.
- Existing slot mapping logic remains confirmed:
  - building entry lookup uses `slot + 0x35` into city slot table.

### Additional strategic mutator rename

- `0x0051D7E0` -> `ApplyTileCityIdAndInvalidateLocalOverlays`
  - Writes city-id to `tile+0x14`, clears tile overlay cache bytes `+0x07/+0x08/+0x09`, and invalidates selected tile + neighbors.

## User-Confirmed Civilian Map Gameplay Semantics (2026-02-15)

Source: direct gameplay explanation from user.

### Civilian icon-state behavior

- `409..417` = selected/active order-targeting state after click.
- Selected state is visually blinking by alternating between normal and selected-looking frames.
- While selected/blinking, next click issues order for that civilian.
- `418..426` was previously labeled "no orders" in notes, but behavior is better described as:
  - transient unproductive/move-without-productive-task state;
  - unit can appear in this set when moved without assigning productive work.
- "No-order/sleep" context leaves unit in normal state (not productive animation state).
- Separate productive state exists:
  - when a productive order is issued, worker animation starts (see also `14000..14041` work animations).

### Order timing / icon transition timing

- Queueing an order changes icon immediately.
- Changed icon state persists until next turn.

### Selection model

- Single selection only (no group/stack civilian selection behavior).

### Productive order issue model (tile-hover dependent)

- Productive command is context-sensitive to hovered tile + civilian type + tech availability.
- Example (Prospector):
  - hovering valid unprospected mountain -> productive cursor -> click issues prospecting.
  - hovering desert without required oil-related technology -> click issues move only (non-productive).
- Example (Farmer):
  - hovering farm tile already at current max improvement -> move behavior, not productive order.

### Engineer special interaction

Engineer has two distinct issue patterns:

1. Click current tile:
- Opens Construction Options window.
- Options include port/fort/depot depending on conditions.

2. Click neighboring tile:
- Cursor changes to railroad icon.
- Engineer moves and starts building railway from current tile to clicked tile.
- Requires normal build-validity conditions.

### Practical RE implications

- Runtime icon-state transition logic must account for:
  - selected blinking state,
  - immediate post-order state changes,
  - productive vs non-productive decision at click time,
  - tech-gated productive fallback to movement.
- Mapping `400..408` / `409..417` / `418..426` should be interpreted as a state machine driven by:
  - selection latch,
  - productive-order eligibility,
  - per-turn reset timing.

### Follow-up confirmations (2026-02-15)

- Multi-turn productive tasks:
  - There are no generic repeatable civilian tasks.
  - Some productive tasks take multiple turns; during that period civilian stays in animated/working state.
  - After task completion, civilian resets to normal state and requires new orders.

- Sleep vs no-orders semantics:
  - `Sleep` is persistent across turns until user reactivates/clicks unit.
  - `No orders this turn` is a one-turn status.

## Map Order Commit Path Deepening (2026-02-15)

### Confirmed function roles (queue/commit)

- `TryQueueMapOrderFromTileAction @ 0x0055A160`
  - Drives click-to-order queue path after context-action precheck.
  - Writes active entry fields:
    - `entry+0x08` = order type (`1/3/5/6` in observed branches)
    - `entry+0x0C` = target context pointer (action context or province)
  - Calls `RebuildMapOrderEntryChildren` and queue insertion helpers.
  - Final commit call: `FinalizeQueuedMapOrderEntry(entry)`.

- `ApplyMapOrderTypeAndQueue @ 0x00554050`
  - Shared setter/queue helper for type-based map orders.
  - Confirms same storage fields:
    - `this+0x08` = selected order type
    - `this+0x0C` = selected order target argument
  - Uses `MoveMapOrderEntryToQueueHeadIfValid` then `FinalizeQueuedMapOrderEntry`.

- `FinalizeQueuedMapOrderEntry @ 0x005642E0`
  - Post-queue synchronization step (active-nation check, input-state node checks, notify map interaction object).
  - Invokes map interaction notify vfunc `+0x1E8` when `entry+0x30` tile notify index is valid.
  - Clears manager current-entry pointer when finalized entry matches.

### Command resolver mapping (raw command ids before type application)

- `ResolveMapOrderCommandFromActionContext @ 0x00554300`
  - Returns command ids in `{0x01, 0x0C, 0x0D, 0x0E, 0x0F}`.
  - `TryQueueMapOrderFromTileAction` maps these to type/target writes and queue behavior.

- `ResolveMapOrderCommandFromProvinceContext @ 0x00554460`
  - Returns `0x10` when province predicate succeeds; else fallback `0x01`.
  - `0x10` branch sets `entry+0x08 = 5` and `entry+0x0C = province`.

- `CanQueueMapOrderForProvinceContext @ 0x00554590`
  - Province gating predicate before allowing province-command resolution.

### UI/dialog path separation note

- `OpenMapContextActionDialogByType @ 0x00599090` and `OpenMapEntryOrderDialog @ 0x00597F80`
  - Primarily localization/dialog text and choice presentation.
  - Not the primary persistence writers for order type/target; persistence occurs in queue/apply paths above.

### Current best storage model for civilian order memory

- Civilian/map order intent is persisted in map-order entry objects managed by global manager(s), primarily via:
  - `entry+0x08` order type,
  - `entry+0x0C` order target context,
  - child-node list at/under `entry+0x10` (rebuilt and pruned during queueing).

- Immediate icon/state transitions observed by user after order issue are expected to be triggered by finalize/notify + downstream UI refresh paths, not only by dialog builders.

## University Orders Persistence + Cost Deduction (2026-02-15)

### Core persistence function identified

- `ApplyCityEntryOrderDeltaAndCosts @ 0x004B7210`
  - This is the key write path for city-entry order quantities (used by production/recruitment entries).
  - Verified behavior:
    - validates target quantity against entry max (`vfunc +0x30`) and non-negative bounds,
    - writes new queued amount to `entry+0x04`,
    - computes `delta = newAmount - oldAmount`,
    - deducts primary resource stock from city array at `city + 0xB6 + resourceId*2` using per-unit cost `entry+0x50`,
    - optionally deducts secondary resource (`entry+0x4E/0x52` when secondary resource id >= 0),
    - applies worker-group/labor delta via manager callback when `entry+0x56 != 0`,
    - deducts cash from city treasury (`city->economy+0x10`) using per-unit cash cost `entry+0x54`,
    - notifies global economy/UI observer via `(*DAT_006A21BC + 0xAC)`.

### Connection to city/university dialogs

- `ApplyCityProductionDialogChanges @ 0x004CEBB0`
  - Commits city dialog changes by calling entry `vfunc +0x2C`, which resolves to `ApplyCityEntryOrderDeltaAndCosts` for standard city-entry objects.

- `ApplyCityViewBuildingOrderDialogResult @ 0x004CA8F0`
  - Similar commit path for building order dialogs.
  - Slot 11 has a special power-plant toggle handler path (`city-model vfunc +0x60`), while normal slots still route through entry delta apply.

### Practical conclusion for RE

- Recruitment/production "what to produce" state is persisted per city-entry object (`entry+0x04` quantity).
- Resource and money deduction happens immediately in the apply-delta path (not only at end-turn).
- University recruitment rows appear to be backed by the same city-entry order machinery (same entry field family `+0x4C/+0x4E/+0x50/+0x52/+0x54/+0x56` visible in university refresh/requirements code).

## Continued Map/University Legibility Pass (2026-02-15)

### Map interaction redraw/selection helper naming pass

Renamed and documented:

- `0x00565F80` -> `InvalidateMapRegionForOrderEntry`
  - Computes and invalidates redraw rectangle for a map-order entry region.

- `0x00566060` -> `ComputeTileClassBoundsInViewport`
  - Scans strategic tiles and computes min/max viewport bounds for tiles matching entry class (`entry+0x12`).

- `0x00598840` -> `InvalidateMapRegionForEntryIfUiPassive`
  - Calls invalidation only when interaction UI is in passive mode (`entry+0x94 == 0`).

- `0x00599A50` -> `EnterMapInteractionOverlayMode`
  - Switches interaction into overlay-oriented UI state and syncs linked view/cursor widgets.

- `0x00560B00` -> `CanDisplayMapOrderEntryInCurrentContext`
  - Eligibility predicate used by mode-2 traversal in `CycleMapInteractionSelectionAfterHandledClick`.

Result: `CycleMapInteractionSelectionAfterHandledClick` now decompiles with substantially more readable intent in mode-switch and panel-refresh branches.

### University/City entry spec table structure confirmed

From `InitializeCityProductionState @ 0x004B2570`:

- Entry objects are allocated and initialized from compact 7-word spec tables:
  - `DAT_00695C5A` (first group, constructor call uses final flag `0`)
  - `DAT_00695CE8` (second group, constructor call uses final flag `1`)

- Constructor pattern for each row:
  - `entry->Init(pCityState, w0, w1, w2, w3, w4, w5, w6, modeFlag)`

- Observed row stride: 14 bytes (7 x `short`).

- This matches downstream field usage in `ApplyCityEntryOrderDeltaAndCosts` and `AccumulateCityEntryCostsByAmount`:
  - resource ids/costs and labor-group-style routing fields are table-driven per entry.

### Additional city-entry helper naming

- `0x004B7320` -> `AccumulateCityEntryCostsByAmount`
  - Produces projected resource/labor requirement vector for a requested amount.

## University Dialog Deepening Pass (2026-02-15, later)

### Readability updates applied in Ghidra
- `OpenCityViewProductionDialog @ 0x004CE5A0`
  - Local renames applied for legibility:
    - `pUiControlByTag` -> `pNameControl`
    - `pUiControlMatch` -> `pCostControl`
    - `pDialogObject` -> `pUpgradeControl`
    - `pNameTextControl` -> `nNameTextControlId`
    - `pCapacityTextControl` -> `nCapacityTextControlId`
    - `pCostTextControl` -> `nCostTextControlId`
    - `pfnFindControlByTagHash` -> `pfnFindControlByTag`
    - `pfnFormatProductionValue` -> `pfnFormatValueFromEntry`
    - `pCityStateCtx` -> `pCityStateObject`
  - Prototype refreshed to:
    - `void OpenCityViewProductionDialog(int nBuildingSlotId, void* pCityState, int nDialogFlags)` (`__thiscall`)
  - Plate comment expanded with explicit Algorithm/Parameters/Returns/Special Cases.

### University UI construction and icon wiring (confirmed)
- `BuildUniversityDialogControls @ 0x00474AC5`
  - Builds the base 9900-series university view layout.
  - Includes background and major tagged controls (`clu*`, `civ*`, `num*`, `numb`, `papa`, `pacp`, `desc`, `titl`, `fix*`, etc.).

- `BuildUniversityRecruitmentRows @ 0x00475F84`
  - Creates repeatable recruitment rows and numeric controls.
  - Confirmed row icon mapping in code comments and control creation flow:
    - Miner row icon family uses 9920-series.
    - Prospector row icon family uses 9922-series.
    - Farmer row icon family uses 9924-series.
  - This matches user-provided asset mapping and validates the recruitment row builder anchor.

### University refresh/selection path (confirmed)
- `RefreshUniversityRecruitmentDialog @ 0x004CACE0`
  - Populates base recruitment rows (`clu0..clu8`), including current queued counts.
- `SelectUniversityRecruitmentEntry @ 0x004CB320`
  - Moves selected entry pointer and updates title/description/requirement pips.
- `RefreshUniversityRecruitmentRequirements @ 0x004CBB20`
  - Updates paper/area requirement visuals and availability cap indicators.
- `RefreshUniversityAdvancedRecruitmentDialog @ 0x004CEE20`
  - Refreshes advanced numeric rows (`num0..num7`) and availability rows (`ava*`).
- `RefreshUniversitySpecialistAvailability @ 0x004CF5C0`
  - Computes per-entry trainable cap and updates availability widgets.

### University vtable/thunk map (important)
A dedicated university-oriented vtable cluster is present at `0x00652CC0`.
Observed entries include thunks for:
- `ThunkRefreshUniversityAdvancedRecruitmentDialog @ 0x00401F46`
- `ThunkRefreshUniversitySpecialistAvailability @ 0x00402789`
- `ThunkSetUniversityDialogLocalizedTextAndRefresh @ 0x00402A22`
- `ThunkSetUniversityDialogTextAndRefresh @ 0x00402DD3`
- `ThunkSelectUniversityAdvancedEntry @ 0x00404F2F`
- `ThunkUpdateUniversityDialogSelectionState @ 0x00405A8D`

This confirms that university refresh/selection is handled through a dedicated virtual interface path rather than the simple building-production dialog path alone.

### What is still unresolved (next concrete target)
- The final OK/commit callback for university recruitment (the exact point where edited `num*` values are persisted and where resource deductions are finalized) remains indirect through virtual/control callbacks.
- Next pass should focus on command dispatch around:
  - control tag routing for `okay`/`cncl`
  - callback targets associated with `num*`/`numb` controls
  - virtual methods in the `0x00652CC0` table not yet semantically named.

### Numeric control class lead for university order commit
- University `num*`/`numb` controls are instantiated through `thunk_FUN_00429500` (constructor-like wrapper).
- That class installs vtable `PTR_ThunkNumericEntryMethod_00406d0c_0063E8B0`.
- Key recovered methods in this class path:
  - `ThunkNumericEntryMethod_00407A7C -> FUN_004912B0` (alloc/init clone path)
  - `ThunkNumericEntryMethod_00407CCA -> FUN_00490AD0` (teardown/release path)
  - `ThunkNumericEntryMethod_0040465B` (focus/context guard)
  - `thunk_FUN_0048E710` handles key actions `0x1F/0x20/0x21` and dispatches to vfunc `+0x1C0`.
  - `thunk_FUN_00490C30 -> FUN_00490C30` dispatches via vfunc `+0x1D8`.

Interpretation:
- University recruitment amount edits are likely applied through numeric-control virtual handlers (`+0x1C0`/`+0x1D8`) rather than only on the final dialog OK action.
- Next concrete task: identify concrete overrides for those virtual slots in the university dialog object and trace where they call city-entry order mutators (expected linkage to entry vfunc `+0x2C` behavior).

## Recruitment Writeback Cluster Identified (2026-02-15, continuation)

### Core discovery
The key recruitment persistence path is now identified in a city-entry order cluster near `0x004B7000`:

- `CommitCityRecruitmentOrderDelta @ 0x004B73B0`
- `ComputeMaxRecruitableDeltaForCityEntry @ 0x004B7080`
- `ApplyRecruitmentSliderDeltaAndRebalancePools @ 0x004B5990`
- `ComputeRecruitmentCapFromPools @ 0x004B58F0`
- `InitializeCityRecruitmentOrderContext @ 0x004B6FE0`

### What this means for “how orders are remembered”
- Recruitment edits are staged in context fields (not directly final each click).
- Slider changes adjust staging pools through `ApplyRecruitmentSliderDeltaAndRebalancePools`.
- Final persistence happens in `CommitCityRecruitmentOrderDelta`, which:
  - consumes pending delta,
  - writes queue/order effects into city/state structures,
  - creates per-unit/per-specialist order objects,
  - calls nation callback (`+0x2C0`) with mode/entry id/amount,
  - clears pending delta afterward.

### What this means for resource deduction timing
- Deduction/availability impact is computed and staged during slider adjustments (`ApplyRecruitmentSliderDeltaAndRebalancePools`, cap functions).
- The definitive commit pass is `CommitCityRecruitmentOrderDelta`.
- This is currently the strongest anchor for “where resources for creating civilians are deducted/confirmed”.

### Ghidra naming updates performed
- `FUN_004B73B0 -> CommitCityRecruitmentOrderDelta`
- `FUN_004B7080 -> ComputeMaxRecruitableDeltaForCityEntry`
- `FUN_004B5990 -> ApplyRecruitmentSliderDeltaAndRebalancePools`
- `FUN_004B58F0 -> ComputeRecruitmentCapFromPools`
- `FUN_004B6FE0 -> InitializeCityRecruitmentOrderContext`
- `FUN_004B4F70 -> InitializeBasicCityOrderContext`
- Related thunk names updated for readability.

### User-confirmed university interaction model (important correction)
- University dialog has no explicit OK/Cancel buttons.
- Recruitment edits are live-applied through row interactions (`+/-` / slider-style controls).
- Therefore, the `ApplyRecruitmentSliderDeltaAndRebalancePools` -> `CommitCityRecruitmentOrderDelta` path should be treated as immediate writeback path for university recruitment, not deferred by a separate dialog confirmation step.

## Deferred City Command Execution Cluster (2026-02-15, rollover pass)

### New core function recovered
- `ExecuteDeferredCityOrderCommand @ 0x005ADDE0` (renamed from `FUN_005adde0`)
  - Executes one queued city order command at turn processing time.
  - Applies as much delta as possible to city entry/storage.
  - If remaining delta still cannot be satisfied, dispatches follow-up handlers by slot-id class through vtable methods.
  - Returns completion status (done vs still pending/retry).

### Command vtable method map (`0x0066A9A8` family)
Recovered virtual entries used by this command object family:
- `+0x2C -> QueueCityOrderType10CommandIfReady @ 0x005AE010`
- `+0x30 -> ApplyProductionDistributionToCitySlots @ 0x005AE420`
- `+0x34 -> QueueCityRecruitmentSupportCommandsIfDeficit @ 0x005AE0E0`
- `+0x38 -> QueueCityOrderInputDeltaCommands @ 0x005AE240`
- `+0x3C -> QueueCityProductionOrderCommand @ 0x005AE4B0`

Thunks were created/renamed for all of the above to keep call graphs legible.

### Recruitment-relevant slot classification discovered
Inside `ExecuteDeferredCityOrderCommand`, slot-id ranges control which follow-up path is used when direct apply is insufficient.

Most important for university civilians:
- Slot range `0x35..0x3B` and slot `0x33` dispatch to `+0x34`
  (`QueueCityRecruitmentSupportCommandsIfDeficit`).

Interpretation:
- This strongly suggests civilian recruitment orders are in the `0x33/0x35..0x3B` slot class.
- Recruitment deficits are reconciled by queueing compensating commands (types `9` and `0x0B`) based on city pools (offsets `+0xC8` and `+0xCC` in the city context).

### Persistence model refinement (university + rollover)
- University UI edits stage/commit recruitment deltas in the `0x004B7000` writeback cluster.
- Deferred command objects then run in turn processing via `ExecuteDeferredCityOrderCommand`.
- This bridges UI intent to actual turn execution and is currently the strongest path toward pinpointing “new civilian appears at turn rollover”.

### Still pending
- The exact function that instantiates the new civilian unit object after successful recruitment command execution is still unresolved.
- Next pass target: follow queue processing after `ExecuteDeferredCityOrderCommand` completion into unit creation/spawn function(s).

## Recruit Object Creation + Civ Work Execution Bridge (2026-02-15, deeper pass)

### New bridge identified
- `RegisterUnitOrderWithOwnerManager @ 0x005C2530` is a key constructor helper in the recruit path.
  - Called from both civilian and military recruit object initializers.
  - Resolves owner manager pointer and inserts object via manager vfunc `+0x30`.
  - Initializes owner index fields and unique id.

Interpretation:
- Recruit commit does not only mutate city counters; it also creates unit-order objects and registers them into owner managers.
- This is the strongest concrete bridge from city recruitment commit to map/unit runtime structures.

### Civ object runtime lifecycle confirmed
Recovered civ-order methods (renamed):
- `InitializeCivUnitOrderObject` (`0x005C28C0`)
- `SetCivWorkOrderTypeAndDuration` (`0x005C29F0`)
- `AdvanceCivWorkOrderAndApplyCompletion` (`0x005C2A90`)
- `RelinkCivUnitByTileIndex` (`0x005C2B70`)
- `ApplyCompletedCivWorkOrderToMapState` (`0x004D4390`)

What this proves:
- Civ work orders are timed (`+0x24` turns remaining), processed each update tick, and on completion apply map-side effects then reset to idle.
- Tile occupancy is explicit linked-list state via tile field `+0x20`.

### Military branch also present
Recovered military-order constructors/serializers:
- `InitializeMilitaryUnitOrderObject` (`0x005C2DF0`)
- `InitializeMilitaryRecruitOrderState` (`0x005C2F50`)
- `SerializeMilitaryUnitOrderState` / `DeserializeMilitaryUnitOrderState`

This matches the two-branch behavior in `CommitCityRecruitmentOrderDelta`:
- civilian-like object branch (`+0x58 == 0`)
- military-like object branch (`+0x58 != 0`)

### Remaining uncertainty
- We still need the exact manager-side update function that calls `RelinkCivUnitByTileIndex` for freshly recruited civilians (the precise “appears on map at turn rollover” handoff).

## Map Click -> Civilian Work Order Bridge (2026-02-15, continuation)

### New renames this pass

- `InitializeCivWorkOrderState @ 0x005C2940`
- `TickCivWorkOrderCountdownAndComplete @ 0x005C29B0`

Both are now plate-commented in Ghidra and fill previously unnamed gaps in the civ order lifecycle.

### Click path confirmation (productive-order issue)

- `HandleMapClickByInteractionMode @ 0x005964B0` mode split:
  - mode `0`: civilian selection handling
  - mode `1`: province selection handling
  - mode `2`: queue path (`TryQueueMapOrderFromTileAction`)
  - mode `3`: context-only handling
- In mode `2`, successful queueing runs `ThunkCycleMapInteractionSelectionAfterHandledClick`.

This matches the observed gameplay behavior that issuing a productive order updates state immediately on click.

### Civ unit-order virtual interface map

`InitializeCivUnitOrderObject` writes vtable pointer `PTR_GetCivUnitOrderTypeName_0066EE60`.
Selected confirmed slots:

- `0x0066EE60` -> `GetCivUnitOrderTypeName`
- `0x0066EE64` -> `DestroyCivUnitOrderObject`
- `0x0066EE74` -> `SerializeCivUnitOrderState`
- `0x0066EE78` -> `DeserializeCivUnitOrderState`
- `0x0066EE88` -> `RelinkCivUnitByTileIndex`
- `0x0066EE8C` -> `AdvanceCivWorkOrderAndApplyCompletion`
- `0x0066EE90` -> `ClearCivUnitTileLink`
- `0x0066EE94` -> `SetCivWorkOrderTypeAndDuration`
- `0x0066EE98` -> `ResetCivWorkOrderAndRefreshCounters`

### Civ work countdown and completion (reconfirmed)

- `TickCivWorkOrderCountdownAndComplete` decrements remaining turns at `+0x24`.
- On completion:
  - calls `ApplyCompletedCivWorkOrderToMapState`
  - resets order type/state to idle (`this+0x08 = 0`).

This aligns with user-confirmed semantics:
- productive tasks stay in working/animated state until complete,
- then return to normal and require new orders.

### Remaining gap

- Exact owner-manager rollover function that initially relinks freshly recruited civilians to a tile (`RelinkCivUnitByTileIndex` caller chain) is still not directly recovered due virtual indirection.

## Turn Rollover State-Machine Anchor (2026-02-15, continuation)

### Legibility update in city dialog

`OpenCityViewProductionDialog @ 0x004CE5A0`
- Prototype normalized to:
  - `void __thiscall OpenCityViewProductionDialog(int nBuildingSlotId, int* pCityStateData, int nDialogFlags)`
- Decompilation refreshed; slot/city-state parameter semantics are now cleaner.

### New rollover anchor in game flow

`GameFlow::HandleStateTransition @ 0x0057DA70`
- Added plate comment documenting phase behavior.
- Most important state for civilian rollover tracking:
  - state `0x15` iterates active nations and invokes nation virtual methods in sequence:
    - `+0x2B8`
    - `+0x108`

Interpretation:
- Nation vfunc `+0x108` is now the strongest current candidate for the per-turn queue/application pass that may perform civilian order advancement/relink (including freshly recruited civilian appearance at rollover).

Supporting helper renamed:
- `IsNationProfileInMinorRange100To199 @ 0x0057F0E0`
  - used to gate minor-nation profile branches in turn-state logic.

## Rollover Manual Narrowing Pass (2026-02-15)

### Legibility upgrades in state 0x15 dependencies

Renamed:
- `RecomputeTileStrategicScoreHeatmap @ 0x00518130`
- `RecomputeNationOrderPriorityMetrics @ 0x0053FE30`
- `RelinkTileUnitsToCountryOrderManager @ 0x004E6520`
- `ShowCountryOrderTransferNotification @ 0x004E6740`
- `ReassignUnitOrdersForCountryTargetChange @ 0x004E6150`
- `IsNationProfileInMinorRange100To199 @ 0x0057F0E0`

### Refined interpretation of turn rollover sequence

In `GameFlow::HandleStateTransition`, state `0x15` now reads clearly as:
1. strategic tile score recomputation
2. nation priority metric recomputation
3. nation vfunc `+0x2B8` pass
4. nation vfunc `+0x108` pass

This strengthens the working model that nation vfunc `+0x108` is where end-of-turn queued effects are committed, and remains the primary unresolved hook for civilian recruitment-to-map appearance.

### Tooling note

Automated slot scanning via Ghidra scripts is currently blocked in this session:
- Java script provider fails with OSGi bundle cast exception.
- Python script provider unavailable (PyGhidra not enabled).

So the current path is manual vtable/constructor recovery.

## University/City Deferred Command Pipeline (2026-02-15, latest)

### Core persistence is confirmed in city-state serialization

- `DeserializeCityProductionState @ 0x004B30A0`
  - Restores city production/recruitment state from archive stream.
  - Restores per-city entry table at `cityState + 0xE4` (iterates `0x3D` entries).
  - Restores queue container state at `cityState + 0x270` and enqueues reconstructed command objects.
- `SerializeCityProductionState @ 0x004B35D0`
  - Saves the same state, including `+0xE4` entry objects and queue container.

Interpretation:
- Recruitment/production intent is persisted as city entry + queue state, not transient UI-only values.

### Command vtable mapping (confirmed)

`PTR_thunk_FUN_005add00_0066A9A8` entries:
- `+0x28` -> `ThunkExecuteDeferredCityOrderCommand`
- `+0x2C` -> `ThunkQueueCityOrderType10CommandIfReady`
- `+0x30` -> `ThunkApplyProductionDistributionToCitySlots`
- `+0x34` -> `ThunkQueueCityRecruitmentSupportCommandsIfDeficit`
- `+0x38` -> `ThunkQueueCityOrderInputDeltaCommands`
- `+0x3C` -> `ThunkQueueCityProductionOrderCommand`

This is the key deferred city-order state machine used by production/recruitment.

### Where queued orders are actually applied

- `ExecuteDeferredCityOrderCommand`
  - Executes one queued city order step and routes follow-up behavior by slot-id class.
  - Calls queue-helper vfuncs (`+0x2C/+0x30/+0x34/+0x38/+0x3C`) depending on slot range.
- `ApplyProductionDistributionToCitySlots`
  - Builds a 23-slot delta distribution from selected entry context.
  - Applies non-zero deltas through city/order manager virtual calls.

Interpretation:
- This is the turn-processing apply path that commits staged production/recruitment deltas.

### Recruitment support/resource deficit path

- `QueueCityRecruitmentSupportCommandsIfDeficit`
  - Compares requested recruitment delta against city pools (`+0xC8`, `+0xCC`).
  - Queues compensating commands of types `9` and `0x0B` when deficits exist.
- `QueueCityOrderInputDeltaCommands`
  - Computes required input deltas from entry requirement metadata (`entry +0x4E/+0x50/+0x52`).
  - Queues additional slot commands when required inputs are missing.

Interpretation:
- Resource/workforce costs for recruitment are not just UI checks; they are enforced through deferred queue support commands in the city-order engine.

### University bridge

- University selection/refresh path uses city-entry fields in the same family (`+0x4C/+0x4E/+0x50/+0x52/+0x54/+0x56`).
- Therefore university recruitment orders are integrated into the same deferred city production command pipeline.

### Small legibility renames done in this pass

- `0x00415FE0` -> `BuildUniversitySpecialistRecruitmentControls`
- `0x0048A2E0` -> `DispatchUiCommandToHandler`
- `0x0048A3F0` -> `DispatchUiSelectionToHandler`
- `0x0048A6D0` -> `DispatchUiCommand19ToParent`
- `0x0048A3B0` -> `DispatchQueuedUiCommandAndRelease`
- `0x004906F0` -> `SetNumericEntryCheckedState`
- `0x005ADD00` -> `GetCityTaskClassName`
- `0x005AE680` -> `GetShipBuildingTaskClassName`

### Tooling correction

- Python Ghidra scripts are currently working in this session and are now used for batch discovery/mapping.
- Java inline scripts remain flaky due dynamic class-name handling in the inline runner.

## University Recruit Tag-to-Icon Mapping (code-confirmed)

Recovered from `BuildUniversityRecruitmentRows @ 0x00475F84` disassembly:

- `civ0` -> icon `9920` (miner)
- `civ1` -> icon `9922` (prospector)
- `civ2` -> icon `9924` (farmer)
- `civ3` -> icon `9926` (forester)
- `civ4` -> icon `9928` (engineer)
- `civ5` -> icon `9930` (rancher)
- `civ8` -> icon `9936` (driller)

Interpretation (with gameplay confirmation):
- Baseline rows: miner/prospector/farmer/engineer.
- Tech-gated rows: forester/rancher/driller.

## Deferred City Task Vtable (hard-confirmed)

`PTR_thunk_FUN_005add00_0066A9A8`:
- `+0x28` `ExecuteDeferredCityOrderCommand`
- `+0x2C` `QueueCityOrderType10CommandIfReady`
- `+0x30` `ApplyProductionDistributionToCitySlots`
- `+0x34` `QueueCityRecruitmentSupportCommandsIfDeficit`
- `+0x38` `QueueCityOrderInputDeltaCommands`
- `+0x3C` `QueueCityProductionOrderCommand`

This is now the principal turn-rollover execution chain for city production/recruitment order commitment and cost enforcement.

## City/University Capability-State Object (newly resolved)

### Global object identity

- Global `DAT_006A43D8` renamed to `g_pCityOrderCapabilityState`.
- This is **not** a flat static table; it is an allocated runtime object with internal arrays.

### Constructor/init chain

- `RebuildGlobalOrderManagersAndCapabilityState @ 0x0057C3B0`
  - allocates capability object (`0x63C` bytes)
  - calls:
    - `ConstructCityOrderCapabilityStateVtable @ 0x005AEF80`
    - `InitializeCityOrderCapabilityStateDefaults @ 0x005AEFF0`
- `InitializeCityOrderCapabilityStateDefaults` initializes multiple era/slot matrices, including blocks rooted near offsets `+0x467`, `+0x338`, `+0x395`.

### Why this matters for university unlocks

- `RefreshUniversityRecruitmentDialog` reads from `g_pCityOrderCapabilityState` using current nation profile index (`thunk_FUN_00581260` -> field `+0x2E`) and `clu*` tag-derived offsets.
- This confirms university row availability is data-driven from the capability-state object, not hardcoded by `if (civ3/civ5/civ8)` branches.

### Practical interpretation

- Baseline vs tech-gated recruit rows are controlled by this runtime capability matrix.
- Forester/Rancher/Driller gating should be decoded by further tracing writes/updates into this object (especially in nation-tech update paths), not by searching only university UI tag constants.

## Nation Slot Rebuild Path Clarification (2026-02-15)

### Key correction
- The function previously named around city-order capability refresh is actually a **GameFlow method** dispatching nation-slot rebuild handlers.
- The call site in `GameFlow::HandleStateTransition` sets `ECX=EBX` before calling thunk `0x00404BBA`, proving the receiver is game-flow state, not `g_pCityOrderCapabilityState`.

### Resolved function mapping
- `0x00404BBA` -> `Thunk_RebuildNationStateSlotsAndAvailability`
- `0x0057CAD0` -> `RebuildNationStateSlotsAndAvailability`
- `0x0057CDA0` -> `RebuildPrimaryNationStateForSlot`
- `0x0057D520` -> `RebuildSecondaryNationStateForSlot`

### Vtable offset note (important)
- Constructor (`thunk_FUN_0057b9e0`) writes vtable pointer `PTR_LAB_00662A58` (not `0x00662A60`).
- Therefore dispatch slots are shifted relative to earlier assumption:
  - `+0x2C` -> thunk `0x0040457A` -> `0x0057CDA0`
  - `+0x30` -> thunk `0x00408189` -> `0x0057D520`

### Practical meaning
- This path rebuilds `g_apNationStates`, `DAT_006A4280`, and `DAT_006A4310` slot tables during game-flow transitions.
- It is foundational for nation/minor-slot object availability and downstream order/UI logic, but is distinct from the dedicated city capability object (`g_pCityOrderCapabilityState`).

## Map Civilian Order Click Pipeline (2026-02-15)

### Confirmed dispatcher path
- `HandleMapClickByInteractionMode`
  - Mode 2 path calls `ThunkTryQueueMapOrderFromTileAction` (`0x004012EE` -> `0x0055A160`).
- `TryQueueMapOrderFromTileAction`
  - Resolves tile context (`GetMapActionContextByTileIndex` or `GetProvinceByTileIndex`).
  - Chooses command id (`0x0A`, `0x0C`, `0x0D`, `0x0E`, `0x0F`, `0x10` observed).
  - Mutates active map-order entry type/target, rebuilds children, queues at head.
  - Commits via `ThunkFinalizeQueuedMapOrderEntry`.

### Finalization behavior
- `ThunkFinalizeQueuedMapOrderEntry` (`0x00407833`) runs after queue commit.
- It checks nation/entry compatibility, then calls virtual method at `entry->vtable + 0x58` with a boolean indicating whether another matching pending order exists.
- This is the strongest current candidate for immediate post-click icon/state refresh (selected/working/no-order visual transition path).

### UI button IDs confirmed in command panel builder
- In `BuildMainMapAndCityCommandControls` constants used for map/city command button images include:
  - `1199` (Next Unit)
  - `1203` (No Orders This Turn)
  - `1209` (Disband Civilian)
  - `1211` (Sleep)
- These match gameplay observations and are now code-confirmed.

## Map Context Action Code Decoder (2026-02-16)

### Source
- `Thunk_ResolveMapTileContextActionCode` (thunk entry `0x00407EE1`).
- Reads per-tile action byte at `(tileBase + 0x16)` from map data stride `0x24`.

### Decoder mapping (code-confirmed)
- Tile action byte `2/4/5/6` -> return action code `0x0B`.
- Tile action byte `7..13` -> return action code `(tileByte - 5)` => `0x02..0x08`.
- Tile action byte `14..21` -> return `0x0A` if tile action context equals currently active entry context; else `0x09`.
- Otherwise -> return `0` (no context action).

### Consumer behavior
- `TryHandleMapContextAction` dispatches the above action codes:
  - `0x02..0x08`: `OpenMapContextActionDialogByType` with `(code-2)` selector.
  - `0x09`: bind selected tile context as active map-order entry target.
  - `0x0A`: execute active map-order entry immediate callback.
  - `0x0B`: open map-entry order dialog for context-bound entry.

## TryQueueMapOrderFromTileAction Command IDs (2026-02-16)

### Source
- `TryQueueMapOrderFromTileAction` at `0x0055A160`.

### Observed command IDs and mutations
- `0x0A`: execute active-entry callback (`manager +0xF0`).
- `0x0C`: set order type `3`.
- `0x0D`: set order type `1`, target=`GetMapActionContextByTileIndex(tile)`.
- `0x0E`: set order type `6`, target=`GetMapActionContextByTileIndex(tile)`.
- `0x0F`: set order type `1`, special queue-head insertion branch.
- `0x10`: set order type `5`, target=`GetProvinceByTileIndex(tile)`.

### Commit path
- `ThunkMoveMapOrderEntryToQueueHeadIfValid`
- `ThunkFinalizeQueuedMapOrderEntry`

This path remains the strongest code anchor for click-issued civilian productive order queuing.

## Action-Context Command Resolution (2026-02-16)

### Source
- `Thunk_ResolveOrderCommandFromActionContext`
- `Thunk_ResolveOrderCommandFromProvinceContext`

### Action-context decision tree (code-confirmed)
Inputs:
- active map-order entry (`param_1`),
- candidate action context (`param_2`).

Branches:
- If candidate is null or equals active context (`param_1+0x18`):
  - returns `0x01` when virtual `+0x38` is true.
  - otherwise returns `0x0C`.
- If candidate differs:
  - if virtual `+0x38` is false and virtual `+0x34` is true -> returns `0x0F`.
  - if virtual `+0x38` is true and virtual `+0x40(nation)` is true -> returns `0x0D`.
  - if virtual `+0x44(nation)` is true and first child target equals active context -> returns `0x0E`.
  - fallback -> returns `0x01`.

### Province-context resolver
- `Thunk_ResolveOrderCommandFromProvinceContext` returns `0x10` when manager check `(*DAT_006A43D0 + 0x48)` succeeds, else `0x01`.

### Interpretation status
- Command IDs and branch conditions are code-confirmed.
- Exact gameplay names for `0x0D/0x0E/0x0F/0x10` remain semantic-inference candidates pending direct behavior correlation.

## User-Confirmed Map/Civilian Behavior Notes (2026-02-16)

Source: direct gameplay validation by user.

### Productive vs non-productive click behavior
- Prospector on valid mountain: starts working immediately (animated state).
- Prospector on desert:
  - without relevant oil tech: simple move only.
  - with oil tech: starts prospecting, unless tile was already prospected.
- Farmer on already max-improved farm: simple move only.
- Miner on plain: simple move with no-work/disabled/grey sprite.
- Civilians cannot be moved to irrelevant tiles (tile not clickable for that action context).

### Engineer behavior
- Clicking engineer's current tile always opens "Construction Options" dialog, even when nothing is buildable.
- Clicking neighboring valid build tile starts work animation immediately (rail build flow).

### Existing-order interaction
- Clicking a civilian that already has orders opens "Civilian Report" dialog.
- Dialog contains text like:
  - "<civilian> in the province of <province>"
  - "<Building iron mine/Improving local farms/...>"
  - "Time to completion: <...>"
- Buttons:
  - "Rescind Orders" (clicked bitmap 3013)
  - "Confirm Orders" (clicked bitmap 3014)
- Dialog background bitmap: 3012.
- Clicking "Rescind Orders": refunds money and unit returns to awaiting-orders state.

### Cancel behavior
- In engineer Construction Options, clicking Cancel gives no order (no state change in orders).

## STR#ENU Anchors for Map/Civilian UI (2026-02-16)

Using decoded stringtable IDs from `STR#ENU.GOB` (`strenu-strings.tsv`):
- `64662`: `Construction Options`
- `18988`: `Civilian Report`
- `18989`: `Rescind Orders`
- `18990`: `Confirm Orders`
- `18986`: `Time to completion: [1:number] months`

These are strong anchors for identifying engineer click dialogs and existing-order civilian report flows in code.

## 2026-02-16: Tech Experiment Pointer
- Detailed notes: `tech-experiment-university-unlocks.md`
- Summary: `tabsenu.gob` `.SCN` files contain machine-readable `tech` records (`"tech" + nationIndex + techId`, big-endian uint32 values).
- Relevance: likely scenario-start tech grants that feed unit/building availability checks in UI (including university unit unlock gates).
