# Agent 1 Working Log

## Mission
Make Imperialism decompilation legible in Ghidra, with emphasis on map/civilian order logic and concrete output (renames/prototypes/comments), not open-ended analysis.

## Anti-Loop Rules (Mandatory)
- Rename-first cycle: each cycle must rename/prototype/comment real functions before deeper tracing.
- Rabbit-hole timeout: max 20 minutes on uncertain branch, then park it and move to next actionable function.
- Output quota: report only concrete counts (`N` functions renamed this cycle).
- Scope lock: prioritize map/civilian order flow unless a dependency is directly required.
- If blocked by uncertainty, use provisional descriptive names and document assumptions in plate comments.

## Current Focus
- Civilian map click -> action code -> queue order -> rollover -> completion.
- Tech-gated productive-vs-move behavior (prospector/farmer/engineer).
- University only when directly needed for capability-flag mapping.

## Immediate TODO
- [x] Rename/prototype/comment `0x00513ed0` -> `CheckTileProspectingDiscoveryCandidate`.
- [x] Rename/prototype/comment `0x0054ab20` -> `DispatchTileRedrawInvalidateEvent`.
- [x] Rename/prototype/comment `0x0054abf0` -> `DispatchCityRedrawInvalidateEvent`.
- [x] Rename/prototype/comment `0x004ee8c0` -> `RebuildCivilianOrderCompatibilityMatrices`.
- [x] Rename/prototype/comment `0x005af330` -> `GenerateRandomCapabilityPrioritySlots`.
- [x] Continue map/civilian order chain from `OpenCityViewProductionDialog` callers/callees; rename/document two+ functions per cycle.
- [x] Confirm civilian map command tags in handler (`done`,`dfnd`,`latr`,`garr`) and ctrl+disband ledger branch.
- [x] Confirm where civilian work order state is stored and advanced on rollover.
- [x] Continue map/civilian order chain: `ResolveCivilianTileOrderActionCode` -> `HandleCivilianTileOrderAction` -> queue/move/report branches.
- [x] Confirm civilian immediate command mapping from panel tags to order codes (`done`/`dfnd`/`latr`/`garr` -> 4/2/3/disband-or-ledger).
- [x] Confirm rollover behavior source function for sleep/next-unit/no-orders clearing.
- [x] Confirm rescind refund sources and fixed costs for depot/port/fort/rail/resource orders.
- [ ] Continue next branch pass: engineer-specific handlers (`HandleEngineerConstructionAction`, `PromptAndQueueEngineerRailOrder`) and map interaction callbacks.
- [ ] Confirm where university recruitment orders are persisted at turn rollover and where input resources are deducted.
- [ ] Define a concrete struct type for civilian order state and apply it to key functions to remove `void*` params.
- [ ] Clean up `HandleCivilianReportDecision` local-variable SSA noise (stack/register aliasing around `this`).
- [ ] Continue from civilian map orders into map-side order execution (`ApplyMapOrderTypeExecutionEffects`, `ApplyMapOrderTypeAndQueue`) to connect UI actions to simulation.
- [ ] Append progress line after every batch using format below.
- [ ] Save program after each rename batch.

## Critical Findings (Civilian Orders)
- Civilian order state fields (confirmed from `SetCivWorkOrderTypeTargetTileAndDuration` and rollover path):
  - `+0x08`: order type code
  - `+0x0C`: target tile index
  - `+0x24`: remaining turns
  - `+0x26`: queued/completion message marker token
- Immediate command path (`QueueImmediateCivilianCommandAndCycleSelection`):
  - dispatches order code via selected order vfunc `+0x34`
  - cycles selection immediately when map interaction context exists
- Command-panel tags (`HandleCivilianMapCommandPanelAction`):
  - `'done'` -> immediate command type `4` (`No orders this turn`)
  - `'dfnd'` -> immediate command type `2` (`Sleep`)
  - `'latr'` -> immediate command type `3` (`Next Unit`)
  - `'garr'` -> Disband flow; `Ctrl+click` opens civilian ledger instead
- Costed productive queue path (`QueueCivilianWorkOrderWithCostCheck`):
  - affordability check uses `g_adwCivilianWorkOrderCostByClass`
  - cash deducted immediately via nation callback `+0x38` on success
- Turn rollover (`AdvanceCivWorkOrderAndApplyCompletion`):
  - sleep (type `2`) persists
  - productive orders decrement `+0x24`, then call completion apply when <=0
  - immediate markers (e.g., no-orders/next-unit) are cleared to idle type `0`
- Action code dispatcher mapping (confirmed in `HandleCivilianTileOrderAction`):
  - `2`: select clicked civilian
  - `3`: queue move/no-work
  - `4..7`: engineer construction/rail branches
  - `8`: immediate order type 8
  - `9`: queue costed work order
  - `10`: open Civilian Report
  - `11`: prompt engineer rail order
- Civilian report rescind (`HandleCivilianReportDecision`):
  - refunds are immediate and order-type specific (rail/depot/port/resource/fort variants)
  - order state is reset and tile linkage is removed, then UI selection/command panel is refreshed
- Explicit rescind refund mapping (`HandleCivilianReportDecision`):
  - type `5`: rail section (terrain table + connected-tile delta helper)
  - type `6`: depot refund `$2000`
  - type `7`: port refund `$3000`
  - type `10`: civilian work order by cost class table
  - type `12`: fort refund by fort-level table
  - type `13`: engineer rail refund via `ThunkCalculateEngineerRailBuildCost`
- Idle/report gate (`IsCivilianOrderInIdleSelectionState`):
  - idle-selection states are order types `0`, `2` (Sleep), and `3` (Next Unit marker)
  - all other active/productive types route to Civilian Report path on click
- Stack panel refresh behavior (`RefreshCivilianStackButtonsForTile`):
  - stack controls are `stk0..stk5`
  - selected-backdrop tag is slot tag, else `'nada'`
  - command buttons enabled/disabled from selection state:
    - `'dfnd'` (Sleep)
    - `'latr'` (Next Unit)
    - `'done'` (No orders this turn)
- Civilian ledger path (`ShowCivilianLedgerDialogAndSelectUnit`):
  - opened from CTRL+Disband or hotkey `'t'`
  - uses dialog resource `0x0DAC`
  - selected ledger row re-focuses map tile and selected civilian

## Critical Findings (University)
- `BuildUniversityRecruitmentRows` confirms row tags and icon IDs for university recruit entries:
  - `civ0` -> miner (`9920`)
  - `civ1` -> prospector (`9922`)
  - `civ2` -> farmer (`9924`)
  - `civ3` -> forester (`9926`)
  - `civ4` -> engineer (`9928`)
  - `civ5` -> rancher (`9930`)
  - `civ8` -> driller (`9936`)
- Selection/update path for recruit rows remains `SelectUniversityRecruitmentEntry` with requirement-pip updates (`fix2/fix3/fix4`) from capability state.

## Critical Findings (Trade School)
- Trade School UI builder path identified from dialog-factory registration chain:
  - `InitializeTurnEventDialogFactoryRegistry` pushes `0x00401401`
  - `0x00401401` thunk calls `0x00415fe0`
- Renames applied:
  - `0x00401401` -> `ThunkBuildTradeSchoolDialogControls`
  - `0x00415fe0` -> `BuildTradeSchoolDialogControls`
- Prototype updates applied:
  - `int * __fastcall ThunkBuildTradeSchoolDialogControls(dword dwPanelId, short nDialogTypeTag)`
  - `int * __fastcall BuildTradeSchoolDialogControls(dword dwPanelId, short nDialogTypeTag)`
- Evidence notes:
  - this path is registry-backed and not the generic `OpenCityViewProductionDialog` flow
  - large control-construction body at `0x00415fe0` indicates dedicated dialog UI build path

## Prototype Pitfall (Do Not Repeat)
- For `__thiscall` in this codebase, do **not** add an explicit object pointer parameter in `set_function_prototype`.
- Correct form example:
  - `void QueueImmediateCivilianCommandAndCycleSelection(int nCommandType)`
- Wrong form (causes duplicate synthetic parameters and decompiler confusion):
  - `void QueueImmediateCivilianCommandAndCycleSelection(void *pState, int nCommandType)`

## Gameplay Facts to Remember (from user)
- Single civilian selection; selected sprite blinks.
- Queueing an order changes icon immediately and persists until turn rollover.
- Sleep persists across turns; “No orders this turn” auto-clears at rollover.
- Productive orders switch unit to working animation immediately and remain until task completion.
- If a productive order is not valid, unit moves and remains non-productive (normal/grey/no-work look).
- Prospector on desert:
  - without oil tech: move only
  - with oil tech: prospect (unless already prospected)
- Engineer:
  - clicking own tile always opens Construction Options
  - neighboring valid tile can queue rail build
  - construction dialog always includes Cancel
- Civilian report dialog supports Confirm/Rescind; rescind refunds cost.
- Known panel commands:
  - `Next Unit`
  - `No orders this turn`
  - `Sleep`
- Ctrl+click disband opens civilian ledger (list of civilian units and current tasks).

## Known UI/Bitmap Anchors (quick recall)
- University:
  - background `9900`
  - miner `9920/9921`, prospector `9922`, farmer `9924`, engineer `9928`
  - forester `9926`, rancher `9930`, driller `9936` (tech-gated)
- Production dialogs:
  - backgrounds `9250+`
  - upgrade button `9244`
- Civilian command icons:
  - disband `1209/1210`
  - sleep `1211/1212`
  - next unit `1199`
  - no orders this turn `1203`

## Progress Logging Format
- `YYYY-MM-DD HH:MM` - `Renamed: X` / `Prototyped: Y` / `Commented: Z` / `Saved: yes|no`
- Next queued targets: `addr1, addr2, ...`

## Batch Progress Log
- `2026-02-16 17:18` - `Renamed: 3` / `Prototyped: 3` / `Commented: 3` / `Saved: no`
- Next queued targets: `0x004ee8c0, 0x005af330, (next map/civilian order handlers after these)`
- `2026-02-16 17:33` - `Renamed: 5 funcs + 3 globals + many vars` / `Prototyped: 8` / `Commented: 8` / `Saved: yes (mid-batch)`
- Next queued targets: `0x004d26d0 (HandleCivilianTileOrderAction), 0x004d3070 (HandleCivilianReportDecision), university recruitment persistence chain`
- `2026-02-16 17:33` - `Renamed: vars/comments in civilian map chain` / `Prototyped: fixed __thiscall signatures` / `Commented: +map action/rescind docs` / `Saved: pending final save`
- Next queued targets: `HandleEngineerConstructionAction`, `PromptAndQueueEngineerRailOrder`, university recruitment persistence/deduction path
- `2026-02-16 18:05` - `Renamed: +local vars in report path and type fixes` / `Prototyped: 3 (HandleCivilianReportDecision + GetHexDirection thunk/core)` / `Commented: +5 functions` / `Saved: pending`
- Next queued targets: `0x004d3a60, 0x004d3610, 0x004b6fe0/0x004b7210/0x004b73b0 caller chain, map execution bridge (0x005540b0/0x00556100)`
- `2026-02-16 18:28` - `Renamed: +6 vars (engineer handler cleanup)` / `Prototyped: 0` / `Commented: +4 functions` / `Saved: yes`
- Next queued targets: `Map execution bridge (0x005540b0, 0x00556100), university order-context dispatch chain, civilian-order struct typing pass`
- `2026-02-16 19:xx` - `Renamed: 2 (trade school path)` / `Prototyped: 2` / `Commented: 1 plate` / `Saved: pending`
- Next queued targets: `trace BuildTradeSchoolDialogControls callers->state persistence/deduction, rename adjacent dialog handlers in factory registry`
