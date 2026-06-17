# Ghidra decomp improvement plan

Roadmap for raising the quality of the Ghidra database (and therefore the
decompiled output the porting loop reads). Ordered by value vs. risk. Numbers
come from a survey of the live project (June 2026): 517 recovered class
namespaces, 5282 `__thiscall` / 61 `__cdecl` / 47 `__fastcall` functions, 323
unnamed `FUN_`/`SUB_` functions.

Mechanisms already in place that several of these items reuse:

- `config/recovered_globals.csv` + `config/recovered_fields.csv` — evidence-curated
  typed globals / interior class fields, applied by `apply_mfc_rtti.py` (step 7).
- `config/recovered_data.csv` — misidentified data labels reclassified as structs
  (e.g. string → indexed table).
- `config/dissolve_namespaces.csv` — placeholder pseudo-class namespaces dissolved
  back into Global by `apply_mfc_rtti.py`.
- `config/calling_convention_overrides.csv` — verified `__cdecl`/`__fastcall`
  mislabels corrected to `__thiscall` (or confirmed `__cdecl`).
- The decompiler `this`-argument resolver prototype (measured low yield for fully
  automatic inference, so curated tables are preferred for now).

## Tier 1 — high value, low risk, mechanism exists

### 1a. Type the recovered singleton globals — **done (first pass)**
Recorded in `config/recovered_globals.csv` and applied by `apply_mfc_rtti.py`
(optional `object_size` column seeds a minimal struct when the class namespace
exists but RTTI did not emit one, e.g. `Config` / `UiRuntimeContext`).

| global | typed as |
| --- | --- |
| `g_apNationStates` | `TGreatPower *[7]` |
| `g_apSecondaryNationStateSlots` | `TMinor *[36]` |
| `g_apTerrainTypeDescriptorTable` | `TCountry *[23]` |
| `g_pGameFlowState` | `Config *` |
| `g_pLocalizationTable` | `TSimMgr *` (manual: `TLocalizationRuntime`) |
| `g_pUiRuntimeContext` | `UiRuntimeContext *` |
| `g_pApplicationUiRootController` | `ApplicationUiRootController *` |
| `g_pGlobalUiRootController` | `TApplication *` |
| `g_pNationInteractionStateManager` | `TTradeMgr *` |
| `g_pDiplomacyTurnStateManager` | `TDiplomacyMgr *` |
| `g_pGlobalMapState` | `TMapMgr *` (manual: `TGlobalMapState`) |
| `g_pCityOrderCapabilityState` | `TTechMgr *` |
| `g_pSelectedCivilianOrderState` | `CivilianMapInteractionManager *` |
| `g_pNavyOrderManager` | `TNavyMgr *` |
| `g_pInterNationEventQueueManager` | `TInterNationEventQueueManager *` |
| `g_pSfxPlaybackSystem` | `TSoundPlayer *` |
| `g_pActiveMapOrderContext` | `TOcean *` (manual: `TMapOrderContext`) |
| `g_pMapActionContextListHead` | `TZone *` |
| `g_pNavyPrimaryOrderListHead` | `TShip *` |
| `g_pMapContextActionManager` | `TArmyMgr *` |

**Next:** `g_apMinorNationCapabilityObjects` / `g_apNationAuxRuntimeStateSlots`
(overlap `g_apTerrainTypeDescriptorTable` / `g_apSecondaryNationStateSlots` at
fixed offsets — need overlay labels or accessor typing, not a second array type),
`g_pActiveQuickDrawSurfaceContext`, `g_pCursorControlPanel`, remaining `g_p*`.

### 1b. Grow `recovered_fields.csv` — **in progress**
Rows applied so far:

| class | offset | field |
| --- | --- | --- |
| `TGreatPower` | `0x894` | `city` (`TCity*`) |
| `TBuildingConstructionView` | `0x90` | `pCity` |
| `TIndustryView` | `0x94` | `pCity` |
| `TCityProductionView` | `0x94` | `pCity` |

Keep adding rows for hot structs using unanimous resolver / decompile-store
evidence + offset-fits-object-size gating; never overwrite an already-typed field.

## Tier 2 — bounded cleanup, same family as the dissolve work

### 2a. Triage address-named pseudo-classes — **done**
All ten `T...State_<hexaddr>` namespaces from the original list are in
`config/dissolve_namespaces.csv` and dissolved back to Global.

### 2b. Fix mislabeled calling conventions — **in progress**
`config/calling_convention_overrides.csv` + apply pass. Initial batch: 4
`__cdecl`→`__thiscall` fixes (`SumWeightedNeighborLinkScoreForLinkedNodes`,
`SumNavyOrderPriority*`, `ComputeOrderNodeCompositeEconomicScore`) plus the
earlier 21-entry batch. Re-scan after each apply:

```bash
rg '__cdecl' config/symbols.csv | awk -F'|' '{print $1}' | xargs -I{} just scan-cdecl-thiscall 0x{}
```

Skip CRT imports (`strrev`, `strrchr`) and EH-frame false positives already
listed as confirmed `__cdecl`.

## Tier 3 — bigger levers, more effort

- **Interior field recovery at scale.** Most class structs are still `{vftable}` +
  `field_0x...`. Keep curated/gated.
- **Vtable slots → named virtuals + signatures.** Decompiles still show
  `(*this->vftable[0x3a].slot_0x04)(...)`.
- **Name the 323 `FUN_`/`SUB_` functions.** Extend locality/caller attribution in
  `apply_mfc_rtti.py`.
- **Reclassify misidentified data.** — **started:** `0x006960e0` string →
  `TradeSummarySelectionMap` via `config/recovered_data.csv` (renamed
  `g_kTradeSummarySelectionMap`). More `s_*` / `DAT_*` table labels to triage.

## Validation

Calling-convention and field-type changes directly affect the C++ port, so route
impactful changes through `just build` + reccmp (`just compare` / `just stats`) to
confirm they help (or at least don't regress) the match, not just readability.
