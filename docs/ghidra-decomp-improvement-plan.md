# Ghidra decomp improvement plan

Roadmap for raising the quality of the Ghidra database (and therefore the
decompiled output the porting loop reads). Ordered by value vs. risk. Numbers
come from a survey of the live project (June 2026): 517 recovered class
namespaces, 5282 `__thiscall` / 61 `__cdecl` / 47 `__fastcall` functions, 323
unnamed `FUN_`/`SUB_` functions.

Mechanisms already in place that several of these items reuse:

- `config/recovered_globals.csv` + `config/recovered_fields.csv` — evidence-curated
  typed globals / interior class fields, applied by `apply_mfc_rtti.py` (step 7).
  Globals pass supports optional `rename` column (creates/renames the label at the
  address). `object_size` bootstraps pointer targets with no Ghidra namespace
  (e.g. `TQuickDrawSurfaceContext`).
- `config/recovered_data.csv` — misidentified data labels reclassified as structs
  (e.g. string → indexed table). Field specs accept optional names:
  `0x28:dword[6]:summaryTags`.
- `config/vtable_slot_method_overrides.csv` — evidence-curated exceptions for
  `ensure_vtbl_struct` slot naming/signatures (primary source is
  `just gen-vtable-slot-overrides` suggestions merged after review).
- `config/class_vtable_aliases.csv` — alias class names that share a canonical
  vtable (`TLocalizationRuntime` → `TSimMgr`); overrides resolve through the alias.
- `config/classes/<Class>.yml` `curated.layout` — per-class `recovered` vs
  `in_progress` layout policy (`status`/`header`) and the derived-class prefix
  `base_offset`/`base_class` (`TGreatPower` @ `0x94` after `TCountry`). Enforced by
  `just field-layout-gate` (see `docs/reference/field-layout-annotations.md`).
  *(Replaced the former `class_layout_status.csv` / `class_layout_bases.csv`.)*
- `tools/common/recovered_field_type.py` — shared `field_type` grammar for CSV
  emission and `apply_mfc_rtti` Ghidra datatype mapping.
- `just gen-recovered-fields-from-headers` — pcpp + cxxheaderparser scan of
  `include/game/*.h` → `config/recovered_fields.generated.csv` (review before merge).
- `just gen-vtable-slot-overrides` — suggest slot override rows from `// VTABLE:`
  headers + Ghidra slot bodies → `config/vtable_slot_method_overrides.generated.csv`.
- `just ghidra-vtable-struct-check` — datatype-level regression on vtable struct
  field names (independent of decompiler composite indexing).
- `just ghidra-decomp-check` — regression gate: vtable struct checks plus nine
  benchmark decompiles (`tools/ghidra/decomp_check.py`). Run after every
  `just apply-mfc-rtti --apply`.
- `config/dissolve_namespaces.csv` — placeholder pseudo-class namespaces dissolved
  back into Global by `apply_mfc_rtti.py`.
- `config/calling_convention_overrides.csv` — verified `__cdecl`/`__fastcall`
  mislabels corrected to `__thiscall` (or confirmed `__cdecl`).
- `config/function_class_overrides.csv` — evidence-curated move of mis-placed
  `__thiscall` methods into the correct class namespace + `this` typing.
- The decompiler `this`-argument resolver prototype (measured low yield for fully
  automatic inference, so curated tables are preferred for now).

## Decompile benchmark suite

Run `just ghidra-decomp-check` after each apply. `--strict` also fails on missing
“should-improve” patterns (useful while driving the next tier).

| Address | Function | Must keep | Improved this pass |
| --- | --- | --- | --- |
| `0x00588b70` | `TIndustryCluster::OrphanLeaf_NoCall_Ins07_004d8920` | `g_apNationStates[s]->city`, `TCity::GetCityBuildingProductionValueBySlot`, `TAmtBarCluster::` | `summaryTags`; `orderSlotsE4` on `TCity` |
| `0x004ca571` | `TBuildingConstructionView::OpenCityViewBuildingOrderDialog` | `this->pCity`, `GetCityBuildingProductionValueBySlot` | `orderSlotsE4` via `this->pCity` |
| `0x0057c578` | `RebuildGlobalOrderManagersAndCapabilityState` | typed manager globals | `g_pUiAnimator` (`TAnimator*`, was `DAT_006a43e0`) |
| `0x0057c8a0` | `RebuildMapContextAndGlobalMapState` | `TOcean` / `TMapMgr` globals | `nationCount`, `contextArray` on `g_pActiveMapOrderContext` |
| `0x0049df00` | `InitializeGlobalRuntimeSystemsFromConfig` | `TSimMgr` / `UiRuntimeContext` | `g_pUiViewManager` (`TAssetMgr*`) |
| `0x0051794e` | `ComputeRepresentativeTileIndexForTerrainTypeWithWrapBias` | `g_apTerrainTypeDescriptorTable[i]` as `TCountry*` | `ownerNationSlot`, `ownedRegionList` |
| `0x0050c1bf` | `TMacViewMgr::RefreshCityProductionDetailPanelAndArrowWidgets` | `g_apNationStates`, `g_pLocalizationTable` | `needCapA6`, `fieldB6[]`; localization slot `0x84` still decompiles as `vftable[0x10].slot_0x04` (see note below) |
| `0x004d83c0` | `SumWeightedNeighborLinkScoreForLinkedNodes` | `__thiscall`, `TCountry*` | `ownedRegionList` via `this->ownedRegionList` |
| `0x00496230` | `SetActiveQuickDrawSurfaceContext` | assigns `g_pActiveQuickDrawSurfaceContext` | param/global typed `TQuickDrawSurfaceContext*` |

**Regression guards:** no `TCity::TCity::` double qualification (`decompile_one.py`
thunk fix); dissolved pseudo-classes stay gone (`dissolve_namespaces.csv`).

**TSimMgr vtable indexing (`0x0050c1bf`):** listing shows `CALL dword ptr [EAX+0x84]`
on `g_pLocalizationTable`; `TSimMgrVtbl` slot `0x21` is typed and named
`LoadUiStringByCodeGroupAndOffset` in the DB (`just ghidra-vtable-struct-check`
asserts the datatype field name at byte `0x84`). The decompiler may still render
`g_pLocalizationTable->vftable[0x10].slot_0x04` because it models each vfunc as an
8-byte `{fn, +4}` composite (`0x10 * 8 + 4 = 0x84`). Decompile benchmark accepts
`LoadUiStringByCodeGroupAndOffset` or `vftable[0x21]` when the decompiler catches up;
struct check guards the DB naming regardless. Full method-name propagation in decompile
needs a decompiler-side fix or 8-byte vtable struct emission (deferred — must not
break 4-byte PE vtable listing).

**Deferred — vtable call at `[vptr+0x1d4]` in `0x00588b70`:** listing shows
`CALL dword ptr [EDX+0x1d4]`; `TIndustryCluster` vtable `@0x00662f98` slot `0x75`
(byte `0x1d4`) resolves to `0x00402716`, which is **not** a function body (MFC
runtime-class descriptor / data slot). Decompiler still displays
`vftable[0x3a].slot_0x04`. Do not add a `vtable_slots.csv` row until a real
override method is identified.

## Tier 1 — high value, low risk, mechanism exists

### 1a. Type the recovered singleton globals — **done (second pass)**
Recorded in `config/recovered_globals.csv` and applied by `apply_mfc_rtti.py`
(optional `object_size` column seeds a minimal struct when RTTI did not emit one).

| global | typed as |
| --- | --- |
| `g_apNationStates` | `TGreatPower *[7]` |
| `g_apSecondaryNationStateSlots` | `TMinor *[36]` |
| `g_apTerrainTypeDescriptorTable` | `TCountry *[23]` |
| `g_pGameFlowState` | `Config *` |
| `g_pLocalizationTable` | `TSimMgr *` (manual: `TLocalizationRuntime`) |
| `g_pUiRuntimeContext` | `UiRuntimeContext *` |
| `g_pUiViewManager` | `TAssetMgr *` |
| `g_pApplicationUiRootController` | `ApplicationUiRootController *` |
| `g_pGlobalUiRootController` | `TApplication *` |
| `g_pNationInteractionStateManager` | `TTradeMgr *` |
| `g_pDiplomacyTurnStateManager` | `TDiplomacyMgr *` |
| `g_pGlobalMapState` | `TMapMgr *` (manual: `TGlobalMapState`) |
| `g_pCityOrderCapabilityState` | `TTechMgr *` |
| `g_pSelectedCivilianOrderState` | `CivilianMapInteractionManager *` |
| `g_pUiAnimator` | `TAnimator *` (was address-only `DAT_006a43e0`) |
| `g_pNavyOrderManager` | `TNavyMgr *` |
| `g_pInterNationEventQueueManager` | `TInterNationEventQueueManager *` |
| `g_pSfxPlaybackSystem` | `TSoundPlayer *` |
| `g_pActiveMapOrderContext` | `TOcean *` (manual: `TMapOrderContext`) |
| `g_pMapActionContextListHead` | `TZone *` |
| `g_pNavyPrimaryOrderListHead` | `TShip *` |
| `g_pMapContextActionManager` | `TArmyMgr *` |
| `g_pActiveQuickDrawSurfaceContext` | `TQuickDrawSurfaceContext *` |
| `g_pCursorControlPanel` | `TControl *` (manual: `TCursorControlPanel*`) |

**Next:** `g_apMinorNationCapabilityObjects` / `g_apNationAuxRuntimeStateSlots`
(overlap parent arrays — use `g_apTerrainTypeDescriptorTable + 7` pointer arithmetic,
not a second array type), `g_pActiveCityDialogLegendSelectionOwner` (deferred until writer
found), `TOcean` tail fields past `0x14` when alloc size grows beyond `0x18`.

### 1b. Grow `recovered_fields.csv` — **in progress**
Rows applied so far:

| class | offset | field |
| --- | --- | --- |
| `TGreatPower` | `0x894` | `city` (`TCity*`) |
| `TBuildingConstructionView` | `0x90` | `pCity` |
| `TIndustryView` | `0x94` | `pCity` |
| `TCityProductionView` | `0x94` | `pCity` |
| `TCity` | `0xb6` | `fieldB6` (`short[0x17]`) |
| `TCity` | `0xe4` | `orderSlotsE4` (`void*[0x3d]`) |
| `TCountry` | `0x88` | `ownerNationSlot` (`int`) |
| `TCountry` | `0x90` | `ownedRegionList` (`TPtrList*`) |
| `TOcean` | `0x04` | `nationCount` (`short`) |
| `TOcean` | `0x08` | `contextArray` (`int*`) |
| `TOcean` | `0x0c` | `field0c` (`short`) |
| `TOcean` | `0x10` | `keyMask` (`int`) |
| `TOcean` | `0x14` | `field14` (`int`) |
| `TGreatPower` | `0xa6` | `needCapA6` (`short`) |
| `TGreatPower` | `0xa8` | `needsOverCapFlag` (`short`) |
| `TGreatPower` | `0x10e` | `needCurrentByType` (`short[0x17]`) |
| `TGreatPower` | `0x13c` | `needTargetByType` (`short[0x17]`) |

Curated fields are applied in ascending offset order per class so array rows at
lower offsets do not clobber named fields at array boundaries (e.g. `fieldB6` then
`orderSlotsE4` at `0xe4`). Array specs: `short[0x17]`, `void*[0x3d]`.

Keep adding rows via `just gen-recovered-fields-from-headers` + manual review;
never overwrite an already-typed USER_DEFINED Ghidra field.

### Closed loop (generate → review → apply → check)

1. `just gen-recovered-fields-from-headers` — pcpp + cxxheaderparser emit
   `config/recovered_fields.generated.csv` from `include/game/*.h` offset comments
   and the manifest `curated.layout.base_offset`.
2. Merge reviewed rows into `config/recovered_fields.csv`; set
   `curated.layout.status: recovered` in the manifest when every member is annotated.
3. `just field-layout-gate` — verify annotations for listed classes.
4. `just gen-vtable-slot-overrides` — emit slot-name suggestions from `// VTABLE:`
   headers; merge exceptions into `config/vtable_slot_method_overrides.csv`.
5. `just apply-mfc-rtti --apply --verbose` — applies fields, globals, vtable aliases,
   and overlap-clipped struct fields.
6. `just ghidra-decomp-check` — vtable struct checks + decompile benchmark suite.

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
listed as confirmed `__cdecl`. Remaining scan: `OrphanDeadLeaf_NoRefs_0051da60`
— verify listing before override.

## Tier 3 — bigger levers, more effort

- **Interior field recovery at scale.** Most class structs are still `{vftable}` +
  `field_0x...`. Use `gen_recovered_fields_from_headers` + gated CSV merge.
- **Vtable slots → named virtuals + signatures.** Hot `TSimMgr` slots `0x1d`–`0x21`
  named via `vtable_slot_method_overrides.csv`; decompiler composite indexing
  remains a ceiling until struct emission matches the 8-byte model.
- **Name the 323 `FUN_`/`SUB_` functions.** Extend locality/caller attribution in
  `apply_mfc_rtti.py`.
- **Reclassify misidentified data.** — **in progress:** `0x006960e0` string →
  `TradeSummarySelectionMap` with named `summaryTags` / `primaryControlTag`.
  `0x696108` is `summaryTags[0]` inside that struct (not a separate label).

## Validation

Ghidra-only changes: `just ghidra-decomp-check` after `just apply-mfc-rtti --apply`.
Calling-convention and field-type changes that sync to manual source should also
route through `just build` + reccmp (`just compare` / `just stats`).
