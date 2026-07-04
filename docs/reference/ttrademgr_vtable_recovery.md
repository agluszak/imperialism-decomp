# TTradeMgr class recovery (vtable 0x0066d990)

Groundwork for recovering the **TTradeMgr** class (the "nation interaction / trade
metric" manager). This is the class-recovery that unblocks the `TTradeMgr::` stub
cluster (~10 methods) and the vtable dispatch in
`TMapMgr::CalculateDeveloperTilePurchaseCost` (0x518b40, slot 0x13).

> **UPDATE — this is an entangled *detangle*, not a from-scratch creation.**
> The object is **already modeled** in the tree, incorrectly, as `TDealList`:
> `include/game/TDealList.h` declares `typedef TDealList TNationInteractionStateManager;`
> and `g_pNationInteractionStateManager` is typed `TDealList*`. That `TDealList` class is a
> conflation: it keeps the *real* TDealList's generated vtable comment (0x66da38, 0x18,
> `: TSortedPtrList`) but has hand-added manager fields (`NationMetricCategoryRow
> categoryRows[0x11]` — 0xa0 each — plus `categoryRankLists[0x11]`) and **four of the
> 0x66d990-vtable methods as *non-virtual* `Slot3C/4C/60/84` methods** (0x5b8d70 slot 0x0f,
> 0x5b8fe0 slot 0x13, 0x5b94d0 slot 0x18, 0x5ba090 slot 0x21 — the `SlotXX` byte offsets
> are TTradeMgr vtable byte offsets). A from-scratch `TTradeMgr` **duplicates and conflicts**
> with this (marker/ownership collisions on those 4 addresses, and a second class modeling
> the same object). Attempted and reverted.
>
> The correct recovery is a **careful detangle**: separate the real 0x18 `TDealList` from the
> manager class, decide whether the manager is a distinct `TTradeMgr` or the same object the
> `TDealList` frankenclass already sizes, make the 0x66d990 slot methods **virtual** on the
> owning class (so `CalculateDeveloperTilePurchaseCost`'s `[vtbl+0x4c]` dispatch pairs), and
> fix the typedef/global. This touches existing *working* `TDealList`/manager code, so it is a
> dedicated, regression-sensitive pass — not the mechanical promotion the plan below assumed.
> **Do NOT create a parallel `TTradeMgr` class without first reconciling the existing
> `TDealList` modeling.** The slot map below is still the authoritative vtable reference.

## Diagnosis: the global is mis-typed

`g_pNationInteractionStateManager` (0x006a43cc) is declared `TDealList*` in
`global_data_tables.h`, but that is **wrong**:

- `recovered_globals.csv` records the instance as **TTradeMgr**, allocated **0xaf0**
  bytes and constructed via `ConstructNationInteractionStateManager_Vtbl0066d990`
  (0x5b7a20) — it installs vtable **0x0066d990**.
- `TDealList` is a *different* class: `TDealList : TSortedPtrList`, vtable **0x0066da38**,
  object size **0x18**.

So `TTradeMgr` is a real RTTI class (mangled `?CreateObject@TTradeMgr@@`,
`?GetRuntimeClass@TTradeMgr@@UBE...`) that simply **has no header yet**, and the global
is typed as the wrong (much smaller) class. Retype it `TTradeMgr*` once the class exists.

## Base: `TTradeMgr : TObject`

Vtable slots 0x02–0x04, 0x08–0x09 are the TObject/CObject base methods (Serialize,
AssertValid, Dump, ShallowClone, ShallowFree). TObject provides slots **0x00–0x09**
(10 slots), so TTradeMgr's **introduced** virtuals begin at slot **0x0a**. Object size
**0xaf0**.

## Full primary vtable (0x0066d990, 35 slots)

Each slot's stored value is an ILT `jmp` thunk (reccmp auto-resolves these); the table
below lists the resolved target and its curated name. TTradeMgr overrides the TObject
slots 0x00/0x01/0x05/0x06/0x07; slot 0x0a onward are introduced.

| slot | byte | target | function |
|------|------|--------|----------|
| 0x00 | 0x000 | 0x005b7a00 | TTradeMgr::GetRuntimeClass |
| 0x01 | 0x004 | 0x005b7a40 | TTradeMgr::DestructTTradeMgrAndMaybeFree |
| 0x02 | 0x008 | 0x00485e90 | TObject::Serialize |
| 0x03 | 0x00c | 0x00412bf0 | CObject::AssertValid |
| 0x04 | 0x010 | 0x00412c10 | CObject::Dump |
| 0x05 | 0x014 | 0x005b7d90 | TTradeMgr::WrapperFor_HandleCityDialogNoOpSlot14_At005b7d90 |
| 0x06 | 0x018 | 0x005b7c10 | TTradeMgr::WrapperFor_HandleCityDialogNoOpSlot18_At005b7c10 |
| 0x07 | 0x01c | 0x005b7bc0 | OrphanCallChain_C2_I25_005b7bc0 |
| 0x08 | 0x020 | 0x004798d0 | TObject::ShallowClone |
| 0x09 | 0x024 | 0x00415ce0 | TObject::ShallowFree |
| 0x0a | 0x028 | 0x005b7fc0 | OrphanCallChain_C3_I50_005b7fc0 |
| 0x0b | 0x02c | 0x005b8080 | TTradeMgr::AccumulateDiplomacyRelationChangesAndQueueEvents |
| 0x0c | 0x030 | 0x005b8aa0 | DispatchNationMetricUpdatePassForAllSlots |
| 0x0d | 0x034 | 0x005b8ad0 | TTradeMgr::ComputeNationMetricBaselineValueForSlot |
| 0x0e | 0x038 | 0x005b8d40 | TTradeMgr::GetNationMetricWeightedScoreForSlot |
| 0x0f | 0x03c | 0x005b8d70 | TTradeMgr::GetNationMetricAuxWordForSlot |
| 0x10 | 0x040 | 0x005b8da0 | ComputeNationMetricDispatchScoreAndResolveScale |
| 0x11 | 0x044 | 0x005b8f80 | TTradeMgr::GetNationMetricRosterWordAtOffset0E |
| 0x12 | 0x048 | 0x005b8fb0 | TTradeMgr::GetNationMetricRosterWordAtOffset0C |
| 0x13 | 0x04c | 0x005b8fe0 | TTradeMgr::ResolveNationMetricScaleFromCodeOrRosterWordAtOffset0A |
| 0x14 | 0x050 | 0x005b9030 | TTradeMgr::GetNationMetricBucketValueByIndex |
| 0x15 | 0x054 | 0x005b9060 | TTradeMgr::ApplyDiplomacyTransferEffectsAcrossNationMetricRoster |
| 0x16 | 0x058 | 0x005b9190 | TTradeMgr::WrapperFor_ProcessPendingDiplomacyTransferEntriesUntilBlocked_At005b9190 |
| 0x17 | 0x05c | 0x005b9410 | TTradeMgr::RebuildNationMetricPassesAndClampRowsByBaseline |
| 0x18 | 0x060 | 0x005b94d0 | ApplyDiplomacyTransferEffectsAndMaybeEmitTurnEvent1C |
| 0x19 | 0x064 | 0x005b9790 | TTradeMgr::SetNationMetricCellValueByIndex |
| 0x1a | 0x068 | 0x005b97c0 | TTradeMgr::RunNationUpdatePassesAndResetTransitionFlags |
| 0x1b | 0x06c | 0x005b9890 | TTradeMgr::RunNationMetricPreUpdatePassAcrossSecondaryNations |
| 0x1c | 0x070 | 0x005b9b30 | TTradeMgr::BuildSecondaryNationMetricBucketsAndWeightedTrendScores |
| 0x1d | 0x074 | 0x005b98d0 | TTradeMgr::BuildEligibleNationMetricBucketsAndWeightedTrendScores |
| 0x1e | 0x078 | 0x005b9f70 | TTradeMgr::IsNationMetricCellNegative |
| 0x1f | 0x07c | 0x005b9fa0 | TTradeMgr::IsNationMetricCellPositive |
| 0x20 | 0x080 | 0x005b9fd0 | TTradeMgr::AllocateAndPopulateLinkedValueCollectionFromRosterFilter |
| 0x21 | 0x084 | 0x005ba090 | SelectPreferredNationMetricCodeFromLookup |
| 0x22 | 0x088 | 0x005b9f30 | ComputeNationMetricPowerScale |

(Slots 0x23–0x29 are NULL padding; 0x2a+ in that address region belong to *adjacent*
vtables — TDealList @ +0xa8, TNextTradeCommand @ +0x100 — not TTradeMgr.)

## Recovery plan (mechanical, do in one pass to keep the vtable coherent)

1. **Create `include/game/TTradeMgr.h`**: `class TTradeMgr : public TObject` with
   `// VTABLE: IMPERIALISM 0x0066d990`, `ASSERT_SIZE(TTradeMgr, 0xaf0)` (pad unknown
   fields), `DECLARE_DYNCREATE(TTradeMgr)`. Declare, in slot order:
   - overrides of the TObject slots TTradeMgr replaces: GetRuntimeClass (0x00), the
     scalar dtor (0x01), WriteTo (0x05), ReadFrom (0x06), Free (0x07);
   - the introduced virtuals 0x0a–0x22 (25 slots) from the table above, in order.
   Signatures only need to be self-consistent — reccmp pairs the slot by the function's
   address (marker), not the signature — but give slot 0x13
   (`ResolveNationMetricScaleFromCodeOrRosterWordAtOffset0A`) a real
   `int(int code)`-ish shape since `CalculateDeveloperTilePurchaseCost` scales its result.
2. **Consolidate the bodies into `src/game/TTradeMgr.cpp`**: most slot functions are
   autogen stubs; a few are already (mis-)owned by `src/game/TDealList.cpp` (e.g.
   0x5b8fe0 slot 0x13) and must be **moved** here. Promote each: real `TTradeMgr::Method`
   with its `// FUNCTION:` marker at the listed address (honest bodies are fine — vtable
   slot correctness is body-independent). Keep markers ascending by address.
3. `just regen-stubs` (drops the promoted stubs) → `just build` → `just vtable TTradeMgr`
   and iterate to 100% (classify each residual per the vtable-matching skill:
   scalar-deleting-dtor pairing for slot 0x01, missing overrides, etc.).
4. **Retype the global**: `g_pNationInteractionStateManager` → `TTradeMgr*` in
   `global_data_tables.h`; fix any callsite that used it as `TDealList`.
5. **Port the consumer**: `TMapMgr::CalculateDeveloperTilePurchaseCost` (0x518b40) — it
   loops `terrainStateTable[nTileIndex].resourceTypeByEdge[0..1]`, and for each resource
   type `< 0x11` calls the slot-0x13 virtual on `g_pNationInteractionStateManager`,
   scaling the result ×0x14 (plus fixed +10000 for type 0x15, +4000 for 0x16). This
   method is itself mis-attributed to `TCivToolbar` — its `this->field0c` is
   `TMapMgr::terrainStateTable`, so reattribute it to **TMapMgr** first (see
   decomp-loop/heuristics.md #46).

## Why this wasn't force-completed in one session

The recovery spans a new 35-slot header, ~30 cross-file method promotions (several
currently mis-owned by TDealList.cpp), a 0xaf0 field layout, a global retype, and a
consumer port — a dedicated pass. The analysis above (the slot map + the mis-type
diagnosis) is the hard part; the execution is mechanical against this table.
