# TTradeMgr class recovery (vtable 0x0066d990)

> **STATUS — DONE (detangle executed).** `class TTradeMgr : public TObject` now exists
> (`include/game/TTradeMgr.h` / `src/game/TTradeMgr.cpp`), split cleanly out of the former
> `TDealList` frankenclass. Results:
> - `just vtable TTradeMgr` = **100%** (all 35 primary slots owned: 5 TObject overrides +
>   25 introduced virtuals 0x0a–0x22 + inherited), `just vtable TDealList` still **100%**.
> - Field layout **recovered from the accessors' disassembly**: `categoryRows` at class
>   offset 0x04, stride **0xa0** (row fields at struct 0x06 / 0x14), `categoryRankLists`
>   (TDealList*) at 0xaa8, object size **0xaf0**. `categoryRankLists` holds real `TDealList`
>   instances (InitializeDefaults installs vtable 0x66da38 into each) — the composition edge
>   that caused the original conflation.
> - Moved-method deltas: `IsCapabilityCategoryActiveSlot3C` 60→**100%**,
>   `InitializeNationInteractionStateManagerDefaults` 54→**79%**,
>   `QueryProposalWeightSlot4C` 37→**64%**; ctor 20% (unchanged — installs the *correct*
>   vtable now; residual is the systemic out-of-line `TObject::TObject` base-ctor call),
>   `DispatchProposalAmountSlot60`/`ResolveProposalCodeForCategorySlot84` unchanged.
> - Global `g_pNationInteractionStateManager` retyped `TTradeMgr*`, definition moved to
>   `global_data_tables.cpp` with its `// GLOBAL:` marker; `typedef TDealList
>   TNationInteractionStateManager` dropped; the `TNationInteractionStateManager.h` alias
>   header now points at `TTradeMgr.h`.
> - Net stats: +3 aligned functions, +0.06pp avg similarity (13 improved, 2 newly paired,
>   3 minor caller regressions accepted — they stem from the accessors becoming correct
>   `short`-param real virtuals).
>
> **UPDATE — port complete.** All 24 introduced-slot functions (0x0a–0x22) now carry real,
> ported bodies (no `return 0` stubs remain; none left in the autogen stubs). Every vtable
> dispatch was resolved by byte-offset → class slot → address → ILT target → curated `.cpp`
> marker name and issued as a real `obj->Method()` (no raw `vftable[]`, no
> `reinterpret_cast`-thiscall). Highlights: 7 slots at 100% (effective) plus `Free` 100% and
> `ComputeNationMetricPowerScale` 92%; the rest are faithful partials (24–80%) whose
> residuals are codegen-level only (FPU intermediate ordering, SEH frame prologues, stack
> event-record layout, return-register allocation). Supporting work: recovered the full
> `0xa0` row-field layout from the accessors; added the `g_nationMetricSlotDispatchOrder`
> global (0x66d810); widened `TSoundChannelNode::SoundChannelNodeDummy00` to its real
> one-arg signature; claimed the non-virtual impl `ProcessPendingDiplomacyTransferEntriesUntilBlocked` (0x5b91e0). `just vtable TTradeMgr`/`TDealList` still 100%; all cross-class
> receiver classes (TCountry/TGreatPower/TMinor/TDiplomacyMgr/TSortedPtrList/TSoundChannelNode)
> unchanged at 100%.
>
> **UPDATE — consumer wired (step 5 done).** `CalculateDeveloperTilePurchaseCost` (0x518b40)
> reattributed from `TCivToolbar` to **TMapMgr** (its `this->field0c` is
> `TMapMgr::terrainStateTable`; heuristic 46) and ported: it sums the two edge resources of a
> tile, weighting each real resource type via `g_pNationInteractionStateManager->
> QueryProposalWeightSlot4C(...)` (the real slot-0x13 virtual on TTradeMgr) ×0x14, with the
> fixed +10000/+4000 surcharges for types 0x15/0x16. **95.24%** (sole residual is a 1-byte
> loop-back jump offset). This closes the dispatch that motivated the whole recovery.

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
> **Definitive structure (verified): two distinct classes conflated into one.**
> - **Real `TDealList`** — vtable **0x66da38** (`TDealList::GetRuntimeClass` 0x5ba1a0, scalar
>   dtor 0x5ba1f0, `CompareUnsignedIntsAscending` 0x5ba260), base `TSortedPtrList`, size 0x18.
>   `just vtable TDealList` is **100% matched** today — this half is correct and must not break.
>   Note `0x66da38 = 0x66d990 + 0xa8`; they sit adjacently in the binary's vtable section but
>   belong to different classes.
> - **The manager** (`TTradeMgr`/`TNationInteractionStateManager`) — vtable **0x66d990**, base
>   `TObject`, size 0xaf0, ctor **0x5b7a20** (`MOV [EAX],0x66d990`). Its ctor, its
>   `NationMetricCategoryRow categoryRows[0x11]` fields, and its metric methods (the
>   `SlotXX` set + slots 0x0a–0x22) are currently **bolted onto `TDealList`**, so they match
>   *poorly* because the class model is wrong: ctor **20%**, `IsCapabilityCategoryActiveSlot3C`
>   60%, `QueryProposalWeightSlot4C` 37%, `DispatchProposalAmountSlot60` 33%,
>   `ResolveProposalCodeForCategorySlot84` 6%.
>
> **The detangle** = pull the manager out of `TDealList` into its own `class TTradeMgr :
> public TObject` (VTABLE 0x66d990, size 0xaf0): move the ctor 0x5b7a20,
> `InitializeNationInteractionStateManagerDefaults`, `categoryRows`/`categoryRankLists`, and
> the SlotXX methods out of `TDealList.{h,cpp}`; declare the metric methods **virtual** at
> their slots (per the map below) so `CalculateDeveloperTilePurchaseCost`'s `[vtbl+0x4c]`
> dispatch pairs; retype `g_pNationInteractionStateManager` → `TTradeMgr*` and drop the
> `typedef TDealList TNationInteractionStateManager`. Leave the real `TDealList` (0x66da38,
> 100%) untouched.
>
> **Blast radius (measured — good news):** the 19 external `g_pNationInteractionStateManager->`
> callsites (TForeignMinister/TGreatPower/TMinor/TSimMgr) call **only** the four manager
> methods (`QueryProposalWeightSlot4C` ×10, `IsCapabilityCategoryActiveSlot3C`/
> `DispatchProposalAmountSlot60`/`ResolveProposalCodeForCategorySlot84` ×3 each) — all of which
> move to `TTradeMgr` — plus 3 type-agnostic pointer copies. **No caller uses it as a TDealList
> list**, so retyping the global `TTradeMgr*` is clean.
>
> **Remaining blocker (why the move alone isn't enough):** those methods match only 6–60% today
> because their `this + off` field accesses (into `categoryRows`) assume the wrong base
> (`TSortedPtrList`). The **real field offsets in the TObject-derived 0xaf0 manager are still
> unrecovered** — the move must be paired with reading each method's `[this+X]` accesses to
> place `categoryRows`/`categoryRankLists` at their true offsets. That layout recovery, plus
> the class split, is the dedicated pass.
>
> **Regression surface / gating:** keep `just vtable TDealList` at **100%** throughout, don't
> disturb the shared 0x66d990/0x66da38 vtable region, `just stats` after the global retype.
> Revert on any drop. The slot map below is the authoritative primary-vtable (0x66d990)
> reference for the move.

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
