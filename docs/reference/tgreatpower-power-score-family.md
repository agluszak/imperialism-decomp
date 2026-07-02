# TGreatPower power-score family — recovered ground truth

Discoveries from the 2026-06-10 batch port (commit `20e9f01`) of TGreatPower vtable
slots 0x86 and 0x8e–0x9e, the `CIterator` list cursor, and the nation border-link
check. Everything below is read from the binary listings (the Ghidra decompile of
this family is unreliable — phantom `unaff_EBX`/`unaff_retaddr` floats); use this as
the lookup contract when extending the family or porting its callers.

## Slot map (vtable 0x00653938)

| Slot | Body | Method | Score | Shape |
|------|------------|--------|-------|-------|
| 0x86 | 0x004e0500 | `SumNavyOrderPriorityForNationSlot86()` | 100% | walk navy primary-order list (head `0x005505c0`, node `next` at +0x24), filter `node->shortAt(0x14) == nationSlot`, sum `GetIndustryActionCostWeightByResourceType(node->shortAt(4))` (`0x00550970`, `__cdecl(short)`) |
| 0x8e | 0x004e07b0 | `ComputeArmyCommitBudgetSlot8E()` | 85% | `min(scenario cap, production slots, metric 0x10, armyPower/2)`; scenario cap = `GetCityState()->scenarioTradeDescriptor->valueAt1C`, production = `->productionSlots->valueAt4` |
| 0x8f | 0x004e0890 | `GetScoreFactorSlot23C()` — **army strength score** | 81% | `armyPower + commitBudget + min((int)(float)prod(3), (int)(armyPower * 0.25f))` |
| 0x90 | 0x004e09a0 | `GetScoreFactorSlot240()` — **navy strength score** | 71% | ship production (capability bytes 0x1a8/0x1a5 pick slot-8D arg 2 / avg(4,2) / 4) + navy priority (slot 0x86) + fleet power, each term min-clamped |
| 0x91 | 0x004e0b20 | `ComputeArmyScoreRatioVsNation(target)` | 83% | `self23C / (target23C + 0.25*allySum23C)` |
| 0x92 | 0x004e0c10 | `ComputeArmyScoreStandingRatioVsNation(target)` | 74% | `(yearTerm + self23C + 90) / (standing[my][target] + 0.25*allySum + target23C)` |
| 0x93 | 0x004e0d80 | `ComputeNavyScoreRatioVsNation(target)` | 83% | 0x91 with slot 0x240 |
| 0x94 | 0x004e0e70 | `ComputeNavyScoreStandingRatioVsNation(target)` | 74% | 0x92 with slot 0x240 |
| 0x95 | 0x004e0fe0 | `ComputeArmyScoreRatioVsNationWithSecondary(target, secondary)` | 73% | numerator adds `g_apSecondaryNationStateSlots[secondary]` army power; target score picks 23C vs 240 by border link |
| 0x96 | 0x004e1170 | `ComputeArmyScoreStandingRatioVsNationPair(target, partner)` | 77% | `(standing[my][partner] + self23C) / (standing[my][target] + 0.25*allySum + targetScoreMixed)` |
| 0x97 | 0x004e1300 | `ComputeNavyScoreRatioVsNationWithSecondary(...)` | 73% | 0x95 with 240 self/allies (target choice still 23C-if-linked) |
| 0x98 | 0x004e1490 | `ComputeNavyScoreStandingRatioVsNationPair(...)` | 77% | 0x96 with 240 |
| 0x99 | 0x004e1620 | `ComputeArmyScoreRatioForNationPair(a, b, swapRoles)` | 90% | `swapRoles==0`: opponent=a, partner=b, partner weight **+0.5**; else opponent=b, partner=a, weight **+0.25** |
| 0x9a | 0x004e1750 | `ComputeArmyScoreStandingRatioForNationPair(a, b, swapRoles)` | 63% | 0x99 plus standing terms on both numerator and denominator |
| 0x9b | 0x004e1910 | `ComputeNavyScoreRatioForNationPair(...)` | 90% | 0x99 with 240 |
| 0x9c | 0x004e1a40 | `ComputeNavyScoreStandingRatioForNationPair(...)` | 63% | 0x9a with 240 |
| 0x9e | 0x004e1c20 | `EvaluateJoinWarAgainstNationAndQueueEvent(target)` | 51% | join-war check, see below |

Common conventions in every ratio body:

- "allySum" loops re-query `g_pDiplomacyTurnStateManager->CountMajorAllianceRelationsSlot8c(target)`
  at the **bottom** of each iteration (do-while with count recheck) and read allies via
  `GetNthAlliedMajorNationSlot90(i, target)`.
- "standing" = `g_pDiplomacyTurnStateManager->relationStandingScoreMatrix79c[mySlot * 0x17 + x]`
  with `movsx` short indices.
- "yearTerm" = `min((short)(TSimMgr::quarterGateTick2c / 4), 0x3c)` —
  elapsed quarters/4, capped at 60.
- Division guarded by `denominator == 0.0f` → return the numerator unchanged.

## Slot 0x9e join-war logic (0x004e1c20)

1. `HasPolicyWithNationSlot44(mySlot, target)` — **result ignored** (kept for match).
2. Bail unless `g_apNationStates[target]->CompareMissionScoreVariantsByMode(0)` and `(1)`
   both return 0 — this proved `CompareMissionScoreVariantsByMode` (0x004dc540) is
   **virtual slot 0x52** (`call [vt+0x148]`), now declared so in the header.
3. Join if `ComputeMinisterSkillFloatSlot8C() < this->slotA3(target)` — slot 0xa3
   (vt+0x28c, body 0x004e1f40, **not yet ported**; provisional inline returns 0.0f).
4. On join: for each eligible nation `i<7` with `GetRelationTierSlot70(my, i) == 2` and
   `HasPolicyWithNationSlot44(i, target)`, call `ApplyRelationCode4Slot7c(my, i, 1)`;
   then `TInterNationEventQueueManager::QueueInterNationEventRecordDeduped(0x1c, target, my, 0)`.

## CIterator (0x00487ef0 / 0x00487f20 / 0x00487f40)

Mac CodeWarrior symbols name this class `CIterator` with `Reset`/`More`/`Advance` —
exactly the three Windows bodies. 12-byte stack cursor over a TPtrList-backed list:

```
+0x00 nextNode   (CPtrListNode*)
+0x04 ownerList  (set by the inline ctor — callers store the list then call Reset)
+0x08 current    (payload of the current node)
```

`Reset` reads `ownerList->listState.headNode` (TPtrList: vptr + CPtrList at +4, head at
+8) and returns the first payload; `More` tests `current != 0`; `Advance` steps the
MFC `CPtrListNode {next, prev, data}` chain. Files: `include/game/CIterator.h`,
`src/game/CIterator.cpp` (92/100/91%).

## Border-link check (0x00517c30)

Ghidra labeled this `IsNationCodeLinkedInNationGraph` (`__cdecl`); it is really a
`__thiscall` method on the global-map-state object at `0x006a43d4` — now
`TGlobalMapState::AreNationsBorderLinked(nationA, nationB)`:

- region list = `g_apTerrainTypeDescriptorTable[nationA]` (`0x006a4310`, TMinor rows)
  `->ownedRegionList90` (offset 0x90, same as `TGreatPower::ownedRegionList`);
- region records = `TGlobalMapState::cityScoreTable` (this+0x10), stride 0xa8, with
  **owner nation code byte at +0x00**, **adjacent-region count byte at +0x08**, and
  **adjacent region ids `short[0x18]` at +0x0a** (fields added to
  `TGlobalMapCityScoreRecord`);
- returns 1 when any region owned by `nationA` has a neighbor owned by `nationB`.
- list calls: count via `[vt+0x28]` (no args, int), get-by-ordinal (1-based) via
  `[vt+0x24]` — see the TListObject finding below.

## TListObject slot 0x28 off-by-one (latent interface drift)

Both 0x00517c30 and 0x004dbf00 (`AdvanceOwnedRegionDevelopmentCountersAndDispatchEvents`)
read the region-list **count from `[vt+0x28]`** and consume EAX. The old
`TListObject::GetCountSlot28` declaration sat at decl index 11 and therefore emitted
offset **0x2c** — every caller through it carried a silent off-by-one-slot dispatch.
Fix applied: decl index 10 (was `void ReleaseSlot24()`) is now
`int GetCountOrReleaseSlot28()`, and `List_GetCountSlot28` in TGreatPower.cpp routes
through it. **Caveat:** every `SlotXX` name in TListObject after index 10 is suspect of
the same +1 drift (the `// overload` comments mark inserted decls); before promoting
any of them to a real virtual, verify the emitted `call [reg+0xNN]` offset against the
original diff (same class of bug as the CPtrArray-family misalignment in heuristics
note 96). Heuristics note 98 tracks this.

## Named data globals (operand pairing)

Defined in `src/game/global_data_tables.cpp` with their `config/symbols.csv` names:

| Address | Symbol | Value |
|---------|--------|-------|
| 0x653700 | `g_Compute_Advisory_Handler_LookupTable_00653700` | 0.0f |
| 0x653714 | `g_Compute_Advisory_Handler_LookupTable_00653714` | -0.25f |
| 0x653718 | `g_Iterate_Linked_List_Value_00653718` | 0.25f |
| 0x65371c | `g_Compute_City_Order_Value_0065371C` | 0.5f |
| 0x653720 | `g_Compute_Advisory_Handler_LookupTable_00653720` | -90.0f |
| 0x653724 | `g_Compute_Advisory_Peer_LookupTable_00653724` | -0.5f |
| 0x695cd4 | `g_Classify_Nation_Military_LookupTable_00695CD4` | per-unit-type records, **0xe bytes each, power weight short at +0**; indexed by the unit-entry type id short at payload+4 |

Write the arithmetic against the named constants in the original FPU shape
(e.g. `x - sum * g_..._00653714` mirrors `FMUL`/`FSUBR` of -0.25) so the operand pairs.

## Nation-object arrays and layouts

| Address | Symbol | Type |
|---------|--------|------|
| 0x6a4280 | `g_apSecondaryNationStateSlots` | `TMinor*[36]` — secondary (minor-power) rows |
| 0x6a4310 | `g_apTerrainTypeDescriptorTable` | `TMinor*[23]` |
| 0x6a4370 | `g_apNationStates` | `TGreatPower*[7]` |
| 0x6a43d0 | `g_pDiplomacyTurnStateManager` | manager (alliance slots 0x8c/0x90, standing matrix +0x79c) |
| 0x6a43d4 | `g_pGlobalMapState` | receiver of `AreNationsBorderLinked` |
| 0x6a43d8 | `g_pCityOrderCapabilityState` | capability bytes 0x1a5/0x1a8 used by slot 0x90 |
| 0x6a43e8 | `g_pInterNationEventQueueManager` | event queue (event 0x1c from slot 0x9e) |

`TMinor` and `TGreatPower` share the nation-state prefix layout: **military unit list
at +0x44** (`militaryUnitList44`, entries carry the unit type id short at +4) and
**owned region list at +0x90** (`ownedRegionList90` / `ownedRegionList`). Both fields
are now real typed members on both classes.

## Residual Notes

- Slot 0xa3 (0x004e1f40, 452B, war-commitment threshold) is tracked as Beads
  issue `imperialism-decomp-1uj.33`.
- Residual score gaps in the family are register allocation / x87 scheduling noise,
  not structure; slot 0x9e (51%) additionally inlines `joinsWar` flag spills.
- 0x00517c30 (36%) is shape-correct; the original keeps its `found` flag in AL while
  the recompile spills it — cosmetic.
