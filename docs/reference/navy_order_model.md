# Navy order model audit (TShip / TTaskForce / order-node protocol)

Bounded model audit requested to stop patch-until-it-compiles porting of the navy
subsystem. Conclusions are grounded in raw listings, xrefs, Windows RTTI, and the
Mac CodeWarrior oracle (name/signature only — never Windows ABI).

## Headline findings

1. **`TShip` is a real naval unit, not "just" an order record.** The Mac oracle
   lists ~50 `TShip` methods that are pure ship gameplay: `Capture`, `Damage`,
   `Sink`, `Repair`, `MoveTo(TZone*)`, `IsInHomePort`, `LaunchShip`,
   `GetFirepower`/`GetArmorFactor`/`GetBattleSpeed`/`GetInvasionCapacity`,
   `ComputeValueForMission(eNavyMissionType)`, `GetFirst`/`GetNth`/`GetIndex`,
   `GetTurnDistanceTo(TZone*)`, `SetTaskForce(TTaskForce*)`. Windows RTTI confirms
   `TShip : TObject`, size 0x38. The class model is not wrong — it is **incomplete
   (no combat methods ported) and polluted (UNavy free functions dumped in the
   same TU)**. `TShip` is also list-managed (a global roster with
   `nextOlder24`/`prevNewer28`); a ship being on a roster list is normal, not a
   sign it is "really" a link node.

2. **The shared +0x04/+0x1c/+0x30 layout is a duck-typed protocol, NOT a shared
   base or a shared sub-struct.** Windows RTTI: `TShip` and `TTaskForce` both
   derive **directly** from `TObject` — no common intermediate base. The three
   aligned offsets are scattered (0x04, 0x1c, 0x30 with unrelated fields between:
   `TShip` has `displayName18`/`admiralBacklink20`/`nextOlder24`; `TTaskForce` has
   `owner0c`/`childOrderList10`/`queue_prev28`). So there is no contiguous
   `NavyOrderNodeState` sub-struct to compose into both classes — that specific
   sketch is **not supported** by the layout. What both classes share is a
   protocol: an order node exposes `{type@0x04 (short), count@0x1c (short),
   metric@0x30 (short)}`.

3. **`ComputeNavyOrderPriorityContributionPercentByCategory` (0x54ff00) is a
   generic order-node scorer, not a `TShip` method.** Raw listing: `__thiscall`,
   reads only `[ecx+0x04]` and `[ecx+0x30]` (plus `[ecx+0x1c]` in other cases) and
   a `category` stack arg; touches nothing `TShip`-specific. Its callers are
   navy-scoring loops (`BuildMissionQueuedOrderCategoryWeightsAndReturnTotal`
   0x536840, `BuildNavyOrderCategoryVectorForNationWithExclusion` 0x537900) that
   run it over order-node payloads — `TShip` in `TNavyMission::orderList24`,
   `TTaskForce` in `childOrderList`. Modeling it as a `TShip` method forces the
   task-force callers to pun `TTaskForce*`→`TShip*`. It should be a free function
   over the protocol, receiver typed as the shared shape (or `void*`, quarantined),
   never a `TShip` method reached by a sibling cast.

## Function classification (everything currently in `src/game/TShip.cpp`)

| Addr | Current name | True bucket |
|---|---|---|
| 0x54f500 | `TShip::TShip` | **real TShip member** (ctor; prepends to roster list) |
| 0x54f640 | `TShip::Free` | **real TShip member** (unlink + free) |
| 0x54fab0 | `TShip::WriteTo` | **real TShip member** (serialize) |
| 0x54fb50 | `TShip::ReadFrom` | **real TShip member** (serialize) |
| 0x54f460/4e0/5c0 | CreateObject / GetRuntimeClass / scalar-deleting-dtor | **real TShip member** (compiler-synthesized) |
| 0x550610 | `GetIndexInPrimaryOrderList` | **real TShip member** (Mac `TShip::GetIndex`) |
| 0x550550 | `ComputeOrderNodeDistanceQuotientByDescriptorWord24(TZone*)` | **real TShip member** (Mac `TShip::GetTurnDistanceTo(TZone*)`) |
| 0x550b60 | `ComputeOrderNodeCompositeEconomicScore` | **real TShip member** (order/mission valuation; likely Mac `ComputeValueForMission` family) |
| 0x54ff00 | `ComputeNavyOrderPriorityContributionPercentByCategory` | **generic order-node function** (protocol scorer; called on TShip *and* TTaskForce) |
| 0x5509c0 | `PruneOrPromoteOrderNodeWhenChildCostDepleted` | **real TShip member, but order-tree logic** (this=TShip leaf; reaches into `owner->childOrderList` and re-prunes it — duplicates the prune algorithm inline) |
| 0x53b800 | `ComputeNavyOrderDistributionScoreForNation(short)` | **navy free function** (UNavy neighbour) |
| 0x54fbf0 | `RegenerateNavyPrimaryOrderDisplayNameUntilUnique(TShip*)` | **navy free function** (takes TShip* by arg) |
| 0x54fd50 | `RecomputeGlobalCapabilityAverages()` | **navy free function** (global recompute) |
| 0x54fee0 | `GetNavyContextPointerFromGlobalTableByIndex(int)` | **navy free function / global-list utility** |
| 0x550090 | `GetNormalizedIndustryActionResourceCostPercent(int,short)` | **industry/economy free function** (not navy at all) |
| 0x5505a0 | `GetNavyOrderNormalizationBaseByResourceType(short)` | **navy free function** (descriptor-table read) |
| 0x5505c0 | `GetNavyPrimaryOrderListHead()` | **global-list utility** (Mac `TShip::GetFirst`) |
| 0x550640 | `GetNavyPrimaryOrderNodeByIndex(short)` | **global-list utility** (Mac `TShip::GetNth`) |
| 0x550970 | `GetIndustryActionCostWeightByResourceType(short)` | **industry/economy free function** |
| 0x550e70 | `GetResourceDescriptorWeightWord0ByType(short)` | **descriptor-table free function** |
| 0x5519d0 | `FindCumulativeWeightBucketIndex(short*,short)` | **generic weight-table utility** |

So ~9 of the ~20 markers are free functions that are UNavy/economy/utility
neighbours, not `TShip` at all. `GetFirst`/`GetNth` are genuinely `TShip` statics
in the Mac oracle but currently modeled as bare free functions.

## TShip*↔TTaskForce* interchange points

- **0x54ff00** — the generic scorer, run on both payload types (root cause of the
  `reinterpret_cast<TShip*>`/`ShipPayload()` churn already partly cleaned in the
  `TMapOrderChildLinkNode` pass).
- **`TMapOrderChildLinkNode::payload`** — one cell type carries `TShip*`
  (orderList24) and `TTaskForce*` (childOrderList); already remodeled to `TObject*`
  with per-site `static_cast` (see that commit). The remaining puns are the
  shared-order-node field reads (`order_type`/`required_count` off a `TShip`).
- **0x5509c0** — a `TShip` reaching into its owner `TTaskForce`'s child list; not a
  cast, but a cross-class reach that duplicates `PruneDefeated`'s body.

Every interchange traces back to the same fact: **there is no shared C++ base for
"order node"; the game duck-types the {type,count,metric} protocol.**

## API pollution: `include/game/TShip.h`

Eight non-`TShip` free functions are declared in the `TShip` header, so every TU
that needs the `TShip` class also drags in navy/economy utilities:
`GetNavyPrimaryOrderListHead`, `GetNavyPrimaryOrderNodeByIndex`,
`FindCumulativeWeightBucketIndex`, `GetIndustryActionCostWeightByResourceType`,
`ComputeNavyOrderDistributionScoreForNation`,
`GetNavyOrderNormalizationBaseByResourceType`,
`GetNormalizedIndustryActionResourceCostPercent`,
`CreateNavyPrimaryOrderNodeAndAssignDisplayName`. These belong in a navy-order
header, not the ship class header.

## TPortZone

Already boring and mostly done: `TPortZone : TZone` with one `short field48`
(coastal-tile index) and capability overrides; `TPortZone.cpp` has 12 real ported
bodies and 0 stubs. No architectural project needed — finish any remaining slot
bodies normally. It is not the source of the mess.

## Recommended bounded plan (in risk order)

1. **API hygiene (safe, codegen-neutral):** move the eight free-function
   declarations out of `TShip.h` into a dedicated `navy_order.h`; keep `TShip.h`
   to actual `TShip` members. Fix includes in consumers. No score impact.
2. **Name the global-list statics honestly:** `GetNavyPrimaryOrderListHead`/
   `...ByIndex`/`GetIndexInPrimaryOrderList` are Mac `TShip::GetFirst`/`GetNth`/
   `GetIndex` — model as `TShip` statics/members with those names.
3. **Model 0x54ff00 as a protocol free function** (receiver = the shared shape or
   `void*` with quarantined offset reads), delete the `TShip`-method framing, and
   drop the last payload puns at the call sites. This is the change that removes
   the recurring casts — do it against the listing, verify 0x536840/0x537900.
4. **Consolidate the duplicated prune** in 0x5509c0 against
   `TMapOrderChildLinkNode::PruneDefeated*` only if the inlined bodies are provably
   the same shape; otherwise leave the inline (reccmp) with a one-line note.
5. **Trim the narration** in `TShip.h`/`TShip.cpp` to the evidence that is still
   unresolved once 1–3 land.

Do NOT: introduce a shared "order node" base or a contiguous `NavyOrderNodeState`
sub-struct (no RTTI/layout evidence); cast `TTaskForce`→`TShip`; port more combat
bodies before the protocol boundary in step 3 is settled.

## Unresolved / needs more evidence

- The exact original identity of 0x54ff00's receiver type (a named protocol class
  vs. a free function the game called on both) — the Mac oracle has no matching
  method name, so it is most likely a file-scope free function in UNavy.
- Whether `ComputeOrderNodeCompositeEconomicScore` (0x550b60) is the Windows form
  of Mac `TShip::ComputeValueForMission` (signature differs; confirm before
  renaming).


---

## Pass 1 outcome (implemented): ship-node re-attribution

Deeper listing evidence OVERTURNED part of the original audit: the "TTaskForce
child payloads" reading was itself the misattribution. Both child lists --
`TTaskForce::childOrderList` AND `TNavyMission::orderList24` -- hold **TShip\***
order nodes. Proof (all from raw listings, not the decompiler):

- `GetOrCreateMissionOrderEntryForNode` (0x5503a0) raw-reads `this+0x14` as a
  SHORT (impossible on TTaskForce, whose +0x14 is a pointer; natural on TShip:
  `ownerNationSlot14`), seeds the new entry's zone from `this+0x08`
  (TShip::field08), and links `this` itself into the entry's childOrderList.
- `SetOwnerOrderEntryAndCacheType` (0x551220, ex "SetMapOrderActiveChildEntry")
  wrote `this+0x34` -- past TTaskForce's 0x34-byte end, documented as an
  "overrun"; on the 0x38-byte TShip it is simply `field34`. The "+0x10 reuse
  pun" is `quantityFlag10`.
- `ReassignOrderNodeNationAndRebindParentCounters` (0x551100) reads a
  `TMission*` at `this+0x2c` (TShip::missionBacklink2c; TNavyMission slot-0x84/
  0x8C attach/detach write the same field) and writes nation to `this+0x14`.
- The depleted-prune paths write -666 to payload+0x1c (`stockLevel1c`) and call
  the payload's virtual Free -- TShip::Free (roster unlink).
- TTechMgr's capability sweep walks the primary SHIP roster and called 0x550370
  through a `reinterpret_cast<TTaskForce*>(node)` -- deleted.
- `SelectPreferredMapOrderEntryByPriorityRules` (0x550670): the binary reads
  `[ecx+0x20]`/`[edi+0x20]` (admiral backlink) SYMMETRICALLY and then each
  admiral's `experiencePoints`; the old TTaskForce-receiver body misread the receiver
  side as +0x08/+0x06 (attachment/order_strength) -- a genuine logic mis-port,
  fixed by the migration.
- `SelectEligibleMapOrderInteractionForNationAndContext` (0x557f10) at 0x5582a2
  scores `[childOrderList->payload]` (the head child SHIP), not the entry; the
  port called it on the entry -- fixed with the binary's null guard.

Methods re-attributed TTaskForce -> TShip (markers moved to TShip.cpp):
0x5501b0 CalculateMissionOrderPriorityScore, 0x550370 AdjustMapOrderNodeStat-
Capped499, 0x5503a0 GetOrCreateMissionOrderEntryForNode, 0x550510/0x550820
GetOrderNodeDescriptorWord20/0C, 0x550670 SelectPreferred..., 0x550840/0x550aa0
node-score family, 0x550f80 DecrementRequiredCount, 0x550ff0 RemoveNode,
0x551100 Reassign..., 0x551220 SetOwnerOrderEntryAndCacheType. Field model:
TShip::field2c -> `TMission* missionBacklink2c`; TTaskForce::activeChildEntry ->
`TShip*`; TNavyTacUnit::sourceTaskForce34 -> `TShip*`;
FindOrCreateChildOrderLink takes `TShip*`. All the "cross-type pun"/"+0x34
overrun"/"+0x10 reuse" narration those fields carried is deleted -- the puns
were artifacts of the wrong receiver class, exactly as the model audit
predicted. API hygiene: the 8 UNavy free functions moved from TShip.h to
include/game/navy_order.h.

Verified: build + gates + tooling tests green; all 12 moved addresses pair at
their prior-or-better scores (the 2 corrected mis-ports changed codegen at
0x550670/0x557f10 by fixing real bugs); stats net -1 aligned / -0.00pp
(TU-relocation wobble; 3 improved).

Still open (follow-ups): the entry-side +0x1e bucket-counter region is still
raw-cast (unmodeled TTaskForce fields); `TTaskForce::owner`'s remaining
entry-receiver readers (TNavyMgr queue passes, PromoteMapOrderChainAndQueue's
owner-as-TZone read) deserve the same listing-level receiver audit; GetFirst/
GetNth/GetIndex Mac-name alignment; TShip's ~50 unported Mac combat methods.
