#pragma once

#include "compat.h"
#include "decomp_types.h"
#include "game/TObject.h"
#include "game/mfc.h"
#include "game/TMapOrderChildLinkNode.h"
#include "game/TShip.h"
#include "game/globals/navy_globals.h"

class TTaskForce;
class TStream;
class CString;
class TZone;
class TShip;
struct Province;

// The former TMapOrderEntryOwnerContext placeholder struct (this comment block
// used to sit here) is gone: bd 1uj.16.1 resolved Add's
// receiver to be TTaskForce itself (the parent order entry), not a distinct
// manager class -- see Add's own declaration. The `target`
// slot (+0x0c) that was previously flagged UNRESOLVED is now modeled as the
// shipOrders-keyed union TMapOrderContext (see the field comment below); a full
// writer/receiver disassembly inventory confirmed the discriminator mapping and
// found no wrong-receiver/wrong-offset defect.

// Map-order queue entry (0x34 bytes). RTTI-confirmed real name TTaskForce
// (CRuntimeClass chain: TTaskForce -> TObject -> CObject; see
// config/symbols.csv rtti-sourced rows at 0x552770/0x5527e0/0x552870). Was
// previously modeled under the placeholder name TMapOrderEntry; merged into
// the RTTI name once TTaskForce's own vtable (0x0065c468) was found to be the
// SAME vtable TNavyMission.cpp's map-order bridges dispatch through (bd
// 1uj.16). Objects live in a global doubly-linked queue headed by
// TNavyMgr::orderQueueHead (g_pNavyOrderManager @ 0x6a43e4), threaded via
// previousForce/nextForce; TTaskForce::Free (0x552930) unlinks from that queue.
// VTABLE: IMPERIALISM 0x0065c468
class TTaskForce : public TObject {
public:
  DECLARE_DYNCREATE(TTaskForce)
  ~TTaskForce() override;                          // slot 0x01 (scalar deleting destructor)
  virtual void WriteTo(TStream* stream) override;  // slot 0x05 0x552b90
  virtual void ReadFrom(TStream* stream) override; // slot 0x06 0x552d10
  virtual void Free() override;                    // slot 0x07 0x552930

  // TTaskForce's own fields start at absolute offset +0x04: the inherited
  // TObject vtable pointer already occupies +0x00-0x03 (TObject is
  // ASSERT_SIZE 0x4). A leftover `field_00` here (from before this struct
  // was RTTI-merged from the standalone, non-TObject-derived TMapOrderEntry)
  // double-counted that slot and pushed sizeof(TTaskForce) to 0x38; removed
  // so aggression lands at +0x04, matching every `[this+4]` disassembly read
  // cited across this file, and the total size matches the RTTI-confirmed
  // 0x34 bytes (0x04 inherited + 0x30 own).
  // Mac oracle: eAgro. SetAggression writes the complete dword, ships cache the
  // complete dword, and the battle resolver uses it to index its three-entry
  // aggression threshold table.
  int aggression;
  // Mac oracle: eShipOrders. This is the submitted ship-order kind. TNavyMgr's
  // RemoveMatchingTaskForceOrders (0x557170 cluster) checks this == 5 for
  // "task force" queue entries; OrderEvade (0x552f80) sets it to
  // 9 for the map-order-9 kind.
  int shipOrders;
  // +0x0c order-context payload: a discriminated variant keyed by `shipOrders` (+0x08).
  // The order-entry machinery reuses this one 4-byte slot for the order's context object,
  // whose concrete type depends on the order kind:
  //   shipOrders 1/2/3/4/6 -> asZone       (map/port-zone context; walked through the zone
  //                           neighbor graph in OrderSailTowards, dispatched via
  //                           TZone vtable slot 0x4c in CreateIngot)
  //   shipOrders 5         -> asProvince   (record in the 384-entry province table; its
  //                           +0xa1 owner-nation flag is read by ApplyMapOrderTypeExecution-
  //                           Effects, and GetProvinceIndex resolves it)
  //   shipOrders 9 / 0     -> null (OrderEvade never writes it; ctor nulls it)
  // Proven a real tagged union (not incidental reuse) by WriteTo/ReadFrom (0x552b90/
  // 0x552d10), which serialize THIS slot two different ways depending on shipOrders==5 (a
  // city-table index) vs otherwise (a generic CObject reference). Every reader/writer
  // touches [this+0xc] as one 4-byte pointer, so the members alias at offset 0 and codegen
  // is identical to the former raw pointer.
  union TMapOrderContext {
    TZone* asZone;
    Province* asProvince;
  } target;
  // Head of this entry's own child order-node chain (was opaque pad_10[0]).
  // Same TMapOrderChildLinkNode shape TNavyMission::orderList24 walks. When
  // `this` is referenced via a child's taskForce pointer, this is that child's
  // sibling list head (former TMapOrderEntryOwnerContext::head).
  TMapOrderChildLinkNode* shipList; // +0x10
  // Cached "preferred active child" pointer, recomputed by
  // ElectFlagship (0x553e30) folding
  // Finest over shipList -- the
  // same role this plays for TAdmiral's primary-order force and for a child's force.
  TShip* flagship; // +0x14
  // +0x18 map-action context zone. Unlike `target`, this is NOT a tagged variant: every
  // writer stores a zone/context and every reader treats it as TZone* -- equality vs a
  // primary order node's own +0x08 (TShip::location, a TZone*), and vtable dispatch through
  // TZone slots 0x2c (AssignZoneDisplayName), 0x38, 0x4c (tile search) and 0x54 (coastal
  // heuristic). Serialized as a single CObject reference regardless of shipOrders. Seeded
  // from the source order node's +0x08 when the entry is created (0x5503a0); the 2-arg ctor
  // takes the real TZone* directly.
  TZone* location; // +0x18
  s16 nation;
  // +0x1e..+0x25: total ships available in each of the four UI classes. Every writer
  // indexes this region with the resource descriptor's bucket and every reader treats
  // it as the same flat four-short array; RefreshMapOrderEntryPanel feeds these values
  // to the Mac-evidenced cls0..cls3 TShipFractionCluster controls.
  short shipCountsByToolbarSlot[4];
  // Set to 1 by AttemptToEvade (0x555c20) when this entry loses a
  // tie-break against a competing entry; checked by
  // Encounter (0x555420) to short-circuit an
  // already-eliminated candidate (was pad_24[2]).
  char defeated;
  char pad_27;
  TTaskForce* previousForce;
  TTaskForce* nextForce;
  s16 ingotTileIndex;
  char pad_32[0x02];

  TTaskForce();
  // Real constructor used when a task-force order entry is created for a specific
  // context/nation slot (CreateTaskForceFromNavyOrdersForNationIfEligible 0x560a78,
  // TNavyMission::CombineForce 0x536dce). `nationArg` seeds nation.
  TTaskForce(TZone* locationArg, short nationArg);

  void LinkTo(TTaskForce* prev_node, TTaskForce* next_node);

  // Mac oracle: RegainVirginity(int, TZone*). Removes every child ship and resets
  // the task force's nation/context identity for a new map selection.
  void RegainVirginity(int nationArg, TZone* contextZone); // 0x552a70
  // 0x005528c0 — empty post-construction slot invoked thiscall (no args) by both
  // TTaskForce factory sites right after the ctor; the real body is a single ret.
  void ITaskForce();
  // 0x005548e0 — averages each child's cached aggression and stores the rounded result.
  void DemocraticallyDetermineAggressionLevel();
  // 0x005539c0 — recomputes this task force's per-order selection flags for the active
  // nation's current orders (`mode` selects the pass; the caller passes 0).
  void MaxOut(unsigned char mode);
  // 0x00553fe0 — frees the head child order node when defeated (nation <= 0),
  // prunes remaining defeated children, rebinds shipList/flagship;
  // returns 1 (marking this entry eliminated) when no child survives.
  char SinkOrSwimShips();
  // Mac oracle: SetAggression(eAgro).
  void SetAggression(int value); // 0x552f60
  // 0x554660 -- drops inactive children (owner cleared, bucket counter decremented,
  // node unlinked+freed), refolds flagship, then moves this entry to the head
  // of g_pNavyOrderManager's queue (or Free()s it when no children survive) and
  // finalizes through g_pActiveMapOrderContext.
  void CommitToOrders();

  // Null-safe (returns true on null `this`). Sums shipCountsByToolbarSlot.
  bool IsEmpty() const; // 0x553b10
  // Mac oracle: NoSelection() const. Null/empty task forces and forces with no active
  // child return true; the first active child returns false.
  bool NoSelection() const; // 0x553b50
  // 0x00554460 -- province-context command resolver (returns 0x10 or 1); asks the
  // diplomacy manager about this entry's nation vs the province's owner.
  char MouseCodeForTarget(Province* province) const;
  // 0x00554590 -- returns the province's +0xa0 eligibility byte when this entry has an
  // active queued child, else 0.
  unsigned int IsValidTarget(Province* province);
  // 0x00554300 -- action-context command resolver (0x0C/0x0D/0x0E/0x0F, fallback 1) from
  // this entry's location zone and a candidate context zone's capability slots.
  int MouseCodeForTarget(TZone* candidate) const;
  // This entry's 0-based rank among g_pNavyOrderManager->orderQueueHead entries
  // sharing the same nation value; -1 if `this` is null or not found in the
  // queue.
  int GetNationalIndex() const; // 0x5563d0
  // Clears this order's map marker tile if one is set (ingotTileIndex != -1).
  void DestroyIngot(); // 0x5564f0
  // Recomputes and repaints this order's map-tile marker from its `shipOrders` kind,
  // dispatching through the order's zone (target/location as TZone) tile-search
  // virtuals; called on a TTaskForce entry by FinalizeQueuedMapOrderEntry and ReadFrom.
  void CreateIngot(); // 0x556410
  // Walks the nextForce chain starting at `this`, clearing defeated on each
  // node.
  void RechargeAll(); // 0x557870

  // Builds a localized selection-overlay label ("<N> <unit(s)> <terrain owner> at
  // <context> (<order kind>)") via scanBracketExpressions' bracket-template expander.
  // Bracket substitutions: singular/plural unit template (string group 0x2762, index
  // 0x11/0x12), g_apTerrainTypeDescriptorTable[nation]'s terrain/nation name,
  // location's (real TZone*, see TMapOrderEntryOwnerContext note above)
  // AssignZoneDisplayNameToOutputRef label, the decimal child count, and the
  // order-kind label (string group 0x2762, index shipOrders+0x13). 0x554c90.
  // Used by BuildMapOrderBattleSideSnapshot for its overlay label field.
  void GetSnooperDescription(CString* out) const; // 0x554c90

  // Mac oracle: TTaskForce::GetCompositionDescription(CStr255&) const. Counts the
  // child ships by resource type and joins the localized, pluralized labels.
  void GetCompositionDescription(CString* out) const; // 0x554b20
  // Mac oracle: TTaskForce::GetGeneralDescription(CStr255&) const. Builds the concise
  // "fleet of N <current order>" status line used outside the detailed overlay.
  void GetGeneralDescription(CString* out) const; // 0x554e70
  // Mac oracle: GetAuthority / CancelOrders. GetAuthority names the admiral or
  // captain commanding flagship; CancelOrders removes this queue entry.
  void GetAuthority(CString* out) const;             // 0x5551d0
  void CancelOrders(unsigned char cancellationMode); // 0x5547d0

  // Null-safe tail-recursive nextForce walk used by TNavyMgr::CarryOutOrders
  // to rebuild the order queue head: prunes (Free()s) any entry with no active children,
  // or a live entry whose shipOrders is 0/1/4/7/8, or (shipOrders == 5) whose target
  // city's diplomacy relation stamp with this entry's nation is out of date; every
  // other live entry survives. Always recurses into nextForce first regardless of
  // outcome. 0x555090.
  TTaskForce* RemoveStragglers();

  // Number of shipList entries; null-safe on `this` (returns 0), matching a call
  // site that invokes it without checking for a null receiver first.
  short CountShips() const; // 0x5562c0

  // Minimum resource-type descriptorWeight across active shipList entries;
  // returns 0 if none are active (used as a gating predicate for map-order actions).
  unsigned int GetWorstSpeed() const; // 0x554a80

  // Finds the shipList entry whose payload == ship (head fast-path,
  // else FindNodeMatching from the second node) and, if found, sets its active; when
  // the flag is nonzero also clears the ship's task-force selection state.
  void Select(TShip* ship, unsigned char activeFlag); // 0x5549a0

  // Counts active shipList entries whose descriptor enabledFlagOrBucketOffset
  // (low short, reused here as a nation/bucket class) equals nationClass.
  int GetSelected(short nationClass) const; // 0x554a30

  // Average (x10) of the resource-type descriptorWeight column across active
  // shipList entries; 0 if none are active.
  int GetDeciSpeed() const; // 0x554ad0

  // Mac oracle: GetBattleStrengthRating() const. Sum of each child ship's corresponding
  // battle-strength rating over every shipList entry (each
  // entry's own aggression/ingotTileIndex/nation, not this entry's own).
  int GetBattleStrengthRating() const; // 0x556010

  // Immediate/deferred execution effects for a resolved queue entry
  // (TNavyMgr::CarryOutOrders' tail passes): no-op once already eliminated.
  // Type 1 propagates target.asZone into every active child's location. Type 5
  // sets the target city's owner-flag bit
  // for this entry's nation and, in single-player mode, invalidates that city's redraw.
  // Type 8 advances every active child's strength by a quarter-step toward its
  // resource-type's stockCap. Any other type asserts once, then (except type 1) marks
  // this entry processed.
  // Mac oracle: CarryOutOrders().
  void CarryOutOrders(); // 0x556100

  // Compares this entry's best (lowest descriptorWeight) active child against `other`'s
  // average active-child rating; rolls against the gap to decide a tie-break winner.
  // On a loss, marks `this` (not `other`) eliminated (defeated = 1) and returns
  // 1; else returns 0. Only the low byte of the original's return value is ever
  // consulted by callers.
  bool AttemptToEvade(const TTaskForce* other); // 0x555c20

  // Sub-step of TNavyMgr::CarryOutOrders' pairwise resolution pass (called
  // after the caller's own TryToSpot gate): bails (0) if
  // either side has no active children; if the active nation preference is set and
  // owns either side, returns 1 without resolving; otherwise hands off to
  // g_pNavyOrderManager->ResolveStrategicBattle(this, other), clears the caller's
  // unresolved-force reference, and returns false.
  bool BattleWith(TTaskForce* other, TTaskForce*& unresolvedForce); // 0x555d10

  // this->GetBattleStrengthRating()*100 < kOrderTypePriorityWeight[aggression] *
  // other->GetBattleStrengthRating(). Same per-order-type {200,100,50}
  // weight table Encounter uses.
  bool IsAfraidOf(TTaskForce* other) const; // 0x555de0

  // Top-level task-force order-conflict resolver: bails if either side has no active
  // children; force-attempts resolution for ship-order kinds 5/6, else rolls against a
  // priority-gap threshold (childRating average delta + child-count overflow); if
  // attempted, compares aggregate scores (weighted by kOrderTypePriorityWeight) both
  // ways and falls back to AttemptToEvade on a near-tie; on a
  // resolved conflict with both sides still non-empty, returns true immediately if
  // either side is the active nation (when g_pSimMgr->preferenceValues[3] is set), else
  // hands off to TNavyMgr::ResolveStrategicBattle and returns false.
  bool Encounter(TTaskForce* other); // 0x555420

  // Standalone sibling of the identical inline "shouldAttempt" computation in
  // Encounter: bails if either side has no active
  // children; force-attempts for ship-order kinds 5/6; else rolls against a priority-gap
  // threshold (childRating average delta + child-count overflow past 10).
  bool TryToSpot(const TTaskForce* other) const; // 0x555720

  // Direct sibling of Encounter/ComputeTaskForceOrder-
  // TieBreakScore -- same per-order-type {200,100,50} weighted-heuristic-sum comparison,
  // checked both ways, but with its own inline elimination roll (not a call to either
  // sibling): whichever side's GetBattleStrengthRating-summed heuristic total
  // is priority-weighted weaker gets one shot at elimination (gap between the OTHER
  // side's best active child and this side's average active-child rating), and only when
  // the reciprocal aggregate-score check doesn't already favor it and it isn't already
  // eliminated. Returns 0 when `this` or `other` gets defeated set (or the
  // reciprocal check bails early), 1 when no elimination happens.
  bool ResolveEncounterWith(TTaskForce* other); // 0x555920

  // Low word of this order's resource-type enabledFlagOrBucketOffset column (same field
  // ReassignToForce reads as a bucket_offset).
  // This order's resource-type calculateWeight column.

  // Marks every active shipList entry's order node (payload+0x34 -- same
  // out-of-bounds write documented on Add) with a 1-or-2
  // selection-mode code depending on `reserveExtraSlot`, then scans the global primary
  // navy order list (g_pNavyPrimaryOrderListHead) for TShip nodes matching this entry's
  // location/nation and re-attaches each one via Add,
  // and finally recomputes each shipList entry's active from whether its
  // node+0x34 slot was left at 0.
  void DropShips(unsigned char reserveExtraSlot); // 0x553a50

  // Finds the first shipList entry whose order node's resource-type bucket
  // (g_NavyOrderResourceDescriptorTable[...].enabledFlagOrBucketOffset, low word) equals
  // `nationClass` and whose active differs from `activeFlag`; sets that entry's
  // active and, when activating (activeFlag != 0), clears its order node's +0x34
  // slot (same overrun as above).
  // Mac oracle: Select(short, unsigned char).
  void Select(short toolbarSlot, unsigned char activeFlag); // 0x554930

  // Recursively destroys the whole nextForce chain (tail-first: recurses before
  // freeing `this`) then Free()s `this`. Deliberately null-safe on `this` itself --
  // callers (e.g. a manager's own Free()) invoke it on a possibly-null queue head
  // without checking first, matching the original's `test esi,esi; jz` guard.
  void FreeAll(); // 0x556820

  // Folds Finest over shipList into
  // flagship (bd 1uj.16 target cluster).
  void ElectFlagship(); // 0x553e30

  // Removes every shipList entry whose link node is inactive (unlink + delete,
  // clearing the freed entry's owner and decrementing its resource-type bucket counter
  // -- same +0x1e-based bucket region DropShips /
  // SinkOrSwimShips use), then recomputes flagship over the
  // survivors. The original inlines both passes here rather than calling
  // ElectFlagship for the second pass.
  void FreeAvailables(); // 0x553f10

  // Mac oracle: Remove(TShip*). Removes the ship's child link, updates its class
  // count and the preferred-child cache, then clears the ship's owner backlink.
  // Mac oracle: TTaskForce::Remove(TShip*). The class-body definition is material:
  // VC5 both expands it in RegainVirginity and retains its COMDAT copy at 0x553d40.
  // FUNCTION: IMPERIALISM 0x00553d40
  void Remove(TShip* ship) {
    TMapOrderChildLinkNode* matchingLink;
    if (shipList == 0) {
      matchingLink = 0;
    } else if (shipList->payload != ship) {
      matchingLink = shipList->next->FindNodeMatching(ship);
    } else {
      matchingLink = shipList;
    }

    if (matchingLink != 0) {
      if (shipList != 0) {
        if (shipList->payload == ship) {
          shipList = shipList->DeleteMapOrderChildLinkAndReturnNext();
        } else {
          shipList->next->RemoveLinkedOrderNodeByValueRecursive(ship);
        }
      }
      short bucketIndex = static_cast<short>(
          g_NavyOrderResourceDescriptorTable[ship->type].enabledFlagOrBucketOffset);
      --shipCountsByToolbarSlot[bucketIndex];
    }

    if (ship == flagship) {
      ElectFlagship();
    }
    ship->taskForce = 0;
  }

  // Mac oracle: SubmitOrders(eShipOrders, void*). `orderContext` is interpreted as a
  // TZone* or Province* according to orderType.
  void SubmitOrders(int orderType, void* orderContext); // 0x5540b0

  // bd 1uj.16 target: sets shipOrders=9 (map-order kind 9), frees any
  // shipList entries whose owning link is inactive, recomputes
  // flagship, then either self-Frees (no live children) or
  // (re)inserts `this` at the head of g_pNavyOrderManager->orderQueueHead
  // and notifies g_pActiveMapOrderContext.
  void OrderEvade(); // 0x552f80

  // Opens by re-seeding the zone-graph BFS distance levels from `pContextAnchor`
  // (TZone::PropagateMapActionContextDistanceLevelsRecursive(-1), via ILT thunk
  // 0x4081cf -- this resolved the `owner` field's TZone identity for this call
  // site: `target.asZone` (this+0xc) is read/written here with TZone's own
  // primaryNeighbors stretch shape (vfptr/data/capacity/count at
  // target+0x24/+0x28/+0x2c/+0x30, matching TZonePrimaryNeighborStretch exactly)
  // and TZone::distanceLevel44. Then walks target.asZone->primaryNeighbors,
  // promoting the first neighbor closer to the destination; finally the
  // same free-shipList / recompute / self-Free-or-queue tail as
  // OrderEvade.
  void OrderSailTowards(TZone* pContextAnchor); // 0x5533f0

  // bd 1uj.16.2/1uj.16.5 target: sibling of OrderEvade for map-order kind
  // 6 (port-zone blockade orders) -- stores the port-zone context in target.asZone, sets
  // shipOrders=6, then the identical free-inactive-children / recompute /
  // self-Free-or-queue tail as OrderEvade. Ghidra/symbols.csv mis-attribute
  // this to TControlSeaZoneMission, but its body only ever reads TTaskForce's own field
  // offsets (target/shipOrders/shipList/flagship/bucket-count region) --
  // real owner is TTaskForce, called from TControlSeaZoneMission::GiveActionOrders (0x539640)
  // and TBlockadePortMission::GiveActionOrders (0x53ba40, "QueueMapOrderType6FromContext
  // Pointer") on the map-order entry passed to that virtual slot.
  void OrderBlockade(TZone* orderTarget); // 0x5536c0

  // Sibling of OrderBlockade for map-order kind 5 -- byte-identical body except
  // it stores shipOrders=5 instead of 6 (target=orderTarget, flagship=null, same
  // free-inactive-children / recompute / self-Free-or-queue tail). Ghidra/symbols.csv model
  // it as a free __thiscall function; real owner is TTaskForce (body reads only this class's
  // own field offsets).
  void OrderSendInTheMarines(Province* orderTarget); // 0x553840

  // bd 1uj.16.2 target: another OrderEvade sibling, for map-order kind 3
  // (useType4 == 0) or 4 (useType4 != 0); does not touch `target`. Same mis-attribution
  // to a free function as OrderBlockade -- real owner is TTaskForce (body only
  // reads this class's own field offsets). Called from TControlSeaZoneMission::GiveActionOrders
  // when no matching port-zone context was found.
  void OrderPatrol(unsigned char useType4); // 0x5530f0

  // Called from ReassignToForce's tail (0x550ff0, via ILT thunk 0x4027de) with
  // ReassignToForce's `self` argument re-attached as `node`'s new owner, and from
  // DropShips for each stale TShip
  // primary-order node matching this entry's location/nation.
  // Searches shipList for an existing link to `node`; if none exists,
  // allocates (operator new, 0x606f73) and inserts a new TMapOrderChildLinkNode
  // in priority-sorted order (by g_NavyOrderResourceDescriptorTable[node->type]
  // .enabledFlagOrBucketOffset), bumps this entry's bucket counter, sets
  // node->taskForce = this, then calls this->AssertValid() (CObject virtual, slot
  // 0xc) and copies this entry's aggression dword and
  // ship-order-kind gate onto `node` -- the same fields/gate
  // TShip::SetTaskForce applies, just with `this` playing the role of
  // that method's `newEntry` parameter (bd 1uj.16.1).
  void Add(TShip* node); // 0x553bc0
};

ASSERT_SIZE(TTaskForce, 0x34);
