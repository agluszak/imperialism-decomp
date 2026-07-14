#pragma once

#include "compat.h"
#include "decomp_types.h"
#include "game/TObject.h"
#include "game/mfc.h"

class TTaskForce;
class TStream;
class CString;
class TZone;

// Child-link node for map-order mission trees (NOT TOcean / TZone).
struct TMapOrderChildLinkNode {
  TTaskForce* object_ptr;
  TMapOrderChildLinkNode* next;
  TMapOrderChildLinkNode* prev_link;
  unsigned char active_flag;
  unsigned char pad_0d;
  unsigned char pad_0e;
  unsigned char pad_0f;

  // Real __thiscall method (0x552510, ECX=this node, one stack arg, RET 4) --
  // was mis-modeled as a "static" TTaskForce member taking (node, child_node) as
  // two ordinary params, which mismatched the callee-cleans-1-arg convention Ghidra
  // showed (bd 1uj.16.1 fix). Walks `this` and its `next` chain (null-safe on `this`)
  // for the first node whose object_ptr == child_node.
  TMapOrderChildLinkNode* FindNodeMatching(TTaskForce* child_node); // 0x552510

  // Real __thiscall method (0x536f70, ECX=this node, one stack arg, RET 4) -- was mis-
  // modeled as a "static" TScatteredShipsMission member taking (node, flag), same class
  // of bug FindNodeMatching had (bd 1uj.16.3 fix). Null-safe on `this`; sets active_flag
  // on `this` and every following node in the `next` chain.
  void SetChainActiveFlag(unsigned char flag); // 0x536f70

  // Real __thiscall method (0x5525d0, ECX=this node, one stack arg, RET 4) -- same
  // mis-modeled-as-static bug as FindNodeMatching. Null-safe on `this`; removes the first
  // node in the `this`/`next` chain whose object_ptr == child_node (unlink + delete) and
  // returns the chain head as seen from this node.
  TMapOrderChildLinkNode* RemoveLinkedOrderNodeByValueRecursive(TTaskForce* child_node); // 0x5525d0

  // Real __thiscall method (0x552650, ECX=this node, one stack arg, RET 4) -- same
  // mis-modeled-as-static bug as FindNodeMatching (was a TTaskForce static taking
  // (next_node, child_node)). Allocates a fresh node (raw operator new, no zeroing)
  // that prepends before `this` (the next node), links it in, and returns it.
  // Null-safe on `this` (guards the back-link write), and asserts on alloc failure.
  TMapOrderChildLinkNode* CreateLinkedOrderNode(TTaskForce* child_node); // 0x552650
};

ASSERT_SIZE(TMapOrderChildLinkNode, 0x10);

// The former TMapOrderEntryOwnerContext placeholder struct (this comment block
// used to sit here) is gone: bd 1uj.16.1 resolved FindOrCreateChildOrderLink's
// receiver to be TTaskForce itself (the parent order entry), not a distinct
// manager class -- see the `owner` field comment below and FindOrCreateChildOrderLink's
// own declaration. `owner` remains genuinely dual-purpose (TTaskForce::
// PromoteMapOrderChainAndQueue instead reads it as TZone*, per bd 1uj.47.2 --
// see that method's body for the local reinterpret_cast), consistent with the
// type-modeling guardrail's "opaque/polymorphic slot" exception.

// Map-order queue entry (0x34 bytes). RTTI-confirmed real name TTaskForce
// (CRuntimeClass chain: TTaskForce -> TObject -> CObject; see
// config/symbols.csv rtti-sourced rows at 0x552770/0x5527e0/0x552870). Was
// previously modeled under the placeholder name TMapOrderEntry; merged into
// the RTTI name once TTaskForce's own vtable (0x0065c468) was found to be the
// SAME vtable TNavyMission.cpp's map-order bridges dispatch through (bd
// 1uj.16). Objects live in a global doubly-linked queue headed by
// TNavyMgr::orderListHead04 (g_pNavyOrderManager @ 0x6a43e4), threaded via
// queue_prev/queue_next; TTaskForce::Free (0x552930) unlinks from that queue.
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
  // so order_type lands at +0x04, matching every `[this+4]` disassembly read
  // cited across this file, and the total size matches the RTTI-confirmed
  // 0x34 bytes (0x04 inherited + 0x30 own).
  s16 order_type;
  s16 order_strength;
  // Order/entry "kind" tag (was named `attachment`): TNavyMgr's
  // RemoveMatchingTaskForceOrders (0x557170 cluster) checks this == 5 for
  // "task force" queue entries; SetMapOrderType9AndQueue (0x552f80) sets it to
  // 9 for the map-order-9 kind. Kept the established `attachment` spelling
  // (already used by TTaskForce::SelectPreferredMapOrderEntryByPriorityRules)
  // to avoid touching working code; see bd 1uj.16 notes.
  int attachment;
  // Was read as a generic "targetRecord" pointer (compared against a
  // cityRecordPtr) by TNavyMgr's order filter, and, when a child order node's
  // own owner, as the PARENT TTaskForce entry acting as this node's queue/bucket
  // owner (bd 1uj.16.1 merge): RemoveNode (0x550ff0), ReassignOrderNodeNation-
  // AndRebindParentCounters, and FindOrCreateChildOrderLink (0x553bc0) all read
  // the pointee at the SAME offsets childOrderList/activeChildEntry/bucket-count
  // region use on `this` -- i.e. `owner` doesn't point at a distinct manager
  // object (the former TMapOrderEntryOwnerContext guess), it points at another
  // TTaskForce (the parent order this entry is queued under). TAdmiral's own
  // primary-order-node accessors (TAdmiral.cpp) read the same +0xc/+0x10/+0x14
  // shape off a TShip-typed primary order node.
  TTaskForce* owner;
  // Head of this entry's own child order-node chain (was opaque pad_10[0]).
  // Same TMapOrderChildLinkNode shape TNavyMission::orderList24 walks. When
  // `this` is referenced via a child's `owner` pointer, this is that child's
  // sibling list head (former TMapOrderEntryOwnerContext::head).
  TMapOrderChildLinkNode* childOrderList; // +0x10
  // Cached "preferred active child" pointer, recomputed by
  // RecomputeMapOrderChildAggregateMetric (0x553e30) folding
  // SelectPreferredMapOrderEntryByPriorityRules over childOrderList -- the
  // same role this plays for TAdmiral's primary-order owner and for a child's
  // `owner->activeChildEntry` (former TMapOrderEntryOwnerContext::active_node).
  TTaskForce* activeChildEntry; // +0x14
  // Copied from the source order node's own +0x08 field when this entry is
  // created (GetOrCreateMissionOrderEntryForNode, 0x5503a0); compared against
  // sibling nodes' own +0x08 field by ConsolidateMissionOrderEntriesByTarget-
  // AndQueue. Real pointee type unconfirmed (was opaque pad_10[8]).
  int contextAnchor; // +0x18
  s16 required_count;
  char pad_1e[0x02];
  int attached_entity;
  char pad_24[0x02];
  // Set to 1 by ComputeTaskForceOrderTieBreakScore (0x555c20) when this entry loses a
  // tie-break against a competing entry; checked by
  // ResolveTaskForceOrderConflictAndPickCandidate (0x555420) to short-circuit an
  // already-eliminated candidate (was pad_24[2]).
  char eliminatedFlag26;
  char pad_27;
  TTaskForce* queue_prev;
  TTaskForce* queue_next;
  s16 tiebreak_strength;
  char pad_32[0x02];

  TTaskForce();
  // Real constructor used when a task-force order entry is created for a specific
  // context/nation slot (CreateTaskForceFromNavyOrdersForNationIfEligible 0x560a78,
  // RebuildMapOrderEntryChildrenForContext 0x536dce). `contextAnchorArg` is an opaque
  // caller-supplied value stored verbatim into contextAnchor (its real pointee type
  // varies by caller -- see the contextAnchor field comment); `requiredCountArg` seeds
  // required_count.
  TTaskForce(int contextAnchorArg, short requiredCountArg);

  static TMapOrderChildLinkNode*
  DeleteMapOrderChildLinkAndReturnNext(TMapOrderChildLinkNode* child_link_node);
  static TMapOrderChildLinkNode*
  PruneDefeatedMapOrderChildrenAndReturnHead(TMapOrderChildLinkNode* child_link_head);

  void RelinkMapOrderQueueNodeBetween(TTaskForce* prev_node, TTaskForce* next_node);

  // Map-order selection helpers driven by TOcean::EnsureSelectedTaskForceForOrderOwnerAndRefresh.
  // 0x00552a70 — drops this task force's queued order nodes belonging to `nation` and
  // clears the selection state tied to `contextZone` (the selected map-order context).
  void RemoveTaskForceOrderNodesByNationAndClearSelectionState(int nation, TZone* contextZone);
  // 0x005528c0 — empty post-construction slot invoked thiscall (no args) by both
  // TTaskForce factory sites right after the ctor; the real body is a single ret.
  void NoOpTaskForceInitSlot();
  // 0x005548e0 — averages each child order entry's +0x10 slot and stores the rounded
  // result as a 32-bit value over this entry's order_type/order_strength dword. See the
  // .cpp: the +0x10 read semantics are unresolved, so the body is deferred.
  void RecomputeTaskForceAverageOrderScore();
  // 0x005539c0 — recomputes this task force's per-order selection flags for the active
  // nation's current orders (`mode` selects the pass; the caller passes 0).
  void RefreshTaskForceSelectionFlagsForCurrentNationOrders(int mode);
  void DecrementRequiredCount(short decrement);
  // 0x00553fe0 — frees the head child order node when defeated (required_count <= 0),
  // prunes remaining defeated children, rebinds childOrderList/activeChildEntry;
  // returns 1 (marking this entry eliminated) when no child survives.
  char PruneInactiveTaskForceOrderHead();
  // 0x00551100 — hands this order node to `nation` and rebinds the parent counters
  // (naval capture path).
  void ReassignOrderNodeNationAndRebindParentCounters(short nation);
  // Adds delta to tiebreak_strength, capped at 499.
  void AdjustMapOrderNodeStatCapped499(short delta); // 0x550370
  // Real target is the packed order_type/order_strength dword, not an owner pointer
  // despite the Ghidra-guessed name; only known caller (MissionSlot44's mode-1 branch)
  // passes 0, resetting both fields to a fresh-order state.
  void ResetOrderTypeAndStrengthDword(int packedValue); // 0x552f60
  TTaskForce* SelectPreferredMapOrderEntryByPriorityRules(TTaskForce* candidate,
                                                          int compareAttachedFlag);
  // `self` is the caller's own order entry, re-attached as `this` child's new owner
  // (see the RemoveNode body for the exact unlink/rebind sequence).
  void RemoveNode(TTaskForce* self);

  // Null-safe (returns true on null `this`). Sums 4 consecutive shorts spanning
  // pad_1e, attached_entity's two halves, and pad_24 -- the original reads this whole
  // +0x1e..+0x25 region as a flat 4-short block rather than per individual field.
  bool HasNoMapOrderEntryChildrenQueued(); // 0x553b10
  // Null-safe (returns true on null `this`). Same +0x1e..+0x25 sum check as
  // HasNoMapOrderEntryChildrenQueued short-circuits to true; otherwise scans
  // childOrderList for any active entry. The "found" path returns the node pointer
  // itself (mask is a no-op for an aligned allocation) rather than a clean bool --
  // preserved raw since no confirmed caller needs more than a non-zero test.
  unsigned int HasActiveMapOrderEntryChildren(); // 0x553b50
  // This entry's 0-based rank among g_pNavyOrderManager->orderListHead04 entries
  // sharing the same required_count value; -1 if `this` is null or not found in the
  // queue.
  int GetNavyOrderRankWithinNationBucket(); // 0x5563d0
  // Clears this order's map marker tile if one is set (tiebreak_strength != -1).
  void ClearNavyOrderMapMarker(); // 0x5564f0
  // Walks the queue_next chain starting at `this`, clearing eliminatedFlag26 on each
  // node.
  void ClearMapOrderProcessedFlagsChain(); // 0x557870

  // Builds a localized selection-overlay label ("<N> <unit(s)> <terrain owner> at
  // <context> (<order kind>)") via scanBracketExpressions' bracket-template expander.
  // Bracket substitutions: singular/plural unit template (string group 0x2762, index
  // 0x11/0x12), g_apTerrainTypeDescriptorTable[required_count]'s terrain/nation name,
  // contextAnchor's (real TZone*, see TMapOrderEntryOwnerContext note above)
  // AssignZoneDisplayNameToOutputRef label, the decimal child count, and the
  // order-kind label (string group 0x2762, index attachment+0x13). 0x554c90.
  // Used by BuildMapOrderBattleSideSnapshot for its overlay label field.
  void BuildTaskForceSelectionOverlayLabelText(CString* out); // 0x554c90

  // Per-entry candidate score blending this order's tiebreak_strength bucket against
  // its resource-type's navy-priority/resolve/calculate/task-force weight columns
  // (g_NavyOrderResourceDescriptorTable[order_type]) plus required_count. Used by the
  // order-selection cluster to rank candidate task-force order entries.
  // Simplified single-term variant of ComputeMapOrderEntryHeuristicScore. 0x550840.
  int ComputeOrderNodeDerivedScoreFromQuantityAndWord18();
  int ComputeMapOrderEntryHeuristicScore(); // 0x550aa0

  // Weighted 4-category priority score for the given score profile: sums each
  // category's ComputeNavyOrderPriorityContributionPercentByCategory contribution
  // (over this entry's order_type/required_count/tiebreak_strength) scaled by the
  // profile's per-category weight row in g_Populate_Beachhead_Mission_LookupTable
  // (4 shorts per profile). Called by TScatteredShipsMission::QueueMissionOrders-
  // ByPriorityForContext with profile 3 to pick the top child order entry.
  int CalculateMissionOrderPriorityScore(int nScoreProfileId); // 0x5501b0

  // Number of childOrderList entries; null-safe on `this` (returns 0), matching a call
  // site that invokes it without checking for a null receiver first.
  int GetMapOrderEntryChildCount(); // 0x5562c0

  // Minimum resource-type descriptorWeight across active childOrderList entries;
  // returns 0 if none are active (used as a gating predicate for map-order actions).
  unsigned int GetMinActionThresholdFromEntryChildren(); // 0x554a80

  // Finds the childOrderList entry whose object_ptr == targetOrderObject (head fast-path,
  // else FindNodeMatching from the second node) and, if found, sets its active_flag; when
  // the flag is nonzero also clears targetOrderObject's +0x34 dword (same idiom as
  // SetTaskForceOrderSelectionByNationClassAndFlag).
  void SetTaskForceOrderSelectionByNodeId(TTaskForce* targetOrderObject,
                                          char activeFlag); // 0x5549a0

  // Counts active childOrderList entries whose descriptor enabledFlagOrBucketOffset
  // (low short, reused here as a nation/bucket class) equals nationClass.
  int CountTaskForceSelectedOrdersByNationClass(short nationClass); // 0x554a30

  // Average (x10) of the resource-type descriptorWeight column across active
  // childOrderList entries; 0 if none are active.
  int CalculateMapOrderEntryAverageChildRatingX10(); // 0x554ad0

  // Sum of ComputeMapOrderEntryHeuristicScore() over every childOrderList entry (each
  // entry's own order_type/tiebreak_strength/required_count, not this entry's own).
  int ComputeTaskForceOrderAggregateScore(); // 0x556010

  // Compares this entry's best (lowest descriptorWeight) active child against `other`'s
  // average active-child rating; rolls against the gap to decide a tie-break winner.
  // On a loss, marks `this` (not `other`) eliminated (eliminatedFlag26 = 1) and returns
  // 1; else returns 0. Only the low byte of the original's return value is ever
  // consulted by callers, so this is modeled returning char rather than int.
  char ComputeTaskForceOrderTieBreakScore(TTaskForce* other); // 0x555c20

  // this->ComputeTaskForceOrderAggregateScore()*100 < kOrderTypePriorityWeight[order_type] *
  // other->ComputeTaskForceOrderAggregateScore(). Same per-order-type {200,100,50}
  // weight table ResolveTaskForceOrderConflictAndPickCandidate uses.
  char IsTaskForceOrderMixWithinPriorityThresholds(TTaskForce* other); // 0x555de0

  // Top-level task-force order-conflict resolver: bails if either side has no active
  // children; force-attempts resolution for type-5/6 attachments, else rolls against a
  // priority-gap threshold (childRating average delta + child-count overflow); if
  // attempted, compares aggregate scores (weighted by kOrderTypePriorityWeight) both
  // ways and falls back to ComputeTaskForceOrderTieBreakScore on a near-tie; on a
  // resolved conflict with both sides still non-empty, returns true immediately if
  // either side is the active nation (when g_pSimMgr->preferenceValues[3] is set), else
  // hands off to TNavyMgr::ResolveMapOrderPairConflictStep and returns false.
  char ResolveTaskForceOrderConflictAndPickCandidate(TTaskForce* other); // 0x555420

  // Low word of this order's resource-type enabledFlagOrBucketOffset column (same field
  // RemoveNode reads as a bucket_offset).
  short GetOrderNodeDescriptorWord20ByResourceType(); // 0x550510
  // This order's resource-type calculateWeight column.
  short GetOrderNodeDescriptorWord0CByResourceType(); // 0x550820

  // Marks every active childOrderList entry's order node (object_ptr+0x34 -- same
  // out-of-bounds write documented on FindOrCreateChildOrderLink) with a 1-or-2
  // selection-mode code depending on `reserveExtraSlot`, then scans the global primary
  // navy order list (g_pNavyPrimaryOrderListHead) for TShip nodes matching this entry's
  // contextAnchor/required_count and re-attaches each one via FindOrCreateChildOrderLink,
  // and finally recomputes each childOrderList entry's active_flag from whether its
  // node+0x34 slot was left at 0.
  void ApplyTaskForceSelectionModeForCurrentNationOrders(char reserveExtraSlot); // 0x553a50

  // Finds the first childOrderList entry whose order node's resource-type bucket
  // (g_NavyOrderResourceDescriptorTable[...].enabledFlagOrBucketOffset, low word) equals
  // `nationClass` and whose active_flag differs from `activeFlag`; sets that entry's
  // active_flag and, when activating (activeFlag != 0), clears its order node's +0x34
  // slot (same overrun as above).
  void SetTaskForceOrderSelectionByNationClassAndFlag(short nationClass,
                                                      char activeFlag); // 0x554930

  // Recursively destroys the whole queue_next chain (tail-first: recurses before
  // freeing `this`) then Free()s `this`. Deliberately null-safe on `this` itself --
  // callers (e.g. a manager's own Free()) invoke it on a possibly-null queue head
  // without checking first, matching the original's `test esi,esi; jz` guard.
  void DestroyNavyOrderAndChildren(); // 0x556820

  // Sets owner (was misread as "active child entry"); when newEntry is
  // non-null it AssertValid()s newEntry, copies newEntry's packed
  // order_type/order_strength dword into this entry's dual-purpose +0x10 slot,
  // and clears the +0x34 overrun word unless newEntry's kind is 0/4/7/8. The
  // bd 1uj.16 target cluster only ever calls it with nullptr.
  void SetMapOrderActiveChildEntry(TTaskForce* newEntry); // 0x551220

  // Folds SelectPreferredMapOrderEntryByPriorityRules over childOrderList into
  // activeChildEntry (bd 1uj.16 target cluster).
  void RecomputeMapOrderChildAggregateMetric(); // 0x553e30

  // bd 1uj.16 target: sets attachment=9 (map-order kind 9), frees any
  // childOrderList entries whose owning link is inactive, recomputes
  // activeChildEntry, then either self-Frees (no live children) or
  // (re)inserts `this` at the head of g_pNavyOrderManager->orderListHead04
  // and notifies g_pActiveMapOrderContext.
  void SetMapOrderType9AndQueue(); // 0x552f80

  // Opens by re-seeding the zone-graph BFS distance levels from `pContextAnchor`
  // (TZone::PropagateMapActionContextDistanceLevelsRecursive(-1), via ILT thunk
  // 0x4081cf -- this resolved the `owner` field's TZone identity for this call
  // site: `owner` (this+0xc) is read/written here with TZone's own
  // primaryNeighbors stretch shape (vfptr/data/capacity/count at
  // owner+0x24/+0x28/+0x2c/+0x30, matching TZonePrimaryNeighborStretch exactly)
  // and TZone::field44 (owner+0x44)). Then walks owner->primaryNeighbors
  // looking for a neighbor whose BFS distance (field44) beats owner's own,
  // promoting the first such neighbor found to be the new `owner`; finally the
  // same free-childOrderList / recompute / self-Free-or-queue tail as
  // SetMapOrderType9AndQueue.
  void PromoteMapOrderChainAndQueue(TZone* pContextAnchor); // 0x5533f0

  // bd 1uj.16.2/1uj.16.5 target: sibling of SetMapOrderType9AndQueue for map-order kind
  // 6 (port-zone blockade orders) -- stores `nOrderTarget` into the dual-purpose `owner`
  // slot (same pun PromoteMapOrderChainAndQueue uses for `contextAnchor`), sets
  // attachment=6, then the identical free-inactive-children / recompute /
  // self-Free-or-queue tail as SetMapOrderType9AndQueue. Ghidra/symbols.csv mis-attribute
  // this to TControlSeaZoneMission, but its body only ever reads TTaskForce's own field
  // offsets (owner/attachment/childOrderList/activeChildEntry/bucket-count region) --
  // real owner is TTaskForce, called from TControlSeaZoneMission::NoOpSlot9C (0x539640)
  // and TBlockadePortMission::NoOpSlot9C (0x53ba40, "QueueMapOrderType6FromContext
  // Pointer") on the map-order entry passed to that virtual slot.
  void SetMapOrderType6AndQueue(int nOrderTarget); // 0x5536c0

  // bd 1uj.16.2 target: another SetMapOrderType9AndQueue sibling, for map-order kind 3
  // (fUseType4 == 0) or 4 (fUseType4 != 0); does not touch `owner`. Same mis-attribution
  // to a free function as SetMapOrderType6AndQueue -- real owner is TTaskForce (body only
  // reads this class's own field offsets). Called from TControlSeaZoneMission::NoOpSlot9C
  // when no matching port-zone context was found.
  void SetMapOrderType3Or4AndQueue(char fUseType4); // 0x5530f0

  // Called from RemoveNode's tail (0x550ff0, via ILT thunk 0x4027de) with
  // RemoveNode's `self` argument re-attached as `node`'s new owner, and from
  // ApplyTaskForceSelectionModeForCurrentNationOrders for each stale TShip
  // primary-order node matching this entry's contextAnchor/required_count.
  // Searches childOrderList for an existing link to `node`; if none exists,
  // allocates (operator new, 0x606f73) and inserts a new TMapOrderChildLinkNode
  // in priority-sorted order (by g_NavyOrderResourceDescriptorTable[order_type]
  // .enabledFlagOrBucketOffset), bumps this entry's bucket counter, sets
  // node->owner = this, then calls this->AssertValid() (CObject virtual, slot
  // 0xc) and copies this entry's own packed order_type/order_strength dword and
  // attachment-kind gate onto `node` -- the same fields/gate
  // SetMapOrderActiveChildEntry applies, just with `this` playing the role of
  // that method's `newEntry` parameter (bd 1uj.16.1).
  void FindOrCreateChildOrderLink(TTaskForce* node); // 0x553bc0
};

ASSERT_SIZE(TTaskForce, 0x34);
