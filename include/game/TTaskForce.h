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
};

ASSERT_SIZE(TMapOrderChildLinkNode, 0x10);

// Per-owner bucket table for active map-order entries (Ghidra: ObjectPoolOwner).
// NOTE (bd 1uj.16 follow-up): the internal shape past +0x18 is still under
// investigation. TTaskForce::RemoveNode (0x550ff0) relies on the
// {head@0x10, active_node@0x14, bucket_counts_base@0x18} reading used here, but
// TTaskForce::PromoteMapOrderChainAndQueue (0x5533f0) separately reads a
// stretch<T>-shaped growable array (data/capacity/count at +0x28/+0x2c/+0x30,
// realloc'd via the same 0x5e7fc0 helper TZone's primary/secondaryNeighbors use)
// plus a short comparison field at +0x44 off the SAME owner pointer -- a shape
// that does not obviously square with a flat 0x100-byte bucket-count table
// starting at +0x18. Left opaque pending a dedicated class-recovery pass rather
// than guessing a layout that could silently corrupt the already-working
// TTaskForce::RemoveNode / TAdmiral.cpp accessors.
struct TMapOrderEntryOwnerContext {
  char pad_00[0x10];
  TMapOrderChildLinkNode* head;
  TTaskForce* active_node;
  char bucket_counts_base[0x100];

  // Called from TTaskForce::RemoveNode's tail (0x550ff0, via ILT thunk
  // 0x4027de) with RemoveNode's own `self` int parameter reinterpreted as
  // this receiver -- confirmed __thiscall via ECX=this register evidence
  // (0x553bc0 immediately does `mov edi, ecx`), and this receiver's own
  // +0x10/+0x14 fields are read/compared exactly like head/active_node here.
  // Searches head for an existing link to `node`; if none exists, allocates
  // (operator new, 0x606f73) and inserts a new TMapOrderChildLinkNode in
  // priority-sorted order (via a lookup table at 0x698120), bumps a bucket
  // counter, and then makes a virtual dispatch through this receiver's own
  // (still-uncharted) vtable whose consequences are not yet understood --
  // including a write at node+0x34, past TTaskForce's own 0x34-byte size,
  // that is only reached when this receiver's own +0x8 field takes an
  // uncommon value. Left `// TODO: promote body` rather than guess at the
  // owner's own polymorphic identity; see bd 1uj.16 follow-up notes.
  void FindOrCreateChildOrderLink(TTaskForce* node); // 0x553bc0
};

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
  // cityRecordPtr) by TNavyMgr's order filter, and as a
  // TMapOrderEntryOwnerContext* by RemoveNode -- an opaque per-order owner/
  // target-context pointer whose real class is still unconfirmed.
  TMapOrderEntryOwnerContext* owner;
  // Head of this entry's own child order-node chain (was opaque pad_10[0]).
  // Same TMapOrderChildLinkNode shape TNavyMission::orderList24 walks.
  TMapOrderChildLinkNode* childOrderList; // +0x10
  // Cached "preferred active child" pointer, recomputed by
  // RecomputeMapOrderChildAggregateMetric (0x553e30) folding
  // SelectPreferredMapOrderEntryByPriorityRules over childOrderList -- the
  // same role TMapOrderEntryOwnerContext::active_node plays for TAdmiral's
  // primary-order owner (was opaque pad_10[4]).
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

  static TMapOrderChildLinkNode* FindMissionOrderNodeById(TMapOrderChildLinkNode* node,
                                                          TTaskForce* child_node);
  static TMapOrderChildLinkNode*
  DeleteMapOrderChildLinkAndReturnNext(TMapOrderChildLinkNode* child_link_node);
  static void RemoveLinkedOrderNodeByValueRecursive(TMapOrderChildLinkNode* node,
                                                    TTaskForce* child_node);
  static TMapOrderChildLinkNode* CreateLinkedOrderNode(TMapOrderChildLinkNode* next_node,
                                                       TTaskForce* child_node);
  static TMapOrderChildLinkNode*
  PruneDefeatedMapOrderChildrenAndReturnHead(TMapOrderChildLinkNode* child_link_head);

  void RelinkMapOrderQueueNodeBetween(TTaskForce* prev_node, TTaskForce* next_node);

  // Map-order selection helpers driven by TOcean::EnsureSelectedTaskForceForOrderOwnerAndRefresh.
  // 0x00552a70 — drops this task force's queued order nodes belonging to `nation` and
  // clears the selection state tied to `contextZone` (the selected map-order context).
  void RemoveTaskForceOrderNodesByNationAndClearSelectionState(int nation, TZone* contextZone);
  // 0x005539c0 — recomputes this task force's per-order selection flags for the active
  // nation's current orders (`mode` selects the pass; the caller passes 0).
  void RefreshTaskForceSelectionFlagsForCurrentNationOrders(int mode);
  void DecrementRequiredCount(short decrement);
  // 0x00553fe0 — drops the order-list head entries that are no longer active. Body TODO.
  void PruneInactiveTaskForceOrderHead();
  // 0x00551100 — hands this order node to `nation` and rebinds the parent counters
  // (naval capture path). Body TODO.
  void ReassignOrderNodeNationAndRebindParentCounters(short nation);
  // Adds delta to tiebreak_strength, capped at 499.
  void AdjustMapOrderNodeStatCapped499(short delta); // 0x550370
  // Real target is the packed order_type/order_strength dword, not an owner pointer
  // despite the Ghidra-guessed name; only known caller (MissionSlot44's mode-1 branch)
  // passes 0, resetting both fields to a fresh-order state.
  void ResetOrderTypeAndStrengthDword(int packedValue); // 0x552f60
  TTaskForce* SelectPreferredMapOrderEntryByPriorityRules(TTaskForce* candidate,
                                                          int compareAttachedFlag);
  void RemoveNode(int self);

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

  // Builds a localized selection-overlay label describing this task-force order entry
  // (nation name + attachment count) via g_pLocalizationTable's format-string expander.
  // 0x554c90, 370 bytes. TODO: port body -- the exact resource-string IDs and format
  // args aren't recovered yet; used by BuildMapOrderBattleSideSnapshot for its overlay
  // label field, which only needs a real, correctly-typed call site.
  void BuildTaskForceSelectionOverlayLabelText(CString* out); // 0x554c90

  // Per-entry candidate score blending this order's tiebreak_strength bucket against
  // its resource-type's navy-priority/resolve/calculate/task-force weight columns
  // (g_NavyOrderResourceDescriptorTable[order_type]) plus required_count. Used by the
  // order-selection cluster to rank candidate task-force order entries.
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
  // out-of-bounds write documented on TMapOrderEntryOwnerContext::FindOrCreateChildOrderLink)
  // with a 1-or-2 selection-mode code depending on `reserveExtraSlot`, then scans the
  // global primary navy order list (g_pNavyPrimaryOrderListHead) for TShip nodes
  // matching this entry's contextAnchor/required_count and re-attaches each one via the
  // same `this`-as-TMapOrderEntryOwnerContext reinterpretation RemoveNode's tail uses,
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
  // non-null also touches a still-unrecovered dual-purpose region at +0x10
  // (see bd 1uj.16 follow-up notes). Only ever called with nullptr by the
  // bd 1uj.16 target cluster.
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

  // bd 1uj.16 target: candidate-promotion pass over `owner`'s still-uncharted
  // growable-array region (see TMapOrderEntryOwnerContext note above), then
  // the same free-childOrderList / recompute / self-Free-or-queue tail as
  // SetMapOrderType9AndQueue. The candidate-search body (owner's array) is
  // left `// TODO: promote body` pending that follow-up class-recovery pass;
  // the tail is ported for real.
  void PromoteMapOrderChainAndQueue(void* pContextAnchor); // 0x5533f0
};

ASSERT_SIZE(TTaskForce, 0x34);
