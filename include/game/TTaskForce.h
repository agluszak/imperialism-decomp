#pragma once

#include "compat.h"
#include "decomp_types.h"
#include "game/TObject.h"
#include "game/mfc.h"
#include "game/TMapOrderChildLinkNode.h"

class TTaskForce;
class TStream;
class CString;
class TZone;
class TShip;
struct TGlobalMapCityScoreRecord;

// The former TMapOrderEntryOwnerContext placeholder struct (this comment block
// used to sit here) is gone: bd 1uj.16.1 resolved FindOrCreateChildOrderLink's
// receiver to be TTaskForce itself (the parent order entry), not a distinct
// manager class -- see FindOrCreateChildOrderLink's own declaration. The `owner`
// slot (+0x0c) that was previously flagged UNRESOLVED is now modeled as the
// attachment-keyed union TMapOrderContext (see the field comment below); a full
// writer/receiver disassembly inventory confirmed the discriminator mapping and
// found no wrong-receiver/wrong-offset defect.

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
  // +0x0c order-context payload: a discriminated variant keyed by `attachment` (+0x08).
  // The order-entry machinery reuses this one 4-byte slot for the order's context object,
  // whose concrete type depends on the order kind:
  //   attachment 1/2/3/4/6 -> asZone       (map/port-zone context; walked through the zone
  //                           neighbor graph in PromoteMapOrderChainAndQueue, dispatched via
  //                           TZone vtable slot 0x4c in UpdateNavyOrderMapMarkerByOrderType)
  //   attachment 5         -> asCityTarget (record in the 384-entry city-score table; its
  //                           +0xa1 owner-nation flag is read by ApplyMapOrderTypeExecution-
  //                           Effects, and GetCityIndexFromCityStatePointer resolves it)
  //   attachment 9 / 0     -> null (SetMapOrderType9AndQueue never writes it; ctor nulls it)
  // Proven a real tagged union (not incidental reuse) by WriteTo/ReadFrom (0x552b90/
  // 0x552d10), which serialize THIS slot two different ways depending on attachment==5 (a
  // city-table index) vs otherwise (a generic CObject reference). Every reader/writer
  // touches [this+0xc] as one 4-byte pointer, so the members alias at offset 0 and codegen
  // is identical to the former raw pointer.
  union TMapOrderContext {
    TZone* asZone;
    TGlobalMapCityScoreRecord* asCityTarget;
    int raw; // packed set-path value / pointer-identity compares
  } owner;
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
  TShip* activeChildEntry; // +0x14
  // +0x18 map-action context zone. Unlike `owner`, this is NOT a tagged variant: every
  // writer stores a zone/context and every reader treats it as TZone* -- equality vs a
  // primary order node's own +0x08 (TShip::field08, a TZone*), and vtable dispatch through
  // TZone slots 0x2c (AssignZoneDisplayName), 0x38, 0x4c (tile search) and 0x54 (coastal
  // heuristic). Serialized as a single CObject reference regardless of attachment. Seeded
  // from the source order node's +0x08 when the entry is created (0x5503a0); the 2-arg ctor
  // takes the real TZone* directly.
  TZone* contextAnchor; // +0x18
  s16 required_count;
  // +0x1e..+0x25: total ships available in each of the four UI classes. Every writer
  // indexes this region with the resource descriptor's bucket and every reader treats
  // it as the same flat four-short array; RefreshMapOrderEntryPanel feeds these values
  // to the Mac-evidenced cls0..cls3 TShipFractionCluster controls.
  short shipCountsByClass[4];
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
  // TNavyMission::CombineForce 0x536dce). `requiredCountArg` seeds required_count.
  TTaskForce(TZone* contextAnchorArg, short requiredCountArg);

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
  // 0x00553fe0 — frees the head child order node when defeated (required_count <= 0),
  // prunes remaining defeated children, rebinds childOrderList/activeChildEntry;
  // returns 1 (marking this entry eliminated) when no child survives.
  char PruneInactiveTaskForceOrderHead();
  // Real target is the packed order_type/order_strength dword, not an owner pointer
  // despite the Ghidra-guessed name; only known caller (GiveOrders's mode-1 branch)
  // passes 0, resetting both fields to a fresh-order state.
  void ResetOrderTypeAndStrengthDword(int packedValue); // 0x552f60
  // 0x554660 -- drops inactive children (owner cleared, bucket counter decremented,
  // node unlinked+freed), refolds activeChildEntry, then moves this entry to the head
  // of g_pNavyOrderManager's queue (or Free()s it when no children survive) and
  // finalizes through g_pActiveMapOrderContext.
  void RequeueMapOrderEntry();

  // Null-safe (returns true on null `this`). Sums shipCountsByClass.
  bool HasNoMapOrderEntryChildrenQueued(); // 0x553b10
  // Null-safe (returns true on null `this`). Same +0x1e..+0x25 sum check as
  // HasNoMapOrderEntryChildrenQueued short-circuits to true; otherwise scans
  // childOrderList for any active entry. The "found" path returns the node pointer
  // itself (mask is a no-op for an aligned allocation) rather than a clean bool --
  // preserved raw since no confirmed caller needs more than a non-zero test.
  unsigned int HasActiveMapOrderEntryChildren(); // 0x553b50
  // 0x00554460 -- province-context command resolver (returns 0x10 or 1); asks the
  // diplomacy manager about this entry's required_count nation vs the province's owner.
  char ResolveMapOrderCommandFromProvinceContext(void* province);
  // 0x00554590 -- returns the province's +0xa0 eligibility byte when this entry has an
  // active queued child, else 0.
  unsigned int CanQueueMapOrderForProvinceContext(void* province);
  // 0x00554300 -- action-context command resolver (0x0C/0x0D/0x0E/0x0F, fallback 1) from
  // this entry's contextAnchor zone and a candidate context zone's capability slots.
  int ResolveMapOrderCommandFromActionContext(TZone* candidate);
  // This entry's 0-based rank among g_pNavyOrderManager->orderListHead04 entries
  // sharing the same required_count value; -1 if `this` is null or not found in the
  // queue.
  int GetNavyOrderRankWithinNationBucket(); // 0x5563d0
  // Clears this order's map marker tile if one is set (tiebreak_strength != -1).
  void ClearNavyOrderMapMarker(); // 0x5564f0
  // Recomputes and repaints this order's map-tile marker from its `attachment` kind,
  // dispatching through the order's zone (owner/contextAnchor as TZone) tile-search
  // virtuals; called on a TTaskForce entry by FinalizeQueuedMapOrderEntry and ReadFrom.
  void UpdateNavyOrderMapMarkerByOrderType(); // 0x556410
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

  // Mac oracle: TTaskForce::GetCompositionDescription(CStr255&) const. Counts the
  // child ships by resource type and joins the localized, pluralized labels.
  void GetCompositionDescription(CString* out) const; // 0x554b20
  // Mac oracle: TTaskForce::GetGeneralDescription(CStr255&) const. Builds the concise
  // "fleet of N <current order>" status line used outside the detailed overlay.
  void GetGeneralDescription(CString* out) const; // 0x554e70
  // Mac oracle: GetAuthority / CancelOrders. GetAuthority names the admiral or
  // captain commanding activeChildEntry; CancelOrders removes this queue entry.
  void GetAuthority(CString* out) const;             // 0x5551d0
  void CancelOrders(unsigned char cancellationMode); // 0x5547d0

  // Null-safe tail-recursive queue_next walk used by ResolveMapOrderChainsForTurnPhase
  // to rebuild the order queue head: prunes (Free()s) any entry with no active children,
  // or a live entry whose order_type is 0/1/4/7/8, or (order_type == 5) whose target
  // city's diplomacy relation stamp with this entry's nation is out of date; every
  // other live entry survives. Always recurses into queue_next first regardless of
  // outcome. 0x555090.
  TTaskForce* PruneNavyOrderIfUnserviceableOrNoChildren();

  // Per-entry candidate score blending this order's tiebreak_strength bucket against
  // its resource-type's navy-priority/resolve/calculate/task-force weight columns
  // (g_NavyOrderResourceDescriptorTable[order_type]) plus required_count. Used by the
  // order-selection cluster to rank candidate task-force order entries.
  // Simplified single-term variant of ComputeMapOrderEntryHeuristicScore. 0x550840.

  // Weighted 4-category priority score for the given score profile: sums each
  // category's ComputeNavyOrderPriorityContributionPercentByCategory contribution
  // (over this entry's order_type/required_count/tiebreak_strength) scaled by the
  // profile's per-category weight row in g_Populate_Beachhead_Mission_LookupTable
  // (4 shorts per profile). Called by TScatteredShipsMission::QueueMissionOrders-

  // Number of childOrderList entries; null-safe on `this` (returns 0), matching a call
  // site that invokes it without checking for a null receiver first.
  int GetMapOrderEntryChildCount(); // 0x5562c0

  // Minimum resource-type descriptorWeight across active childOrderList entries;
  // returns 0 if none are active (used as a gating predicate for map-order actions).
  unsigned int GetMinActionThresholdFromEntryChildren(); // 0x554a80

  // Finds the childOrderList entry whose payload == targetOrderObject (head fast-path,
  // else FindNodeMatching from the second node) and, if found, sets its active; when
  // the flag is nonzero also clears targetOrderObject's +0x34 dword (same idiom as
  // SetTaskForceOrderSelectionByNationClassAndFlag).
  void SetTaskForceOrderSelectionByNodeId(TObject* targetOrderObject,
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

  // Immediate/deferred execution effects for a resolved queue entry
  // (ResolveMapOrderChainsForTurnPhase's tail passes): no-op once already eliminated.
  // Type 1 propagates the raw `owner` payload value into every active child's own
  // attachment field. Type 5 sets the target city's owner-flag bit
  // for this entry's nation and, in single-player mode, invalidates that city's redraw.
  // Type 8 advances every active child's required_count by a quarter-step toward its
  // resource-type's stockCap. Any other type asserts once, then (except type 1) marks
  // this entry processed.
  void ApplyMapOrderTypeExecutionEffects(); // 0x556100

  // Compares this entry's best (lowest descriptorWeight) active child against `other`'s
  // average active-child rating; rolls against the gap to decide a tie-break winner.
  // On a loss, marks `this` (not `other`) eliminated (eliminatedFlag26 = 1) and returns
  // 1; else returns 0. Only the low byte of the original's return value is ever
  // consulted by callers, so this is modeled returning char rather than int.
  char ComputeTaskForceOrderTieBreakScore(TTaskForce* other); // 0x555c20

  // Sub-step of ResolveMapOrderChainsForTurnPhase's pairwise resolution pass (called
  // after the caller's own ShouldAttemptMapOrderPairResolution gate): bails (0) if
  // either side has no active children; if the active nation preference is set and
  // owns either side, returns 1 without resolving; otherwise hands off to
  // g_pNavyOrderManager->ResolveMapOrderPairConflictStep(this, other), clears
  // *pResolvedFlag to signal the caller a resolution happened, and returns 0.
  char TryResolveMapOrderEntryPairExecution(TTaskForce* other, int* pResolvedFlag); // 0x555d10

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

  // Standalone sibling of the identical inline "shouldAttempt" computation in
  // ResolveTaskForceOrderConflictAndPickCandidate: bails if either side has no active
  // children; force-attempts for type-5/6 attachments; else rolls against a priority-gap
  // threshold (childRating average delta + child-count overflow past 10).
  char ShouldAttemptMapOrderPairResolution(TTaskForce* other); // 0x555720

  // Direct sibling of ResolveTaskForceOrderConflictAndPickCandidate/ComputeTaskForceOrder-
  // TieBreakScore -- same per-order-type {200,100,50} weighted-heuristic-sum comparison,
  // checked both ways, but with its own inline elimination roll (not a call to either
  // sibling): whichever side's ComputeMapOrderEntryHeuristicScore-summed heuristic total
  // is priority-weighted weaker gets one shot at elimination (gap between the OTHER
  // side's best active child and this side's average active-child rating), and only when
  // the reciprocal aggregate-score check doesn't already favor it and it isn't already
  // eliminated. Returns 0 when `this` or `other` gets eliminatedFlag26 set (or the
  // reciprocal check bails early), 1 when no elimination happens.
  char TryMarkLosingMapOrderEntryFromForceBalance(TTaskForce* other); // 0x555920

  // Low word of this order's resource-type enabledFlagOrBucketOffset column (same field
  // RemoveNode reads as a bucket_offset).
  // This order's resource-type calculateWeight column.

  // Marks every active childOrderList entry's order node (payload+0x34 -- same
  // out-of-bounds write documented on FindOrCreateChildOrderLink) with a 1-or-2
  // selection-mode code depending on `reserveExtraSlot`, then scans the global primary
  // navy order list (g_pNavyPrimaryOrderListHead) for TShip nodes matching this entry's
  // contextAnchor/required_count and re-attaches each one via FindOrCreateChildOrderLink,
  // and finally recomputes each childOrderList entry's active from whether its
  // node+0x34 slot was left at 0.
  void ApplyTaskForceSelectionModeForCurrentNationOrders(char reserveExtraSlot); // 0x553a50

  // Finds the first childOrderList entry whose order node's resource-type bucket
  // (g_NavyOrderResourceDescriptorTable[...].enabledFlagOrBucketOffset, low word) equals
  // `nationClass` and whose active differs from `activeFlag`; sets that entry's
  // active and, when activating (activeFlag != 0), clears its order node's +0x34
  // slot (same overrun as above).
  void SetTaskForceOrderSelectionByNationClassAndFlag(short nationClass,
                                                      char activeFlag); // 0x554930

  // Recursively destroys the whole queue_next chain (tail-first: recurses before
  // freeing `this`) then Free()s `this`. Deliberately null-safe on `this` itself --
  // callers (e.g. a manager's own Free()) invoke it on a possibly-null queue head
  // without checking first, matching the original's `test esi,esi; jz` guard.
  void DestroyNavyOrderAndChildren(); // 0x556820

  // Folds SelectPreferredMapOrderEntryByPriorityRules over childOrderList into
  // activeChildEntry (bd 1uj.16 target cluster).
  void RecomputeMapOrderChildAggregateMetric(); // 0x553e30

  // Removes every childOrderList entry whose link node is inactive (unlink + delete,
  // clearing the freed entry's owner and decrementing its resource-type bucket counter
  // -- same +0x1e-based bucket region ApplyTaskForceSelectionModeForCurrentNationOrders /
  // PruneInactiveTaskForceOrderHead use), then recomputes activeChildEntry over the
  // survivors. The original inlines both passes here rather than calling
  // RecomputeMapOrderChildAggregateMetric for the second pass.
  void RebuildMapOrderEntryChildren(); // 0x553f10

  // Mac oracle: Remove(TShip*). Removes the ship's child link, updates its class
  // count and the preferred-child cache, then clears the ship's owner backlink.
  void Remove(TShip* ship); // 0x553d40

  // Mac oracle: SubmitOrders(eShipOrders, void*). The Windows ABI passes both values
  // as dwords; orderArgument is the attachment-specific zone/city context payload.
  void SubmitOrders(int orderType, int orderArgument); // 0x5540b0

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
  // 6 (port-zone blockade orders) -- stores `nOrderTarget` (a port-zone TZone* passed as an
  // opaque value) into the `owner` variant via owner.raw, read back as owner.asZone under
  // attachment 6, sets
  // attachment=6, then the identical free-inactive-children / recompute /
  // self-Free-or-queue tail as SetMapOrderType9AndQueue. Ghidra/symbols.csv mis-attribute
  // this to TControlSeaZoneMission, but its body only ever reads TTaskForce's own field
  // offsets (owner/attachment/childOrderList/activeChildEntry/bucket-count region) --
  // real owner is TTaskForce, called from TControlSeaZoneMission::GiveActionOrders (0x539640)
  // and TBlockadePortMission::GiveActionOrders (0x53ba40, "QueueMapOrderType6FromContext
  // Pointer") on the map-order entry passed to that virtual slot.
  void SetMapOrderType6AndQueue(int nOrderTarget); // 0x5536c0

  // Sibling of SetMapOrderType6AndQueue for map-order kind 5 -- byte-identical body except
  // it stores attachment=5 instead of 6 (owner=nOrderTarget, activeChildEntry=null, same
  // free-inactive-children / recompute / self-Free-or-queue tail). Ghidra/symbols.csv model
  // it as a free __thiscall function; real owner is TTaskForce (body reads only this class's
  // own field offsets).
  void SetMapOrderType5AndQueue(int nOrderTarget); // 0x553840

  // bd 1uj.16.2 target: another SetMapOrderType9AndQueue sibling, for map-order kind 3
  // (fUseType4 == 0) or 4 (fUseType4 != 0); does not touch `owner`. Same mis-attribution
  // to a free function as SetMapOrderType6AndQueue -- real owner is TTaskForce (body only
  // reads this class's own field offsets). Called from TControlSeaZoneMission::GiveActionOrders
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
  // TShip::SetOwnerOrderEntryAndCacheType applies, just with `this` playing the role of
  // that method's `newEntry` parameter (bd 1uj.16.1).
  void FindOrCreateChildOrderLink(TShip* node); // 0x553bc0
};

ASSERT_SIZE(TTaskForce, 0x34);
