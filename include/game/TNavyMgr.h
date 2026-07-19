#pragma once

#include "game/global_data_tables.h"

class TStream;
class TTaskForce;

// Result buffer filled by SelectEligibleMapOrderInteractionForNationAndContext for the
// first eligible queued interaction: the offering nation code, the packed exchange-
// direction flags (low 2 bits), and the chosen order entry.
struct TMapOrderInteractionSelection {
  short offerNationCode;       // +0x00
  short pad02;                 // +0x02
  unsigned int directionFlags; // +0x04 packed direction bits (bit0/bit1)
  TTaskForce* selectedEntry;   // +0x08
};

// VTABLE: IMPERIALISM 0x0065c4c8
class TNavyMgr : public TObject {
public:
  DECLARE_DYNCREATE(TNavyMgr)
  virtual ~TNavyMgr() override; // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  virtual void WriteTo(TStream* stream) override;  // slot 0x05 0x5568c0
  virtual void ReadFrom(TStream* stream) override; // slot 0x06 0x556aa0
  virtual void Free() override;                    // slot 0x07 0x5567a0
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  // Head of the global task-force order queue (was `void*`; retyped once
  // TTaskForce -- née TMapOrderEntry -- was RTTI-confirmed as the real
  // element class, see bd 1uj.16). TTaskForce::Free/SetMapOrderType9AndQueue/
  // PromoteMapOrderChainAndQueue (TTaskForce.cpp) all read/write this same
  // field via the g_pNavyOrderManager global.
  TTaskForce* orderListHead04;
  // ctor initializes to -1; real purpose not yet identified from any confirmed reader.
  short field08;
  char pad0a[2];
  // Transient dialog/context task-force reference: ResolveMapOrderChainsForTurnPhase's
  // prologue (0x5578ad) is field0c's only confirmed reader/writer -- it Free()s the
  // pointee (vtable slot 0x1c) if non-null, then clears field0c, at the start of every
  // turn-phase order resolution pass.
  TTaskForce* field0c;

  void RemoveOrdersByNationFromPrimarySecondaryAndTaskForceLists(short nationSlot);

  // Clears every cityScoreTable record's exploredByNationMaskA1 flag (dispatching a
  // per-province redraw-invalidate event through g_pGameFlowState while g_pSimMgr's
  // multiplayer/session-mode field44 == 1, for each record found dirty), stores
  // `phaseId` into field08, revalidates/requeues the map-order queue for the new turn
  // phase, then clears eliminatedFlag26 across the whole orderListHead04 chain
  // (directly on the head, via ClearMapOrderProcessedFlagsChain for the rest). 0x5577b0.
  void PrepareMapOrdersForExecutionPhase(short phaseId);

  // Finds the first orderListHead04 entry with attachment==7 (a "type 7" task-force
  // order kind) and matching required_count, then walks its childOrderList setting each
  // child's active: false if the child's required_count is below its resource
  // type's stockCap column, otherwise a chancePercent-vs-rand()%100 coin flip. Returns
  // the matched entry (or null). 0x557e10.
  TTaskForce* UpdateType7NavyOrderChildSelectionByChanceThreshold(short requiredCount,
                                                                  short chancePercent);

  // 0x5568f0 - stream out the three navy order lists (primary TShip chain tail-first,
  // TAdmiral secondary chain, orderListHead04 task-force chain), each prefixed with a
  // 16-bit count; nationFilter -1 serializes every nation's entries.
  void SerializeNavyOrderListsByNation(TStream* stream, short nationFilter);
  // 0x556ad0 - receive-side twin of SerializeNavyOrderListsByNation: rebuild the three
  // navy order lists from the stream for `nationFilter` (-1 = all nations).
  void DeserializeNavyOrderListsByNation(TStream* stream, short nationFilter);
  // 0x557170. Walks orderListHead04 (the same raw task-force-order node list
  // RemoveMatchingTaskForceOrders in the .cpp already indexes via node[7]=
  // nationSlot@+0x1c, node[0xb]=next@+0x2c); matches nodes with orderType@+0x8==5,
  // targetRecord@+0xc==cityRecordPtr, and (filterValue==0 || filterTag@+0x18==
  // filterValue), then sums a per-TShip weighted cost from the sub-list at +0x10
  // (each entry is {TShip*, next}; TShip::resourceType04/stockLevel1c line up with
  // the entry's ship's own fields).
  short ComputeAggregateWeightedChildCostForMatchingType5NavyOrders(short nationSlot,
                                                                    void* cityRecordPtr,
                                                                    int filterValue);

  // bd 1uj.16: if `entry` is already linked into orderListHead04, returns
  // true (no-op). Otherwise, if `entry` has no live childOrderList entries,
  // frees it and returns false; else unlinks it from wherever it is
  // currently queued and (re)inserts it at orderListHead04, returning true.
  bool MoveMapOrderEntryToQueueHeadIfValid(TTaskForce* entry); // 0x557080

  // Called from TTaskForce::ResolveTaskForceOrderConflictAndPickCandidate's tail
  // (ECX=g_pNavyOrderManager evidence at that callsite) when neither entry's priority
  // clears the other's threshold and no tie-break resolves it outright. Runs the
  // tier-scoring / random-attrition resolution between the two order entries' children.
  void ResolveMapOrderPairConflictStep(TTaskForce* leftEntry, TTaskForce* rightEntry); // 0x55a780

  // Zeroes every g_pNavyPrimaryOrderListHead ship's field0c, destroys the whole
  // orderListHead04 task-force queue, clears the head, and notifies
  // g_pActiveMapOrderContext that no order entry is selected anymore.
  void ResetPrimaryOrderActiveFlagsAndClearManagerState(); // 0x556fd0

  // 0x558960 (3485 bytes). Called twice in sequence from the map-order turn-phase
  // resolver (ResolveMapOrderChainsForTurnPhase, 0x5578a0) with `mode` = 1 then 2
  // -- confirmed __thiscall on this (TNavyMgr) via the `MOV ECX,EBP; PUSH mode;
  // CALL` sequence at 0x557ca7/0x557cb1 and the callee's `RET 4`. Sweeps the 7
  // playable nations that have a live city, and for each its 17 tracked map-order
  // interaction slots, reading every queued entry via TGreatPower's tracked-slot
  // virtuals (GetTrackedSlotEntryCountLow @ slot 0x6d, ReadTrackedSlotEntryFields @
  // slot 0x6f). Each live entry builds a localized diplomacy/order-exchange event
  // message and, gated by `mode` (1 = offer pass, 2 = accept pass) and flags derived
  // from that message, applies the exchange outcome (resource transfers, capped-at-499
  // order-node stat writes, per-nation counter deltas). The query skeleton is fully
  // ported; the message/outcome spine is an unblocked (large) decomp-loop follow-up --
  // the "g_pLocalizationTable" Ghidra shows in the body is g_pSimMgr itself (a modeled
  // TSimMgr, vtable 0x662a58; the string calls are TSimMgr::GetStringPrelude/GetString),
  // so no class recovery is required.
  // 0x557f10 (1901 bytes). Scans orderListHead04 for the first queued order entry
  // whose interaction is eligible to fire this turn for `nation`: gates the nation's
  // own type-7 entry children by a priority-vs-descriptor roll, then for each
  // non-eliminated queued entry checks attachment/context match + diplomacy relation
  // (g_pDiplomacyTurnStateManager) and an order-score comparison (the same
  // ComputeMapOrderEntryHeuristicScore / ComputeTaskForceOrderAggregateScore /
  // ResolveMapOrderPairConflictStep helpers the conflict resolver uses). On the first
  // eligible entry it fills `outResult` and returns 1; otherwise 0. `portZoneContext`
  // is the resolved TZone* (as int), `offerAmount` the transfer size.
  char
  SelectEligibleMapOrderInteractionForNationAndContext(TMapOrderInteractionSelection* outResult,
                                                       int portZoneContext, short nation,
                                                       short offerAmount);

  void ProcessNationMapOrderInteractionsAndApplyOutcomes(short mode); // 0x558960

  // 0x5578a0 (1102 bytes). Per-turn-phase map-order conflict resolver: clears any
  // pending field0c context reference, then runs 6 filter/inner-loop passes over
  // orderListHead04 pairing competing order entries (3/4-vs-6, 6-vs-1, direct
  // type-1 apply, 3/4-vs-non-6, 1-vs-5 with an inlined threshold roll, direct
  // type-5/8 apply), returning immediately if any pairwise resolution reports a
  // result. Finishes by running the two-pass nation nation-interaction sweep,
  // rebuilding orderListHead04 via PruneNavyOrderIfUnserviceableOrNoChildren,
  // clearing the primary TShip list's transient field34 flag, and refreshing the
  // active map-order context's overlays.
  void ResolveMapOrderChainsForTurnPhase(); // 0x5578a0

  // Map-hover label lookups. These are real __thiscall members on the navy manager;
  // 0x559e00 additionally resolves the active task-force entry against the clicked
  // sea-zone or province context before choosing a cursor token.
  unsigned short GetMapContextActionLabelTokenByActionCode(short nTileIndex,
                                                           int nInputFlags); // 0x559dd0
  unsigned short GetMapContextActionLabelToken(short nTileIndex,
                                               int nInputFlags); // 0x559e00

  // 0x0055a020 -- resolves and executes a context-sensitive map click action against this
  // manager's active map-order state (dialogs for actions 2..8, set-active-entry for 9,
  // UI-runtime slot 0xf0 for 10, entry-order dialog for 11 which walks orderListHead04).
  // Returns true if the click was consumed. Ghidra's `int` prototype is a mislabel --
  // callers store the result in a `char fHandled` and test `!= '\0'`, and the real codegen
  // only ever sets/tests AL. Not virtual -- called directly (via an ILT thunk) from
  // TWorldView::HandleMapClickByInteractionMode and from TryQueueMapOrderFromTileAction.
  bool TryHandleMapContextAction(short nTileIndex, int nInputFlags);
  // 0x0055a160 -- when a click is not consumed by immediate context handling, resolves a
  // map-order command from the active entry's tile-action/province context and runs the
  // set-type + rebuild/queue/finalize pipeline. Receiver at every call site is
  // g_pNavyOrderManager (this manager).
  int TryQueueMapOrderFromTileAction(short nTileIndex, int nInputFlags);

  TNavyMgr();
};

ASSERT_SIZE(TNavyMgr, 0x10);

// 0x557560 -- free __cdecl per-turn map-order revalidation sweep over every
// map-action context zone x great-power slot (body in TNavyMgr.cpp; called by
// TNavyMgr::PrepareMapOrdersForExecutionPhase).
void RevalidateAndRequeueMapOrdersForTurn();
