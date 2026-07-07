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

// TODO(manifest): describe TNavyMgr and its role. Base edge (TObject) recovered from RTTI CRuntimeClass chain: TNavyMgr -> TObject -> CObject.
// VTABLE: IMPERIALISM 0x0065c4c8
class TNavyMgr : public TObject {
public:
  // === BEGIN GENERATED DECLS (TNavyMgr) — refreshed by recover-class; do not hand-edit ===
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
  // === END GENERATED DECLS (TNavyMgr) ===
  // Head of the global task-force order queue (was `void*`; retyped once
  // TTaskForce -- née TMapOrderEntry -- was RTTI-confirmed as the real
  // element class, see bd 1uj.16). TTaskForce::Free/SetMapOrderType9AndQueue/
  // PromoteMapOrderChainAndQueue (TTaskForce.cpp) all read/write this same
  // field via the g_pNavyOrderManager global.
  TTaskForce* orderListHead04;
  // ctor initializes to -1; real purpose not yet identified from any confirmed reader.
  short field08;
  char pad0a[2];
  // ctor initializes to 0; real purpose not yet identified from any confirmed reader.
  int field0c;

  void RemoveOrdersByNationFromPrimarySecondaryAndTaskForceLists(short nationSlot);
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

  TNavyMgr();
};

ASSERT_SIZE(TNavyMgr, 0x10);
