#pragma once

#include "game/global_data_tables.h"

class TStream;
class TTaskForce;

// TODO(manifest): describe TNavyMgr and its role. Base edge (TObject) recovered from RTTI CRuntimeClass chain: TNavyMgr -> TObject -> CObject.
// VTABLE: IMPERIALISM 0x0065c4c8
class TNavyMgr : public TObject {
public:
  // === BEGIN GENERATED DECLS (TNavyMgr) — refreshed by recover-class; do not hand-edit ===
  DECLARE_DYNCREATE(TNavyMgr)
  virtual ~TNavyMgr(); // slot 0x01 (scalar deleting destructor)
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
  // clears the other's threshold and no tie-break resolves it outright. 2934 bytes with
  // a heavy CString-building body (SEH frame, ~500-byte format buffer); not yet
  // reverse-engineered in detail.
  void ResolveMapOrderPairConflictStep(TTaskForce* leftEntry, TTaskForce* rightEntry); // 0x55a780

  // Zeroes every g_pNavyPrimaryOrderListHead ship's field0c, destroys the whole
  // orderListHead04 task-force queue, clears the head, and notifies
  // g_pActiveMapOrderContext that no order entry is selected anymore.
  void ResetPrimaryOrderActiveFlagsAndClearManagerState(); // 0x556fd0

  TNavyMgr();
};

ASSERT_SIZE(TNavyMgr, 0x10);

// === BEGIN GENERATED (TNavyMgr) — refreshed by `just gen-class TNavyMgr`; do not hand-edit ===
// clang-format off
// vtable @ 0x0065c4c8 (10 slots), object size 0x10, base TObject
//   slot 0x00  byte 0x00  0x00556570  override  GetRuntimeClass
//   slot 0x01  byte 0x04  0x005565c0  scalar_dtor (scalar deleting destructor)
//   slot 0x02  byte 0x08  0x00485e90  inherited Serialize
//   slot 0x03  byte 0x0c  0x00412bf0  inherited AssertValid
//   slot 0x04  byte 0x10  0x00412c10  inherited Dump
//   slot 0x05  byte 0x14  0x005568c0  override  WriteTo
//   slot 0x06  byte 0x18  0x00556aa0  override  ReadFrom
//   slot 0x07  byte 0x1c  0x005567a0  override  Free
//   slot 0x08  byte 0x20  0x004798d0  inherited ShallowClone
//   slot 0x09  byte 0x24  0x00415ce0  inherited ShallowFree
// object size 0x10 (RTTI) unverified against the header layout;
// set curated.layout.size_verified to emit a sizeof static_assert.
// clang-format on
// === END GENERATED (TNavyMgr) ===
