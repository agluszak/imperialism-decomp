#pragma once

#include "decomp_types.h"
#include "game/mfc.h"
#include "game/TSortedPtrList.h"

class CArchive;

// Mac oracle: TDealList (a small sorted-ptr-list variant). Instances are held by
// TTradeMgr::categoryRankLists (its ctor installs this vtable, 0x66da38). This is a
// distinct class from the TTradeMgr manager it was previously conflated with.
// VTABLE: IMPERIALISM 0x0066da38
class TDealList : public TSortedPtrList {
public:
  // === BEGIN GENERATED DECLS (TDealList) — refreshed by recover-class; do not hand-edit ===
  DECLARE_DYNCREATE(TDealList)
  virtual ~TDealList() override; // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x412bd0)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  // slot 0x05 EnumerateStateEntriesAndInvokeObjectCallback inherited unchanged (0x5e1f10)
  // slot 0x06 EnumerateStreamEntriesWithDualCallbacksAndTempBuffer inherited unchanged (0x5e1e50)
  // slot 0x07 ClearAndFreeAllPtrListRecords inherited unchanged (0x4880a0)
  // slot 0x08 InvokePtrListResetHook inherited unchanged (0x4880f0)
  // slot 0x09 ResetPtrListAndShrinkCapacity inherited unchanged (0x488110)
  // slot 0x0a OrphanCallChain_C11_I88_004874b0 inherited unchanged (0x488140)
  // slot 0x0b GetPtrListEntryByOneBasedIndex inherited unchanged (0x488160)
  // slot 0x0c RemovePtrListEntryByOneBasedIndexAndFree inherited unchanged (0x488190)
  // slot 0x0d RemoveFirstPtrListEntry inherited unchanged (0x4881d0)
  // slot 0x0e UpsertPtrListRecordByComparator inherited unchanged (0x4881f0)
  // slot 0x0f AppendCopiedRecordToPtrList inherited unchanged (0x4882c0)
  // slot 0x10 InsertCopiedRecordAtFrontOfPtrList inherited unchanged (0x488310)
  // Deal-priority comparator: weighted (value * priority) score, inverted for deal
  // kinds 0xd-0x10, with a mod-7 pseudo-random tiebreak over the record fields.
  short Compare(void* a, void* b) override; // slot 0x11 0x5ba260
  // === END GENERATED DECLS (TDealList) ===

  TDealList();
};
