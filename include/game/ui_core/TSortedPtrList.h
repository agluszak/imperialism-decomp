#pragma once

#include "compat.h"
#include "decomp_types.h"
#include "game/CPtrArray.h"
#include "game/mfc.h"

struct CRuntimeClass;
class TStream;

// CPtrArray-derived by-value record list base (vtable 0x00649010, 18 slots 0x00-0x44;
// GetRuntimeClass 0x004883e0 returns the "TSortedPtrList" CRuntimeClass descriptor).
// Every mutator copies recordSize14 bytes into a freshly allocated record, so the
// array owns fixed-size POD records rather than caller-owned pointers. The derived
// TPtrList owns vtable 0x00649068 and adds exactly one slot (0x48).
// Base recovered from CRuntimeClass descriptor: TSortedPtrList -> CPtrArray -> CObject.
// VTABLE: IMPERIALISM 0x00649010
class TSortedPtrList : public CPtrArray {
public:
  DECLARE_DYNCREATE(TSortedPtrList)

  // Byte size of one record; every caller assigns it right after construction
  // (4/8/0xC/0x10/0x24 across the queues) and the serializers stream it.
  short recordSize14; // +0x14
  short pad16;        // +0x16

  TSortedPtrList();
  virtual ~TSortedPtrList() override;

  // List-operation virtuals introduced by TSortedPtrList (slots 5-17):
  virtual void WriteTo(TStream* stream);                                    // 5  (0x14) 0x5e1f10
  virtual void ReadFrom(TStream* stream);                                   // 6  (0x18) 0x5e1e50
  virtual void ClearAndFreeAllPtrListRecords();                             // 7  (0x1c) 0x4880a0
  virtual void InvokePtrListResetHook();                                    // 8  (0x20) 0x4880f0
  virtual void ReleasePtrList();                                            // 9  (0x24) 0x488110
  virtual void SelfDelete();                                                // 10 (0x28) 0x488140
  virtual void* GetPtrListEntryByOneBasedIndex(int oneBasedIndex);          // 11 (0x2c) 0x488160
  virtual void RemovePtrListEntryByOneBasedIndexAndFree(int oneBasedIndex); // 12 (0x30) 0x488190
  virtual void* PeekFirstPtrListEntry();                                    // 13 (0x34) 0x4881d0
  virtual void InsertCopiedRecordSortedByComparator(void* record);          // 14 (0x38) 0x4881f0
  virtual void AppendCopiedRecordToPtrList(void* record);                   // 15 (0x3c) 0x4882c0
  virtual void InsertCopiedRecordAtFrontOfPtrList(void* record);            // 16 (0x40) 0x488310
  // Default record comparator used by the sorted insert: unsigned three-way compare of
  // the raw record pointers, short verdict in AX (the sorted-list leaves override this
  // with real field comparisons). Same shape as TSortedList::Compare on the sibling
  // CPtrList-backed chain.
  virtual short Compare(void* a, void* b); // 17 (0x44) 0x488360
};

ASSERT_SIZE(TSortedPtrList, 0x18);
