#pragma once

#include "compat.h"
#include "decomp_types.h"
#include "game/CPtrArray.h"
#include "game/mfc.h"

struct CRuntimeClass;
class TStream;

// VTABLE: IMPERIALISM 0x00649010
class TSortedPtrList : public CPtrArray {
public:
  DECLARE_DYNCREATE(TSortedPtrList)

  short recordSize14; // +0x14
  short pad16;        // +0x16

  // NOOP: verified empty in original 0x00488063 (no standalone TSortedPtrList::TSortedPtrList body exists: CreateObject 0x00488030 inlines this default ctor, calling the CPtrArray base ctor directly at that site)
  TSortedPtrList() {}

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
  virtual short Compare(void* a, void* b); // 17 (0x44) 0x488360
};

ASSERT_SIZE(TSortedPtrList, 0x18);
