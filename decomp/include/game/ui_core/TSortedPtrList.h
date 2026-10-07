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

  short recordSize;
  short pad16;

  // NOOP: verified empty in original 0x00488063
  TSortedPtrList() {}

  virtual ~TSortedPtrList() override;

  // List-operation virtuals introduced by TSortedPtrList (slots 5-17):
  virtual void WriteTo(TStream* stream);
  virtual void ReadFrom(TStream* stream);
  virtual void DeleteAll();
  virtual void InvokePtrListResetHook();
  virtual void FreeList();
  virtual void SelfDelete();
  virtual void* GetPtrListEntryByOneBasedIndex(int oneBasedIndex);
  virtual void RemovePtrListEntryByOneBasedIndexAndFree(int oneBasedIndex);
  virtual void* First();
  virtual void Insert(void* record);
  virtual void AppendCopiedRecordToPtrList(void* record);
  virtual void InsertCopiedRecordAtFrontOfPtrList(void* record);
  virtual short Compare(void* a, void* b);
};

ASSERT_SIZE(TSortedPtrList, 0x18);
