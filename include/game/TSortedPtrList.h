#pragma once

#include "compat.h"
#include "game/TIndexAndRankList.h"

int AllocateWithFallbackHandler(undefined4 size_bytes);

// VTABLE: IMPERIALISM 0x00649068
class TSortedPtrList : public TIndexAndRankList {
public:
  short relationType;
  short pad16;

  // Compiler emits the 0x649068 vtable write.
  TSortedPtrList();
  virtual ~TSortedPtrList();

  static void* GetTSortedPtrListClassNamePointer();
  static TSortedPtrList* ConstructTSortedPtrListBaseState();
  void ResetPtrListAndShrinkCapacity();
  void* GetPtrListEntryByOneBasedIndex(int oneBasedIndex);
};

ASSERT_SIZE(TSortedPtrList, 0x18);

void* __fastcall GetPtrListEntryByOneBasedIndex(TSortedPtrList* self, int unusedEdx,
                                                int oneBasedIndex);
void __fastcall thunk_ResetPtrListAndShrinkCapacity(TSortedPtrList* self);
void* __fastcall thunk_GetPtrListEntryByOneBasedIndex(TSortedPtrList* self, int unusedEdx,
                                                      int oneBasedIndex);
