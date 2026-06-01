#pragma once

#include "game/TIndexAndRankList.h"

class TSortedPtrList : public TIndexAndRankList {
 public:
  int reserved14;

  static void* GetTSortedPtrListClassNamePointer();
  static TSortedPtrList* ConstructTSortedPtrListBaseState();
  void ResetPtrListAndShrinkCapacity();
  void* GetPtrListEntryByOneBasedIndex(int oneBasedIndex);
};

typedef char TSortedPtrListSizeMustMatch[(sizeof(TSortedPtrList) == 0x18) ? 1 : -1];

void* __fastcall GetPtrListEntryByOneBasedIndex(TSortedPtrList* self, int unusedEdx,
                                                int oneBasedIndex);
void __fastcall thunk_ResetPtrListAndShrinkCapacity(TSortedPtrList* self);
void* __fastcall thunk_GetPtrListEntryByOneBasedIndex(TSortedPtrList* self, int unusedEdx,
                                                      int oneBasedIndex);
