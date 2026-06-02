#pragma once

#include "game/TIndexAndRankList.h"

int AllocateWithFallbackHandler(undefined4 size_bytes);

extern "C" char g_vtblTSortedPtrList;

// VTABLE: IMPERIALISM 0x00649068
class TSortedPtrList : public TIndexAndRankList {
 public:
  union {
    int reserved14;
    struct {
      short relationType;
      short pad16;
    } rel;
  };

  TSortedPtrList() : TIndexAndRankList() {
    *reinterpret_cast<void**>(this) = reinterpret_cast<void*>(&g_vtblTSortedPtrList);
  }
  void* operator new(unsigned int size) {
    return reinterpret_cast<void*>(AllocateWithFallbackHandler(size));
  }
  void operator delete(void* ptr) { (void)ptr; }

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
