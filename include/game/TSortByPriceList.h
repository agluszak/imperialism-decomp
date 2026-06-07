#pragma once

#include "compat.h"
#include "game/TIndexAndRankList.h"

int AllocateWithFallbackHandler(undefined4 size_bytes);

// VTABLE: IMPERIALISM 0x00659ef0
class TSortByPriceList : public TIndexAndRankList {
public:
  int reserved14;

  // 0x00534710: real ctor; compiler emits the 0x659ef0 vtable write.
  TSortByPriceList();
  void* DeletingDestructTSortByPriceList(byte freeSelfFlag);
  void DestructTSortByPriceList();

  void* operator new(unsigned int size) {
    return reinterpret_cast<void*>(AllocateWithFallbackHandler(size));
  }
  void operator delete(void* ptr) {
    (void)ptr;
  }

  static void* GetTSortByPriceListClassNamePointer();
  static TSortByPriceList* AllocateAndConstructTSortByPriceList();
};

ASSERT_SIZE(TSortByPriceList, 0x18);
