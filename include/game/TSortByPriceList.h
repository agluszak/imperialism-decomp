#pragma once

#include "compat.h"
#include "game/TIndexAndRankList.h"

int AllocateWithFallbackHandler(undefined4 size_bytes);

extern "C" char g_vtblTSortByPriceList;

// VTABLE: IMPERIALISM 0x00659ef0
class TSortByPriceList : public TIndexAndRankList {
 public:
  int reserved14;

  TSortByPriceList() : TIndexAndRankList() {
    *reinterpret_cast<void**>(this) = reinterpret_cast<void*>(&g_vtblTSortByPriceList);
  }
  void* DeletingDestructTSortByPriceList(byte freeSelfFlag);
  void DestructTSortByPriceList();

  void* operator new(unsigned int size) {
    return reinterpret_cast<void*>(AllocateWithFallbackHandler(size));
  }
  void operator delete(void* ptr) { (void)ptr; }

  static void* GetTSortByPriceListClassNamePointer();
  static TSortByPriceList* AllocateAndConstructTSortByPriceList();
  TSortByPriceList* ConstructTSortByPriceList();
};

ASSERT_SIZE(TSortByPriceList, 0x18);
