#pragma once

#include "compat.h"
#include "game/TIndexAndRankList.h"

// VTABLE: IMPERIALISM 0x00659ef0
class TSortByPriceList : public TIndexAndRankList {
public:
  int reserved14;

  // 0x00534710: real ctor; compiler emits the 0x659ef0 vtable write.
  TSortByPriceList();
  // Destructor is compiler-generated (implicit virtual dtor).

  static void* GetTSortByPriceListClassNamePointer();
  static TSortByPriceList* AllocateAndConstructTSortByPriceList();
};

ASSERT_SIZE(TSortByPriceList, 0x18);
