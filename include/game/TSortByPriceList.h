#pragma once

#include "compat.h"
#include "game/TIndexAndRankList.h"

struct CRuntimeClass;
// VTABLE: IMPERIALISM 0x00659ef0
class TSortByPriceList : public TIndexAndRankList {
public:
  int reserved14;

  // 0x00534710: real ctor; compiler emits the 0x659ef0 vtable write.
  TSortByPriceList();
  CRuntimeClass* GetRuntimeClass() const override;
  // Destructor is compiler-generated (implicit virtual dtor).
  static TSortByPriceList* AllocateAndConstructTSortByPriceList();
};

ASSERT_SIZE(TSortByPriceList, 0x18);
