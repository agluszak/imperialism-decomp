#pragma once

#include "compat.h"
#include "game/ui_core/TSortedPtrList.h"

// VTABLE: IMPERIALISM 0x00659ef0
class TSortByPriceList : public TSortedPtrList {
public:
  DECLARE_DYNCREATE(TSortByPriceList)

  TSortByPriceList();
  void ISortByPriceList();
  // Ascending by the price short at record+2 (ties compare as 1).
  short Compare(void* a, void* b) override;
};

ASSERT_SIZE(TSortByPriceList, 0x18);
