#pragma once

#include "compat.h"
#include "game/ui_core/TSortedPtrList.h"

// Base recovered from CRuntimeClass descriptor: TSortByPriceList -> TSortedPtrList -> CPtrArray.
// VTABLE: IMPERIALISM 0x00659ef0
class TSortByPriceList : public TSortedPtrList {
public:
  DECLARE_DYNCREATE(TSortByPriceList)

  TSortByPriceList();
  // Ascending by the price short at record+2 (ties compare as 1).
  short Compare(void* a, void* b) override; // slot 0x44 0x5347b0
};

ASSERT_SIZE(TSortByPriceList, 0x18);
