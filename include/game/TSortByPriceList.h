#pragma once

#include "compat.h"
#include "game/TSortedPtrList.h"

// Base recovered from CRuntimeClass descriptor: TSortByPriceList -> TSortedPtrList -> CPtrArray.
// VTABLE: IMPERIALISM 0x00659ef0
class TSortByPriceList : public TSortedPtrList {
public:
  DECLARE_DYNCREATE(TSortByPriceList)

  TSortByPriceList();
};

ASSERT_SIZE(TSortByPriceList, 0x18);
