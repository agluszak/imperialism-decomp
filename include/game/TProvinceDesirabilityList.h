#pragma once

#include "compat.h"
#include "game/TSortedPtrList.h"

// Base recovered from CRuntimeClass descriptor: TProvinceDesirabilityList -> TSortedPtrList -> CPtrArray.
// VTABLE: IMPERIALISM 0x00653810
class TProvinceDesirabilityList : public TSortedPtrList {
public:
  DECLARE_DYNCREATE(TProvinceDesirabilityList)

  TProvinceDesirabilityList();
};

ASSERT_SIZE(TProvinceDesirabilityList, 0x18);
