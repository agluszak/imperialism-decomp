#pragma once

#include "compat.h"
#include "game/ui_core/TSortedPtrList.h"

// VTABLE: IMPERIALISM 0x00653810
class TProvinceDesirabilityList : public TSortedPtrList {
public:
  // FUNCTION: IMPERIALISM 0x004d65f0
  ~TProvinceDesirabilityList() override {}
  DECLARE_DYNCREATE(TProvinceDesirabilityList)

  TProvinceDesirabilityList();
  // Descending by the desirability short at record+2; ties broken pseudo-randomly.
  short Compare(void* a, void* b) override; // slot 0x44 0x4d6630

  void IProvinceDesirabilityList(); // 0x4d6610
};

ASSERT_SIZE(TProvinceDesirabilityList, 0x18);
