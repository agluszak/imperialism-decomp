#pragma once

#include "compat.h"
#include "game/TIndexAndRankList.h"

// VTABLE: IMPERIALISM 0x00653810
struct CRuntimeClass;
class TProvinceDesirabilityList : public TIndexAndRankList {
public:
  short relationType;
  short pad16;

  TProvinceDesirabilityList();
  CRuntimeClass* GetRuntimeClass() override;
  static TProvinceDesirabilityList* CreateTProvinceDesirabilityListInstance();
};

ASSERT_SIZE(TProvinceDesirabilityList, 0x18);
