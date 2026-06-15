#pragma once

#include "compat.h"
#include "game/TIndexAndRankList.h"

struct CRuntimeClass;
// VTABLE: IMPERIALISM 0x00653810
class TProvinceDesirabilityList : public TIndexAndRankList {
public:
  short relationType;
  short pad16;

  TProvinceDesirabilityList();
  CRuntimeClass* GetRuntimeClass() const override;
  static TProvinceDesirabilityList* CreateTProvinceDesirabilityListInstance();
};

ASSERT_SIZE(TProvinceDesirabilityList, 0x18);
