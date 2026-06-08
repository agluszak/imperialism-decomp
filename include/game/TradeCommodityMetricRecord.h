#pragma once

#include "decomp_types.h"
#include "game/TAmtBar.h"

struct TradeCommodityMetricRecord {
  void* vftable;
  short controlValue;
  char pad_06[0x4c];
  short buildingSlot;

  short QueryStepValue() {
    return reinterpret_cast<TAmtBar*>(this)->QueryStepValue();
  }
};
