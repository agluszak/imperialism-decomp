#pragma once

#include "decomp_types.h"
#include "game/TAmtBar.h"

struct TradeCommodityMetricRecord {
  void* vftable;
  short controlValue;
  short shortAt6;
  short buyQuantityStepRaw;
  char pad_0a[0x48];
  short buildingSlot;

  short QueryStepValue() {
    return reinterpret_cast<TAmtBar*>(this)->QueryStepValue();
  }
};
