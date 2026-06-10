#pragma once

#include "decomp_types.h"
#include "game/TAmtBar.h"

struct TradeCommodityMetricRecord {
  void* vftable;
  short controlValue;
  short shortAt6;
  short buyQuantityStepRaw;
  char pad_0a[0x44 - 0x0a];
  int accumulatedValue44; // 0x44 — summed by TGreatPower slot 0xac (0x004e06d0)
  char pad_48[0x52 - 0x48];
  short buildingSlot;

  short QueryStepValue() {
    return reinterpret_cast<TAmtBar*>(this)->QueryStepValue();
  }
};
