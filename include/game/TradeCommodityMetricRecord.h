#pragma once

#include "decomp_types.h"

class TradeCommodityMetricRecord {
public:
  virtual void vmethod_0000() = 0;
  virtual void vmethod_0001() = 0;
  virtual void vmethod_0002() = 0;
  virtual void vmethod_0003() = 0;
  virtual void vmethod_0004() = 0;
  virtual void vmethod_0005() = 0;
  virtual void vmethod_0006() = 0;
  virtual void vmethod_0007() = 0;
  virtual void vmethod_0008() = 0;
  virtual void vmethod_0009() = 0;
  virtual void vmethod_0010() = 0;
  virtual void vmethod_0011() = 0;
  virtual short QueryStepValue() = 0;

  short controlValue;
  short shortAt6;
  short buyQuantityStepRaw;
  char pad_0a[0x44 - 0x0a];
  int accumulatedValue44; // 0x44 — summed by TGreatPower slot 0xac (0x004e06d0)
  char pad_48[0x52 - 0x48];
  short buildingSlot;
};
