#pragma once

#include "compat.h"

// Singly-linked node in per-region stationed-unit chain (cityScoreTable +0x98).
class TStationedUnitNode {
public:
  unsigned char pad00[4];
  short unitTypeId04;
  unsigned char pad06[0x14 - 0x06];
  TStationedUnitNode* next14;

  short GetUnitMovementClassId();
};
