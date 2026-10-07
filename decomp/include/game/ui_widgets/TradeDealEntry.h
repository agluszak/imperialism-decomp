#pragma once

#include "compat.h"

struct TradeDealEntry {
  short sourceNationSlot;
  short targetNationSlot;
  short relationDelta;
  short relationStanding;
  int dispatchScore;
  short category;
};
ASSERT_SIZE(TradeDealEntry, 0x10);
