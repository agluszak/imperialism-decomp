#pragma once

#include "compat.h"

struct TradeDealEntry {
  short sourceNationSlot; // +0x00
  short targetNationSlot; // +0x02
  short relationDelta;    // +0x04
  short relationStanding; // +0x06
  int dispatchScore;      // +0x08
  short category;         // +0x0c
};
ASSERT_SIZE(TradeDealEntry, 0x10);
