#pragma once

#include "compat.h"

struct OrderSheet {
  short slotByResourceCode[0x3f];

  short& ForResourceCode(int resourceCode) {
    return slotByResourceCode[resourceCode];
  }
};

ASSERT_SIZE(OrderSheet, 0x7e);
