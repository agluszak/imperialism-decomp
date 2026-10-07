#pragma once

#include "compat.h"

struct OrderSheet {
  short slotByResourceCode[63];

  short& ForResourceCode(int resourceCode) {
    return slotByResourceCode[resourceCode];
  }
};

ASSERT_SIZE(OrderSheet, 0x7e);
