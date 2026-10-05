#pragma once

#include "decomp_types.h"
class TScopedQuickDrawBrush {
public:
  TScopedQuickDrawBrush(RECT* rect) {
    ::CopyRect(&paintRect, rect);
    ::CopyRect(&sourceRect, rect);
  }

  RECT paintRect;
  RECT sourceRect;
};
ASSERT_SIZE(TScopedQuickDrawBrush, 0x20);
