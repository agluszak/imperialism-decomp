#pragma once

#include "decomp_types.h"
// QuickDraw.cpp's rectangle fill helper keeps two scoped copies of the requested
// brush bounds. The actual CBrush remains a neighboring automatic so its MFC
// destruction state is tracked independently by VC5.
class TScopedQuickDrawBrush {
public:
  TScopedQuickDrawBrush(RECT* rect) {
    ::CopyRect(&paintRect00, rect);
    ::CopyRect(&sourceRect10, rect);
  }

  RECT paintRect00;
  RECT sourceRect10;
};
ASSERT_SIZE(TScopedQuickDrawBrush, 0x20);
