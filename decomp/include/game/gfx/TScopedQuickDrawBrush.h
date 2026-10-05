#pragma once

#include "decomp_types.h"
// QuickDraw.cpp's rectangle fill helper keeps two scoped copies of the requested
// brush bounds. The actual CBrush remains a neighboring automatic so its MFC
// destruction state is tracked independently by VC5.
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
