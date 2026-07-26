#pragma once

#include "decomp_types.h"
#include "game/globals/shared_globals.h"
#include "game/globals/ui_core_globals.h"
#include "game/mfc.h"

// QuickDraw.cpp's oval helpers keep the previous GDI pen in a CPen-derived local.
// Its destructor restores that pen before CPen/CGdiObject perform normal MFC teardown.
// VTABLE: IMPERIALISM 0x0064b948
class TScopedQuickDrawPen : public CPen {
public:
  TScopedQuickDrawPen() {
    int penSize = g_nQuickDrawPenHorizontalSize;
    if (penSize <= g_nQuickDrawPenVerticalSize) {
      penSize = g_nQuickDrawPenVerticalSize;
    }
    CreatePen(PS_SOLID, penSize, g_QuickDrawForegroundColor);

    CDC* dc = g_pQuickDrawMemoryDc;
    if (dc == 0) {
      dc = g_pScopedMapQuickDrawDcHandleObject;
    }
    previousPen08 = dc->SelectObject(this);
  }

  // FUNCTION: IMPERIALISM 0x00498610
  ~TScopedQuickDrawPen() override {
    CDC* dc = g_pQuickDrawMemoryDc;
    if (dc == 0) {
      dc = g_pScopedMapQuickDrawDcHandleObject;
    }
    dc->SelectObject(previousPen08);
  }

  CPen* previousPen08;
};
ASSERT_SIZE(TScopedQuickDrawPen, 0x0c);
