#pragma once

#include "decomp_types.h"
#include "game/mfc.h"

// QuickDraw.cpp's oval helpers keep the previous GDI pen in a CPen-derived local.
// Its destructor restores that pen before CPen/CGdiObject perform normal MFC teardown.
// VTABLE: IMPERIALISM 0x0064b948
class TScopedQuickDrawPen : public CPen {
public:
  // NOOP: verified empty in original 0x004983da (no standalone derived-ctor body exists;
  // QDFrameOval inlines it and calls the real CPen constructor at this call site)
  TScopedQuickDrawPen() {}
  ~TScopedQuickDrawPen() override;

  CPen* previousPen08;
};
ASSERT_SIZE(TScopedQuickDrawPen, 0x0c);
