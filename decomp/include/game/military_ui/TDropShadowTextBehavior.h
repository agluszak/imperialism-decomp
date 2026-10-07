#pragma once

#include "compat.h"

#include "game/ui_core/TBehavior.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0064eb60
class TDropShadowTextBehavior : public TBehavior {
public:
  DECLARE_DYNCREATE(TDropShadowTextBehavior)
  // FUNCTION: IMPERIALISM 0x004b1100
  virtual ~TDropShadowTextBehavior() override {}
  void Draw(RECT* bounds) override;
  // Draw passes the complete +0x10 dword to SetQuickDrawColorAndPropagateIfChanged.
  COLORREF shadowColor;

  TDropShadowTextBehavior();

  void IDropShadowTextBehavior(COLORREF shadowColor);
};

ASSERT_SIZE(TDropShadowTextBehavior, 0x14);
