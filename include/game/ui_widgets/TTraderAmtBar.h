#pragma once

#include "compat.h"

#include "game/ui_widgets/TAmtBar.h"

struct CRuntimeClass;
// VTABLE: IMPERIALISM 0x666ba0
class TTraderAmtBar : public TAmtBar {
public:
  // FUNCTION: IMPERIALISM 0x0058af60
  ~TTraderAmtBar() override {}
  TTraderAmtBar();
  // ~TTraderAmtBar is compiler-generated (implicit virtual dtor).
  DECLARE_DYNCREATE(TTraderAmtBar)
  void DoPostCreate(int arg) override;
  short ApplyMoveClamp(int baseValue, short requestedValue) override;
  void RenderPrimarySurfaceOverlayPanelWithClipCache() override;

  void UpdateFromScaleOrRatio(int scaleValue, int ratioValue);
};
ASSERT_SIZE(TTraderAmtBar, 0x68);
