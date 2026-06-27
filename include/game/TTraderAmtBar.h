#pragma once

#include "game/TAmtBar.h"

struct CRuntimeClass;
// VTABLE: IMPERIALISM 0x666ba0
class TTraderAmtBar : public TAmtBar {
public:
  TTraderAmtBar();
  // ~TTraderAmtBar is compiler-generated (implicit virtual dtor).
  DECLARE_DYNCREATE(TTraderAmtBar)
  void NoOpUiLifecycleHook(int arg) override;
  int ApplyMoveClamp(int baseValue, int requestedValue) override;
  void RenderPrimarySurfaceOverlayPanelWithClipCache() override;

  void UpdateFromScaleOrRatio(int scaleValue, int ratioValue);
};
