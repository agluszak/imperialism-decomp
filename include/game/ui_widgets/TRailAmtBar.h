#pragma once

#include "game/ui_widgets/TIndustryAmtBar.h"

struct CRuntimeClass;
// VTABLE: IMPERIALISM 0x666558
class TRailAmtBar : public TIndustryAmtBar {
public:
  // FUNCTION: IMPERIALISM 0x0058a000
  ~TRailAmtBar() override {}
  TRailAmtBar();
  DECLARE_DYNCREATE(TRailAmtBar)

  void DoPostCreate(int arg) override;
  void RenderPrimarySurfaceOverlayPanelWithClipCache() override;
  void RenderQuickDrawOverlayWithHitRegion(short selectedValue) override; // slot 0x6b 0x0058a3b0
};
