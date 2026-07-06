#pragma once

#include "game/TIndustryAmtBar.h"

struct CRuntimeClass;
// VTABLE: IMPERIALISM 0x666558
class TRailAmtBar : public TIndustryAmtBar {
public:
  TRailAmtBar();
  DECLARE_DYNCREATE(TRailAmtBar)

  void NoOpUiLifecycleHook(int arg) override;
  void RenderPrimarySurfaceOverlayPanelWithClipCache() override;
  void RenderQuickDrawOverlayWithHitRegion(short selectedValue) override; // slot 0x6b 0x0058a3b0
};
