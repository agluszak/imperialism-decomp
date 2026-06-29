#pragma once

#include "game/TIndustryAmtBar.h"

struct CRuntimeClass;
// VTABLE: IMPERIALISM 0x666998
class TShipAmtBar : public TIndustryAmtBar {
public:
  TShipAmtBar();
  DECLARE_DYNCREATE(TShipAmtBar)

  void NoOpUiLifecycleHook(int arg) override;
  void RenderPrimarySurfaceOverlayPanelWithClipCache() override;
};
