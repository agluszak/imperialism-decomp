#pragma once

#include "game/TIndustryAmtBar.h"

struct CRuntimeClass;
// VTABLE: IMPERIALISM 0x666558
class TRailAmtBar : public TIndustryAmtBar {
public:
  TRailAmtBar();
  // ~TRailAmtBar is compiler-generated (implicit virtual dtor).
  CRuntimeClass* GetRuntimeClass() override;

  void NoOpUiLifecycleHook(int arg) override;
  void RenderPrimarySurfaceOverlayPanelWithClipCache() override;
};
