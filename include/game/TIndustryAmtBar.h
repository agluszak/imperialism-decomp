#pragma once

#include "game/TAmtBar.h"
#include "game/TradeCommodityMetricRecord.h"

struct CRuntimeClass;
// VTABLE: IMPERIALISM 0x666110
class TIndustryAmtBar : public TAmtBar {
public:
  TradeCommodityMetricRecord* selectedMetricRecord;

  TIndustryAmtBar();
  // ~TIndustryAmtBar is compiler-generated (implicit virtual dtor).
  DECLARE_DYNCREATE(TIndustryAmtBar)
  void NoOpUiLifecycleHook(int arg) override;
  void RenderPrimarySurfaceOverlayPanelWithClipCache() override;
};
