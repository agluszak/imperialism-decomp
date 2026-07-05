#pragma once

#include "game/TAmtBar.h"

class TProductionOrder;

struct CRuntimeClass;
// VTABLE: IMPERIALISM 0x666110
class TIndustryAmtBar : public TAmtBar {
public:
  // The city commodity/production-order slot currently driving this bar's
  // display (see TCity::tradeCommodityRecordPtrs / trailingOrderSlots).
  TProductionOrder* selectedMetricRecord;

  TIndustryAmtBar();
  // ~TIndustryAmtBar is compiler-generated (implicit virtual dtor).
  DECLARE_DYNCREATE(TIndustryAmtBar)
  void NoOpUiLifecycleHook(int arg) override;
  void RenderPrimarySurfaceOverlayPanelWithClipCache() override;
};
