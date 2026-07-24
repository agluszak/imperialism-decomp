#pragma once

#include "compat.h"

#include "game/ui_widgets/TAmtBar.h"

class TProductionOrder;

struct CRuntimeClass;
// VTABLE: IMPERIALISM 0x666110
class TIndustryAmtBar : public TAmtBar {
public:
  // FUNCTION: IMPERIALISM 0x00589240
  ~TIndustryAmtBar() override {}
  // The city commodity/production-order slot currently driving this bar's
  // display (see TCity::tradeCommodityRecordPtrs / trailingOrderSlots).
  TProductionOrder* selectedMetricRecord;

  TIndustryAmtBar();
  // ~TIndustryAmtBar is compiler-generated (implicit virtual dtor).
  DECLARE_DYNCREATE(TIndustryAmtBar)
  void DoPostCreate(int arg) override;
  void RenderPrimarySurfaceOverlayPanelWithClipCache() override;
  // TIndustryAmtBar-introduced virtual at slot 0x6b (byte 0x1ac): store the hit value and
  // repaint the overlay's invalidated rect. TRailAmtBar overrides it.
  virtual void RenderQuickDrawOverlayWithHitRegion(short selectedValue); // 0x00589540
};
ASSERT_SIZE(TIndustryAmtBar, 0x6c);
