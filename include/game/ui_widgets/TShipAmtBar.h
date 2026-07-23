#pragma once

#include "game/ui_widgets/TAmtBar.h"

class TShipOrder;

struct CRuntimeClass;
// VTABLE: IMPERIALISM 0x666998
class TShipAmtBar : public TAmtBar {
public:
  // FUNCTION: IMPERIALISM 0x0058abd0
  ~TShipAmtBar() override {}
  // The navy order currently driving the bar's display.
  TShipOrder* selectedMetricRecord; // 0x68

  TShipAmtBar();
  DECLARE_DYNCREATE(TShipAmtBar)

  void DoPostCreate(int arg) override;
  void RenderPrimarySurfaceOverlayPanelWithClipCache() override;
};

ASSERT_SIZE(TShipAmtBar, 0x6c);
