#pragma once

#include "game/TIndustryAmtBar.h"

class TShipOrder;

struct CRuntimeClass;
// VTABLE: IMPERIALISM 0x666998
class TShipAmtBar : public TIndustryAmtBar {
public:
  TShipAmtBar();
  DECLARE_DYNCREATE(TShipAmtBar)

  void NoOpUiLifecycleHook(int arg) override;
  void RenderPrimarySurfaceOverlayPanelWithClipCache() override;

  // 0x0058abf0 — TShipAmtBar's summary source is always the first navy order
  // slot (cityState->shipOrderSlots[0]), a TShipOrder*, distinct from the
  // base class's TProductionOrder* commodity-tag lookup field.
  TShipOrder* selectedShipOrder;
};
