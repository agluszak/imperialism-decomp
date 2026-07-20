#pragma once

#include "game/TIndustryAmtBar.h"

class TShipOrder;

struct CRuntimeClass;
// VTABLE: IMPERIALISM 0x666998
class TShipAmtBar : public TIndustryAmtBar {
public:
  TShipAmtBar();
  DECLARE_DYNCREATE(TShipAmtBar)

  void DoPostCreate(int arg) override;
  void RenderPrimarySurfaceOverlayPanelWithClipCache() override;

  // 0x0058abf0 — TShipAmtBar's summary source is always the first navy order
  // slot (cityState->shipOrderSlots[0]), a TShipOrder* (TShipOrder : public
  // TProductionOrder). RTTI proves TShipAmtBar adds zero bytes over
  // TIndustryAmtBar (both 0x6c), and ground truth (0x58abf0 writes this->field_0x68,
  // the exact offset of the inherited selectedMetricRecord) confirms this is the
  // SAME slot as TIndustryAmtBar::selectedMetricRecord, not a separate field --
  // TShipAmtBar just always stores a TShipOrder* there via implicit upcast.
};
