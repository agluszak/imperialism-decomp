#pragma once

#include "compat.h"

#include "game/ui_core/TControl.h"
#include "game/mfc.h"

class TShip;

// VTABLE: IMPERIALISM 0x0065db68
class TMiniShipView : public TControl {
public:
  DECLARE_DYNCREATE(TMiniShipView)
  virtual ~TMiniShipView() override;
  virtual void Draw(RECT* rectBuffer) override;
  virtual void DoMouseCommand(CPoint& point, TToolboxEvent* event, CPoint origin) override;
  virtual void Hilite();

  // NOOP: verified empty in original 0x00569df6
  TMiniShipView() {}

  TShip* shipNode;

  void IMiniShipView(TView* panel, int* offsetLayout, int* sizeLayout, TShip* ship);
};
ASSERT_SIZE(TMiniShipView, 0x88);
