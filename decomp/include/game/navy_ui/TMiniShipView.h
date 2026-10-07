#pragma once

#include "compat.h"

#include "game/ui_core/TControl.h"
#include "game/mfc.h"

class TShip;

// VTABLE: IMPERIALISM 0x0065db68
class TMiniShipView : public TControl {
public:
  DECLARE_DYNCREATE(TMiniShipView)
  virtual ~TMiniShipView() override;            // slot 0x01 (scalar deleting destructor)
  virtual void Draw(RECT* rectBuffer) override; // slot 0x44 0x569eb0
  virtual void DoMouseCommand(CPoint& point, TToolboxEvent* event,
                              CPoint origin) override; // slot 0x47 0x56a330
  virtual void Hilite();                               // slot 0x71 0x569d50

  // NOOP: verified empty in original 0x00569df6
  TMiniShipView() {}

  TShip* shipNode;

  void IMiniShipView(TView* panel, int* offsetLayout, int* sizeLayout, TShip* ship);
};
ASSERT_SIZE(TMiniShipView, 0x88);
