#pragma once

#include "game/TControl.h"
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

  TMiniShipView();

  // Original object size is 0x88 (CRuntimeClass m_nObjectSize); the source class ended at 0x84. Trailing 4 byte(s) not yet semantically recovered — declared so sizeof and the recomp's allocation size match the original.
  // The order node this row represents: Draw (0x569eb0) reads
  // type (+4), name (+0x18), strength (+0x1c),
  // admiral (+0x20), and taskForce (+0xc) through this
  // pointer, matching TShip's layout exactly (same shape as TShipView::shipNode60).
  TShip* shipNode84;
};
