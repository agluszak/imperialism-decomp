#pragma once

#include "compat.h"

#include "game/ui_core/TView.h"
#include "game/mfc.h"

class TEventHandler;
class TGreatPower;
class TCity;
class TItemOrder;

// VTABLE: IMPERIALISM 0x00657eb0
class TOrderView : public TView {
public:
  DECLARE_DYNCREATE(TOrderView)
  virtual ~TOrderView() override; // slot 0x01 (scalar deleting destructor)
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler,
                       TEvent* event) override;                  // slot 0x0f 0x00507240
  virtual void StuffValues(TGreatPower* power, short orderSlot); // slot 0x68 0x506b00
  virtual void UpdateFields();                                   // slot 0x69 0x506f90
  // TView's own fields end exactly at 0x60. StuffValues installs the active city and
  // production order used by UpdateFields and DoEvent.
  TCity* city60; // +0x60

  TOrderView();

  TItemOrder* order64; // +0x64 — selected city-production item order
};
ASSERT_SIZE(TOrderView, 0x68);
