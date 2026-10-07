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
  virtual ~TOrderView() override;
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) override;
  virtual void StuffValues(TGreatPower* power, short orderSlot);
  virtual void UpdateFields();
  TCity* city;

  TOrderView();

  TItemOrder* order; // selected city-production item order
};
ASSERT_SIZE(TOrderView, 0x68);
