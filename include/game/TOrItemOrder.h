#pragma once

#include "game/TItemOrder.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0064f8f8
class TOrItemOrder : public TItemOrder {
public:
  DECLARE_DYNCREATE(TOrItemOrder)
  virtual ~TOrItemOrder() override;                 // slot 0x01 (scalar deleting destructor)
  virtual bool SetQuantity(short param_1) override; // slot 0x0b 0x4b5990
  virtual short MaxOrder() override;                // slot 0x0c 0x4b58f0
  virtual void IOrItemOrder(TCity* city, short resourceType, short primaryInputResource,
                            short secondaryInputResource,
                            short productionSlot); // slot 0x12 0x4b5870

  TOrItemOrder();
};
