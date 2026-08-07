#pragma once

#include "compat.h"

#include "game/city/TItemOrder.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0064f8f8
class TOrItemOrder : public TItemOrder {
public:
  DECLARE_DYNCREATE(TOrItemOrder)
  // FUNCTION: IMPERIALISM 0x004b5850
  virtual ~TOrItemOrder() override {}                // slot 0x01 (scalar deleting destructor)
  virtual bool SetQuantity(short quantity) override; // slot 0x0b 0x4b5990
  virtual short MaxOrder() override;                 // slot 0x0c 0x4b58f0
  virtual void IOrItemOrder(TCity* city, short resourceType, short primaryInputResource,
                            short secondaryInputResource,
                            short productionSlot); // slot 0x12 0x4b5870

  // SYNTHETIC: IMPERIALISM 0x004b5800
  // TOrItemOrder::TOrItemOrder
  TOrItemOrder() {}
};
ASSERT_SIZE(TOrItemOrder, 0x54);
