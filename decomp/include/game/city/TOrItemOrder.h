#pragma once

#include "compat.h"

#include "game/city/TItemOrder.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0064f8f8
class TOrItemOrder : public TItemOrder {
public:
  DECLARE_DYNCREATE(TOrItemOrder)
  // FUNCTION: IMPERIALISM 0x004b5850
  virtual ~TOrItemOrder() override {}
  virtual bool SetQuantity(short quantity) override;
  virtual short MaxOrder() override;
  virtual void IOrItemOrder(TCity* city, short resourceType, short primaryInputResource,
                            short secondaryInputResource, short productionSlot);

  TOrItemOrder() {}
};
ASSERT_SIZE(TOrItemOrder, 0x54);
