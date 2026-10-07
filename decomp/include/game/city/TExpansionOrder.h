#pragma once

#include "compat.h"

#include "game/city/TItemOrder.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0064f6d8
class TExpansionOrder : public TItemOrder {
public:
  DECLARE_DYNCREATE(TExpansionOrder)
  // FUNCTION: IMPERIALISM 0x004b8ff0
  virtual ~TExpansionOrder() override {}
  virtual bool SetQuantity(short quantity) override;
  virtual short MaxOrder() override;
  virtual void Produce() override;
  virtual void FillOrderSheet(OrderSheet* orderSheet, short quantity) override;
  virtual void IExpansionOrder(TCity* city, short resourceType, short primaryInputResource,
                               short secondaryInputResource, short productionSlot);

  TExpansionOrder() {}
};
ASSERT_SIZE(TExpansionOrder, 0x54);
