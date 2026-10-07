#pragma once

#include "compat.h"

#include "game/city/TItemOrder.h"

struct CRuntimeClass;

class TCity;

// Capacity (industry production) order.
// VTABLE: IMPERIALISM 0x0064f678
class TCapacityOrder : public TItemOrder {
public:
  DECLARE_DYNCREATE(TCapacityOrder)
  TCapacityOrder() {}

  // FUNCTION: IMPERIALISM 0x004b8d30
  ~TCapacityOrder() override {}

  void Produce() override; // slot 0x0d 0x4b8dd0
  virtual void ICapacityOrder(TCity* city, short resourceType, short primaryInputResource,
                              short secondaryInputResource,
                              short productionSlot); // slot 0x12 0x4b8d50
};
ASSERT_SIZE(TCapacityOrder, 0x54);
