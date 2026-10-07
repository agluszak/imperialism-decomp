#pragma once

#include "compat.h"

#include "game/city/TProductionOrder.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0064f620
class TPopGrowthOrder : public TProductionOrder {
public:
  DECLARE_DYNCREATE(TPopGrowthOrder)
  // FUNCTION: IMPERIALISM 0x004b3080
  virtual ~TPopGrowthOrder() override {}
  virtual bool SetQuantity(short quantity) override;
  virtual short MaxOrder() override;
  virtual void Produce() override;
  virtual void Restock() override;
  virtual void FillOrderSheet(OrderSheet* orderSheet, short quantity) override;
  virtual void IPopGrowthOrder(TCity* city); // Mac-style second-phase init

  // NOOP: verified empty in original 0x004b8112
  TPopGrowthOrder() {}
};
ASSERT_SIZE(TPopGrowthOrder, 0x4c);
