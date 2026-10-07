#pragma once

#include "compat.h"

#include "game/city/TProductionOrder.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0064f7f0
class TFoodProcessingOrder : public TProductionOrder {
public:
  DECLARE_DYNCREATE(TFoodProcessingOrder)
  // FUNCTION: IMPERIALISM 0x004b7e60
  virtual ~TFoodProcessingOrder() override {}
  virtual bool SetQuantity(short quantity) override;
  virtual short MaxOrder() override;
  virtual void Produce() override;
  virtual void Restock() override;
  virtual void FillOrderSheet(OrderSheet* orderSheet, short quantity) override;
  virtual void IFoodProcessingOrder(TCity* city);

  TFoodProcessingOrder() {}
};
ASSERT_SIZE(TFoodProcessingOrder, 0x4c);
