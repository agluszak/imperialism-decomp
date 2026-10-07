#pragma once

#include "compat.h"

#include "game/city/TProductionOrder.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0064f798
class TTrainingOrder : public TProductionOrder {
public:
  DECLARE_DYNCREATE(TTrainingOrder)
  // FUNCTION: IMPERIALISM 0x004b6b00
  virtual ~TTrainingOrder() override {}
  virtual bool SetQuantity(short quantity) override;
  virtual short MaxOrder() override;
  virtual void Produce() override;
  virtual void Restock() override;
  virtual void FillOrderSheet(OrderSheet* orderSheet, short quantity) override;
  virtual void ITrainingOrder(TCity* city, short resourceType);

  TTrainingOrder() {}
};
ASSERT_SIZE(TTrainingOrder, 0x4c);
