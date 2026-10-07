#pragma once

#include "compat.h"

#include "game/city/TProductionOrder.h"
#include "game/mfc.h"

class TStream;

// VTABLE: IMPERIALISM 0x0064f848
class TPowerPlantOrder : public TProductionOrder {
public:
  DECLARE_DYNCREATE(TPowerPlantOrder)
  // FUNCTION: IMPERIALISM 0x004b7a90
  virtual ~TPowerPlantOrder() override {}
  virtual void WriteTo(TStream* stream) override;
  virtual void ReadFrom(TStream* stream) override;
  virtual bool SetQuantity(short quantity) override;
  virtual short MaxOrder() override;
  virtual void Produce() override;
  virtual void Restock() override;
  virtual void FillOrderSheet(OrderSheet* orderSheet, short quantity) override;
  virtual void IPowerPlantOrder(TCity* city);

  short desiredQuantity;

  TPowerPlantOrder() {}
};
ASSERT_SIZE(TPowerPlantOrder, 0x50);
