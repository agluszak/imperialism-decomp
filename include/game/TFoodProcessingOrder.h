#pragma once

#include "game/TProductionOrder.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0064f7f0
class TFoodProcessingOrder : public TProductionOrder {
public:
  DECLARE_DYNCREATE(TFoodProcessingOrder)
  virtual ~TFoodProcessingOrder() override;         // slot 0x01 (scalar deleting destructor)
  virtual bool SetQuantity(short param_1) override; // slot 0x0b 0x4b7f50
  virtual short MaxOrder() override;                // slot 0x0c 0x4b7ed0
  virtual void Produce() override;                  // slot 0x0d 0x4b8060
  virtual void Restock() override;                  // slot 0x0e 0x4b80a0
  virtual void FillOrderSheet(OrderSheet* orderSheet,
                              short quantity) override; // slot 0x10 0x4b80c0
  virtual void IFoodProcessingOrder(TCity* city);       // slot 0x11 0x4b7e80

  TFoodProcessingOrder();
};
