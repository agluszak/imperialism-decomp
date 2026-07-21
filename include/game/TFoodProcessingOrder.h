#pragma once

#include "game/TProductionOrder.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0064f7f0
class TFoodProcessingOrder : public TProductionOrder {
public:
  DECLARE_DYNCREATE(TFoodProcessingOrder)
  virtual ~TFoodProcessingOrder() override; // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  // slot 0x05 WriteTo inherited unchanged (0x4b4fe0)
  // slot 0x06 ReadFrom inherited unchanged (0x4b5060)
  // slot 0x07 Free inherited unchanged (0x4798b0)
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  // slot 0x0a IProductionOrder inherited unchanged (0x4b4f70)
  virtual bool SetQuantity(short param_1) override; // slot 0x0b 0x4b7f50
  virtual short MaxOrder() override;                // slot 0x0c 0x4b7ed0
  virtual void Produce() override;                  // slot 0x0d 0x4b8060
  virtual void Restock() override;                  // slot 0x0e 0x4b80a0
  // slot 0x0f ResetOrderSheet inherited unchanged (0x4b5180)
  virtual void FillOrderSheet(OrderSheet* orderSheet,
                              short quantity) override; // slot 0x10 0x4b80c0
  virtual void IFoodProcessingOrder(TCity* city);       // slot 0x11 0x4b7e80

  TFoodProcessingOrder();
};
