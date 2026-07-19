#pragma once

#include "game/TProductionOrder.h"
#include "game/mfc.h"

// Forward declarations for types referenced by generated signatures.
class TStream;

// VTABLE: IMPERIALISM 0x0064f848
class TPowerPlantOrder : public TProductionOrder {
public:
  DECLARE_DYNCREATE(TPowerPlantOrder)
  virtual ~TPowerPlantOrder() override; // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  virtual void WriteTo(TStream* stream) override;  // slot 0x05 0x4b7cc0
  virtual void ReadFrom(TStream* stream) override; // slot 0x06 0x4b7d40
  // slot 0x07 Free inherited unchanged (0x4798b0)
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  // slot 0x0a InitializeBasicCityOrderContext inherited unchanged (0x4b4f70)
  virtual bool SetQuantity(short param_1) override;           // slot 0x0b 0x4b7b30
  virtual short MaxOrder() override;                          // slot 0x0c 0x4b7b00
  virtual undefined CommitIfPending() override;               // slot 0x0d 0x4b7c20
  virtual void ResetCityOrderItemDerivedStateNoop() override; // slot 0x0e 0x4b7c40
  // slot 0x0f Produce inherited unchanged (0x4b5180)
  virtual void FillOrderSheet(OrderSheet* orderSheet,
                              short quantity) override;   // slot 0x10 0x4b7c90
  virtual undefined InitializeCityProductionState_Impl(); // slot 0x11 0x4b7ab0

  // 0x4c — runtime-derived quantity cap (first field past TProductionOrder's 0x4c
  // base). Zeroed/written by SetQuantity (0x4b7b30); read+restored by the slot-0x0e
  // quantity re-clamp (0x4b7c40). Name hedged by offset. Parallels TItemOrder::field4c.
  short field4c; // 0x4c

  TPowerPlantOrder();
};
