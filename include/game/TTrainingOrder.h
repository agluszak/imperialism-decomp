#pragma once

#include "game/TProductionOrder.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0064f798
class TTrainingOrder : public TProductionOrder {
public:
  // === BEGIN GENERATED DECLS (TTrainingOrder) — refreshed by recover-class; do not hand-edit ===
  DECLARE_DYNCREATE(TTrainingOrder)
  virtual ~TTrainingOrder() override; // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  // slot 0x05 WriteTo inherited unchanged (0x4b4fe0)
  // slot 0x06 ReadFrom inherited unchanged (0x4b5060)
  // slot 0x07 Free inherited unchanged (0x4798b0)
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  // slot 0x0a InitializeBasicCityOrderContext inherited unchanged (0x4b4f70)
  virtual bool SetQuantity(short param_1) override;                // slot 0x0b 0x4b6cd0
  virtual short MaxOrder() override;                               // slot 0x0c 0x4b6b90
  virtual undefined CommitIfPending() override;                    // slot 0x0d 0x4b6e30
  virtual undefined ResetCityOrderItemDerivedStateNoop() override; // slot 0x0e 0x4b6f00
  // slot 0x0f Produce inherited unchanged (0x4b5180)
  virtual void FillOrderSheet(OrderSheet* orderSheet,
                              short quantity) override; // slot 0x10 0x4b6de0
  virtual undefined
  InitializeCityProductionState_Impl_At004b6b20(int param_1,
                                                undefined2 param_2); // slot 0x11 0x4b6b20
  // === END GENERATED DECLS (TTrainingOrder) ===

  TTrainingOrder();
};
