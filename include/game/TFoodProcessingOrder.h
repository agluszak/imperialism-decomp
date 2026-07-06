#pragma once

#include "game/TProductionOrder.h"
#include "game/mfc.h"

// TODO(manifest): describe TFoodProcessingOrder and its role. Base edge (TProductionOrder) recovered from RTTI CRuntimeClass chain: TFoodProcessingOrder -> TProductionOrder -> TObject -> CObject.
// VTABLE: IMPERIALISM 0x0064f7f0
class TFoodProcessingOrder : public TProductionOrder {
public:
// === BEGIN GENERATED DECLS (TFoodProcessingOrder) — refreshed by recover-class; do not hand-edit ===
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
  // slot 0x0a InitializeBasicCityOrderContext inherited unchanged (0x4b4f70)
  virtual bool SetQuantity(short param_1) override; // slot 0x0b 0x4b7f50
  virtual short MaxOrder() override; // slot 0x0c 0x4b7ed0
  virtual undefined CommitIfPending() override; // slot 0x0d 0x4b8060
  virtual undefined ResetCityOrderItemDerivedStateNoop() override; // slot 0x0e 0x4b80a0
  // slot 0x0f Produce inherited unchanged (0x4b5180)
  virtual void FillOrderSheet(void* orderSheet, short quantity) override; // slot 0x10 0x4b80c0
  virtual undefined InitializeCityProductionState_Impl_At004b7e80(int param_1); // slot 0x11 0x4b7e80
// === END GENERATED DECLS (TFoodProcessingOrder) ===
  // TODO(manifest): add data members from the object slice (`just slice-discovery TFoodProcessingOrder 0xCTOR`).

  TFoodProcessingOrder();
};

