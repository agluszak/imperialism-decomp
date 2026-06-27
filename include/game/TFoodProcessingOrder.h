#pragma once

#include "game/TProductionOrder.h"
#include "game/mfc.h"

// TODO(manifest): describe TFoodProcessingOrder and its role. Base edge (TProductionOrder) recovered from RTTI CRuntimeClass chain: TFoodProcessingOrder -> TProductionOrder -> TObject -> CObject.
// VTABLE: IMPERIALISM 0x0064f7f0
class TFoodProcessingOrder : public TProductionOrder {
public:
// === BEGIN GENERATED DECLS (TFoodProcessingOrder) — refreshed by recover-class; do not hand-edit ===
  DECLARE_DYNCREATE(TFoodProcessingOrder)
  virtual ~TFoodProcessingOrder(); // slot 0x01 (scalar deleting destructor)
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
  virtual undefined FillOrderSheet() override; // slot 0x10 0x4b80c0
  virtual undefined InitializeCityProductionState_Impl_At004b7e80(int param_1); // slot 0x11 0x4b7e80
// === END GENERATED DECLS (TFoodProcessingOrder) ===
  // TODO(manifest): add data members from the object slice (`just slice-discovery TFoodProcessingOrder 0xCTOR`).

  TFoodProcessingOrder();
};

// === BEGIN GENERATED (TFoodProcessingOrder) — refreshed by `just gen-class TFoodProcessingOrder`; do not hand-edit ===
// clang-format off
// vtable @ 0x0064f7f0 (18 slots), object size 0x4c, base TProductionOrder
//   slot 0x00  byte 0x00  0x004b7df0  override  GetTProductionOrderClassNamePointer
//   slot 0x01  byte 0x04  0x004b7e30  override  ConstructTFoodProcessingOrderBaseState
//   slot 0x02  byte 0x08  0x00485e90  inherited Serialize
//   slot 0x03  byte 0x0c  0x00412bf0  inherited AssertValid
//   slot 0x04  byte 0x10  0x00412c10  inherited Dump
//   slot 0x05  byte 0x14  0x004b4fe0  inherited WrapperFor_HandleCityDialogNoOpSlot14_At004b4fe0
//   slot 0x06  byte 0x18  0x004b5060  inherited WrapperFor_HandleCityDialogNoOpSlot18_At004b5060
//   slot 0x07  byte 0x1c  0x004798b0  inherited Free
//   slot 0x08  byte 0x20  0x004798d0  inherited ShallowClone
//   slot 0x09  byte 0x24  0x00415ce0  inherited ShallowFree
//   slot 0x0a  byte 0x28  0x004b4f70  inherited InitializeBasicCityOrderContext
//   slot 0x0b  byte 0x2c  0x004b7f50  override  SetQuantity
//   slot 0x0c  byte 0x30  0x004b7ed0  override  MaxOrder
//   slot 0x0d  byte 0x34  0x004b8060  override  CommitIfPending
//   slot 0x0e  byte 0x38  0x004b80a0  override  ResetCityOrderItemDerivedStateNoop
//   slot 0x0f  byte 0x3c  0x004b5180  inherited InitializeCityOrderItemWorkingBuffers
//   slot 0x10  byte 0x40  0x004b80c0  override  FillOrderSheet
//   slot 0x11  byte 0x44  0x004b7e80  override  InitializeCityProductionState_Impl_At004b7e80
// object size 0x4c (RTTI) unverified against the header layout;
// set curated.layout.size_verified to emit a sizeof static_assert.
// clang-format on
// === END GENERATED (TFoodProcessingOrder) ===
