#pragma once

#include "game/TProductionOrder.h"
#include "game/mfc.h"

// TODO(manifest): describe TPopGrowthOrder and its role. Base edge (TProductionOrder) recovered from RTTI CRuntimeClass chain: TPopGrowthOrder -> TProductionOrder -> TObject -> CObject.
// VTABLE: IMPERIALISM 0x0064f620
class TPopGrowthOrder : public TProductionOrder {
public:
// === BEGIN GENERATED DECLS (TPopGrowthOrder) — refreshed by recover-class; do not hand-edit ===
  DECLARE_DYNCREATE(TPopGrowthOrder)
  virtual ~TPopGrowthOrder(); // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  // slot 0x05 WriteTo inherited unchanged (0x4b4fe0)
  // slot 0x06 ReadFrom inherited unchanged (0x4b5060)
  // slot 0x07 Free inherited unchanged (0x4798b0)
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  // slot 0x0a InitializeBasicCityOrderContext inherited unchanged (0x4b4f70)
  virtual bool SetQuantity(short param_1) override; // slot 0x0b 0x4b8230
  virtual short MaxOrder() override; // slot 0x0c 0x4b81b0
  virtual undefined CommitIfPending() override; // slot 0x0d 0x4b82f0
  virtual undefined ResetCityOrderItemDerivedStateNoop() override; // slot 0x0e 0x4b8420
  // slot 0x0f Produce inherited unchanged (0x4b5180)
  virtual undefined FillOrderSheet() override; // slot 0x10 0x4b8440
  virtual undefined ConstructTPopGrowthOrderBaseState(); // slot 0x11 0x4b8160
// === END GENERATED DECLS (TPopGrowthOrder) ===
  // TODO(manifest): add data members from the object slice (`just slice-discovery TPopGrowthOrder 0xCTOR`).

  TPopGrowthOrder();
};

// === BEGIN GENERATED (TPopGrowthOrder) — refreshed by `just gen-class TPopGrowthOrder`; do not hand-edit ===
// clang-format off
// vtable @ 0x0064f620 (18 slots), object size 0x4c, base TProductionOrder
//   slot 0x00  byte 0x00  0x004b8140  override  GetTProductionOrderClassNamePointer
//   slot 0x01  byte 0x04  0x004b3050  override  WrapperFor_FreeHeapBufferIfNotNull_At004b3050
//   slot 0x02  byte 0x08  0x00485e90  inherited Serialize
//   slot 0x03  byte 0x0c  0x00412bf0  inherited AssertValid
//   slot 0x04  byte 0x10  0x00412c10  inherited Dump
//   slot 0x05  byte 0x14  0x004b4fe0  inherited WrapperFor_HandleCityDialogNoOpSlot14_At004b4fe0
//   slot 0x06  byte 0x18  0x004b5060  inherited WrapperFor_HandleCityDialogNoOpSlot18_At004b5060
//   slot 0x07  byte 0x1c  0x004798b0  inherited Free
//   slot 0x08  byte 0x20  0x004798d0  inherited ShallowClone
//   slot 0x09  byte 0x24  0x00415ce0  inherited ShallowFree
//   slot 0x0a  byte 0x28  0x004b4f70  inherited InitializeBasicCityOrderContext
//   slot 0x0b  byte 0x2c  0x004b8230  override  SetQuantity
//   slot 0x0c  byte 0x30  0x004b81b0  override  MaxOrder
//   slot 0x0d  byte 0x34  0x004b82f0  override  CommitIfPending
//   slot 0x0e  byte 0x38  0x004b8420  override  ResetCityOrderItemDerivedStateNoop
//   slot 0x0f  byte 0x3c  0x004b5180  inherited InitializeCityOrderItemWorkingBuffers
//   slot 0x10  byte 0x40  0x004b8440  override  FillOrderSheet
//   slot 0x11  byte 0x44  0x004b8160  override  ConstructTPopGrowthOrderBaseState
// object size 0x4c (RTTI) unverified against the header layout;
// set curated.layout.size_verified to emit a sizeof static_assert.
// clang-format on
// === END GENERATED (TPopGrowthOrder) ===
