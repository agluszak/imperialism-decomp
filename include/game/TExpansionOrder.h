#pragma once

#include "game/TItemOrder.h"
#include "game/mfc.h"

// TODO(manifest): describe TExpansionOrder and its role. Base edge (TItemOrder) recovered from RTTI CRuntimeClass chain: TExpansionOrder -> TItemOrder -> TProductionOrder -> TObject -> CObject.
// VTABLE: IMPERIALISM 0x0064f6d8
class TExpansionOrder : public TItemOrder {
public:
// === BEGIN GENERATED DECLS (TExpansionOrder) — refreshed by recover-class; do not hand-edit ===
  virtual CRuntimeClass* GetRuntimeClass() const override; // slot 0x00 0x4b8f80
  virtual ~TExpansionOrder(); // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  // slot 0x05 WriteTo inherited unchanged (0x4b5670)
  // slot 0x06 ReadFrom inherited unchanged (0x4b5710)
  // slot 0x07 Free inherited unchanged (0x4798b0)
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  // slot 0x0a InitializeBasicCityOrderContext inherited unchanged (0x4b4f70)
  virtual undefined OrphanCallChain_C1_I16_004b5100(short param_1) override; // slot 0x0b 0x4b9260
  virtual undefined OrphanLeaf_NoCall_Ins02_004b50e0() override; // slot 0x0c 0x4b91f0
  virtual undefined OrphanRetStub_004b5160() override; // slot 0x0d 0x4b9090
  // slot 0x0e ResetCityOrderItemDerivedStateNoop inherited unchanged (0x4b5620)
  // slot 0x0f Produce inherited unchanged (0x4b5180)
  virtual undefined CreateTItemOrderInstance() override; // slot 0x10 0x4b9360
  // slot 0x11 InitializeCityProductionState_Impl_At004b5290 inherited unchanged (0x4b5290)
  virtual undefined InitializeCityProductionState_Impl_At004b9010(int param_1, undefined2 param_2, undefined2 param_3, undefined2 param_4, undefined2 param_5); // slot 0x12 0x4b9010
// === END GENERATED DECLS (TExpansionOrder) ===
  // TODO(manifest): add data members from the object slice (`just slice-discovery TExpansionOrder 0xCTOR`).

  TExpansionOrder();
};

// === BEGIN GENERATED (TExpansionOrder) — refreshed by `just gen-class TExpansionOrder`; do not hand-edit ===
// clang-format off
// vtable @ 0x0064f6d8 (19 slots), object size 0x54, base TItemOrder
//   slot 0x00  byte 0x00  0x004b8f80  override  GetTProductionOrderClassNamePointer
//   slot 0x01  byte 0x04  0x004b8fc0  override  ConstructTItemOrderBaseState
//   slot 0x02  byte 0x08  0x00485e90  inherited Serialize
//   slot 0x03  byte 0x0c  0x00412bf0  inherited AssertValid
//   slot 0x04  byte 0x10  0x00412c10  inherited Dump
//   slot 0x05  byte 0x14  0x004b5670  inherited SerializeCityOrderItemContextCore
//   slot 0x06  byte 0x18  0x004b5710  inherited DeserializeCityOrderItemContextCore
//   slot 0x07  byte 0x1c  0x004798b0  inherited Free
//   slot 0x08  byte 0x20  0x004798d0  inherited ShallowClone
//   slot 0x09  byte 0x24  0x00415ce0  inherited ShallowFree
//   slot 0x0a  byte 0x28  0x004b4f70  inherited InitializeBasicCityOrderContext
//   slot 0x0b  byte 0x2c  0x004b9260  override  OrphanCallChain_C1_I16_004b5100
//   slot 0x0c  byte 0x30  0x004b91f0  override  OrphanLeaf_NoCall_Ins02_004b50e0
//   slot 0x0d  byte 0x34  0x004b9090  override  OrphanRetStub_004b5160
//   slot 0x0e  byte 0x38  0x004b5620  inherited ResetCityOrderItemDerivedStateNoop
//   slot 0x0f  byte 0x3c  0x004b5180  inherited InitializeCityOrderItemWorkingBuffers
//   slot 0x10  byte 0x40  0x004b9360  override  CreateTItemOrderInstance
//   slot 0x11  byte 0x44  0x004b5290  inherited InitializeCityProductionState_Impl_At004b5290
//   slot 0x12  byte 0x48  0x004b9010  override  InitializeCityProductionState_Impl_At004b9010
// object size 0x54 (RTTI) unverified against the header layout;
// set curated.layout.size_verified to emit a sizeof static_assert.
// clang-format on
// === END GENERATED (TExpansionOrder) ===
