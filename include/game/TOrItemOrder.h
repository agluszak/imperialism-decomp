#pragma once

#include "game/TItemOrder.h"
#include "game/mfc.h"

// TODO(manifest): describe TOrItemOrder and its role. Base edge (TItemOrder) recovered from RTTI CRuntimeClass chain: TOrItemOrder -> TItemOrder -> TProductionOrder -> TObject -> CObject.
// VTABLE: IMPERIALISM 0x0064f8f8
class TOrItemOrder : public TItemOrder {
public:
// === BEGIN GENERATED DECLS (TOrItemOrder) — refreshed by recover-class; do not hand-edit ===
  virtual CRuntimeClass* GetRuntimeClass() const override; // slot 0x00 0x4b57e0
  virtual ~TOrItemOrder(); // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  // slot 0x05 WriteTo inherited unchanged (0x4b5670)
  // slot 0x06 ReadFrom inherited unchanged (0x4b5710)
  // slot 0x07 Free inherited unchanged (0x4798b0)
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  // slot 0x0a InitializeBasicCityOrderContext inherited unchanged (0x4b4f70)
  virtual undefined OrphanCallChain_C1_I16_004b5100(short param_1) override; // slot 0x0b 0x4b5990
  virtual undefined OrphanLeaf_NoCall_Ins02_004b50e0() override; // slot 0x0c 0x4b58f0
  // slot 0x0d OrphanRetStub_004b5160 inherited unchanged (0x4b5580)
  // slot 0x0e ResetCityOrderItemDerivedStateNoop inherited unchanged (0x4b5620)
  // slot 0x0f Produce inherited unchanged (0x4b5180)
  // slot 0x10 CreateTItemOrderInstance inherited unchanged (0x4b5510)
  // slot 0x11 InitializeCityProductionState_Impl_At004b5290 inherited unchanged (0x4b5290)
  virtual undefined InitializeCityProductionState_Impl_At004b5870(int param_1, undefined2 param_2, undefined2 param_3, undefined2 param_4, undefined2 param_5) override; // slot 0x12 0x4b5870
// === END GENERATED DECLS (TOrItemOrder) ===
  // TODO(manifest): add data members from the object slice (`just slice-discovery TOrItemOrder 0xCTOR`).

  TOrItemOrder();
};

// === BEGIN GENERATED (TOrItemOrder) — refreshed by `just gen-class TOrItemOrder`; do not hand-edit ===
// clang-format off
// vtable @ 0x0064f8f8 (19 slots), object size 0x54, base TItemOrder
//   slot 0x00  byte 0x00  0x004b57e0  override  GetTProductionOrderClassNamePointer
//   slot 0x01  byte 0x04  0x004b5820  override  ConstructTItemOrderBaseState
//   slot 0x02  byte 0x08  0x00485e90  inherited Serialize
//   slot 0x03  byte 0x0c  0x00412bf0  inherited AssertValid
//   slot 0x04  byte 0x10  0x00412c10  inherited Dump
//   slot 0x05  byte 0x14  0x004b5670  inherited SerializeCityOrderItemContextCore
//   slot 0x06  byte 0x18  0x004b5710  inherited DeserializeCityOrderItemContextCore
//   slot 0x07  byte 0x1c  0x004798b0  inherited Free
//   slot 0x08  byte 0x20  0x004798d0  inherited ShallowClone
//   slot 0x09  byte 0x24  0x00415ce0  inherited ShallowFree
//   slot 0x0a  byte 0x28  0x004b4f70  inherited InitializeBasicCityOrderContext
//   slot 0x0b  byte 0x2c  0x004b5990  override  OrphanCallChain_C1_I16_004b5100
//   slot 0x0c  byte 0x30  0x004b58f0  override  OrphanLeaf_NoCall_Ins02_004b50e0
//   slot 0x0d  byte 0x34  0x004b5580  inherited OrphanRetStub_004b5160
//   slot 0x0e  byte 0x38  0x004b5620  inherited ResetCityOrderItemDerivedStateNoop
//   slot 0x0f  byte 0x3c  0x004b5180  inherited InitializeCityOrderItemWorkingBuffers
//   slot 0x10  byte 0x40  0x004b5510  inherited CreateTItemOrderInstance
//   slot 0x11  byte 0x44  0x004b5290  inherited InitializeCityProductionState_Impl_At004b5290
//   slot 0x12  byte 0x48  0x004b5870  override  InitializeCityProductionState_Impl_At004b5870
// object size 0x54 (RTTI) unverified against the header layout;
// set curated.layout.size_verified to emit a sizeof static_assert.
// clang-format on
// === END GENERATED (TOrItemOrder) ===
