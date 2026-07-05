#pragma once

#include "game/TProductionOrder.h"
#include "game/mfc.h"

// Forward declarations for types referenced by generated signatures.
class TStream;

// TODO(manifest): describe TItemOrder and its role. Base edge (TProductionOrder) recovered from RTTI CRuntimeClass chain: TItemOrder -> TProductionOrder -> TObject -> CObject.
// VTABLE: IMPERIALISM 0x0064f958
class TItemOrder : public TProductionOrder {
public:
// === BEGIN GENERATED DECLS (TItemOrder) — refreshed by recover-class; do not hand-edit ===
  DECLARE_DYNCREATE(TItemOrder)
  virtual ~TItemOrder(); // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  virtual void WriteTo(TStream* stream) override; // slot 0x05 0x4b5670
  virtual void ReadFrom(TStream* stream) override; // slot 0x06 0x4b5710
  // slot 0x07 Free inherited unchanged (0x4798b0)
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  // slot 0x0a InitializeBasicCityOrderContext inherited unchanged (0x4b4f70)
  virtual bool SetQuantity(short param_1) override; // slot 0x0b 0x4b53d0
  virtual short MaxOrder() override; // slot 0x0c 0x4b5310
  virtual undefined CommitIfPending() override; // slot 0x0d 0x4b5580
  virtual undefined ResetCityOrderItemDerivedStateNoop() override; // slot 0x0e 0x4b5620
  // slot 0x0f Produce inherited unchanged (0x4b5180)
  virtual undefined FillOrderSheet() override; // slot 0x10 0x4b5510
  virtual undefined InitializeCityProductionState_Impl_At004b5290(int param_1, undefined2 param_2, undefined2 param_3, undefined2 param_4, undefined2 param_5); // slot 0x11 0x4b5290
// === END GENERATED DECLS (TItemOrder) ===
  // TItemOrder is 0x54 bytes vs. TProductionOrder's 0x4c (RTTI), so it adds
  // 8 bytes of its own (0x4c..0x54). Only `buildingSlot` at 0x52 is confirmed
  // (read by TIndustryAmtBar::NoOpUiLifecycleHook / TIndustryCluster::NoOpUiLifecycleHook,
  // 0x00589260 / 0x00588b70); the leading 6 bytes are still unresolved.
  unsigned char pad4c[0x52 - 0x4c];
  short buildingSlot; // 0x52

  TItemOrder();
};

ASSERT_SIZE(TItemOrder, 0x54);

// === BEGIN GENERATED (TItemOrder) — refreshed by `just gen-class TItemOrder`; do not hand-edit ===
// clang-format off
// vtable @ 0x0064f958 (18 slots), object size 0x54, base TProductionOrder
//   slot 0x00  byte 0x00  0x004b5200  override  GetTProductionOrderClassNamePointer
//   slot 0x01  byte 0x04  0x004b5240  override  ConstructTItemOrderBaseState
//   slot 0x02  byte 0x08  0x00485e90  inherited Serialize
//   slot 0x03  byte 0x0c  0x00412bf0  inherited AssertValid
//   slot 0x04  byte 0x10  0x00412c10  inherited Dump
//   slot 0x05  byte 0x14  0x004b5670  override  SerializeCityOrderItemContextCore
//   slot 0x06  byte 0x18  0x004b5710  override  DeserializeCityOrderItemContextCore
//   slot 0x07  byte 0x1c  0x004798b0  inherited Free
//   slot 0x08  byte 0x20  0x004798d0  inherited ShallowClone
//   slot 0x09  byte 0x24  0x00415ce0  inherited ShallowFree
//   slot 0x0a  byte 0x28  0x004b4f70  inherited InitializeBasicCityOrderContext
//   slot 0x0b  byte 0x2c  0x004b53d0  override  SetQuantity
//   slot 0x0c  byte 0x30  0x004b5310  override  MaxOrder
//   slot 0x0d  byte 0x34  0x004b5580  override  CommitIfPending
//   slot 0x0e  byte 0x38  0x004b5620  override  ResetCityOrderItemDerivedStateNoop
//   slot 0x0f  byte 0x3c  0x004b5180  inherited InitializeCityOrderItemWorkingBuffers
//   slot 0x10  byte 0x40  0x004b5510  override  FillOrderSheet
//   slot 0x11  byte 0x44  0x004b5290  override  InitializeCityProductionState_Impl_At004b5290
// object size 0x54 (RTTI) unverified against the header layout;
// set curated.layout.size_verified to emit a sizeof static_assert.
// clang-format on
// === END GENERATED (TItemOrder) ===
