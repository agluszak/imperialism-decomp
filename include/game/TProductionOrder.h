#pragma once

#include "game/TObject.h"
#include "game/mfc.h"

// Forward declarations for types referenced by generated signatures.
class TStream;
class TCity;

// TProductionOrder is the common base for the city order-slot family
// (TShipOrder, TTrainingOrder, TItemOrder/TOrItemOrder, TUnitOrder,
// TPowerPlantOrder, TFoodProcessingOrder, TPopGrowthOrder, TCapacityOrder,
// TExpansionOrder). Base edge (TObject) recovered from RTTI CRuntimeClass
// chain: TProductionOrder -> TObject -> CObject.
// VTABLE: IMPERIALISM 0x0064fa18
class TProductionOrder : public TObject {
public:
// === BEGIN GENERATED DECLS (TProductionOrder) — refreshed by recover-class; do not hand-edit ===
  DECLARE_DYNCREATE(TProductionOrder)
  virtual ~TProductionOrder(); // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  virtual void WriteTo(TStream* stream) override; // slot 0x05 0x4b4fe0
  virtual void ReadFrom(TStream* stream) override; // slot 0x06 0x4b5060
  // slot 0x07 Free inherited unchanged (0x4798b0)
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  virtual undefined InitializeBasicCityOrderContext(int param_1, undefined2 param_2); // slot 0x0a 0x4b4f70
  virtual bool SetQuantity(short param_1); // slot 0x0b 0x4b5100
  virtual short MaxOrder(); // slot 0x0c 0x4b50e0
  virtual undefined CommitIfPending(); // slot 0x0d 0x4b5160
  virtual undefined ResetCityOrderItemDerivedStateNoop(); // slot 0x0e 0x4b5140
  virtual undefined InitializeCityOrderItemWorkingBuffers(undefined4 * param_1); // slot 0x0f 0x4b5180
  virtual undefined FillOrderSheet(); // slot 0x10 0x4b51b0
// === END GENERATED DECLS (TProductionOrder) ===
  // Field layout recovered from the RTTI object-size match: TProductionOrder
  // and several direct children (TShipOrder, TTrainingOrder,
  // TFoodProcessingOrder, TPopGrowthOrder) are ALL exactly 0x4c bytes per
  // `config/rtti_class_oracle.csv`, so those children add zero fields of
  // their own — every field previously modeled on TShipOrder at these same
  // offsets is really this base's own layout. Cross-checked against
  // TUnitOrder::CommitIfPending (0x004b73b0, a sibling with its own extra
  // 0x10 bytes) reading the identical offsets +0x04/+0x08/+0x48 for the same
  // roles (pending quantity, owning city, resource/entry id).
  short quantityField04;         // 0x04 — pending order quantity
  TCity* cityField08;            // 0x08 — owning city
  void* summaryField0c;          // 0x0c — summary/list link (unresolved use)
  short trackingSlots10[0x17];   // 0x10..0x3e — per-resource tracking slots
  short field3e;                 // 0x3e
  short field40;                 // 0x40
  int accumulatedValue;          // 0x44 — summed by TGreatPower::SumCommodityRecordAccumulatedValues (0x004e06d0)
  short resourceTypeIndex48;     // 0x48 — resource/entry type index
  short field4a;                 // 0x4a

  TProductionOrder();
};

ASSERT_SIZE(TProductionOrder, 0x4c);

// === BEGIN GENERATED (TProductionOrder) — refreshed by `just gen-class TProductionOrder`; do not hand-edit ===
// clang-format off
// vtable @ 0x0064fa18 (17 slots), object size 0x4c, base TObject
//   slot 0x00  byte 0x00  0x004b4ee0  override  GetRuntimeClass
//   slot 0x01  byte 0x04  0x004b4f20  scalar_dtor (scalar deleting destructor)
//   slot 0x02  byte 0x08  0x00485e90  inherited Serialize
//   slot 0x03  byte 0x0c  0x00412bf0  inherited AssertValid
//   slot 0x04  byte 0x10  0x00412c10  inherited Dump
//   slot 0x05  byte 0x14  0x004b4fe0  override  WriteTo
//   slot 0x06  byte 0x18  0x004b5060  override  ReadFrom
//   slot 0x07  byte 0x1c  0x004798b0  inherited Free
//   slot 0x08  byte 0x20  0x004798d0  inherited ShallowClone
//   slot 0x09  byte 0x24  0x00415ce0  inherited ShallowFree
//   slot 0x0a  byte 0x28  0x004b4f70  override  InitializeBasicCityOrderContext
//   slot 0x0b  byte 0x2c  0x004b5100  override  SetQuantity
//   slot 0x0c  byte 0x30  0x004b50e0  override  MaxOrder
//   slot 0x0d  byte 0x34  0x004b5160  override  CommitIfPending
//   slot 0x0e  byte 0x38  0x004b5140  override  ResetCityOrderItemDerivedStateNoop
//   slot 0x0f  byte 0x3c  0x004b5180  override  InitializeCityOrderItemWorkingBuffers
//   slot 0x10  byte 0x40  0x004b51b0  override  FillOrderSheet
// object size 0x4c (RTTI) unverified against the header layout;
// set curated.layout.size_verified to emit a sizeof static_assert.
// clang-format on
// === END GENERATED (TProductionOrder) ===
