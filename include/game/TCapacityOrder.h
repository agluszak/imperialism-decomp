#pragma once

#include "game/TItemOrder.h"

struct CRuntimeClass;

class TCity;

// Mac oracle: TCapacityOrder (capacity / industry production order).
// VTABLE: IMPERIALISM 0x0064f678
class TCapacityOrder : public TItemOrder {
public:
  CRuntimeClass* GetRuntimeClass() const override;
  ~TCapacityOrder();

  undefined CommitIfPending() override; // slot 0x0d 0x4b8dd0
  virtual undefined InitializeCityProductionState_Impl_At004b8d50(
      TCity* city, short resourceType, short trackingIndex4e, short trackingIndex50,
      short field52); // slot 0x12 0x4b8d50

  explicit TCapacityOrder(TCity* city);
  short ComputeCapacityOrderMaxQuantity();
  bool SetCapacityOrderQuantity(short quantity);
  void CommitCapacityOrderIfPending();
  void FillOrderSheet(void* orderSheet, short quantity);
  bool CanMakeFromCityStock();
  bool CanFillOrderSheet(void* orderSheet);
  static TCapacityOrder* NewForCity(TCity* city);

  short quantityField04;
  TCity* cityField08;
  class TPopulationMgr* summaryField0c;
  short trackingSlots10[0x17];
  short field3e;
  short field40;
  int field44;
  short resourceTypeIndex48;
  short field4c;
  short trackingIndex4e;
  short trackingIndex50;
  short field52;
};

// === BEGIN GENERATED (TCapacityOrder) — refreshed by `just gen-class TCapacityOrder`; do not hand-edit ===
// clang-format off
// vtable @ 0x0064f678 (19 slots), object size 0x54, base TItemOrder
//   slot 0x00  byte 0x00  0x004b8cc0  override  GetTProductionOrderClassNamePointer
//   slot 0x01  byte 0x04  0x004b8d00  override  ConstructTItemOrderBaseState
//   slot 0x02  byte 0x08  0x00485e90  inherited GetTTaskClassNamePointer
//   slot 0x03  byte 0x0c  0x00412bf0  inherited ConstructTTaskBaseState
//   slot 0x04  byte 0x10  0x00412c10  inherited GetTEventHandlerClassNamePointer
//   slot 0x05  byte 0x14  0x004b5670  inherited SerializeCityOrderItemContextCore
//   slot 0x06  byte 0x18  0x004b5710  inherited DeserializeCityOrderItemContextCore
//   slot 0x07  byte 0x1c  0x004798b0  inherited QueueCityRecruitmentSupportCommandsIfDeficit
//   slot 0x08  byte 0x20  0x004798d0  inherited DeserializeCityProductionQueueCommand
//   slot 0x09  byte 0x24  0x00415ce0  inherited OrphanRetStub_0059add0
//   slot 0x0a  byte 0x28  0x004b4f70  inherited InitializeBasicCityOrderContext
//   slot 0x0b  byte 0x2c  0x004b53d0  inherited SetQuantity
//   slot 0x0c  byte 0x30  0x004b5310  inherited MaxOrder
//   slot 0x0d  byte 0x34  0x004b8dd0  override  CommitIfPending
//   slot 0x0e  byte 0x38  0x004b5620  inherited ResetCityOrderItemDerivedStateNoop
//   slot 0x0f  byte 0x3c  0x004b5180  inherited InitializeCityOrderItemWorkingBuffers
//   slot 0x10  byte 0x40  0x004b5510  inherited FillOrderSheet
//   slot 0x11  byte 0x44  0x004b5290  inherited InitializeCityProductionState_Impl_At004b5290
//   slot 0x12  byte 0x48  0x004b8d50  new       InitializeCityProductionState_Impl_At004b8d50
// object size 0x54 (RTTI) unverified against the header layout;
// set curated.layout.size_verified to emit a sizeof static_assert.
// clang-format on
// === END GENERATED (TCapacityOrder) ===
