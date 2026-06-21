#pragma once

#include "game/TCityTask.h"
#include "game/mfc.h"

// Forward declarations for types referenced by generated signatures.
class TStream;

// TODO(manifest): describe TShipBuildingTask and its role. Base edge (TCityTask) recovered from RTTI CRuntimeClass chain: TShipBuildingTask -> TCityTask -> TTask -> TObject -> CObject.
// VTABLE: IMPERIALISM 0x0066a9f8
class TShipBuildingTask : public TCityTask {
public:
// === BEGIN GENERATED DECLS (TShipBuildingTask) — refreshed by recover-class; do not hand-edit ===
  virtual CRuntimeClass* GetRuntimeClass() const override; // slot 0x00 0x5ae680
  virtual ~TShipBuildingTask(); // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  virtual void WriteTo(TStream* stream) override; // slot 0x05 0x5ae9e0
  virtual void ReadFrom(TStream* stream) override; // slot 0x06 0x5aea70
  // slot 0x07 Free inherited unchanged (0x4798b0)
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  virtual undefined OrphanLeaf_NoCall_Ins04_005adc30() override; // slot 0x0a 0x5ae780
  // slot 0x0b QueueCityOrderType10CommandIfReady inherited unchanged (0x5ae010)
  // slot 0x0c ApplyProductionDistributionToCitySlots inherited unchanged (0x5ae420)
  // slot 0x0d QueueCityRecruitmentSupportCommandsIfDeficit inherited unchanged (0x5ae0e0)
  // slot 0x0e QueueCityOrderInputDeltaCommands inherited unchanged (0x5ae240)
  // slot 0x0f QueueCityProductionOrderCommand inherited unchanged (0x5ae4b0)
// === END GENERATED DECLS (TShipBuildingTask) ===
  // TODO(manifest): add data members from the object slice (`just slice-discovery TShipBuildingTask 0xCTOR`).

  TShipBuildingTask();
};

// === BEGIN GENERATED (TShipBuildingTask) — refreshed by `just gen-class TShipBuildingTask`; do not hand-edit ===
// clang-format off
// vtable @ 0x0066a9f8 (16 slots), object size 0x18, base TCityTask
//   slot 0x00  byte 0x00  0x005ae680  override  GetTTaskClassNamePointer
//   slot 0x01  byte 0x04  0x005ae6c0  override  ConstructTTaskBaseState
//   slot 0x02  byte 0x08  0x00485e90  inherited Serialize
//   slot 0x03  byte 0x0c  0x00412bf0  inherited AssertValid
//   slot 0x04  byte 0x10  0x00412c10  inherited Dump
//   slot 0x05  byte 0x14  0x005ae9e0  override  SerializeCityProductionQueueCommand
//   slot 0x06  byte 0x18  0x005aea70  override  DeserializeCityProductionQueueCommand
//   slot 0x07  byte 0x1c  0x004798b0  inherited Free
//   slot 0x08  byte 0x20  0x004798d0  inherited ShallowClone
//   slot 0x09  byte 0x24  0x00415ce0  inherited ShallowFree
//   slot 0x0a  byte 0x28  0x005ae780  override  OrphanLeaf_NoCall_Ins04_005adc30
//   slot 0x0b  byte 0x2c  0x005ae010  inherited QueueCityOrderType10CommandIfReady
//   slot 0x0c  byte 0x30  0x005ae420  inherited ApplyProductionDistributionToCitySlots
//   slot 0x0d  byte 0x34  0x005ae0e0  inherited QueueCityRecruitmentSupportCommandsIfDeficit
//   slot 0x0e  byte 0x38  0x005ae240  inherited DeserializeCityProductionQueueCommand
//   slot 0x0f  byte 0x3c  0x005ae4b0  inherited OrphanRetStub_0059add0
// object size 0x18 (RTTI) unverified against the header layout;
// set curated.layout.size_verified to emit a sizeof static_assert.
// clang-format on
// === END GENERATED (TShipBuildingTask) ===
