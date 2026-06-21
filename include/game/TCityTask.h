#pragma once

#include "game/TTask.h"
#include "game/mfc.h"

// Forward declarations for types referenced by generated signatures.
class TStream;

// TODO(manifest): describe TCityTask and its role. Base edge (TTask) recovered from RTTI CRuntimeClass chain: TCityTask -> TTask -> TObject -> CObject.
// VTABLE: IMPERIALISM 0x0066a9a8
class TCityTask : public TTask {
public:
// === BEGIN GENERATED DECLS (TCityTask) — refreshed by recover-class; do not hand-edit ===
  virtual CRuntimeClass* GetRuntimeClass() const override; // slot 0x00 0x5add00
  virtual ~TCityTask(); // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  virtual void WriteTo(TStream* stream) override; // slot 0x05 0x5ae570
  virtual void ReadFrom(TStream* stream) override; // slot 0x06 0x5ae5e0
  // slot 0x07 Free inherited unchanged (0x4798b0)
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  virtual undefined OrphanLeaf_NoCall_Ins04_005adc30() override; // slot 0x0a 0x5adde0
  virtual undefined QueueCityOrderType10CommandIfReady(int* param_1) override; // slot 0x0b 0x5ae010
  virtual void ApplyProductionDistributionToCitySlots() override; // slot 0x0c 0x5ae420
  virtual void QueueCityRecruitmentSupportCommandsIfDeficit(void* pCommandQueue) override; // slot 0x0d 0x5ae0e0
  virtual void DeserializeCityProductionQueueCommand(void* pCommandQueue) override; // slot 0x0e 0x5ae240
  virtual void OrphanRetStub_0059add0(void* pCommandQueue) override; // slot 0x0f 0x5ae4b0
// === END GENERATED DECLS (TCityTask) ===
  // TODO(manifest): add data members from the object slice (`just slice-discovery TCityTask 0xCTOR`).

  TCityTask();
};

// === BEGIN GENERATED (TCityTask) — refreshed by `just gen-class TCityTask`; do not hand-edit ===
// clang-format off
// vtable @ 0x0066a9a8 (16 slots), object size 0x14, base TTask
//   slot 0x00  byte 0x00  0x005add00  override  GetTTaskClassNamePointer
//   slot 0x01  byte 0x04  0x005add40  override  ConstructTTaskBaseState
//   slot 0x02  byte 0x08  0x00485e90  inherited Serialize
//   slot 0x03  byte 0x0c  0x00412bf0  inherited AssertValid
//   slot 0x04  byte 0x10  0x00412c10  inherited Dump
//   slot 0x05  byte 0x14  0x005ae570  override  SerializeCityProductionQueueCommand
//   slot 0x06  byte 0x18  0x005ae5e0  override  DeserializeCityProductionQueueCommand
//   slot 0x07  byte 0x1c  0x004798b0  inherited Free
//   slot 0x08  byte 0x20  0x004798d0  inherited ShallowClone
//   slot 0x09  byte 0x24  0x00415ce0  inherited ShallowFree
//   slot 0x0a  byte 0x28  0x005adde0  override  OrphanLeaf_NoCall_Ins04_005adc30
//   slot 0x0b  byte 0x2c  0x005ae010  override  QueueCityOrderType10CommandIfReady
//   slot 0x0c  byte 0x30  0x005ae420  override  ApplyProductionDistributionToCitySlots
//   slot 0x0d  byte 0x34  0x005ae0e0  override  QueueCityRecruitmentSupportCommandsIfDeficit
//   slot 0x0e  byte 0x38  0x005ae240  override  DeserializeCityProductionQueueCommand
//   slot 0x0f  byte 0x3c  0x005ae4b0  override  OrphanRetStub_0059add0
// object size 0x14 (RTTI) unverified against the header layout;
// set curated.layout.size_verified to emit a sizeof static_assert.
// clang-format on
// === END GENERATED (TCityTask) ===
