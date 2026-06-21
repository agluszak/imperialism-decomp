#pragma once

#include "game/TProductionOrder.h"
#include "game/mfc.h"

// Forward declarations for types referenced by generated signatures.
class TStream;

// TODO(manifest): describe TUnitOrder and its role. Base edge (TProductionOrder) recovered from RTTI CRuntimeClass chain: TUnitOrder -> TProductionOrder -> TObject -> CObject.
// VTABLE: IMPERIALISM 0x0064f8a0
class TUnitOrder : public TProductionOrder {
public:
// === BEGIN GENERATED DECLS (TUnitOrder) — refreshed by recover-class; do not hand-edit ===
  virtual CRuntimeClass* GetRuntimeClass() const override; // slot 0x00 0x4b6f50
  virtual ~TUnitOrder(); // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  virtual void WriteTo(TStream* stream) override; // slot 0x05 0x4b7850
  virtual void ReadFrom(TStream* stream) override; // slot 0x06 0x4b7920
  // slot 0x07 Free inherited unchanged (0x4798b0)
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  // slot 0x0a InitializeBasicCityOrderContext inherited unchanged (0x4b4f70)
  virtual undefined OrphanCallChain_C1_I16_004b5100(short param_1) override; // slot 0x0b 0x4b7210
  virtual undefined OrphanLeaf_NoCall_Ins02_004b50e0() override; // slot 0x0c 0x4b7080
  virtual undefined OrphanRetStub_004b5160() override; // slot 0x0d 0x4b73b0
  // slot 0x0e ResetCityOrderItemDerivedStateNoop inherited unchanged (0x4b5140)
  // slot 0x0f InitializeCityOrderItemWorkingBuffers inherited unchanged (0x4b5180)
  virtual undefined CreateTItemOrderInstance() override; // slot 0x10 0x4b7320
  virtual void InitializeCityRecruitmentOrderContext(void * pCityState, short nEntryId, short nPrimaryInputResourceId, short nPrimaryInputPerUnit, short nSecondaryInputResourceId, short nSecondaryInputPerUnit, short nCashCostPerUnit, short nWorkforceMode, byte bSpecialistMode) override; // slot 0x11 0x4b6fe0
// === END GENERATED DECLS (TUnitOrder) ===
  // TODO(manifest): add data members from the object slice (`just slice-discovery TUnitOrder 0xCTOR`).

  TUnitOrder();
};

// === BEGIN GENERATED (TUnitOrder) — refreshed by `just gen-class TUnitOrder`; do not hand-edit ===
// clang-format off
// vtable @ 0x0064f8a0 (18 slots), object size 0x5c, base TProductionOrder
//   slot 0x00  byte 0x00  0x004b6f50  override  GetTProductionOrderClassNamePointer
//   slot 0x01  byte 0x04  0x004b6f90  override  ConstructTUnitOrderBaseState
//   slot 0x02  byte 0x08  0x00485e90  inherited Serialize
//   slot 0x03  byte 0x0c  0x00412bf0  inherited AssertValid
//   slot 0x04  byte 0x10  0x00412c10  inherited Dump
//   slot 0x05  byte 0x14  0x004b7850  override  WrapperFor_HandleCityDialogNoOpSlot14_At004b7850
//   slot 0x06  byte 0x18  0x004b7920  override  SyncCityEntryOrderStateWithArchive
//   slot 0x07  byte 0x1c  0x004798b0  inherited Free
//   slot 0x08  byte 0x20  0x004798d0  inherited ShallowClone
//   slot 0x09  byte 0x24  0x00415ce0  inherited ShallowFree
//   slot 0x0a  byte 0x28  0x004b4f70  inherited InitializeBasicCityOrderContext
//   slot 0x0b  byte 0x2c  0x004b7210  override  OrphanCallChain_C1_I16_004b5100
//   slot 0x0c  byte 0x30  0x004b7080  override  OrphanLeaf_NoCall_Ins02_004b50e0
//   slot 0x0d  byte 0x34  0x004b73b0  override  OrphanRetStub_004b5160
//   slot 0x0e  byte 0x38  0x004b5140  inherited ResetCityOrderItemDerivedStateNoop
//   slot 0x0f  byte 0x3c  0x004b5180  inherited InitializeCityOrderItemWorkingBuffers
//   slot 0x10  byte 0x40  0x004b7320  override  CreateTItemOrderInstance
//   slot 0x11  byte 0x44  0x004b6fe0  override  InitializeCityRecruitmentOrderContext
// object size 0x5c (RTTI) unverified against the header layout;
// set curated.layout.size_verified to emit a sizeof static_assert.
// clang-format on
// === END GENERATED (TUnitOrder) ===
