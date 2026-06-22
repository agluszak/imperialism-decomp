#pragma once

#include "game/TObject.h"
#include "game/mfc.h"

// Forward declarations for types referenced by generated signatures.
class TStream;

// TODO(manifest): describe TArmyMgr and its role. Base edge (TObject) recovered from RTTI CRuntimeClass chain: TArmyMgr -> TObject -> CObject.
// VTABLE: IMPERIALISM 0x0064c928
class TArmyMgr : public TObject {
public:
// === BEGIN GENERATED DECLS (TArmyMgr) — refreshed by recover-class; do not hand-edit ===
  virtual CRuntimeClass* GetRuntimeClass() const override; // slot 0x00 0x4a1850
  virtual ~TArmyMgr(); // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  virtual void WriteTo(TStream* stream) override; // slot 0x05 0x4a1dd0
  virtual void ReadFrom(TStream* stream) override; // slot 0x06 0x4a1b80
  virtual void Free() override; // slot 0x07 0x4a1a00
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  virtual undefined OrphanCallChain_C4_I26_004a1e40(); // slot 0x0a 0x4a1e40
  virtual undefined ProcessTileUnitListsAndApplyRandomStatusUpdates(); // slot 0x0b 0x4a1f80
  virtual undefined OrphanCallChain_C12_I108_004a2390(); // slot 0x0c 0x4a2390
  virtual undefined IterateLinkedListCursorAndClearPerTileByte0F(); // slot 0x0d 0x4a2500
  virtual undefined TryCreateTacticalBattleViewForTileArmies(); // slot 0x0e 0x4a3200
  virtual undefined Helper_Uses_GenerateThreadLocalRandom15_At004a35e0(int param_1, short param_2); // slot 0x0f 0x4a35e0
  virtual undefined OrphanCallChain_C2_I40_004a37b0(int param_1); // slot 0x10 0x4a37b0
  virtual undefined UpdateDualLinkedEntryMetersAndBlinkState(); // slot 0x11 0x4a3830
  virtual undefined WrapperFor_IsNationSlotEligibleForEventProcessing_At004a3bc0(); // slot 0x12 0x4a3bc0
  virtual undefined OrphanCallChain_C3_I52_004a3d90(short param_1); // slot 0x13 0x4a3d90
  virtual undefined SelectMovableUnitOnCurrentTileAndPlaySfx(); // slot 0x14 0x4a3e50
  virtual undefined CommitCityActionGateCostIfAffordable(); // slot 0x15 0x4a3f30
  virtual undefined OrphanCallChain_C1_I34_004a4260(); // slot 0x16 0x4a4260
  virtual undefined HandleMapClickByComputedCursorState(); // slot 0x17 0x4a4870
  virtual undefined HandleMapClickByCivilianCursorState(); // slot 0x18 0x4a4ad0
// === END GENERATED DECLS (TArmyMgr) ===
  // TODO(manifest): add data members from the object slice (`just slice-discovery TArmyMgr 0xCTOR`).

  TArmyMgr();
};

// === BEGIN GENERATED (TArmyMgr) — refreshed by `just gen-class TArmyMgr`; do not hand-edit ===
// clang-format off
// vtable @ 0x0064c928 (25 slots), object size 0x3a8, base TObject
//   slot 0x00  byte 0x00  0x004a1850  override  GetRuntimeClass
//   slot 0x01  byte 0x04  0x004a18a0  scalar_dtor (scalar deleting destructor)
//   slot 0x02  byte 0x08  0x00485e90  inherited Serialize
//   slot 0x03  byte 0x0c  0x00412bf0  inherited AssertValid
//   slot 0x04  byte 0x10  0x00412c10  inherited Dump
//   slot 0x05  byte 0x14  0x004a1dd0  override  WriteTo
//   slot 0x06  byte 0x18  0x004a1b80  override  ReadFrom
//   slot 0x07  byte 0x1c  0x004a1a00  override  Free
//   slot 0x08  byte 0x20  0x004798d0  inherited ShallowClone
//   slot 0x09  byte 0x24  0x00415ce0  inherited ShallowFree
//   slot 0x0a  byte 0x28  0x004a1e40  override  OrphanCallChain_C4_I26_004a1e40
//   slot 0x0b  byte 0x2c  0x004a1f80  override  ProcessTileUnitListsAndApplyRandomStatusUpdates
//   slot 0x0c  byte 0x30  0x004a2390  override  OrphanCallChain_C12_I108_004a2390
//   slot 0x0d  byte 0x34  0x004a2500  override  IterateLinkedListCursorAndClearPerTileByte0F
//   slot 0x0e  byte 0x38  0x004a3200  override  TryCreateTacticalBattleViewForTileArmies
//   slot 0x0f  byte 0x3c  0x004a35e0  override  Helper_Uses_GenerateThreadLocalRandom15_At004a35e0
//   slot 0x10  byte 0x40  0x004a37b0  override  OrphanCallChain_C2_I40_004a37b0
//   slot 0x11  byte 0x44  0x004a3830  override  UpdateDualLinkedEntryMetersAndBlinkState
//   slot 0x12  byte 0x48  0x004a3bc0  override  WrapperFor_IsNationSlotEligibleForEventProcessing_At004a3bc0
//   slot 0x13  byte 0x4c  0x004a3d90  override  OrphanCallChain_C3_I52_004a3d90
//   slot 0x14  byte 0x50  0x004a3e50  override  SelectMovableUnitOnCurrentTileAndPlaySfx
//   slot 0x15  byte 0x54  0x004a3f30  override  CommitCityActionGateCostIfAffordable
//   slot 0x16  byte 0x58  0x004a4260  override  OrphanCallChain_C1_I34_004a4260
//   slot 0x17  byte 0x5c  0x004a4870  override  HandleMapClickByComputedCursorState
//   slot 0x18  byte 0x60  0x004a4ad0  override  HandleMapClickByCivilianCursorState
// object size 0x3a8 (RTTI) unverified against the header layout;
// set curated.layout.size_verified to emit a sizeof static_assert.
// clang-format on
// === END GENERATED (TArmyMgr) ===
