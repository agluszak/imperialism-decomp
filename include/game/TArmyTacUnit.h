#pragma once

#include "game/TTacticalUnit.h"
#include "game/mfc.h"

// TODO(manifest): describe TArmyTacUnit and its role. Base edge (TTacticalUnit) recovered from RTTI CRuntimeClass chain: TArmyTacUnit -> TTacticalUnit -> TObject -> CObject.
// VTABLE: IMPERIALISM 0x00669660
class TArmyTacUnit : public TTacticalUnit {
public:
// === BEGIN GENERATED DECLS (TArmyTacUnit) — refreshed by recover-class; do not hand-edit ===
  DECLARE_DYNCREATE(TArmyTacUnit)
  virtual ~TArmyTacUnit(); // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  // slot 0x05 WriteTo inherited unchanged (0x485f70)
  // slot 0x06 ReadFrom inherited unchanged (0x485f90)
  // slot 0x07 Free inherited unchanged (0x4798b0)
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  virtual undefined OrphanTiny_ReturnZero_005a5d40() override; // slot 0x0a 0x5a6120
  virtual undefined OrphanTiny_ReturnZero_005a5d60() override; // slot 0x0b 0x5a6140
  virtual undefined OrphanLeaf_NoCall_Ins02_005a5d80() override; // slot 0x0c 0x5a6180
  virtual undefined OrphanLeaf_NoCall_Ins02_005a5da0() override; // slot 0x0d 0x5a61a0
  virtual undefined VTableSlot0E(int param_1) override; // slot 0x0e 0x5a61c0
  // slot 0x0f CreateTArmyTacUnitInstance inherited unchanged (0x5a5eb0)
// === END GENERATED DECLS (TArmyTacUnit) ===
  // TODO(manifest): add data members from the object slice (`just slice-discovery TArmyTacUnit 0xCTOR`).

  TArmyTacUnit();
};

// === BEGIN GENERATED (TArmyTacUnit) — refreshed by `just gen-class TArmyTacUnit`; do not hand-edit ===
// clang-format off
// vtable @ 0x00669660 (16 slots), object size 0x58, base TTacticalUnit
//   slot 0x00  byte 0x00  0x005a5f00  override  GetTTacticalUnitClassNamePointer
//   slot 0x01  byte 0x04  0x0059b390  override  ConstructTTacticalPlayerBaseState
//   slot 0x02  byte 0x08  0x00485e90  inherited Serialize
//   slot 0x03  byte 0x0c  0x00412bf0  inherited AssertValid
//   slot 0x04  byte 0x10  0x00412c10  inherited Dump
//   slot 0x05  byte 0x14  0x00485f70  inherited WriteTo
//   slot 0x06  byte 0x18  0x00485f90  inherited ReadFrom
//   slot 0x07  byte 0x1c  0x004798b0  inherited Free
//   slot 0x08  byte 0x20  0x004798d0  inherited ShallowClone
//   slot 0x09  byte 0x24  0x00415ce0  inherited ShallowFree
//   slot 0x0a  byte 0x28  0x005a6120  override  OrphanTiny_ReturnZero_005a5d40
//   slot 0x0b  byte 0x2c  0x005a6140  override  OrphanTiny_ReturnZero_005a5d60
//   slot 0x0c  byte 0x30  0x005a6180  override  OrphanLeaf_NoCall_Ins02_005a5d80
//   slot 0x0d  byte 0x34  0x005a61a0  override  OrphanLeaf_NoCall_Ins02_005a5da0
//   slot 0x0e  byte 0x38  0x005a61c0  override  RunTacticalAutoTurnControllerForActiveUnit
//   slot 0x0f  byte 0x3c  0x005a5eb0  inherited CreateTArmyTacUnitInstance
// object size 0x58 (RTTI) unverified against the header layout;
// set curated.layout.size_verified to emit a sizeof static_assert.
// clang-format on
// === END GENERATED (TArmyTacUnit) ===
