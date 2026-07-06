#pragma once

#include "game/TTacticalUnit.h"
#include "game/mfc.h"

// TODO(manifest): describe TArmyTacUnit and its role. Base edge (TTacticalUnit) recovered from RTTI CRuntimeClass chain: TArmyTacUnit -> TTacticalUnit -> TObject -> CObject.
// VTABLE: IMPERIALISM 0x00669660
class TArmyTacUnit : public TTacticalUnit {
public:
// === BEGIN GENERATED DECLS (TArmyTacUnit) — refreshed by recover-class; do not hand-edit ===
  DECLARE_DYNCREATE(TArmyTacUnit)
  virtual ~TArmyTacUnit() override; // slot 0x01 (scalar deleting destructor)
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

