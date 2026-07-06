#pragma once

#include "game/TObject.h"
#include "game/mfc.h"

// TODO(manifest): describe TTacticalUnit and its role. Base edge (TObject) recovered from RTTI CRuntimeClass chain: TTacticalUnit -> TObject -> CObject.
// VTABLE: IMPERIALISM 0x0066a1b8
class TTacticalUnit : public TObject {
public:
// === BEGIN GENERATED DECLS (TTacticalUnit) — refreshed by recover-class; do not hand-edit ===
  DECLARE_DYNCREATE(TTacticalUnit)
  virtual ~TTacticalUnit(); // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  // slot 0x05 WriteTo inherited unchanged (0x485f70)
  // slot 0x06 ReadFrom inherited unchanged (0x485f90)
  // slot 0x07 Free inherited unchanged (0x4798b0)
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  virtual undefined OrphanTiny_ReturnZero_005a5d40(); // slot 0x0a 0x5a5d40
  virtual undefined OrphanTiny_ReturnZero_005a5d60(); // slot 0x0b 0x5a5d60
  virtual undefined OrphanLeaf_NoCall_Ins02_005a5d80(); // slot 0x0c 0x5a5d80
  virtual undefined OrphanLeaf_NoCall_Ins02_005a5da0(); // slot 0x0d 0x5a5da0
  virtual undefined VTableSlot0E(int param_1); // slot 0x0e 0x5a5e70
  virtual undefined CreateTArmyTacUnitInstance(); // slot 0x0f 0x5a5eb0
// === END GENERATED DECLS (TTacticalUnit) ===
  // TODO(manifest): add data members from the object slice (`just slice-discovery TTacticalUnit 0xCTOR`).

  TTacticalUnit();
};

