#pragma once

#include "game/TLineData.h"
#include "game/mfc.h"

// TODO(manifest): describe TMiniArmyLine and its role. Base edge (TLineData) recovered from RTTI CRuntimeClass chain: TMiniArmyLine -> TLineData -> TObject -> CObject.
// VTABLE: IMPERIALISM 0x0064d510
class TMiniArmyLine : public TLineData {
public:
// === BEGIN GENERATED DECLS (TMiniArmyLine) — refreshed by recover-class; do not hand-edit ===
  DECLARE_DYNCREATE(TMiniArmyLine)
  virtual ~TMiniArmyLine(); // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  // slot 0x05 WriteTo inherited unchanged (0x485f70)
  // slot 0x06 ReadFrom inherited unchanged (0x485f90)
  // slot 0x07 Free inherited unchanged (0x4798b0)
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  virtual undefined OrphanRetStub_0056f460() override; // slot 0x0a 0x4aa960
  // slot 0x0b OrphanRetStub_0056f480 inherited unchanged (0x56f480)
// === END GENERATED DECLS (TMiniArmyLine) ===
  // TODO(manifest): add data members from the object slice (`just slice-discovery TMiniArmyLine 0xCTOR`).

  TMiniArmyLine();
};

