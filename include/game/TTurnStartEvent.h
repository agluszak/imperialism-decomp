#pragma once

#include "game/TObject.h"
#include "game/mfc.h"

// TODO(manifest): describe TTurnStartEvent and its role. Base edge (TObject) recovered from RTTI CRuntimeClass chain: TTurnStartEvent -> TObject -> CObject.
// VTABLE: IMPERIALISM 0x00653d90
class TTurnStartEvent : public TObject {
public:
// === BEGIN GENERATED DECLS (TTurnStartEvent) — refreshed by recover-class; do not hand-edit ===
  DECLARE_DYNCREATE(TTurnStartEvent)
  virtual ~TTurnStartEvent(); // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  // slot 0x05 WriteTo inherited unchanged (0x485f70)
  // slot 0x06 ReadFrom inherited unchanged (0x485f90)
  // slot 0x07 Free inherited unchanged (0x4798b0)
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  virtual undefined ApplyJoinEmpireMode2FinalizeNationNameState(); // slot 0x0a 0x4e6610
// === END GENERATED DECLS (TTurnStartEvent) ===
  // TODO(manifest): add data members from the object slice (`just slice-discovery TTurnStartEvent 0xCTOR`).

  TTurnStartEvent();
};

