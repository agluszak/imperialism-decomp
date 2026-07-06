#pragma once

#include "game/TObject.h"
#include "game/mfc.h"

// TODO(manifest): describe TTacticalPlayer and its role. Base edge (TObject) recovered from RTTI CRuntimeClass chain: TTacticalPlayer -> TObject -> CObject.
// VTABLE: IMPERIALISM 0x00669598
class TTacticalPlayer : public TObject {
public:
// === BEGIN GENERATED DECLS (TTacticalPlayer) — refreshed by recover-class; do not hand-edit ===
  DECLARE_DYNCREATE(TTacticalPlayer)
  virtual ~TTacticalPlayer() override; // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  // slot 0x05 WriteTo inherited unchanged (0x485f70)
  // slot 0x06 ReadFrom inherited unchanged (0x485f90)
  virtual void Free() override; // slot 0x07 0x59aee0
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  virtual undefined OrphanRetStub_0059ad70(); // slot 0x0a 0x59ad70
  virtual undefined OrphanRetStub_0059ad90(); // slot 0x0b 0x59ad90
  virtual undefined TArmyTacUnit_VtblSlot00(); // slot 0x0c 0x59adb0
  virtual undefined OrphanRetStub_0059add0(); // slot 0x0d 0x59add0
  virtual undefined Helper_Uses_FindListNodeByKeyFromNodeOrHead_At0059afa0(); // slot 0x0e 0x59afa0
  virtual undefined WrapperFor_AddHead_At0059afe0(int * param_1); // slot 0x0f 0x59afe0
  virtual undefined TArmyTacUnit_VtblSlot04(); // slot 0x10 0x59adf0
  virtual undefined OrphanRetStub_0059ae10(); // slot 0x11 0x59ae10
// === END GENERATED DECLS (TTacticalPlayer) ===
  // TODO(manifest): add data members from the object slice (`just slice-discovery TTacticalPlayer 0xCTOR`).

  TTacticalPlayer();
};

