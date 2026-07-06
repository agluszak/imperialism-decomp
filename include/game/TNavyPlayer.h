#pragma once

#include "game/TTacticalPlayer.h"
#include "game/mfc.h"

// TODO(manifest): describe TNavyPlayer and its role. Base edge (TTacticalPlayer) recovered from RTTI CRuntimeClass chain: TNavyPlayer -> TTacticalPlayer -> TObject -> CObject.
// VTABLE: IMPERIALISM 0x006696b0
class TNavyPlayer : public TTacticalPlayer {
public:
// === BEGIN GENERATED DECLS (TNavyPlayer) — refreshed by recover-class; do not hand-edit ===
  DECLARE_DYNCREATE(TNavyPlayer)
  virtual ~TNavyPlayer(); // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  // slot 0x05 WriteTo inherited unchanged (0x485f70)
  // slot 0x06 ReadFrom inherited unchanged (0x485f90)
  // slot 0x07 Free inherited unchanged (0x59aee0)
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  // slot 0x0a OrphanRetStub_0059ad70 inherited unchanged (0x59ad70)
  // slot 0x0b OrphanRetStub_0059ad90 inherited unchanged (0x59ad90)
  // slot 0x0c TArmyTacUnit_VtblSlot00 inherited unchanged (0x59adb0)
  virtual undefined OrphanRetStub_0059add0() override; // slot 0x0d 0x59edd0
  virtual undefined Helper_Uses_FindListNodeByKeyFromNodeOrHead_At0059afa0() override; // slot 0x0e 0x59ee60
  virtual undefined WrapperFor_AddHead_At0059afe0(int * param_1) override; // slot 0x0f 0x59eea0
  // slot 0x10 TArmyTacUnit_VtblSlot04 inherited unchanged (0x59adf0)
  // slot 0x11 OrphanRetStub_0059ae10 inherited unchanged (0x59ae10)
// === END GENERATED DECLS (TNavyPlayer) ===
  // TODO(manifest): add data members from the object slice (`just slice-discovery TNavyPlayer 0xCTOR`).

  TNavyPlayer();
};

