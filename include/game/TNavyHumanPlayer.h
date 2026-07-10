#pragma once

#include "game/TNavyPlayer.h"
#include "game/mfc.h"

// TODO(manifest): describe TNavyHumanPlayer and its role. Base edge (TNavyPlayer) recovered from RTTI CRuntimeClass chain: TNavyHumanPlayer -> TNavyPlayer -> TTacticalPlayer -> TObject -> CObject.
// VTABLE: IMPERIALISM 0x00669760
class TNavyHumanPlayer : public TNavyPlayer {
public:
  // === BEGIN GENERATED DECLS (TNavyHumanPlayer) — refreshed by recover-class; do not hand-edit ===
  DECLARE_DYNCREATE(TNavyHumanPlayer)
  virtual ~TNavyHumanPlayer() override; // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  // slot 0x05 WriteTo inherited unchanged (0x485f70)
  // slot 0x06 ReadFrom inherited unchanged (0x485f90)
  // slot 0x07 Free inherited unchanged (0x59aee0)
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  // slot 0x0a StartBattle inherited unchanged (0x59ad70)
  // slot 0x0b OrphanRetStub_0059ad90 inherited unchanged (0x59ad90)
  // slot 0x0c TArmyTacUnit_VtblSlot00 inherited unchanged (0x59adb0)
  // slot 0x0d OrphanRetStub_0059add0 inherited unchanged (0x59edd0)
  // slot 0x0e Helper_Uses_FindListNodeByKeyFromNodeOrHead_At0059afa0 inherited unchanged (0x59ee60)
  // slot 0x0f WrapperFor_AddHead_At0059afe0 inherited unchanged (0x59eea0)
  // slot 0x10 TArmyTacUnit_VtblSlot04 inherited unchanged (0x59adf0)
  // slot 0x11 OrphanRetStub_0059ae10 inherited unchanged (0x59ae10)
  virtual undefined ConstructTNavyHumanPlayerBaseState(); // slot 0x12 0x59efc0
  // === END GENERATED DECLS (TNavyHumanPlayer) ===
  // TODO(manifest): add data members from the object slice (`just slice-discovery TNavyHumanPlayer 0xCTOR`).

  TNavyHumanPlayer();
};
