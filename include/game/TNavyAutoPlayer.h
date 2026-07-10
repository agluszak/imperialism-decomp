#pragma once

#include "game/TNavyPlayer.h"
#include "game/mfc.h"

// TODO(manifest): describe TNavyAutoPlayer and its role. Base edge (TNavyPlayer) recovered from RTTI CRuntimeClass chain: TNavyAutoPlayer -> TNavyPlayer -> TTacticalPlayer -> TObject -> CObject.
// VTABLE: IMPERIALISM 0x006697c0
class TNavyAutoPlayer : public TNavyPlayer {
public:
  // === BEGIN GENERATED DECLS (TNavyAutoPlayer) — refreshed by recover-class; do not hand-edit ===
  DECLARE_DYNCREATE(TNavyAutoPlayer)
  virtual ~TNavyAutoPlayer() override; // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  // slot 0x05 WriteTo inherited unchanged (0x485f70)
  // slot 0x06 ReadFrom inherited unchanged (0x485f90)
  // slot 0x07 Free inherited unchanged (0x59aee0)
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  virtual undefined StartBattle() override;            // slot 0x0a 0x59f110
  virtual undefined OrphanRetStub_0059ad90() override; // slot 0x0b 0x59f160
  // slot 0x0c TArmyTacUnit_VtblSlot00 inherited unchanged (0x59adb0)
  // slot 0x0d OrphanRetStub_0059add0 inherited unchanged (0x59edd0)
  // slot 0x0e Helper_Uses_FindListNodeByKeyFromNodeOrHead_At0059afa0 inherited unchanged (0x59ee60)
  // slot 0x0f WrapperFor_AddHead_At0059afe0 inherited unchanged (0x59eea0)
  // slot 0x10 TArmyTacUnit_VtblSlot04 inherited unchanged (0x59adf0)
  // slot 0x11 OrphanRetStub_0059ae10 inherited unchanged (0x59ae10)
  // === END GENERATED DECLS (TNavyAutoPlayer) ===
  // TODO(manifest): add data members from the object slice (`just slice-discovery TNavyAutoPlayer 0xCTOR`).

  TNavyAutoPlayer();
};
