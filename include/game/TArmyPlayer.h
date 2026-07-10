#pragma once

#include "game/TTacticalPlayer.h"
#include "game/mfc.h"

// TODO(manifest): describe TArmyPlayer and its role. Base edge (TTacticalPlayer) recovered from RTTI CRuntimeClass chain: TArmyPlayer -> TTacticalPlayer -> TObject -> CObject.
// VTABLE: IMPERIALISM 0x006695f0
class TArmyPlayer : public TTacticalPlayer {
public:
  // === BEGIN GENERATED DECLS (TArmyPlayer) — refreshed by recover-class; do not hand-edit ===
  DECLARE_DYNCREATE(TArmyPlayer)
  virtual ~TArmyPlayer() override; // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  // slot 0x05 WriteTo inherited unchanged (0x485f70)
  // slot 0x06 ReadFrom inherited unchanged (0x485f90)
  // slot 0x07 Free inherited unchanged (0x59aee0)
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  virtual undefined StartBattle() override;            // slot 0x0a 0x59b830
  virtual undefined OrphanRetStub_0059ad90() override; // slot 0x0b 0x59e3e0
  // slot 0x0c TArmyTacUnit_VtblSlot00 inherited unchanged (0x59adb0)
  virtual undefined OrphanRetStub_0059add0() override; // slot 0x0d 0x59b3e0
  virtual undefined
  Helper_Uses_FindListNodeByKeyFromNodeOrHead_At0059afa0() override;      // slot 0x0e 0x59b4f0
  virtual undefined WrapperFor_AddHead_At0059afe0(int* param_1) override; // slot 0x0f 0x59b540
  // slot 0x10 TArmyTacUnit_VtblSlot04 inherited unchanged (0x59adf0)
  virtual undefined OrphanRetStub_0059ae10() override;            // slot 0x11 0x59eb40
  virtual undefined TArmyTacUnit_VtblSlot06();                    // slot 0x12 0x59bc80
  virtual undefined TArmyTacUnit_VtblSlot07();                    // slot 0x13 0x59c3c0
  virtual undefined RunTacticalAutoTurnControllerForActiveUnit(); // slot 0x14 0x59e4f0
  virtual undefined TArmyTacUnit_VtblSlot09();                    // slot 0x15 0x59ea60
  // === END GENERATED DECLS (TArmyPlayer) ===
  // TODO(manifest): add data members from the object slice (`just slice-discovery TArmyPlayer 0xCTOR`).

  TArmyPlayer();
};
