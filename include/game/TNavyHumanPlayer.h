#pragma once

#include "game/TNavyPlayer.h"
#include "game/mfc.h"

// TODO(manifest): describe TNavyHumanPlayer and its role. Base edge (TNavyPlayer) recovered from RTTI CRuntimeClass chain: TNavyHumanPlayer -> TNavyPlayer -> TTacticalPlayer -> TObject -> CObject.
// VTABLE: IMPERIALISM 0x00669760
class TNavyHumanPlayer : public TNavyPlayer {
public:
// === BEGIN GENERATED DECLS (TNavyHumanPlayer) — refreshed by recover-class; do not hand-edit ===
  DECLARE_DYNCREATE(TNavyHumanPlayer)
  virtual ~TNavyHumanPlayer(); // slot 0x01 (scalar deleting destructor)
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

// === BEGIN GENERATED (TNavyHumanPlayer) — refreshed by `just gen-class TNavyHumanPlayer`; do not hand-edit ===
// clang-format off
// vtable @ 0x00669760 (19 slots), object size 0x30, base TNavyPlayer
//   slot 0x00  byte 0x00  0x0059ef70  override  GetTTacticalPlayerClassNamePointer
//   slot 0x01  byte 0x04  0x0059ef20  override  WrapperFor_FreeHeapBufferIfNotNull_At0059ef20
//   slot 0x02  byte 0x08  0x00485e90  inherited Serialize
//   slot 0x03  byte 0x0c  0x00412bf0  inherited AssertValid
//   slot 0x04  byte 0x10  0x00412c10  inherited Dump
//   slot 0x05  byte 0x14  0x00485f70  inherited WriteTo
//   slot 0x06  byte 0x18  0x00485f90  inherited ReadFrom
//   slot 0x07  byte 0x1c  0x0059aee0  inherited ConstructTTacticalPlayerBaseState
//   slot 0x08  byte 0x20  0x004798d0  inherited ShallowClone
//   slot 0x09  byte 0x24  0x00415ce0  inherited ShallowFree
//   slot 0x0a  byte 0x28  0x0059ad70  inherited OrphanRetStub_0059ad70
//   slot 0x0b  byte 0x2c  0x0059ad90  inherited OrphanRetStub_0059ad90
//   slot 0x0c  byte 0x30  0x0059adb0  inherited TArmyTacUnit_VtblSlot00
//   slot 0x0d  byte 0x34  0x0059edd0  inherited OrphanRetStub_0059add0
//   slot 0x0e  byte 0x38  0x0059ee60  inherited Helper_Uses_FindListNodeByKeyFromNodeOrHead_At0059ee60
//   slot 0x0f  byte 0x3c  0x0059eea0  inherited AddOrderNodeToHeadAndReassignNationCounters
//   slot 0x10  byte 0x40  0x0059adf0  inherited TArmyTacUnit_VtblSlot04
//   slot 0x11  byte 0x44  0x0059ae10  inherited OrphanRetStub_0059ae10
//   slot 0x12  byte 0x48  0x0059efc0  override  ConstructTNavyHumanPlayerBaseState
// object size 0x30 (RTTI) unverified against the header layout;
// set curated.layout.size_verified to emit a sizeof static_assert.
// clang-format on
// === END GENERATED (TNavyHumanPlayer) ===
