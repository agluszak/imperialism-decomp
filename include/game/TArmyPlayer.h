#pragma once

#include "game/TTacticalPlayer.h"
#include "game/mfc.h"

// TODO(manifest): describe TArmyPlayer and its role. Base edge (TTacticalPlayer) recovered from RTTI CRuntimeClass chain: TArmyPlayer -> TTacticalPlayer -> TObject -> CObject.
// VTABLE: IMPERIALISM 0x006695f0
class TArmyPlayer : public TTacticalPlayer {
public:
// === BEGIN GENERATED DECLS (TArmyPlayer) — refreshed by recover-class; do not hand-edit ===
  virtual CRuntimeClass* GetRuntimeClass() const override; // slot 0x00 0x59b190
  virtual ~TArmyPlayer(); // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  // slot 0x05 WriteTo inherited unchanged (0x485f70)
  // slot 0x06 ReadFrom inherited unchanged (0x485f90)
  // slot 0x07 Free inherited unchanged (0x59aee0)
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  virtual undefined OrphanRetStub_0059ad70() override; // slot 0x0a 0x59b830
  virtual undefined OrphanRetStub_0059ad90() override; // slot 0x0b 0x59e3e0
  // slot 0x0c TArmyTacUnit_VtblSlot00 inherited unchanged (0x59adb0)
  virtual undefined OrphanRetStub_0059add0() override; // slot 0x0d 0x59b3e0
  virtual undefined Helper_Uses_FindListNodeByKeyFromNodeOrHead_At0059afa0() override; // slot 0x0e 0x59b4f0
  virtual undefined WrapperFor_AddHead_At0059afe0(int * param_1) override; // slot 0x0f 0x59b540
  // slot 0x10 TArmyTacUnit_VtblSlot04 inherited unchanged (0x59adf0)
  virtual undefined OrphanRetStub_0059ae10() override; // slot 0x11 0x59eb40
  virtual undefined TArmyTacUnit_VtblSlot06() override; // slot 0x12 0x59bc80
  virtual undefined TArmyTacUnit_VtblSlot07(undefined4 param_1) override; // slot 0x13 0x59c3c0
  virtual undefined RunTacticalAutoTurnControllerForActiveUnit() override; // slot 0x14 0x59e4f0
  virtual undefined TArmyTacUnit_VtblSlot09() override; // slot 0x15 0x59ea60
// === END GENERATED DECLS (TArmyPlayer) ===
  // TODO(manifest): add data members from the object slice (`just slice-discovery TArmyPlayer 0xCTOR`).

  TArmyPlayer();
};

// === BEGIN GENERATED (TArmyPlayer) — refreshed by `just gen-class TArmyPlayer`; do not hand-edit ===
// clang-format off
// vtable @ 0x006695f0 (22 slots), object size 0x54, base TTacticalPlayer
//   slot 0x00  byte 0x00  0x0059b190  override  GetTTacticalPlayerClassNamePointer
//   slot 0x01  byte 0x04  0x0059b140  override  WrapperFor_FreeHeapBufferIfNotNull_At0059b140
//   slot 0x02  byte 0x08  0x00485e90  inherited Serialize
//   slot 0x03  byte 0x0c  0x00412bf0  inherited AssertValid
//   slot 0x04  byte 0x10  0x00412c10  inherited Dump
//   slot 0x05  byte 0x14  0x00485f70  inherited WriteTo
//   slot 0x06  byte 0x18  0x00485f90  inherited ReadFrom
//   slot 0x07  byte 0x1c  0x0059aee0  inherited ConstructTTacticalPlayerBaseState
//   slot 0x08  byte 0x20  0x004798d0  inherited ShallowClone
//   slot 0x09  byte 0x24  0x00415ce0  inherited ShallowFree
//   slot 0x0a  byte 0x28  0x0059b830  override  OrphanRetStub_0059ad70
//   slot 0x0b  byte 0x2c  0x0059e3e0  override  OrphanRetStub_0059ad90
//   slot 0x0c  byte 0x30  0x0059adb0  inherited TArmyTacUnit_VtblSlot00
//   slot 0x0d  byte 0x34  0x0059b3e0  override  OrphanRetStub_0059add0
//   slot 0x0e  byte 0x38  0x0059b4f0  override  TArmyTacUnit_VtblSlot02
//   slot 0x0f  byte 0x3c  0x0059b540  override  TArmyTacUnit_VtblSlot03
//   slot 0x10  byte 0x40  0x0059adf0  inherited TArmyTacUnit_VtblSlot04
//   slot 0x11  byte 0x44  0x0059eb40  override  OrphanRetStub_0059ae10
//   slot 0x12  byte 0x48  0x0059bc80  override  TArmyTacUnit_VtblSlot06
//   slot 0x13  byte 0x4c  0x0059c3c0  override  TArmyTacUnit_VtblSlot07
//   slot 0x14  byte 0x50  0x0059e4f0  override  RunTacticalAutoTurnControllerForActiveUnit
//   slot 0x15  byte 0x54  0x0059ea60  override  TArmyTacUnit_VtblSlot09
// object size 0x54 (RTTI) unverified against the header layout;
// set curated.layout.size_verified to emit a sizeof static_assert.
// clang-format on
// === END GENERATED (TArmyPlayer) ===
