#pragma once

#include "game/TObject.h"
#include "game/mfc.h"

// TODO(manifest): describe TTacticalPlayer and its role. Base edge (TObject) recovered from RTTI CRuntimeClass chain: TTacticalPlayer -> TObject -> CObject.
// VTABLE: IMPERIALISM 0x00669598
class TTacticalPlayer : public TObject {
public:
// === BEGIN GENERATED DECLS (TTacticalPlayer) — refreshed by recover-class; do not hand-edit ===
  virtual CRuntimeClass* GetRuntimeClass() const override; // slot 0x00 0x59ae80
  virtual ~TTacticalPlayer(); // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  // slot 0x05 WriteTo inherited unchanged (0x485f70)
  // slot 0x06 ReadFrom inherited unchanged (0x485f90)
  virtual void Free() override; // slot 0x07 0x59aee0
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  virtual undefined OrphanRetStub_0059ad70() override; // slot 0x0a 0x59ad70
  virtual undefined OrphanRetStub_0059ad90() override; // slot 0x0b 0x59ad90
  virtual undefined TArmyTacUnit_VtblSlot00() override; // slot 0x0c 0x59adb0
  virtual undefined OrphanRetStub_0059add0() override; // slot 0x0d 0x59add0
  virtual undefined Helper_Uses_FindListNodeByKeyFromNodeOrHead_At0059afa0() override; // slot 0x0e 0x59afa0
  virtual undefined WrapperFor_AddHead_At0059afe0(int * param_1) override; // slot 0x0f 0x59afe0
  virtual undefined TArmyTacUnit_VtblSlot04() override; // slot 0x10 0x59adf0
  virtual undefined OrphanRetStub_0059ae10() override; // slot 0x11 0x59ae10
// === END GENERATED DECLS (TTacticalPlayer) ===
  // TODO(manifest): add data members from the object slice (`just slice-discovery TTacticalPlayer 0xCTOR`).

  TTacticalPlayer();
};

// === BEGIN GENERATED (TTacticalPlayer) — refreshed by `just gen-class TTacticalPlayer`; do not hand-edit ===
// clang-format off
// vtable @ 0x00669598 (18 slots), object size 0x28, base TObject
//   slot 0x00  byte 0x00  0x0059ae80  override  GetRuntimeClass
//   slot 0x01  byte 0x04  0x0059ae30  scalar_dtor (scalar deleting destructor)
//   slot 0x02  byte 0x08  0x00485e90  inherited Serialize
//   slot 0x03  byte 0x0c  0x00412bf0  inherited AssertValid
//   slot 0x04  byte 0x10  0x00412c10  inherited Dump
//   slot 0x05  byte 0x14  0x00485f70  inherited WriteTo
//   slot 0x06  byte 0x18  0x00485f90  inherited ReadFrom
//   slot 0x07  byte 0x1c  0x0059aee0  override  Free
//   slot 0x08  byte 0x20  0x004798d0  inherited ShallowClone
//   slot 0x09  byte 0x24  0x00415ce0  inherited ShallowFree
//   slot 0x0a  byte 0x28  0x0059ad70  override  OrphanRetStub_0059ad70
//   slot 0x0b  byte 0x2c  0x0059ad90  override  OrphanRetStub_0059ad90
//   slot 0x0c  byte 0x30  0x0059adb0  override  TArmyTacUnit_VtblSlot00
//   slot 0x0d  byte 0x34  0x0059add0  override  OrphanRetStub_0059add0
//   slot 0x0e  byte 0x38  0x0059afa0  override  Helper_Uses_FindListNodeByKeyFromNodeOrHead_At0059afa0
//   slot 0x0f  byte 0x3c  0x0059afe0  override  WrapperFor_AddHead_At0059afe0
//   slot 0x10  byte 0x40  0x0059adf0  override  TArmyTacUnit_VtblSlot04
//   slot 0x11  byte 0x44  0x0059ae10  override  OrphanRetStub_0059ae10
// object size 0x28 (RTTI) unverified against the header layout;
// set curated.layout.size_verified to emit a sizeof static_assert.
// clang-format on
// === END GENERATED (TTacticalPlayer) ===
