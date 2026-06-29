#pragma once

#include "game/TCommand.h"
#include "game/mfc.h"

// TODO(manifest): describe TNextMoveCommand and its role. Base edge (TCommand) recovered from RTTI
// CRuntimeClass chain: TNextMoveCommand -> TCommand -> TEvent -> TObject -> CObject.
// VTABLE: IMPERIALISM 0x0066a100
class TNextMoveCommand : public TCommand {
public:
  // === BEGIN GENERATED DECLS (TNextMoveCommand) — refreshed by recover-class; do not hand-edit ===
  DECLARE_DYNCREATE(TNextMoveCommand)
  virtual ~TNextMoveCommand(); // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  // slot 0x05 WriteTo inherited unchanged (0x485f70)
  // slot 0x06 ReadFrom inherited unchanged (0x485f90)
  // slot 0x07 Free inherited unchanged (0x4878e0)
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  // slot 0x0a NextDiplomacyCommandVtableSlotE8_NotifyOwnerSlot94 inherited unchanged (0x487900)
  virtual void OrphanRetStub_00487a00() override; // slot 0x0b 0x5a6620
  // === END GENERATED DECLS (TNextMoveCommand) ===
  // TODO(manifest): add data members from the object slice (`just slice-discovery TNextMoveCommand
  // 0xCTOR`).

  TNextMoveCommand();
};

// === BEGIN GENERATED (TNextMoveCommand) — refreshed by `just gen-class TNextMoveCommand`; do not
// hand-edit ===
// clang-format off
// vtable @ 0x0066a100 (12 slots), object size 0x1c, base TCommand
//   slot 0x00  byte 0x00  0x005a6540  override  GetTEventClassNamePointer
//   slot 0x01  byte 0x04  0x005a6590  override  OrphanCallChain_C1_I17_00487470
//   slot 0x02  byte 0x08  0x00485e90  inherited Serialize
//   slot 0x03  byte 0x0c  0x00412bf0  inherited AssertValid
//   slot 0x04  byte 0x10  0x00412c10  inherited Dump
//   slot 0x05  byte 0x14  0x00485f70  inherited WriteTo
//   slot 0x06  byte 0x18  0x00485f90  inherited ReadFrom
//   slot 0x07  byte 0x1c  0x004878e0  inherited QueueCityRecruitmentSupportCommandsIfDeficit
//   slot 0x08  byte 0x20  0x004798d0  inherited ShallowClone
//   slot 0x09  byte 0x24  0x00415ce0  inherited ShallowFree
//   slot 0x0a  byte 0x28  0x00487900  inherited NextDiplomacyCommandVtableSlotE8_NotifyOwnerSlot94
//   slot 0x0b  byte 0x2c  0x005a6620  override  OrphanRetStub_00487a00
// object size 0x1c (RTTI) unverified against the header layout;
// set curated.layout.size_verified to emit a sizeof static_assert.
// clang-format on
// === END GENERATED (TNextMoveCommand) ===
