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

