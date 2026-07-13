#pragma once

#include "game/TCommand.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0066f2f0
class TModalMessageCommand : public TCommand {
public:
  // === BEGIN GENERATED DECLS (TModalMessageCommand) — refreshed by recover-class; do not hand-edit
  // ===
  DECLARE_DYNCREATE(TModalMessageCommand)
  virtual ~TModalMessageCommand() override; // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  // slot 0x05 WriteTo inherited unchanged (0x485f70)
  // slot 0x06 ReadFrom inherited unchanged (0x485f90)
  // slot 0x07 Free inherited unchanged (0x4878e0)
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  // slot 0x0a NextDiplomacyCommandVtableSlotE8_NotifyOwnerSlot94 inherited unchanged (0x487900)
  virtual void OrphanRetStub_00487a00() override; // slot 0x0b 0x5dcd10
  // === END GENERATED DECLS (TModalMessageCommand) ===

  // Object slice from the inline-expanded ctor at 0x5dea93 (inside
  // TViewMgr::CreateModalMessageCommandAndQueue 0x5dea60): TCommand base is 0x18
  // bytes, then the message text and one scalar payload.
  CString message; // +0x18
  int payload;     // +0x1c

  // Defined inline: the original constructor exists only inline-expanded at the
  // 0x5dea60 call site (TCommand ctor call + CString member ctor + vptr store).
  TModalMessageCommand() : TCommand() {}
};

ASSERT_SIZE(TModalMessageCommand, 0x20);
