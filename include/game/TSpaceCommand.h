#pragma once

#include "game/TCommand.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00661b10
class TSpaceCommand : public TCommand {
public:
  // === BEGIN GENERATED DECLS (TSpaceCommand) — refreshed by recover-class; do not hand-edit ===
  DECLARE_DYNCREATE(TSpaceCommand)
  virtual ~TSpaceCommand() override; // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  // slot 0x05 WriteTo inherited unchanged (0x485f70)
  // slot 0x06 ReadFrom inherited unchanged (0x485f90)
  // slot 0x07 Free inherited unchanged (0x4878e0)
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  // slot 0x0a NextDiplomacyCommandVtableSlotE8_NotifyOwnerSlot94 inherited unchanged (0x487900)
  virtual void OrphanRetStub_00487a00() override; // slot 0x0b 0x5751f0
  // === END GENERATED DECLS (TSpaceCommand) ===
  int pad18;        // +0x18 (purpose unknown)
  int commandTag1c; // +0x1c — four-char tag identifying interaction type (e.g. "plus"/"minu")

  TSpaceCommand();
};
