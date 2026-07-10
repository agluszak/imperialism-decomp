#pragma once

#include "game/TCommand.h"
#include "game/mfc.h"

// TODO(manifest): describe TPoseMessageDialog and its role. Base edge (TCommand) recovered from
// RTTI CRuntimeClass chain: TPoseMessageDialog -> TCommand -> TEvent -> TObject -> CObject.
// VTABLE: IMPERIALISM 0x0065c0e8
class TPoseMessageDialog : public TCommand {
public:
  // === BEGIN GENERATED DECLS (TPoseMessageDialog) — refreshed by recover-class; do not hand-edit
  // ===
  DECLARE_DYNCREATE(TPoseMessageDialog)
  virtual ~TPoseMessageDialog() override; // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  // slot 0x05 WriteTo inherited unchanged (0x485f70)
  // slot 0x06 ReadFrom inherited unchanged (0x485f90)
  // slot 0x07 Free inherited unchanged (0x4878e0)
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  // slot 0x0a NextDiplomacyCommandVtableSlotE8_NotifyOwnerSlot94 inherited unchanged (0x487900)
  virtual void OrphanRetStub_00487a00() override; // slot 0x0b 0x54aff0
  // === END GENERATED DECLS (TPoseMessageDialog) ===

  // +0x18 — the kicking nation shown by the 'pose' message dialog (written by the
  // turn-event-0xC receive path before the command is queued).
  int kickedByNationSlot18;

  // Fully inlined at every construction site (base TCommand ctor call + vtable
  // store); defined in-class so `new TPoseMessageDialog()` reproduces that shape.
  TPoseMessageDialog() : TCommand() {}
};
