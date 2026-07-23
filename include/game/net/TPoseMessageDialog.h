#pragma once

#include "game/ui_core/TCommand.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0065c0e8
class TPoseMessageDialog : public TCommand {
public:
  DECLARE_DYNCREATE(TPoseMessageDialog)
  virtual ~TPoseMessageDialog() override; // slot 0x01 (scalar deleting destructor)
  virtual void DoIt() override;           // slot 0x0b 0x54aff0

  // +0x18 — the kicking nation shown by the 'pose' message dialog (written by the
  // turn-event-0xC receive path before the command is queued).
  int kickedByNationSlot18;

  // Fully inlined at every construction site (base TCommand ctor call + vtable
  // store); defined in-class so `new TPoseMessageDialog()` reproduces that shape.
  TPoseMessageDialog() : TCommand() {}
};

// Build and queue the 'pose' command for a nation slot. 0x54b0f0, genuine cdecl.
void __cdecl QueuePoseMessageDialogForNationSlot(int nationSlot);
