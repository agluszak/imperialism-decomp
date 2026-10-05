#pragma once

#include "compat.h"

#include "game/ui_core/TCommand.h"
#include "game/multiplayer_session_tags.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0065c0e8
class TPoseMessageDialog : public TCommand {
public:
  DECLARE_DYNCREATE(TPoseMessageDialog)
  virtual ~TPoseMessageDialog() override; // slot 0x01 (scalar deleting destructor)
  virtual void DoIt() override;           // slot 0x0b 0x54aff0

  int kickedByNationSlot;

  TPoseMessageDialog() : TCommand() {}
};
ASSERT_SIZE(TPoseMessageDialog, 0x1c);

// Build and queue the 'pose' command for a nation slot. 0x54b0f0, genuine cdecl.
void __cdecl QueuePoseMessageDialogForNationSlot(int nationSlot);
