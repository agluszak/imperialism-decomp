#pragma once

#include "game/TCommand.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0066f2f0
class TModalMessageCommand : public TCommand {
public:
  DECLARE_DYNCREATE(TModalMessageCommand)
  virtual ~TModalMessageCommand() override; // slot 0x01 (scalar deleting destructor)
  virtual void DoIt() override;             // slot 0x0b 0x5dcd10

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
