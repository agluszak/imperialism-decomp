#pragma once

#include "game/ui_core/TCommand.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0066f2f0
class TModalMessageCommand : public TCommand {
public:
  DECLARE_DYNCREATE(TModalMessageCommand)
  virtual ~TModalMessageCommand() override; // slot 0x01 (scalar deleting destructor)
  virtual void DoIt() override;             // slot 0x0b 0x5dcd10

  CString message; // +0x18
  int payload;     // +0x1c

  TModalMessageCommand() : TCommand() {}
};

ASSERT_SIZE(TModalMessageCommand, 0x20);
