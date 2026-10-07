#pragma once

#include "game/ui_core/TCommand.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0066f2f0
class TModalMessageCommand : public TCommand {
public:
  DECLARE_DYNCREATE(TModalMessageCommand)
  virtual ~TModalMessageCommand() override;
  virtual void DoIt() override;

  CString message;
  int payload;

  TModalMessageCommand() : TCommand() {}
};

ASSERT_SIZE(TModalMessageCommand, 0x20);
