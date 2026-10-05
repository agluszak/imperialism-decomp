#pragma once

#include "compat.h"

#include "game/ui_core/TCommand.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0064c130
class TNewGameCommand : public TCommand {
public:
  DECLARE_DYNCREATE(TNewGameCommand)
  virtual ~TNewGameCommand() override; // slot 0x01 (scalar deleting destructor)
  virtual void DoIt() override;        // slot 0x0b 0x49ddb0

  TNewGameCommand() : TCommand() {}
};
ASSERT_SIZE(TNewGameCommand, 0x18);
