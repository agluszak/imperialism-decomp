#pragma once

#include "compat.h"

#include "game/ui_core/TCommand.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0064c130
class TNewGameCommand : public TCommand {
public:
  DECLARE_DYNCREATE(TNewGameCommand)
  virtual ~TNewGameCommand() override;
  virtual void DoIt() override;

  TNewGameCommand() {}
};
ASSERT_SIZE(TNewGameCommand, 0x18);
