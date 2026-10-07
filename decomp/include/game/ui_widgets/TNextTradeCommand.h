#pragma once

#include "game/ui_core/TCommand.h"
#include "game/ui_tags_military.h"
#include <stddef.h>

// VTABLE: IMPERIALISM 0x0066da90
class TNextTradeCommand : public TCommand {
public:
  TNextTradeCommand();

  DECLARE_DYNCREATE(TNextTradeCommand)
  void DoIt() override; // slot 0x0b 0x5ba4b0

  void INextTradeCommand();
  virtual ~TNextTradeCommand() override;
};

ASSERT_SIZE(TNextTradeCommand, 0x18);
