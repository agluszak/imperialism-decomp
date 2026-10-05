#pragma once

#include "game/ui_core/TCommand.h"
#include "game/ui_tags_military.h"
#include <stddef.h>

// VTABLE: IMPERIALISM 0x0066da90
class TNextTradeCommand : public TCommand {
public:
  // slot 0x00 cmd_slot0 — declared in hand section (0x5ba3e0) slot 0x01 ~TNextTradeCommand /
  // cmd_slot1 — declared in hand section

  // slot 0x0b cmd_slot11 — declared in hand section (0x5ba4b0)
  TNextTradeCommand();

  DECLARE_DYNCREATE(TNextTradeCommand)
  void DoIt() override; // slot 0x0b 0x5ba4b0
  // slot 0x01 (dtor) overridden by ~TNextTradeCommand below (0x5ba430)

  void INextTradeCommand();
  virtual ~TNextTradeCommand() override;
};

ASSERT_SIZE(TNextTradeCommand, 0x18);
