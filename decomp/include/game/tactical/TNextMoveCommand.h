#pragma once

#include "game/ui_core/TCommand.h"
#include "game/mfc.h"

class TTacticalBattle;

// VTABLE: IMPERIALISM 0x0066a100
class TNextMoveCommand : public TCommand {
public:
  DECLARE_DYNCREATE(TNextMoveCommand)
  virtual ~TNextMoveCommand() override;
  virtual void DoIt() override;
  TTacticalBattle* battle;

  // MATCH: inlined at every allocation site; the standalone COMDAT copy stays unclaimed.
  TNextMoveCommand() {}
  void INextMoveCommand(TTacticalBattle* battle);
};

ASSERT_SIZE(TNextMoveCommand, 0x1c);
