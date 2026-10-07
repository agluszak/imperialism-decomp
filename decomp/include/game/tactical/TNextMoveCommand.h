#pragma once

#include "game/ui_core/TCommand.h"
#include "game/mfc.h"

class TTacticalBattle;

// VTABLE: IMPERIALISM 0x0066a100
class TNextMoveCommand : public TCommand {
public:
  DECLARE_DYNCREATE(TNextMoveCommand)
  virtual ~TNextMoveCommand() override; // slot 0x01 (scalar deleting destructor)
  virtual void DoIt() override;         // slot 0x0b 0x5a6620
  TTacticalBattle* battle;              // +0x18

  // MATCH: inlined at every allocation site; the standalone COMDAT copy stays unclaimed.
  TNextMoveCommand() : TCommand() {}
  void INextMoveCommand(TTacticalBattle* battle); // 0x5a65e0
};

ASSERT_SIZE(TNextMoveCommand, 0x1c);
