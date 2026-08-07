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
  // The battle whose action round this command closes (turn event 0x232a); read
  // back by the slot-0x0b override (0x5a6620).
  TTacticalBattle* battle18; // +0x18

  // MATCH: VC5 expands this constructor at every live retail allocation site; the
  // unreferenced standalone COMDAT copy is intentionally left unclaimed.
  TNextMoveCommand() : TCommand() {}
  void INextMoveCommand(TTacticalBattle* battle); // 0x5a65e0
};

ASSERT_SIZE(TNextMoveCommand, 0x1c);
