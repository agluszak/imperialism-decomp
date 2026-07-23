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

  // Keep this in-class: VC5 inlines it as TCommand() + one vtable store in both
  // CreateObject (0x5a64d0) and the posting site (0x5a0d60). The retail compiler also
  // emitted an unused standalone copy at 0x5a6560, while the reproduced build discards
  // that copy. Moving this definition out of line recovers 0x5a6560 but regresses those
  // two live callers from 100% to 49% and 82%, respectively, so the dead copy remains
  // intentionally unclaimed rather than being represented by a fake helper.
  TNextMoveCommand() : TCommand() {}
};

ASSERT_SIZE(TNextMoveCommand, 0x1c);
