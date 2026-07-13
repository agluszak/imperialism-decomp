#pragma once

#include "game/TCommand.h"
#include "game/mfc.h"

class TTacticalBattle;

// VTABLE: IMPERIALISM 0x0066a100
class TNextMoveCommand : public TCommand {
public:
  // === BEGIN GENERATED DECLS (TNextMoveCommand) — refreshed by recover-class; do not hand-edit ===
  DECLARE_DYNCREATE(TNextMoveCommand)
  virtual ~TNextMoveCommand() override; // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  // slot 0x05 WriteTo inherited unchanged (0x485f70)
  // slot 0x06 ReadFrom inherited unchanged (0x485f90)
  // slot 0x07 Free inherited unchanged (0x4878e0)
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  // slot 0x0a NextDiplomacyCommandVtableSlotE8_NotifyOwnerSlot94 inherited unchanged (0x487900)
  virtual void DoIt() override; // slot 0x0b 0x5a6620
  // === END GENERATED DECLS (TNextMoveCommand) ===
  // The battle whose action round this command closes (turn event 0x232a); read
  // back by the slot-0x0b override (0x5a6620).
  TTacticalBattle* battle18; // +0x18

  // The posting site (0x5a0d60) inlines the ctor as TCommand() + vtable store, so it
  // must stay in-class; the original also keeps a compiler-emitted out-of-line copy at
  // 0x5a6560, but our toolchain fully inlines this trivial ctor away at its call
  // sites (no matching recompiled address) -- a genuine optimizer-choice mismatch, not
  // a modeling gap, so that address is left unclaimed rather than faked.
  TNextMoveCommand() : TCommand() {}
};

ASSERT_SIZE(TNextMoveCommand, 0x1c);
