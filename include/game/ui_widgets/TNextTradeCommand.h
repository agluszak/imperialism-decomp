#pragma once

#include "game/ui_core/TCommand.h"
#include "game/ui_tags_military.h"
#include <stddef.h>

// The 'NeXT' ('NeXT') turn-event command enqueued onto the UI root
// controller. Real inheritance from TCommand: the base constructor installs the
// 0x648e28 vtable, then this class's constructor installs 0x0066da90 — reproducing
// the original two-stage vptr write without any manual vtable store. It overrides
// only slots 0, 1 and 11 (0x2c); slots 2-10 are inherited from TCommand.
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

  // Seed the command payload with dispatch message 0x232b targeting the global UI
  // root controller (0x5ba480; diplomacy turn-event code 0x1c path).
  void InitializeRangePairFromDiplomacyConstants();
  virtual ~TNextTradeCommand() override;
};

ASSERT_SIZE(TNextTradeCommand, 0x18);
