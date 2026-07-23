#pragma once

#include "game/ui_core/TCommand.h"

// Diplomacy-phase 'NeXT' command, sibling of TNextTradeCommand (identical 12-slot
// shape; RTTI descriptor 0x654ce8 proves TNextDiplomationCommand -> TCommand ->
// TEvent -> TObject -> CObject). Constructed inline at its call sites
// (HandleDiplomacyTurnEventPacketByCode 0x543f96, the diplomacy turn-event state
// machine 0x5470aa, TSimMgr::AdvanceGlobalTurnStateMachine 0x57df27) — no
// standalone constructor address. Its TU is the 0x4f0xxx-0x4f2xxx diplomacy band.
// VTABLE: IMPERIALISM 0x00654e50
class TNextDiplomationCommand : public TCommand {
public:
  DECLARE_DYNCREATE(TNextDiplomationCommand)
  // slot 0x0b override (0x4f0db0, Ghidra: DispatchProcessQueuedWarTransitions):
  // forwards to g_pDiplomacyTurnStateManager->ProcessQueuedWarTransitions().
  void DoIt() override;

  // Fully inlined at every construction site (base TCommand ctor call + vtable
  // store); defined in-class so `new TNextDiplomationCommand()` reproduces that shape.
  TNextDiplomationCommand() : TCommand() {}

  // Seed the payload with the 'NeXT' four-cc and immediately dispatch this command
  // through the UI root controller (0x4f2930).
  void DispatchUiPacketWithTagNEXT();

  virtual ~TNextDiplomationCommand() override; // slot 0x01 scalar deleting dtor 0x4f0dd0
};

ASSERT_SIZE(TNextDiplomationCommand, 0x18);
