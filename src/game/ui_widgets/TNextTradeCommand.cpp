#include "game/gfx/TAmbitApplication.h"
#include "game/ui_widgets/TNextTradeCommand.h"
#include "game/ui_widgets/TTradeMgr.h"

#include "game/ui_core/TApplication.h"
#include "game/globals/prelude.h"
#include "game/globals/shared_globals.h"

// The base TCommand constructor installs vtable 0x648e28; this constructor then
// installs 0x66da90 (compiler-emitted from the // VTABLE: annotation). No manual
// vptr store. Besides inlined copies at `new TNextTradeCommand()` call sites, a
// standalone out-of-line copy exists at 0x5ba400 (Ghidra name:
// ConstructTNextTradeCommandBaseState), called by the diplomacy turn-event
// state machine.

// FUNCTION: IMPERIALISM 0x005ba400
TNextTradeCommand::TNextTradeCommand() : TCommand() {}

// SYNTHETIC: IMPERIALISM 0x005ba430
// TNextTradeCommand::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x005ba460
TNextTradeCommand::~TNextTradeCommand() {}
// SYNTHETIC: IMPERIALISM 0x005ba370
// TNextTradeCommand::CreateObject

// SYNTHETIC: IMPERIALISM 0x005ba3e0
// TNextTradeCommand::GetRuntimeClass

IMPLEMENT_DYNCREATE(TNextTradeCommand, TCommand)

// FUNCTION: IMPERIALISM 0x005ba480
void TNextTradeCommand::INextTradeCommand() {
  ICommand(0x232b, g_pGlobalUiRootController, 0, 0, 0);
}

// FUNCTION: IMPERIALISM 0x005ba4b0
void TNextTradeCommand::DoIt() {
  g_pNationInteractionStateManager->NextTradeDeal();
}
