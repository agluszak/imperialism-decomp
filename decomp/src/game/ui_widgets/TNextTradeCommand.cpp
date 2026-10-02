#include "game/gfx/TAmbitApplication.h"
#include "game/ui_widgets/TNextTradeCommand.h"
#include "game/ui_widgets/TTradeMgr.h"

#include "game/ui_core/TApplication.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"

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
  ICommand(0x232b, g_pAmbitApplication, 0, 0, 0);
}

// FUNCTION: IMPERIALISM 0x005ba4b0
void TNextTradeCommand::DoIt() {
  g_pTradeMgr->NextTradeDeal();
}
