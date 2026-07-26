#include "game/gfx/TNewGameCommand.h"

#include "game/ui_screens/TSimMgr.h"

// FUNCTION: IMPERIALISM 0x0049ddb0
void TNewGameCommand::DoIt() {
  ReinitializeGameFlowAndPostTurnEventCode(kTurnEventRebuildRegisteredWindows);
}

// SYNTHETIC: IMPERIALISM 0x0049ddd0
// TNewGameCommand::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x0049de00
TNewGameCommand::~TNewGameCommand() {}
// SYNTHETIC: IMPERIALISM 0x0049dd40
// TNewGameCommand::CreateObject

// SYNTHETIC: IMPERIALISM 0x0049de20
// TNewGameCommand::GetRuntimeClass

IMPLEMENT_DYNCREATE(TNewGameCommand, TCommand)
