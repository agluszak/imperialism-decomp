#include "game/gfx/TNewGameCommand.h"

#include "game/ui_screens/TSimMgr.h"

// FUNCTION: IMPERIALISM 0x0049ddb0
void TNewGameCommand::DoIt() {
  RestartGameFlow(kTurnEventRebuildRegisteredWindows);
}

// FUNCTION: IMPERIALISM 0x0049de00
TNewGameCommand::~TNewGameCommand() {}

IMPLEMENT_DYNCREATE(TNewGameCommand, TCommand)
