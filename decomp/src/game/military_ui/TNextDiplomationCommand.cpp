#include "game/gfx/TAmbitApplication.h"
#include "game/ui_tags_military.h"
#include "game/military_ui/TNextDiplomationCommand.h"

#include "game/ui_core/TApplication.h"
#include "game/military_ui/TDiplomacyMgr.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"

IMPLEMENT_DYNCREATE(TNextDiplomationCommand, TCommand)

// Constructed inline at every call site; no standalone constructor address.
// FUNCTION: IMPERIALISM 0x004f0db0
void TNextDiplomationCommand::DoIt() {
  g_pDiplomacyTurnStateManager->ProcessQueuedWarTransitions();
}

// FUNCTION: IMPERIALISM 0x004f0e00
TNextDiplomationCommand::~TNextDiplomationCommand() {}

// FUNCTION: IMPERIALISM 0x004f2930
void TNextDiplomationCommand::PostThyself() {
  ICommand(kControlTagNeXT, g_pAmbitApplication, 0, 0, 0);
  g_pAmbitApplication->DispatchUiSelectionToHandler(this);
}
