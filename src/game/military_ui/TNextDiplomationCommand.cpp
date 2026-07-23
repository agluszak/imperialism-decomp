#include "game/gfx/TAmbitApplication.h"
#include "game/ui_tags_military.h"
#include "game/military_ui/TNextDiplomationCommand.h"

#include "game/ui_core/TApplication.h"
#include "game/military_ui/TDiplomacyMgr.h"
#include "game/globals/prelude.h"
#include "game/globals/shared_globals.h"

IMPLEMENT_DYNCREATE(TNextDiplomationCommand, TCommand)

// Constructed inline at every call site; no standalone constructor address.
// FUNCTION: IMPERIALISM 0x004f0db0
void TNextDiplomationCommand::DoIt() {
  g_pDiplomacyTurnStateManager->ProcessQueuedWarTransitions();
}

// SYNTHETIC: IMPERIALISM 0x004f0dd0
// TNextDiplomationCommand::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x004f0e00
TNextDiplomationCommand::~TNextDiplomationCommand() {}

// SYNTHETIC: IMPERIALISM 0x004f28a0
// TNextDiplomationCommand::CreateObject

// SYNTHETIC: IMPERIALISM 0x004f2910
// TNextDiplomationCommand::GetRuntimeClass

// FUNCTION: IMPERIALISM 0x004f2930
void TNextDiplomationCommand::DispatchUiPacketWithTagNEXT() {
  InitializeRangePair(kControlTagNeXT, g_pGlobalUiRootController, 0, 0, 0);
  g_pGlobalUiRootController->DispatchUiSelectionToHandler(this);
}
