#include "game/TNextDiplomationCommand.h"

#include "game/TApplication.h"
#include "game/TDiplomacyMgr.h"
#include "game/global_data_tables.h"

IMPLEMENT_DYNCREATE(TNextDiplomationCommand, TCommand)

// Constructed inline at every call site; no standalone constructor address.
// FUNCTION: IMPERIALISM 0x004f0db0
void TNextDiplomationCommand::OrphanRetStub_00487a00() {
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
  InitializeRangePair(0x4e655854, g_pGlobalUiRootController, 0, 0, 0);
  g_pGlobalUiRootController->DispatchUiSelectionToHandler(this);
}
