#include "game/TModalMessageCommand.h"

#include "game/TViewMgr.h"
#include "game/globals/prelude.h"
#include "game/globals/shared_globals.h"
#include "game/globals/ui_core_globals.h"

// FUNCTION: IMPERIALISM 0x005dcd10
void TModalMessageCommand::DoIt() {
  g_pUiRuntimeContext->ModalMessage(message, g_ptUiPromptModalMessage, payload, 0);
}

// SYNTHETIC: IMPERIALISM 0x005dcd50
// TModalMessageCommand::`scalar deleting destructor'

// SYNTHETIC: IMPERIALISM 0x005dcd80
// TModalMessageCommand::~TModalMessageCommand
TModalMessageCommand::~TModalMessageCommand() {}

// SYNTHETIC: IMPERIALISM 0x005dcc90
// TModalMessageCommand::CreateObject

// SYNTHETIC: IMPERIALISM 0x005dcdd0
// TModalMessageCommand::GetRuntimeClass

IMPLEMENT_DYNCREATE(TModalMessageCommand, TCommand)
