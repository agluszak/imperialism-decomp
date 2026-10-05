#include "game/ui_core/TModalMessageCommand.h"

#include "game/ui_core/TViewMgr.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"
#include "game/globals/ui_core_globals.h"

// FUNCTION: IMPERIALISM 0x005dcd10
void TModalMessageCommand::DoIt() {
  g_pViewMgr->ModalMessage(message, g_ptUiPromptModalMessage, payload, 0);
}

TModalMessageCommand::~TModalMessageCommand() {}

IMPLEMENT_DYNCREATE(TModalMessageCommand, TCommand)
