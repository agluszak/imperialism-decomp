#include "game/military/TCancelGameOptionsCommand.h"
#include "game/turn_event_codes.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"
#include "game/net/TMultiplayerMgr.h"
#include "game/ui_core/TApplication.h"
#include "game/gfx/TAmbitApplication.h"

// FUNCTION: IMPERIALISM 0x00542520
void TCancelGameOptionsCommand::DoIt() {
  TMultiplayerMgr* flowState = g_pGameFlowState;
  flowState->lobbyDialogView40 = 0;
  flowState->ResetNationStatusArraysAndTurnEventContext();
  g_pAmbitApplication->PostTurnEventCodeMessage2420(kTurnEventMultiplayerGameSetup);
  flowState->queueSyncDword = 0;
}

// SYNTHETIC: IMPERIALISM 0x00542560
// TCancelGameOptionsCommand::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x00542590
TCancelGameOptionsCommand::~TCancelGameOptionsCommand() {}
// SYNTHETIC: IMPERIALISM 0x005424b0
// TCancelGameOptionsCommand::CreateObject

// SYNTHETIC: IMPERIALISM 0x005425b0
// TCancelGameOptionsCommand::GetRuntimeClass

IMPLEMENT_DYNCREATE(TCancelGameOptionsCommand, TCommand)
