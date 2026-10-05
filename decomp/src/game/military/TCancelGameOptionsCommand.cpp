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
  flowState->lobbyDialogView = 0;
  flowState->ResetNationStatusArraysAndTurnEventContext();
  g_pAmbitApplication->PostTurnEventCodeMessage(kTurnEventMultiplayerGameSetup);
  flowState->queueSyncDword = 0;
}

// FUNCTION: IMPERIALISM 0x00542590
TCancelGameOptionsCommand::~TCancelGameOptionsCommand() {}

IMPLEMENT_DYNCREATE(TCancelGameOptionsCommand, TCommand)
