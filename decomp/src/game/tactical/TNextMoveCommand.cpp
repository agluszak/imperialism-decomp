#include "game/tactical/TNextMoveCommand.h"

#include "game/tactical/TArmyBattle.h"
#include "game/military/TArmyMgr.h"
#include "game/tactical/TTacticalBattle.h"
#include "game/map/TTacticalPlayer.h"
#include "game/globals/global_types.h"
#include "game/gfx/TAmbitApplication.h"
#include "game/globals/shared_globals.h"

IMPLEMENT_DYNCREATE(TNextMoveCommand, TCommand)

// FUNCTION: IMPERIALISM 0x005a65c0
TNextMoveCommand::~TNextMoveCommand() {}

// FUNCTION: IMPERIALISM 0x005a65e0
void TNextMoveCommand::INextMoveCommand(TTacticalBattle* battle) {
  ICommand(0x232a, static_cast<TCommandHandler*>(g_pAmbitApplication), 0, 0, 0);
  this->battle = battle;
}

// FUNCTION: IMPERIALISM 0x005a6620
void TNextMoveCommand::DoIt() {
  TTacticalBattle* battle = this->battle;
  if (battle != g_pMapContextActionManager->activeBattleView) {
    return;
  }

  if (battle->battleOutcome != kTacticalBattleInProgress) {
    int sideWonFlag = (battle->battleOutcome == kTacticalBattleSide0Victory);
    battle->players[0]->ApplyChanges(static_cast<unsigned char>(sideWonFlag));
    battle->players[1]->ApplyChanges(static_cast<unsigned char>(!sideWonFlag));
    battle->EndBattle(static_cast<unsigned char>(sideWonFlag));
  } else {
    battle->pendingEndOfActionFlag = true;
    battle->Cycle();
  }
}
