#include "game/tactical/TNextMoveCommand.h"

#include "game/tactical/TArmyBattle.h"
#include "game/military/TArmyMgr.h"
#include "game/tactical/TTacticalBattle.h"
#include "game/map/TTacticalPlayer.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"

// SYNTHETIC: IMPERIALISM 0x005a64d0
// TNextMoveCommand::CreateObject

// SYNTHETIC: IMPERIALISM 0x005a6540
// TNextMoveCommand::GetRuntimeClass

IMPLEMENT_DYNCREATE(TNextMoveCommand, TCommand)

// SYNTHETIC: IMPERIALISM 0x005a6590
// TNextMoveCommand::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x005a65c0
TNextMoveCommand::~TNextMoveCommand() {}

// FUNCTION: IMPERIALISM 0x005a6620
void TNextMoveCommand::DoIt() {
  TTacticalBattle* battle = battle18;
  if (battle != g_pMapContextActionManager->activeBattleView3a4) {
    return;
  }

  if (battle->battleOutcomeCode44 != 0) {
    int sideWonFlag = (battle->battleOutcomeCode44 == 1);
    battle->tacticalPlayer14->ApplyChanges(static_cast<unsigned char>(sideWonFlag));
    battle->tacticalPlayer18->ApplyChanges(static_cast<unsigned char>(!sideWonFlag));
    battle->EndBattle(static_cast<unsigned char>(sideWonFlag));
  } else {
    battle->pendingEndOfActionFlag48 = 1;
    battle->AdvanceToNextTacticalUnitTurnStep();
  }
}
