#include "game/TNextMoveCommand.h"

#include "game/TArmyBattle.h"
#include "game/TArmyMgr.h"
#include "game/TTacticalBattle.h"
#include "game/TTacticalPlayer.h"
#include "game/global_data_tables.h"

// SYNTHETIC: IMPERIALISM 0x005a64d0
// TNextMoveCommand::CreateObject

// SYNTHETIC: IMPERIALISM 0x005a6540
// TNextMoveCommand::GetRuntimeClass

IMPLEMENT_DYNCREATE(TNextMoveCommand, TCommand)

// SYNTHETIC: IMPERIALISM 0x005a6590
// TNextMoveCommand::`scalar deleting destructor'
TNextMoveCommand::~TNextMoveCommand() {}

// FUNCTION: IMPERIALISM 0x005a6620
void TNextMoveCommand::DoIt() {
  if (battle18 != g_pMapContextActionManager->activeBattleView3a4) {
    return;
  }

  if (battle18->battleOutcomeCode44 != 0) {
    bool sideWonFlag = (battle18->battleOutcomeCode44 == 1);
    battle18->tacticalPlayer14->CommitTacticalResultsToSourceUnits(sideWonFlag);
    battle18->tacticalPlayer18->CommitTacticalResultsToSourceUnits(!sideWonFlag);
    battle18->FinalizeTacticalBattleOutcome(sideWonFlag);
  } else {
    battle18->pendingEndOfActionFlag48 = 1;
    battle18->AdvanceToNextTacticalUnitTurnStep();
  }
}
