#include "game/tactical/TNavyHumanPlayer.h"

#include "game/TList.h"
#include "game/tactical/TTacticalBattle.h"
#include "game/tactical/TTacticalUnit.h"

IMPLEMENT_DYNCREATE(TNavyHumanPlayer, TNavyPlayer)

// FUNCTION: IMPERIALISM 0x0059ef90
void TNavyHumanPlayer::INavyHumanPlayer(TTaskForce* force, char isOurSide, int nationIndex) {
  INavyPlayer(force, isOurSide, true, nationIndex);
}

// FUNCTION: IMPERIALISM 0x0059efc0
void TNavyHumanPlayer::DeploymentClick(TacticalTileIndex tileIndex) {
  int ordinal = 1;
  TTacticalUnit* unit;
  while (true) {
    unit = static_cast<TTacticalUnit*>(unitList->GetEntryByOrdinal(ordinal));
    ++ordinal;
    if (unit->tileIndex8 == -2) {
      break;
    }
    if (ordinal > unitList->GetCount()) {
      break;
    }
  }

  if (ordinal > unitList->GetCount()) {
    sideReadyFlag = true;
  } else {
    battle14->DeployUnit(unit, tileIndex);
  }
}
