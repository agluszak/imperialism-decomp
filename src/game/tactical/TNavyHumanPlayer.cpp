#include "game/tactical/TNavyHumanPlayer.h"

#include "game/TList.h"
#include "game/tactical/TTacticalBattle.h"
#include "game/tactical/TTacticalUnit.h"
// SYNTHETIC: IMPERIALISM 0x0059eef0
// TNavyHumanPlayer::CreateObject

// SYNTHETIC: IMPERIALISM 0x0059ef20
// TNavyHumanPlayer::`scalar deleting destructor'

// SYNTHETIC: IMPERIALISM 0x0059ef50
// TNavyHumanPlayer::~TNavyHumanPlayer
TNavyHumanPlayer::~TNavyHumanPlayer() {}

// SYNTHETIC: IMPERIALISM 0x0059ef70
// TNavyHumanPlayer::GetRuntimeClass

IMPLEMENT_DYNCREATE(TNavyHumanPlayer, TNavyPlayer)

// FUNCTION: IMPERIALISM 0x0059ef90
void TNavyHumanPlayer::INavyHumanPlayer(TTaskForce* force, char isOurSide, int nationIndex) {
  INavyPlayer(force, isOurSide, 1, nationIndex);
}

// FUNCTION: IMPERIALISM 0x0059efc0
void TNavyHumanPlayer::DeploymentClick(TacticalTileIndex tileIndex) {
  int ordinal = 1;
  TTacticalUnit* unit;
  while (true) {
    unit = static_cast<TTacticalUnit*>(unitList4->GetEntryByOrdinal(ordinal));
    ++ordinal;
    if (unit->tileIndex8 == -2) {
      break;
    }
    if (ordinal > unitList4->GetCount()) {
      break;
    }
  }

  if (ordinal > unitList4->GetCount()) {
    sideReadyFlag10 = 1;
  } else {
    battle14->DeployTacticalUnitToTile(unit, tileIndex);
  }
}
