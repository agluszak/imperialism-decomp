#include "game/tactical/TNavyHumanPlayer.h"

#include "game/TList.h"
#include "game/tactical/TTacticalBattle.h"
#include "game/tactical/TTacticalUnit.h"

// SYNTHETIC: IMPERIALISM 0x0059ef20
// TNavyHumanPlayer::`scalar deleting destructor'

// SYNTHETIC: IMPERIALISM 0x0059ef50
// TNavyHumanPlayer::~TNavyHumanPlayer
TNavyHumanPlayer::~TNavyHumanPlayer() {}
// SYNTHETIC: IMPERIALISM 0x0059eef0
// TNavyHumanPlayer::CreateObject

// SYNTHETIC: IMPERIALISM 0x0059ef70
// TNavyHumanPlayer::GetRuntimeClass

IMPLEMENT_DYNCREATE(TNavyHumanPlayer, TNavyPlayer)

// NOOP: verified empty in original 0x0059eef2 (no standalone TNavyHumanPlayer::TNavyHumanPlayer body exists: construction is fully inlined into CreateObject 0x0059eef0; that address is its operator-new call site)
TNavyHumanPlayer::TNavyHumanPlayer() {}

// FUNCTION: IMPERIALISM 0x0059efc0
void TNavyHumanPlayer::DeploymentClick(TacticalTileIndex tileIndex) {
  int ordinal = 1;
  TTacticalUnit* unit;
  do {
    unit = static_cast<TTacticalUnit*>(unitList4->GetEntryByOrdinal(ordinal));
    ++ordinal;
    if (unit->tileIndex8 == -2) {
      break;
    }
  } while (ordinal <= unitList4->GetCount());

  if (ordinal > unitList4->GetCount()) {
    sideReadyFlag10 = 1;
  } else {
    battle14->DeployTacticalUnitToTile(unit, tileIndex);
  }
}
