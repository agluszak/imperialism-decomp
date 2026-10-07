#include "game/tactical/TNavyAutoPlayer.h"

#include "game/ui_core/CIterator.h"
#include "game/TList.h"
#include "game/tactical/TTacticalBattle.h"
#include "game/tactical/TTacticalUnit.h"
#include "game/map/map_overlay_geometry.h"

IMPLEMENT_DYNCREATE(TNavyAutoPlayer, TNavyPlayer)

// FUNCTION: IMPERIALISM 0x0059f0e0
void TNavyAutoPlayer::INavyAutoPlayer(TTaskForce* force, char isOurSide, int nationIndex) {
  INavyPlayer(force, isOurSide, true, nationIndex);
}

// FUNCTION: IMPERIALISM 0x0059f110
void TNavyAutoPlayer::StartBattle() {
  int deployTileIndex;
  if (isOurSideFlag != 0) {
    deployTileIndex = battle->battlefieldColumnCount * 6 - 25;
  } else {
    deployTileIndex = 0x29;
  }
  while (!sideReadyFlag) {
    battle->DeployUnit(battle->selectedUnit, deployTileIndex);
    --deployTileIndex;
  }
}

// FUNCTION: IMPERIALISM 0x0059f160
void TNavyAutoPlayer::NextMove() {
  TTacticalUnit* unit = battle->selectedUnit;
  TList* enemyList;
  if (isOurSideFlag != 0) {
    enemyList = battle->players[1]->unitList;
  } else {
    enemyList = battle->players[0]->unitList;
  }

  int* distances = new int[enemyList->GetCount()];
  int currentTileIndex = battle->selectedUnit->tileIndex;

  CIterator enemyIter(enemyList);
  int* distanceCursor = distances;
  for (TTacticalUnit* record = static_cast<TTacticalUnit*>(enemyIter.Reset()); enemyIter.More();
       record = static_cast<TTacticalUnit*>(enemyIter.Advance())) {
    *distanceCursor++ = ComputeHexTileDistanceFromIndices(currentTileIndex, record->tileIndex);
  }

  // Closest enemy ordinal (999 sentinel).
  int bestOrdinal = -1;
  int bestDistance = 999;
  int* scanCursor = distances;
  int ordinal;
  for (ordinal = 0; ordinal < enemyList->GetCount(); ++ordinal) {
    if (*scanCursor < bestDistance) {
      bestOrdinal = ordinal;
      bestDistance = *scanCursor;
    }
    ++scanCursor;
  }

  // GetEntryByOrdinal is 1-based here (bestOrdinal + 1), matching the original.
  TTacticalUnit* targetUnit =
      static_cast<TTacticalUnit*>(enemyList->GetEntryByOrdinal(bestOrdinal + 1));
  int targetTileIndex = targetUnit->tileIndex;
  int bestApproachDistance = ComputeHexTileDistanceFromIndices(currentTileIndex, targetTileIndex);

  // Reachable tile minimizing distance to the target (start: stay put).
  int destinationTileIndex = currentTileIndex;
  int tileIndex;
  for (tileIndex = 0; tileIndex < battle->tacticalTileCount; ++tileIndex) {
    if (battle->tileMoveCostArray[tileIndex] != -1) {
      int approachDistance = ComputeHexTileDistanceFromIndices(tileIndex, targetTileIndex);
      if (approachDistance < bestApproachDistance) {
        destinationTileIndex = tileIndex;
        bestApproachDistance = approachDistance;
      }
    }
  }

  // March there one echoed step at a time while this ship stays selected.
  if (destinationTileIndex != currentTileIndex && battle->selectedUnit == unit) {
    while (unit->tileIndex != destinationTileIndex) {
      battle->MoveTacticalUnitAndQueueEvent232AIfNoAdjacentReachableTarget(unit,
                                                                           destinationTileIndex);
      if (battle->selectedUnit != unit) {
        break;
      }
    }
  }

  // Fire if the target ended up within range.
  int unitRange = unit->GetUnitRange();
  if (bestApproachDistance <= unitRange && battle->selectedUnit == unit) {
    battle->EvaluateAndResolveTacticalActionAgainstTileOccupant(unit, targetTileIndex);
  }

  delete[] distances;

  if (battle->selectedUnit == unit) {
    battle->FinishTacticalActionAndPostNextMoveCommand();
  }
}
