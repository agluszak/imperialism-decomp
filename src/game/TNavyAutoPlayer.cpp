#include "game/TNavyAutoPlayer.h"

#include "game/CIterator.h"
#include "game/TList.h"
#include "game/TTacticalBattle.h"
#include "game/TTacticalUnit.h"
#include "game/map_overlay_geometry.h"

// SYNTHETIC: IMPERIALISM 0x0059f070
// TNavyAutoPlayer::`scalar deleting destructor'
TNavyAutoPlayer::~TNavyAutoPlayer() {}
// SYNTHETIC: IMPERIALISM 0x0059f040
// TNavyAutoPlayer::CreateObject

// SYNTHETIC: IMPERIALISM 0x0059f0c0
// TNavyAutoPlayer::GetRuntimeClass

IMPLEMENT_DYNCREATE(TNavyAutoPlayer, TNavyPlayer)

TNavyAutoPlayer::TNavyAutoPlayer() {}

// FUNCTION: IMPERIALISM 0x0059f110
void TNavyAutoPlayer::StartBattle() {
  // Auto-deploys the whole side: our side deploys from row battlefieldColumnCount34*6
  // - 25 downward, the enemy side from tile 41 downward, feeding the battle's current
  // selection into DeployTacticalUnitToTile until the side reports ready.
  int deployTileIndex;
  if (isOurSideFlagC != 0) {
    deployTileIndex = battle14->battlefieldColumnCount34 * 6 - 25;
  } else {
    deployTileIndex = 0x29;
  }
  while (sideReadyFlag10 == 0) {
    battle14->DeployTacticalUnitToTile(battle14->selectedUnit1c, deployTileIndex);
    --deployTileIndex;
  }
}

// FUNCTION: IMPERIALISM 0x0059f160
void TNavyAutoPlayer::AdvanceTacticalTurnPulse() {
  // Navy AI turn pump (one pulse per selected ship): measures the hex distance from
  // the selected ship to every enemy ship, picks the closest as the target, then the
  // reachable tile (tileMoveCostArray24 != -1) minimizing distance to it, sails there
  // one echoed step at a time, fires if the target ended up within range, and hands
  // the turn back via the 0x232a event.
  TTacticalUnit* unit = battle14->selectedUnit1c;
  TList* enemyList;
  if (isOurSideFlagC != 0) {
    enemyList = battle14->tacticalPlayer18->unitList4;
  } else {
    enemyList = battle14->tacticalPlayer14->unitList4;
  }

  int* distances = new int[enemyList->GetCount()];
  int currentTileIndex = battle14->selectedUnit1c->tileIndex8;

  CIterator enemyIter(enemyList);
  int* distanceCursor = distances;
  for (TTacticalUnit* record = static_cast<TTacticalUnit*>(enemyIter.Reset()); enemyIter.More();
       record = static_cast<TTacticalUnit*>(enemyIter.Advance())) {
    *distanceCursor++ = ComputeHexTileDistanceFromIndices(currentTileIndex, record->tileIndex8);
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
  int targetTileIndex = targetUnit->tileIndex8;
  int bestApproachDistance = ComputeHexTileDistanceFromIndices(currentTileIndex, targetTileIndex);

  // Reachable tile minimizing distance to the target (start: stay put).
  int destinationTileIndex = currentTileIndex;
  int tileIndex;
  for (tileIndex = 0; tileIndex < battle14->tacticalTileCount3c; ++tileIndex) {
    if (battle14->tileMoveCostArray24[tileIndex] != -1) {
      int approachDistance = ComputeHexTileDistanceFromIndices(tileIndex, targetTileIndex);
      if (approachDistance < bestApproachDistance) {
        destinationTileIndex = tileIndex;
        bestApproachDistance = approachDistance;
      }
    }
  }

  // March there one echoed step at a time while this ship stays selected.
  if (destinationTileIndex != currentTileIndex && battle14->selectedUnit1c == unit) {
    while (unit->tileIndex8 != destinationTileIndex) {
      battle14->MoveTacticalUnitAndQueueEvent232AIfNoAdjacentReachableTarget(unit,
                                                                             destinationTileIndex);
      if (battle14->selectedUnit1c != unit) {
        break;
      }
    }
  }

  // Fire if the target ended up within range.
  int unitRange = unit->GetUnitRange();
  if (bestApproachDistance <= unitRange && battle14->selectedUnit1c == unit) {
    battle14->EvaluateAndResolveTacticalActionAgainstTileOccupant(unit, targetTileIndex);
  }

  delete[] distances;

  if (battle14->selectedUnit1c == unit) {
    battle14->QueueTacticalEventPacket232A();
  }
}
