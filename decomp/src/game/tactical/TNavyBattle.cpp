#include "game/tactical/TNavyBattle.h"
#include "game/ui_tags_common.h"

#include "game/navy/TNavyMgr.h"
#include "game/tactical/TNavyPlayer.h"
#include "game/tactical/TNavyTacUnit.h"
#include "game/tactical/TTacticalBattleView.h"
#include "game/map/TTacticalPlayer.h"
#include "game/tactical_ui/TTacticalToolbar.h"
#include "game/tactical/TTacticalUnit.h"
#include "game/globals/global_types.h"
#include "game/globals/navy_globals.h"
#include "game/globals/shared_globals.h"

#include <stdlib.h>

IMPLEMENT_DYNCREATE(TNavyBattle, TTacticalBattle)

// FUNCTION: IMPERIALISM 0x005a5540
void TNavyBattle::InitTacticalBattle(TTacticalPlayer* ourPlayer, TTacticalPlayer* enemyPlayer) {
  tacticalTileCount = 0xb4;
  tacticalTileStride = 6;
  TTacticalBattle::InitTacticalBattle(ourPlayer, enemyPlayer);

  int direction = rand() % 6;
  moveCostRotationStart = direction;
  int costIndex = 0;
  do {
    neighborMoveCostByDirection[direction] = g_anNavyTacticalMoveCostsByDirection[costIndex];
    ++costIndex;
    direction = (direction == 5) ? 0 : direction + 1;
  } while (direction != moveCostRotationStart);
}

// FUNCTION: IMPERIALISM 0x005a55c0
void TNavyBattle::DeployUnit(TTacticalUnit* unit, TacticalTileIndex tileIndex) {
  bool sideIsZero = (unit->side20 == 0);
  bool canDeploy = true;
  int rowIndex = tileIndex / 29;
  if (sideIsZero) {
    if (rowIndex < battlefieldColumnCount - 6) {
      canDeploy = false;
    } else if (rowIndex > battlefieldColumnCount - 5) {
      canDeploy = false;
    }
  } else {
    if (rowIndex > 6) {
      canDeploy = false;
    } else if (rowIndex < 5) {
      canDeploy = false;
    }
  }
  if (tileGrid[tileIndex].occupant4 != 0) {
    canDeploy = false;
  }
  if (!canDeploy) {
    return;
  }

  unit->tileIndex8 = tileIndex;
  tileGrid[tileIndex].occupant4 = unit;
  if (battleView8 != 0) {
    battleView8->InvalidateUnit(unit);
  }

  selectedUnit1c = players[currentSide]->SelectNextTacticalUnitForDoneCommand();
  if (!players[currentSide]->sideReadyFlag) {
    return;
  }

  currentSide = (currentSide == 0);
  selectedUnit1c = players[currentSide]->SelectNextTacticalUnitForDoneCommand();

  if (battleView8 != 0) {
    TTacticalToolbar* toolbar = static_cast<TTacticalToolbar*>(
        battleView8->ownerContext->ResolveControlByTag(kControlTagTool));
    toolbar->AssertValid();
    toolbar->UpdateTacticalCurrentUnitControlAndDialogLabel(selectedUnit1c);
    toolbar->ForceRedraw();
  }

  if (players[currentSide]->sideReadyFlag) {
    FinalizeTacticalTurnStateAndQueueEvent232A();
    return;
  }
  players[currentSide]->StartBattle();
}

// FUNCTION: IMPERIALISM 0x005a5730
void TNavyBattle::EvaluateAndResolveTacticalActionAgainstTileOccupant(
    TTacticalUnit* attackerUnit, TacticalTileIndex targetTileIndex) {
  TNavyTacUnit* defenderUnit = static_cast<TNavyTacUnit*>(tileGrid[targetTileIndex].occupant4);
  defenderUnit->AssertValid();

  int attackerRow = attackerUnit->tileIndex8 / 29;
  int attackerX = (attackerRow & 1) + attackerUnit->tileIndex8 % 29 * 2;
  unsigned int targetRow;
  int targetX;
  ConvertHexTileIndexToRowAndDoubleColumn(targetTileIndex, &targetRow, &targetX);
  if (targetX < attackerX) {
    targetX = attackerX * 2 - targetX;
  }
  int targetRowSigned = static_cast<int>(targetRow);
  if (targetRowSigned < attackerRow) {
    targetRowSigned = attackerRow * 2 - targetRowSigned;
  }
  int rowDelta = targetRowSigned - attackerRow;
  int extraColumns = targetX - rowDelta - attackerX;
  int hexDistance = (extraColumns > 0) ? rowDelta + extraColumns / 2 : rowDelta;

  int range = attackerUnit->GetUnitRange();
  double ratio = hexDistance / (range * g_dNavyHitChanceRangeScale_00669ef8);
  double ratioCubed = ratio * ratio * ratio;
  double denominator = ratioCubed - g_fNavyHitChanceCubeOffset_00669f00;
  float hitThreshold = static_cast<float>(attackerUnit->qualityLevel10 * 5 +
                                          g_fNavyHitChanceNumerator_00669f04 / denominator);

  if (battleView8 != 0) {
    battleView8->PlayAni(attackerUnit->tileIndex8, attackerUnit->unitTypeC + 0xf5a, 1);
  }

  if (static_cast<float>(rand() % 100) < hitThreshold) {
    TTacticalPlayer* attackerSidePlayer = players[currentSide];
    attackerSidePlayer->AssertValid();
    NavyTargeting targeting = static_cast<TNavyPlayer*>(attackerSidePlayer)->targetingMode;
    float attackPower = attackerUnit->GetBaseAttackPower();
    float scaledStrength = attackerUnit->strength4 * attackPower;
    float damageScale = defenderUnit->GetDamageScale();
    float damageAmount = damageScale * scaledStrength;
    defenderUnit->ApplyNavalDamage(damageAmount, targeting);
    if (battleView8 != 0) {
      battleView8->InvalidateUnit(defenderUnit);
    }
    if (defenderUnit->state1c == 3) {
      tileGrid[defenderUnit->tileIndex8].occupant4 = 0;
      defenderUnit->tileIndex8 = -1;
      if (battleView8 != 0) {
        battleView8->PlayAni(targetTileIndex, 0xf42, 12);
      }
    }
  } else {
    if (battleView8 != 0) {
      battleView8->PlayAni(targetTileIndex, 0xf3c, 6);
    }
  }

  attackerUnit->selectedFlag = 0;
  EvaluateTacticalSideStateAndShowBattleSummaryDialog();
}

// FUNCTION: IMPERIALISM 0x005a59a0
void __stdcall ConvertHexTileIndexToRowAndDoubleColumn(TacticalTileIndex tileIndex,
                                                       unsigned int* outRow, int* outCol2X) {
  *outRow = tileIndex / 0x1d;
  *outCol2X = (tileIndex / 0x1d & 1) + (tileIndex % 0x1d) * 2;
}

// FUNCTION: IMPERIALISM 0x005a59f0
void TNavyBattle::CalculateMoveMap(TTacticalUnit* unit) {
  int actionPoints = unit->actionPoints28;
  short* moveCosts = tileMoveCostArray;
  TacticalTileIndex tileIndex;
  for (tileIndex = 0; tileIndex < tacticalTileCount; ++tileIndex) {
    moveCosts[tileIndex] = -1;
  }
  moveCosts[unit->tileIndex8] = 0;

  int costBand;
  for (costBand = 0; costBand <= actionPoints; costBand += 10) {
    short* moveCost = moveCosts;
    for (tileIndex = 0; tileIndex < tacticalTileCount; ++tileIndex, ++moveCost) {
      if (*moveCost < costBand) {
        continue;
      }

      TacticalTileIndex neighborTiles[6];
      GetNeighborList(tileIndex, neighborTiles);
      int direction;
      for (direction = 0; direction < 6; ++direction) {
        TacticalTileIndex neighborTile = neighborTiles[direction];
        if (neighborTile == -1 || tileGrid[neighborTile].occupant4 != 0) {
          continue;
        }

        short nextCost;
        if (unit->unitTypeC < 2) {
          nextCost = static_cast<short>(*moveCost + neighborMoveCostByDirection[direction]);
        } else {
          nextCost = static_cast<short>(*moveCost + 10);
        }
        if (nextCost <= actionPoints &&
            (moveCosts[neighborTile] == -1 || nextCost < moveCosts[neighborTile])) {
          moveCosts[neighborTile] = nextCost;
        }
      }
    }
  }
}

// FUNCTION: IMPERIALISM 0x005a5b70
void TNavyBattle::EndBattle(unsigned char) {
  g_pNavyOrderManager->CarryOutOrders();
}

// FUNCTION: IMPERIALISM 0x005a5b90
void TNavyBattle::SetTargeting(NavyTargeting targeting) {
  static_cast<TNavyPlayer*>(players[currentSide])->targetingMode = targeting;
}

// FUNCTION: IMPERIALISM 0x005a5bc0
void TNavyBattle::ExecuteTacticalActionAndQueueEventIfNoAdjacentValidTarget(
    TTacticalUnit* unit, TacticalTileIndex targetTileIndex) {
  EvaluateAndResolveTacticalActionAgainstTileOccupant(unit, targetTileIndex);
  if (battleOutcome == kTacticalBattleInProgress) {
    TacticalTileIndex neighborTiles[6];
    GetNeighborList(selectedUnit1c->tileIndex8, neighborTiles);
    int direction;
    for (direction = 0; direction < 6; ++direction) {
      TacticalTileIndex neighborTile = neighborTiles[direction];
      if (neighborTile != -1) {
        short moveCost = tileMoveCostArray[neighborTile];
        if (moveCost != -1 && moveCost <= selectedUnit1c->actionPoints28) {
          return;
        }
      }
    }
  }
  FinishTacticalActionAndPostNextMoveCommand();
}

// FUNCTION: IMPERIALISM 0x005a5c50
void TNavyBattle::MoveTacticalUnitAndQueueEvent232AIfNoAdjacentReachableTarget(
    TTacticalUnit* unit, TacticalTileIndex targetTileIndex) {
  MoveTacticalUnitTowardTile(unit, targetTileIndex);
  if (unit->selectedFlag == 0) {
    TacticalTileIndex neighborTiles[6];
    GetNeighborList(selectedUnit1c->tileIndex8, neighborTiles);
    int direction;
    for (direction = 0; direction < 6; ++direction) {
      TacticalTileIndex neighborTile = neighborTiles[direction];
      if (neighborTile != -1) {
        short moveCost = tileMoveCostArray[neighborTile];
        if (moveCost != -1 && moveCost <= selectedUnit1c->actionPoints28) {
          break;
        }
      }
    }
    if (direction == 6) {
      FinishTacticalActionAndPostNextMoveCommand();
      return;
    }
  }
  if (unit->state1c == 0 && battleOutcome == kTacticalBattleInProgress) {
    return;
  }
  FinishTacticalActionAndPostNextMoveCommand();
}
