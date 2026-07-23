#include "game/tactical/TNavyBattle.h"
#include "game/ui_tags_common.h"

#include "game/navy/TNavyMgr.h"
#include "game/tactical/TNavyPlayer.h"
#include "game/tactical/TNavyTacUnit.h"
#include "game/tactical/TTacticalBattleView.h"
#include "game/map/TTacticalPlayer.h"
#include "game/tactical_ui/TTacticalToolbar.h"
#include "game/tactical/TTacticalUnit.h"
#include "game/globals/prelude.h"
#include "game/globals/shared_globals.h"

#include <stdlib.h>
// SYNTHETIC: IMPERIALISM 0x005a5480
// TNavyBattle::CreateObject

// SYNTHETIC: IMPERIALISM 0x005a54d0
// TNavyBattle::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x005a5500
TNavyBattle::~TNavyBattle() {}

// SYNTHETIC: IMPERIALISM 0x005a5520
// TNavyBattle::GetRuntimeClass

IMPLEMENT_DYNCREATE(TNavyBattle, TTacticalBattle)

TNavyBattle::TNavyBattle() {}

// FUNCTION: IMPERIALISM 0x005a55c0
void TNavyBattle::DeployTacticalUnitToTile(TTacticalUnit* unit, TacticalTileIndex tileIndex) {
  // A ship may only deploy on its side's two deploy rows (side 0: rows
  // battlefieldColumnCount34-6..-5; side 1: rows 5..6 -- the field acts as a row
  // bound here) onto an empty tile. On success it places the ship, invalidates its
  // tile rect, advances the current side's selection, and once that side is fully
  // deployed flips the side, refreshes the 'tool' toolbar, and either finalizes
  // deployment or kicks the incoming side's StartBattle (the navy analogue of
  // HandleTacticalCommandTag_retr's tail).
  unsigned char sideIsZero = (unit->side20 == 0);
  unsigned char canDeploy = 1;
  int rowIndex = tileIndex / 29;
  if (sideIsZero != 0) {
    if (rowIndex < battlefieldColumnCount34 - 6) {
      canDeploy = 0;
    } else if (rowIndex > battlefieldColumnCount34 - 5) {
      canDeploy = 0;
    }
  } else {
    if (rowIndex > 6) {
      canDeploy = 0;
    } else if (rowIndex < 5) {
      canDeploy = 0;
    }
  }
  if (tileGrid4[tileIndex].occupant4 != 0) {
    canDeploy = 0;
  }
  if (canDeploy == 0) {
    return;
  }

  unit->tileIndex8 = tileIndex;
  tileGrid4[tileIndex].occupant4 = unit;
  if (battleView8 != 0) {
    battleView8->InvalidateTacticalUnitTileRect(unit);
  }

  selectedUnit1c = (&tacticalPlayer14)[currentSideC]->SelectNextTacticalUnitForDoneCommand();
  if ((&tacticalPlayer14)[currentSideC]->sideReadyFlag10 == 0) {
    return;
  }

  currentSideC = (currentSideC == 0);
  selectedUnit1c = (&tacticalPlayer14)[currentSideC]->SelectNextTacticalUnitForDoneCommand();

  if (battleView8 != 0) {
    TTacticalToolbar* toolbar = static_cast<TTacticalToolbar*>(
        battleView8->ownerContext->ResolveControlByTag(kControlTagTool));
    toolbar->AssertValid();
    toolbar->UpdateTacticalCurrentUnitControlAndDialogLabel(selectedUnit1c);
    toolbar->ForceRedraw();
  }

  if ((&tacticalPlayer14)[currentSideC]->sideReadyFlag10 != 0) {
    FinalizeTacticalTurnStateAndQueueEvent232A();
    return;
  }
  (&tacticalPlayer14)[currentSideC]->StartBattle();
}

// Resolves a naval gun action against the target tile's occupant: computes the hex
// distance to the attacker, derives a hit-chance threshold from the attacker's quality,
// range, and that distance, plays the muzzle-flash effect at the attacker's tile, then
// rolls against the threshold. On a hit, applies scaled damage via
// TNavyTacUnit::ApplyTacticalDamageAndDeathState (damage mode = the attacker side's
// ship-panel toggle), invalidates the defender's tile, and if destroyed clears it from
// the grid and plays the sinking effect; on a miss, plays the splash effect instead.
// FUNCTION: IMPERIALISM 0x005a5730
void TNavyBattle::EvaluateAndResolveTacticalActionAgainstTileOccupant(
    TTacticalUnit* attackerUnit, TacticalTileIndex targetTileIndex) {
  TNavyTacUnit* defenderUnit = static_cast<TNavyTacUnit*>(tileGrid4[targetTileIndex].occupant4);
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
    battleView8->PlayTacticalTileEffect(attackerUnit->tileIndex8, attackerUnit->unitTypeC + 0xf5a,
                                        1);
  }

  if (static_cast<float>(rand() % 100) < hitThreshold) {
    TTacticalPlayer* attackerSidePlayer = (&tacticalPlayer14)[currentSideC];
    attackerSidePlayer->AssertValid();
    int damageMode = static_cast<TNavyPlayer*>(attackerSidePlayer)->shipDisplayMode2c;
    float attackPower = attackerUnit->GetBaseAttackPower();
    float scaledStrength = attackerUnit->strength4 * attackPower;
    float damageScale = defenderUnit->GetDamageScale();
    float damageAmount = damageScale * scaledStrength;
    defenderUnit->ApplyTacticalDamageAndDeathState(damageAmount, damageMode);
    if (battleView8 != 0) {
      battleView8->InvalidateTacticalUnitTileRect(defenderUnit);
    }
    if (defenderUnit->state1c == 3) {
      tileGrid4[defenderUnit->tileIndex8].occupant4 = 0;
      defenderUnit->tileIndex8 = -1;
      if (battleView8 != 0) {
        battleView8->PlayTacticalTileEffect(targetTileIndex, 0xf42, 12);
      }
    }
  } else {
    if (battleView8 != 0) {
      battleView8->PlayTacticalTileEffect(targetTileIndex, 0xf3c, 6);
    }
  }

  attackerUnit->selectedFlag18 = 0;
  EvaluateTacticalSideStateAndShowBattleSummaryDialog();
}

// FUNCTION: IMPERIALISM 0x005a59a0
void __stdcall ConvertHexTileIndexToRowAndDoubleColumn(TacticalTileIndex tileIndex,
                                                       unsigned int* outRow, int* outCol2X) {
  *outRow = tileIndex / 0x1d;
  *outCol2X = (tileIndex / 0x1d & 1) + (tileIndex % 0x1d) * 2;
}

// FUNCTION: IMPERIALISM 0x005a59f0
void TNavyBattle::ComputeTacticalReachableTileCostsByUnitCategory(TTacticalUnit* unit) {
  int actionPoints = unit->actionPoints28;
  short* moveCosts = tileMoveCostArray24;
  TacticalTileIndex tileIndex;
  for (tileIndex = 0; tileIndex < tacticalTileCount3c; ++tileIndex) {
    moveCosts[tileIndex] = -1;
  }
  moveCosts[unit->tileIndex8] = 0;

  int costBand;
  for (costBand = 0; costBand <= actionPoints; costBand += 10) {
    short* moveCost = moveCosts;
    for (tileIndex = 0; tileIndex < tacticalTileCount3c; ++tileIndex, ++moveCost) {
      if (*moveCost < costBand) {
        continue;
      }

      TacticalTileIndex neighborTiles[6];
      GetNeighborList(tileIndex, neighborTiles);
      int direction;
      for (direction = 0; direction < 6; ++direction) {
        TacticalTileIndex neighborTile = neighborTiles[direction];
        if (neighborTile == -1 || tileGrid4[neighborTile].occupant4 != 0) {
          continue;
        }

        short nextCost;
        if (unit->unitTypeC < 2) {
          nextCost = static_cast<short>(*moveCost + neighborMoveCostByDirection7c[direction]);
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
void TNavyBattle::FinalizeTacticalBattleOutcome(int) {
  g_pNavyOrderManager->CarryOutOrders();
}

// FUNCTION: IMPERIALISM 0x005a5bc0
void TNavyBattle::ExecuteTacticalActionAndQueueEventIfNoAdjacentValidTarget(
    TTacticalUnit* unit, TacticalTileIndex targetTileIndex) {
  EvaluateAndResolveTacticalActionAgainstTileOccupant(unit, targetTileIndex);
  if (battleOutcomeCode44 == 0) {
    TacticalTileIndex neighborTiles[6];
    GetNeighborList(selectedUnit1c->tileIndex8, neighborTiles);
    int direction;
    for (direction = 0; direction < 6; ++direction) {
      TacticalTileIndex neighborTile = neighborTiles[direction];
      if (neighborTile != -1) {
        short moveCost = tileMoveCostArray24[neighborTile];
        if (moveCost != -1 && moveCost <= selectedUnit1c->actionPoints28) {
          return;
        }
      }
    }
  }
  QueueTacticalEventPacket232A();
}

// FUNCTION: IMPERIALISM 0x005a5c50
void TNavyBattle::MoveTacticalUnitAndQueueEvent232AIfNoAdjacentReachableTarget(
    TTacticalUnit* unit, TacticalTileIndex targetTileIndex) {
  MoveTacticalUnitTowardTile(unit, targetTileIndex);
  if (unit->selectedFlag18 == 0) {
    TacticalTileIndex neighborTiles[6];
    GetNeighborList(selectedUnit1c->tileIndex8, neighborTiles);
    int direction;
    for (direction = 0; direction < 6; ++direction) {
      TacticalTileIndex neighborTile = neighborTiles[direction];
      if (neighborTile != -1) {
        short moveCost = tileMoveCostArray24[neighborTile];
        if (moveCost != -1 && moveCost <= selectedUnit1c->actionPoints28) {
          break;
        }
      }
    }
    if (direction == 6) {
      QueueTacticalEventPacket232A();
      return;
    }
  }
  if (unit->state1c != 0 || battleOutcomeCode44 != 0) {
    QueueTacticalEventPacket232A();
  }
}
