#include "game/gfx/TAmbitApplication.h"
#include "game/ui_core/TDialogBehavior.h"
#include "game/ui_core/TWindow.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_military.h"
#include "game/tactical/TTacticalBattle.h"

#include <stdlib.h>

#include "game/ui_core/CIterator.h"
#include "game/core/CString.h"
#include "game/tactical/hex_tile_distance.h"
#include "game/assets/TAssetMgr.h"
#include "game/ui_core/TControl.h"
#include "game/city_ui/TCountry.h"
#include "game/ui_widgets/TDeluxeText.h"
#include "game/map/TMapMgr.h"
#include "game/ui_core/TPicture.h"
#include "game/ui_core/TStaticText.h"
#include "game/military/mapped_flavor_text.h"
#include "game/ui_core/quickdraw_rendering.h"
#include "game/tactical/TArmyTacUnit.h"
#include "game/TList.h"
#include "game/military/TMilitaryUnit.h"
#include "game/net/TMultiplayerMgr.h"
#include "game/ui_core/TApplication.h"
#include "game/tactical/TNextMoveCommand.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/ui_widgets/TSoundPlayer.h"
#include "game/tactical/TNavyPlayer.h"
#include "game/tactical/TTacticalBattleView.h"
#include "game/map/TTacticalPlayer.h"
#include "game/tactical_ui/TTacticalToolbar.h"
#include "game/ui_core/TViewMgr.h"
#include "game/globals/global_types.h"
#include "game/globals/map_globals.h"
#include "game/globals/net_globals.h"
#include "game/globals/tactical_globals.h"
#include "game/globals/shared_globals.h"
#include "game/ui_text_label_helpers_decls.h"

// Non-virtual action helpers dispatched above.

// Turn-order comparator (see the header note on the AX/short return).
// FUNCTION: IMPERIALISM 0x0059f610
short __cdecl CompareTacticalUnitsForTurnOrder(void* a, void* b, void* context) {
  TTacticalUnit* unitA = static_cast<TTacticalUnit*>(a);
  TTacticalUnit* unitB = static_cast<TTacticalUnit*>(b);
  unitA->AssertValid();
  unitB->AssertValid();
  if (unitA == unitB) {
    return 0;
  }
  int actionPointsA = unitA->GetBaseActionPoints();
  int actionPointsB = unitB->GetBaseActionPoints();
  if (actionPointsB < actionPointsA) {
    return -1;
  }
  if (actionPointsB > actionPointsA) {
    return 1;
  }
  if (unitB->qualityLevel < unitA->qualityLevel) {
    return -1;
  }
  if (unitB->qualityLevel > unitA->qualityLevel) {
    return 1;
  }
  return (unitA->field24 <= unitB->field24) ? 1 : -1;
}

// FUNCTION: IMPERIALISM 0x0059f710
void TTacticalBattle::DeployUnit(TTacticalUnit* unit, TacticalTileIndex tileIndex) {}

// FUNCTION: IMPERIALISM 0x0059f730
void TTacticalBattle::EndBattle(unsigned char) {
  battleOutcome = kTacticalBattleSide0Victory;
}

IMPLEMENT_DYNCREATE(TTacticalBattle, TObject)

// FUNCTION: IMPERIALISM 0x0059f770
TTacticalBattle::TTacticalBattle() {
  tileGrid = 0;
  battleView = 0;
  tileMoveCostArray = 0;
  selectedUnit = 0;
  battlefieldColumnCount = 0;
  roundCounter = 0;
  recordList = 0;
}

// FUNCTION: IMPERIALISM 0x0059f890
void TTacticalBattle::InitTacticalBattle(TTacticalPlayer* ourPlayer, TTacticalPlayer* enemyPlayer) {
  players[0] = ourPlayer;
  players[1] = enemyPlayer;
  ourPlayer->battle = this;
  enemyPlayer->battle = this;

  {
    CIterator ourIter(ourPlayer->unitList);
    for (TTacticalUnit* ourUnit = static_cast<TTacticalUnit*>(ourIter.Reset()); ourIter.More();
         ourUnit = static_cast<TTacticalUnit*>(ourIter.Advance())) {
      ourUnit->side = 0;
      ourUnit->field24 = static_cast<short>(rand());
      recordList->AddTail(ourUnit);
    }
  }
  {
    CIterator enemyIter(enemyPlayer->unitList);
    for (TTacticalUnit* enemyUnit = static_cast<TTacticalUnit*>(enemyIter.Reset());
         enemyIter.More(); enemyUnit = static_cast<TTacticalUnit*>(enemyIter.Advance())) {
      enemyUnit->side = 1;
      enemyUnit->field24 = static_cast<short>(rand());
      recordList->AddTail(enemyUnit);
    }
  }

  battleLive = 0;
  currentSide = 1;
  battleOutcome = kTacticalBattleInProgress;
  selectedUnit = enemyPlayer->GetNextUnit();

  int maxUnitRange = 0;
  {
    CIterator rangeIter(recordList);
    for (TTacticalUnit* rangeUnit = static_cast<TTacticalUnit*>(rangeIter.Reset());
         rangeIter.More(); rangeUnit = static_cast<TTacticalUnit*>(rangeIter.Advance())) {
      if (rangeUnit->GetUnitRange() > maxUnitRange) {
        maxUnitRange = rangeUnit->GetUnitRange();
      }
    }
  }
  battlefieldColumnCount = maxUnitRange + 11;

  tileMoveCostArray = new short[tacticalTileCount];
  for (int costIdx = 0; costIdx < tacticalTileCount; ++costIdx) {
    tileMoveCostArray[costIdx] = -1;
  }
  tileThreatLevelArray = new char[tacticalTileCount];
  for (int threatIdx = 0; threatIdx < tacticalTileCount; ++threatIdx) {
    tileThreatLevelArray[threatIdx] = 0;
  }
  tileCandidateScorePlane = new int[tacticalTileCount];
  for (int workIdxA = 0; workIdxA < tacticalTileCount; ++workIdxA) {
    tileCandidateScorePlane[workIdxA] = 0;
  }
  tileIntArray = new int[tacticalTileCount];
  for (int workIdxB = 0; workIdxB < tacticalTileCount; ++workIdxB) {
    tileIntArray[workIdxB] = 0;
  }

  if (tileGrid != 0) {
    delete[] tileGrid;
  }
  tileGrid = new TacticalTileRecord[tacticalTileCount];
  TacticalTileRecord* record = tileGrid;
  for (int tile = 0; tile < tacticalTileCount; ++tile, ++record) {
    record->terrainType = 0;
    record->occupant = 0;
    record->deployMark = 0;
    record->mineRunState = -1;
    record->trenchMask = 0;
  }

  g_pActiveTacticalBattle = this;
}

// FUNCTION: IMPERIALISM 0x0059fb50
void TTacticalBattle::Free() {
  if (tileMoveCostArray != 0) {
    delete[] tileMoveCostArray;
  }
  recordList->RemoveAll();
  if (recordList != 0) {
    recordList->Free();
  }
  if (players[0] != 0) {
    players[0]->Free();
  }
  if (players[1] != 0) {
    players[1]->Free();
  }
  if (tileGrid != 0) {
    delete[] tileGrid;
  }
  if (tileThreatLevelArray != 0) {
    delete[] tileThreatLevelArray;
  }
  if (tileCandidateScorePlane != 0) {
    delete[] tileCandidateScorePlane;
  }
  if (tileIntArray != 0) {
    delete[] tileIntArray;
  }
  g_pActiveTacticalBattle = 0;
  delete this;
}

// FUNCTION: IMPERIALISM 0x0059fc20
void TTacticalBattle::StartBattle() {
  players[1]->StartBattle();
}

// FUNCTION: IMPERIALISM 0x0059fcd0
void TTacticalBattle::BeginFighting() {
  if (!players[0]->sideReadyFlag) {
    players[0]->StartBattle();
  }
  if (!players[1]->sideReadyFlag) {
    players[1]->StartBattle();
  }
}

// FUNCTION: IMPERIALISM 0x0059fd10
void TTacticalBattle::HandleRetreatCommand() {
  currentSide = (currentSide == 0);
  selectedUnit = players[currentSide]->GetNextUnit();
  if (battleView != 0) {
    TTacticalToolbar* toolbar =
        static_cast<TTacticalToolbar*>(battleView->ownerContext->FindSubView(kControlTagTool));
    toolbar->AssertValid();
    toolbar->UpdateTacticalCurrentUnitControlAndDialogLabel(selectedUnit);
    toolbar->ForceRedraw();
  }
  TTacticalPlayer* incomingPlayer = players[currentSide];
  if (incomingPlayer->sideReadyFlag) {
    FinishedDeploying();
    return;
  }
  incomingPlayer->StartBattle();
}

// FUNCTION: IMPERIALISM 0x0059fdb0
void TTacticalBattle::FinishedDeploying() {
  players[0]->RemoveReserves();
  players[1]->RemoveReserves();
  recordList->SortBy(&CompareTacticalUnitsForTurnOrder, this);
  battleLive = 1;
  if (battleView != 0) {
    TTacticalToolbar* toolbar =
        static_cast<TTacticalToolbar*>(battleView->ownerContext->FindSubView(kControlTagTool));
    toolbar->AssertValid();
    toolbar->SetActionMode(1);
  }
  // TSortedList ordinals are 1-based, so GetEntryByOrdinal(GetCount()) is the tail.
  selectedUnit = static_cast<TTacticalUnit*>(recordList->GetEntryByOrdinal(recordList->GetCount()));
  FinishedMove();
}

// Selection/UI helpers dispatched by the tactical command family.

// FUNCTION: IMPERIALISM 0x0059fe40
void TTacticalBattle::ApplyTacticalDoneSelectionAndRefreshUi(TTacticalUnit* unit) {
  selectedUnit = unit;
  CalculateMoveMap(unit);
  if (battleView != 0) {
    TTacticalToolbar* toolbar =
        static_cast<TTacticalToolbar*>(battleView->ownerContext->FindSubView(kControlTagTool));
    toolbar->AssertValid();
    toolbar->UpdateTacticalCurrentUnitControlAndDialogLabel(selectedUnit);
    TacticalTileIndex tileIndex = unit->tileIndex;
    int row = tileIndex / 29;
    int column = ((row & 1) + tileIndex % 29 * 2) / 2;
    if (tileIndex >= 0 && row >= 0 && row < 15 && column >= 0 && column < battlefieldColumnCount) {
      battleView->MakeTileVisible(tileIndex);
    }
    battleView->RefreshControl();
    battleView->UpdateSelectionBlink();
  }
}

// FUNCTION: IMPERIALISM 0x0059ff20
void TTacticalBattle::CalculateMoveMap(TTacticalUnit* unit) {
  TacticalTileIndex neighborTiles[6];
  int categoryCode = g_awTacticalUnitCategoryCodeBySlot[unit->unitType];
  short* moveCosts = tileMoveCostArray;
  int actionPoints = unit->actionPoints;
  int fillIndex;
  for (fillIndex = 0; fillIndex < tacticalTileCount; ++fillIndex) {
    moveCosts[fillIndex] = -1;
  }
  TacticalTileIndex startTile = unit->tileIndex;
  if (startTile < 0 || startTile >= tacticalTileCount) {
    return;
  }
  int edgeColumn;
  if (unit->side == 0) {
    edgeColumn = battlefieldColumnCount - 1;
  } else {
    edgeColumn = 0;
  }
  moveCosts[startTile] = 0;
  int costLevel;
  for (costLevel = 0; costLevel <= actionPoints; costLevel += 10) {
    int column = 0;
    short* costCursor = moveCosts + tacticalTileStride;
    int tile;
    for (tile = tacticalTileStride; tile < tacticalTileCount; ++tile) {
      if (column < battlefieldColumnCount && column != edgeColumn && *costCursor >= costLevel) {
        GetNeighborList(tile, neighborTiles);
        int direction;
        TacticalTileIndex* neighborCursor = neighborTiles;
        for (direction = 0; direction < 6; ++direction, ++neighborCursor) {
          short neighborIndex = static_cast<short>(*neighborCursor);
          if (neighborIndex == -1) {
            continue;
          }
          TacticalTileRecord* record = &tileGrid[neighborIndex];
          if (record->occupant != 0) {
            continue;
          }
          if (neighborIndex < tacticalTileStride) {
            continue;
          }
          if (record->deployMark > 1 && fortStrengthPoints[neighborIndex / 0x1d / 2] > 0) {
            int wallRow = neighborIndex / 0x1d;
            int wallColumn = neighborIndex % 0x1d;
            if (wallRow != 5 && wallRow != 7 && wallRow != 9) {
              continue;
            }
            if (((wallRow & 1) + wallColumn * 2) / 2 != battlefieldColumnCount - 6) {
              continue;
            }
            if (unit->side != 1) {
              continue;
            }
          }
          short newCost = static_cast<short>(
              g_awTacticalMoveCostByCategoryAndTerrain[categoryCode * 5 + record->terrainType] +
              *costCursor);
          if (newCost > actionPoints) {
            continue;
          }
          short existingCost = moveCosts[neighborIndex];
          if (existingCost != -1 && existingCost <= newCost) {
            continue;
          }
          bool blockedByAdjacentEnemy = false;
          short prevDirection = static_cast<short>((direction > 0) ? direction - 1 : 5);
          int prevNeighbor = neighborTiles[prevDirection];
          if (prevNeighbor != -1) {
            TTacticalUnit* prevOccupant = tileGrid[prevNeighbor].occupant;
            if (prevOccupant != 0 && prevOccupant->side != unit->side) {
              blockedByAdjacentEnemy = true;
            }
          }
          // ORACLE: retail uses neighbor index 1 for directions 0..4 and 0 otherwise.
          short nextDirection = static_cast<short>((direction >= 5) ? 0 : 1);
          int nextNeighbor = neighborTiles[nextDirection];
          if (nextNeighbor != -1) {
            TTacticalUnit* nextOccupant = tileGrid[nextNeighbor].occupant;
            if (nextOccupant != 0 && nextOccupant->side != unit->side) {
              blockedByAdjacentEnemy = true;
            }
          }
          if (blockedByAdjacentEnemy) {
            continue;
          }
          if (neighborIndex % 0x1d == edgeColumn) {
            continue;
          }
          moveCosts[neighborIndex] = newCost;
        }
      }
      ++column;
      if (column == 0x1d) {
        column = 0;
      }
      ++costCursor;
    }
  }
  CalculateDangerMap(unit);
}

// FUNCTION: IMPERIALISM 0x005a02e0
void TTacticalBattle::CalculateDangerMap(TTacticalUnit* unit) {
  TacticalTileIndex neighborTiles[6];
  char unitSide = static_cast<char>(unit->side);
  char* threatLevels = tileThreatLevelArray;
  TacticalTileIndex seedTile;
  for (seedTile = 0; seedTile < tacticalTileCount; ++seedTile) {
    TTacticalUnit* occupant = tileGrid[seedTile].occupant;
    if (occupant != 0 && occupant->side != unitSide && occupant->state1c == 0) {
      occupant->AssertValid();
      threatLevels[seedTile] = static_cast<char>(occupant->GetUnitRange() + 1);
    } else {
      threatLevels[seedTile] = 0;
    }
  }
  int level;
  for (level = 0x13; level > 0; --level) {
    char* levelCursor = tileThreatLevelArray;
    int tile;
    for (tile = 0; tile < tacticalTileCount; ++tile, ++levelCursor) {
      if (*levelCursor == level) {
        GetNeighborList(tile, neighborTiles);
        int neighborSlot;
        TacticalTileIndex* neighborCursor = neighborTiles;
        for (neighborSlot = 0; neighborSlot < 6; ++neighborSlot, ++neighborCursor) {
          int neighborIndex = *neighborCursor;
          if (neighborIndex != -1) {
            if (threatLevels[neighborIndex] < level - 1) {
              threatLevels[neighborIndex] = static_cast<char>(level - 1);
            }
          }
        }
      }
    }
  }
}

// Whether either of the two neighbor tiles flanking hex direction `hexDirection`
// around `tileIndex` (direction+1 and direction-1, wrapping 0..5) is occupied by a
// unit of the other side. `side` is the friendly side code (0/1).

// FUNCTION: IMPERIALISM 0x005a0420
void TTacticalBattle::GetNeighborList(TacticalTileIndex tileIndex,
                                      TacticalTileIndex* outNeighborTiles6) {
  if ((tileIndex / tacticalTileStride) & 1) {
    outNeighborTiles6[0] = tileIndex - tacticalTileStride + 1;
    outNeighborTiles6[1] = tileIndex + 1;
    outNeighborTiles6[2] = tileIndex + tacticalTileStride + 1;
    outNeighborTiles6[3] = tileIndex + tacticalTileStride;
    outNeighborTiles6[4] = tileIndex - 1;
    outNeighborTiles6[5] = tileIndex - tacticalTileStride;
  } else {
    outNeighborTiles6[0] = tileIndex - tacticalTileStride;
    outNeighborTiles6[1] = tileIndex + 1;
    outNeighborTiles6[2] = tileIndex + tacticalTileStride;
    outNeighborTiles6[3] = tileIndex + tacticalTileStride - 1;
    outNeighborTiles6[4] = tileIndex - 1;
    outNeighborTiles6[5] = tileIndex - tacticalTileStride - 1;
  }
  if ((tileIndex + 1) % tacticalTileStride == 0) {
    // Right edge: no east neighbor; odd rows also lose both +1-column diagonals.
    outNeighborTiles6[1] = -1;
    if ((tileIndex / tacticalTileStride) & 1) {
      outNeighborTiles6[0] = -1;
      outNeighborTiles6[2] = -1;
    }
  } else if (tileIndex % tacticalTileStride == 0) {
    // Left edge: no west neighbor; even rows also lose both -1-column diagonals.
    outNeighborTiles6[4] = -1;
    if (!((tileIndex / tacticalTileStride) & 1)) {
      outNeighborTiles6[3] = -1;
      outNeighborTiles6[5] = -1;
    }
  }
  if (tileIndex >= tacticalTileCount - tacticalTileStride) {
    // Bottom row: no southern neighbors.
    outNeighborTiles6[2] = -1;
    outNeighborTiles6[3] = -1;
  } else if (tileIndex < tacticalTileStride) {
    // Top row: no northern neighbors.
    outNeighborTiles6[0] = -1;
    outNeighborTiles6[5] = -1;
  }
}

// FUNCTION: IMPERIALISM 0x005a0550
bool TTacticalBattle::AreNeighbors(TacticalTileIndex tileIndex,
                                   TacticalTileIndex candidateTileIndex) {
  TacticalTileIndex neighbors[6];
  GetNeighborList(tileIndex, neighbors);
  int direction;
  for (direction = 0; direction < 6; ++direction) {
    if (neighbors[direction] == candidateTileIndex) {
      return true;
    }
  }
  return false;
}

// FUNCTION: IMPERIALISM 0x005a05a0
int TTacticalBattle::GetTileCursor(TacticalTileIndex tileIndex) {
  TTacticalPlayer* currentSidePlayer = players[currentSide];
  if (!currentSidePlayer->IsPlayer()) {
    return 1;
  }

  if (battleLive == 0) {
    TacticalTileRecord* tile = &tileGrid[tileIndex];
    TTacticalUnit* occupant = tile->occupant;
    if (occupant != 0 && occupant->side == currentSide) {
      return 0xc;
    }

    int column = tileIndex % 0x1d;
    if (tileIndex >= 0x1d && tile->terrainType != 4 && occupant == 0) {
      if (currentSide == 0) {
        if (column > 2 && column < 6) {
          return 3;
        }
      } else if (column <= battlefieldColumnCount - 3 && column >= battlefieldColumnCount - 5) {
        return 3;
      }
    }
    return 2;
  }

  short unitCategoryCode0 = g_awTacticalUnitCategoryCodeBySlot[selectedUnit->unitType];
  int state = 0;

  if (unitCategoryCode0 == 8) {
    TacticalTileIndex neighbors[6];
    GetNeighborList(selectedUnit->tileIndex, neighbors);
    bool tileIsNeighbor = false;
    for (int i = 0; i < 6; ++i) {
      if (neighbors[i] == tileIndex) {
        tileIsNeighbor = true;
        break;
      }
    }
    if (tileIsNeighbor) {
      TacticalTileRecord* tile = &tileGrid[tileIndex];
      if (tile->deployMark > 1 && fortStrengthPoints[tileIndex / 58] > 0) {
        state = 9;
      } else if (selectedUnit->actionPoints >=
                     g_awUnitTypeBaseActionPointTable[selectedUnit->unitType] / 2 &&
                 (tile->trenchMask & 0x40) == 0 &&
                 (tileGrid[selectedUnit->tileIndex].trenchMask & 0x40) == 0 &&
                 (tile->trenchMask & 0x80) == 0 && tile->occupant == 0 && tile->terrainType != 4) {
        state = 7;
      }
    }
  } else if (unitCategoryCode0 == 9) {
    TacticalTileIndex neighbors[6];
    GetNeighborList(selectedUnit->tileIndex, neighbors);
    bool tileIsNeighbor = false;
    for (int i = 0; i < 6; ++i) {
      if (neighbors[i] == tileIndex) {
        tileIsNeighbor = true;
        break;
      }
    }
    if (tileIsNeighbor) {
      TTacticalUnit* occupant = tileGrid[tileIndex].occupant;
      if (occupant != 0 && occupant->side == selectedUnit->side) {
        state = 8;
      }
    }
  }

  if (state == 0) {
    TacticalTileRecord* tile = &tileGrid[tileIndex];
    if (tile->deployMark > 1 && fortStrengthPoints[tileIndex / 58] > 0) {
      short unitCategoryCode = g_awTacticalUnitCategoryCodeBySlot[selectedUnit->unitType];
      if (g_afTacticalDirectFireFlagByCategory[unitCategoryCode] ==
          g_fTacticalRetreatQualityWeightDefault) {
        char reachable =
            !selectedUnit->selectedFlag
                ? 0
                : IsTacticalTargetTileReachableForAction(
                      selectedUnit->tileIndex, tileIndex,
                      static_cast<char>(g_afTacticalDirectFireFlagByCategory[unitCategoryCode]),
                      selectedUnit->GetUnitRange());
        if (reachable != 0) {
          return 5;
        }
      }
      if (tileMoveCostArray[tileIndex] > 0 && tile->occupant == 0) {
        return 4;
      }
    } else {
      if (tileMoveCostArray[tileIndex] > 0 && tile->occupant == 0) {
        return 4;
      }
      TTacticalUnit* occupant = tile->occupant;
      if (occupant != 0 && occupant->side != currentSide && unitCategoryCode0 != 8) {
        char reachable =
            !selectedUnit->selectedFlag
                ? 0
                : IsTacticalTargetTileReachableForAction(
                      selectedUnit->tileIndex, tileIndex,
                      static_cast<char>(
                          g_afTacticalDirectFireFlagByCategory
                              [g_awTacticalUnitCategoryCodeBySlot[selectedUnit->unitType]]),
                      selectedUnit->GetUnitRange());
        if (reachable != 0) {
          TacticalTileIndex neighbors[6];
          GetNeighborList(selectedUnit->tileIndex, neighbors);
          bool tileIsNeighbor = false;
          for (int i = 0; i < 6; ++i) {
            if (neighbors[i] == tileIndex) {
              tileIsNeighbor = true;
              break;
            }
          }
          return tileIsNeighbor ? 0xa : 5;
        }
      } else if (occupant == selectedUnit) {
        return 6;
      }
    }
  }
  return state;
}

// FUNCTION: IMPERIALISM 0x005a0a90
short TTacticalBattle::ResolveTacticalHoverCursorResourceId(TacticalTileIndex tileIndex) {
  short cursorsByHoverState[13] = {0,     0x402, 0x3f0, 0x3ec, 0x3ed, 0x3fc, 0x3f0,
                                   0x3ff, 0x41d, 0x3fe, 0x3fd, 0x403, 0x41c};
  int hoverState = GetTileCursor(tileIndex);
  TTacticalPlayer* player = players[currentSide];
  if (player->notWatchedFlag) {
    return 0x402;
  }

  if (selectedUnit != 0 && hoverState == 0) {
    TacticalTileRecord* tile = &tileGrid[tileIndex];
    TTacticalUnit* occupant = tile->occupant;
    short category = g_awTacticalUnitCategoryCodeBySlot[selectedUnit->unitType];
    bool enemyTarget = occupant != 0 && occupant->side != currentSide;
    bool intactFortSection =
        g_afTacticalDirectFireFlagByCategory[category] == g_fTacticalRetreatQualityWeightDefault &&
        tile->deployMark > 1 && fortStrengthPoints[tileIndex / 58] > 0 && selectedUnit->side == 0;
    if (enemyTarget || intactFortSection) {
      char directFire = static_cast<char>(g_afTacticalDirectFireFlagByCategory[category]);
      return IsTacticalTargetTileReachableForAction(selectedUnit->tileIndex, tileIndex, directFire,
                                                    selectedUnit->GetUnitRange())
                 ? 0x403
                 : 0x400;
    }
  }
  return cursorsByHoverState[hoverState];
}

// FUNCTION: IMPERIALISM 0x005a0c50
void TTacticalBattle::HandleTacticalBattleCommandTag(int commandTag) {
  TTacticalPlayer* player = players[currentSide];
  if (player->watchFlag == 0) {
    return;
  }
  switch (commandTag) {
  case kControlTagDone: // 'done'
    if (battleLive == 1) {
      FinishedMove();
      return;
    }
    ApplyTacticalDoneSelectionAndRefreshUi(player->GetNextUnit());
    return;
  case kControlTagAuto: // 'auto'
    player->ProceedAfterBattleIntroAccepted();
    return;
  case kControlTagRetr: // 'retr'
    if (battleLive == 0) {
      HandleRetreatCommand();
      return;
    }
    if (g_pViewMgr->ShowLocalizedUiPromptByGroupAndIndex(0x273d, 0x32, 1, 1)) {
      player = players[currentSide];
      player->retreatOrdered = true;
      player->ProceedAfterBattleIntroAccepted();
    }
    return;
  case kControlTagSkip: // 'skip'
    player->HandleSkipCommand();
    return;
  case kControlTagTarg: // 'targ'
    CycleTarget();
    return;
  }
}

// FUNCTION: IMPERIALISM 0x005a0d60
void TTacticalBattle::FinishedMove() {
  pendingEndOfActionFlag = false;
  TNextMoveCommand* command = new TNextMoveCommand();
  command->ICommand(0x232a, g_pAmbitApplication, 0, 0, 0);
  command->battle = this;
  g_pAmbitApplication->DispatchUiSelectionToHandler(command);
}

// FUNCTION: IMPERIALISM 0x005a0e20
void TTacticalBattle::NextMove() {
  if (battleOutcome != kTacticalBattleInProgress) {
    bool sideWonFlag = battleOutcome == kTacticalBattleSide0Victory;
    players[0]->ApplyChanges(sideWonFlag);
    players[1]->ApplyChanges(!sideWonFlag);
    EndBattle(sideWonFlag);
    return;
  }
  pendingEndOfActionFlag = true;
  Cycle();
}

// FUNCTION: IMPERIALISM 0x005a0ea0
void TTacticalBattle::Cycle() {
  int position;
  if (selectedUnit == 0) {
    position = 1;
  } else {
    position = 1;
    CIterator cursor(recordList);
    for (TTacticalUnit* unit = static_cast<TTacticalUnit*>(cursor.Reset()); cursor.More();
         unit = static_cast<TTacticalUnit*>(cursor.Advance())) {
      unit->AssertValid();
      if (unit == selectedUnit) {
        break;
      }
      ++position;
    }
  }

  TTacticalUnit* candidateUnit;
  for (;;) {
    int totalCount = recordList->GetCount();
    if (position == totalCount) {
      ++roundCounter;
      if (roundCounter >= 0x23) {
        CheckForVictory();
        FinishedMove();
        return;
      }
      position = 1;
    } else {
      ++position;
    }
    candidateUnit = static_cast<TTacticalUnit*>(recordList->GetEntryByOrdinal(position));
    candidateUnit->AssertValid();
    if (candidateUnit->state1c != 3) {
      break;
    }
  }

  candidateUnit->AssertValid();
  LaSelect(candidateUnit, false);
  if (candidateUnit->state1c == 1) {
    ProcessTacticalUnitState1TurnStep(candidateUnit);
    return;
  }
  if (g_awTacticalUnitCategoryCodeBySlot[candidateUnit->unitType] == 8 &&
      static_cast<TArmyTacUnit*>(candidateUnit)->sapTargetTileIndex != -1) {
    ContinueDig(static_cast<TArmyTacUnit*>(candidateUnit));
    return;
  }
  players[currentSide]->NextMove();
}

// Tactical command family: each handler echoes the command to multiplayer when it
// originates locally (remoteFlag == 0), then applies it to the battle state. The
// 0x545940 turn-event dispatcher re-enters these with remoteFlag = 1.

// FUNCTION: IMPERIALISM 0x005a1010
void TTacticalBattle::LaSelect(TTacticalUnit* unit, bool remoteFlag) {
  if (!remoteFlag) {
    bool multiplayerActive = g_pSimMgr->multiplayerSessionRole != kSessionRoleStandalone;
    if (multiplayerActive) {
      g_pGameFlowState->SendTacLa(kControlTagSele, unit, 0, 0);
    }
  }
  if (unit->side != currentSide) {
    currentSide = currentSide == 0;
  }
  if (battleView != 0) {
    battleView->SetCurrentPlayer(static_cast<unsigned char>(unit->side));
  }
  if (battleView != 0) {
    battleView->InvalidateUnit(selectedUnit);
  }
  if (battleView != 0) {
    battleView->InvalidateUnit(unit);
  }
  unit->actionPoints = unit->GetBaseActionPoints();
  unit->selectedFlag = true;
  ApplyTacticalDoneSelectionAndRefreshUi(unit);
}

// FUNCTION: IMPERIALISM 0x005a10e0
void TTacticalBattle::ProcessTacticalUnitState1TurnStep(TTacticalUnit* unit) {
  int bestDistance = 999;
  TacticalTileIndex originalTile = unit->tileIndex;
  MakeRetreatMap(unit->side == 0);

  TacticalTileIndex bestTile = originalTile;
  for (int i = 0; i < tacticalTileCount; ++i) {
    if (tileMoveCostArray[i] != -1 && tileIntArray[i] != -1 &&
        (tileIntArray[i] < bestDistance ||
         (tileIntArray[i] == bestDistance && (rand() & 1) != 0))) {
      bestDistance = tileIntArray[i];
      bestTile = i;
    }
  }
  if (bestTile != unit->tileIndex) {
    MoveTacticalUnitTowardTile(unit, bestTile);
  }

  if (unit->state1c == 1) {
    TList* sideUnitList = (unit->side == 0) ? players[1]->unitList : players[0]->unitList;

    int nearbyThreshold = 0;
    CIterator cursor(sideUnitList);
    for (TTacticalUnit* candidate = static_cast<TTacticalUnit*>(cursor.Reset()); cursor.More();
         candidate = static_cast<TTacticalUnit*>(cursor.Advance())) {
      if (candidate->state1c != 0) {
        continue;
      }
      int distance = ComputeHexTileDistanceFromIndices(unit->tileIndex, candidate->tileIndex);
      if (distance < 3) {
        nearbyThreshold = static_cast<int>(candidate->GetBaseAttackPower() * candidate->strength +
                                           nearbyThreshold);
      }
    }

    int ownThreshold = static_cast<int>(unit->GetBaseAttackPower() * (unit->strength * 3));
    if (nearbyThreshold > ownThreshold) {
      nearbyThreshold = ownThreshold;
    }

    bool shouldDestroy = true;
    if (unit->tileIndex != originalTile) {
      shouldDestroy = false;
      if (nearbyThreshold > 0) {
        int remainder = rand() % nearbyThreshold;
        if (unit->GetBaseAttackPower() * unit->strength < static_cast<float>(remainder)) {
          shouldDestroy = true;
        }
      }
    }

    if (shouldDestroy) {
      if (battleView != 0) {
        battleView->PlayAni(unit->tileIndex, 0xf8c, 10);
      }
      unit->ApplyDamage(unit->strength, 0);
      tileGrid[unit->tileIndex].occupant = 0;
      unit->tileIndex = -1;
      if (battleView != 0) {
        battleView->InvalidateUnit(unit);
      }
    }
  }
  CheckForVictory();
  FinishedMove();
}

// FUNCTION: IMPERIALISM 0x005a1400
bool TTacticalBattle::InZOC(TacticalTileIndex tileIndex, TacticalHexDirection hexDirection,
                            char side) {
  TacticalTileIndex neighborTiles[6];
  bool foundEnemy = false;
  GetNeighborList(tileIndex, neighborTiles);
  int clockwiseDirection = (hexDirection == kTacticalHexDirectionNorthWest)
                               ? kTacticalHexDirectionNorthEast
                               : hexDirection + 1;
  int counterDirection = (hexDirection == kTacticalHexDirectionNorthEast)
                             ? kTacticalHexDirectionNorthWest
                             : hexDirection - 1;
  TacticalTileIndex clockwiseTile = neighborTiles[clockwiseDirection];
  if (clockwiseTile != -1) {
    TTacticalUnit* clockwiseOccupant = tileGrid[clockwiseTile].occupant;
    if (clockwiseOccupant != 0 && clockwiseOccupant->side != side) {
      foundEnemy = true;
    }
  }
  if (!foundEnemy) {
    TacticalTileIndex counterTile = neighborTiles[counterDirection];
    if (counterTile != -1) {
      TTacticalUnit* counterOccupant = tileGrid[counterTile].occupant;
      if (counterOccupant != 0 && counterOccupant->side != side) {
        foundEnemy = true;
      }
    }
  }
  return foundEnemy;
}

// FUNCTION: IMPERIALISM 0x005a14d0
void TTacticalBattle::UndeployUnit(TacticalTileIndex tileIndex) {
  TTacticalUnit* unit = tileGrid[tileIndex].occupant;
  if (battleView != 0) {
    battleView->InvalidateUnit(unit);
  }
  unit->tileIndex = -2;
  tileGrid[tileIndex].occupant = 0;
}

IMPERIALISM_BEGIN_RETAIL_UNINITIALIZED_READ
// FUNCTION: IMPERIALISM 0x005a1520
void TTacticalBattle::MoveTacticalUnitTowardTile(TTacticalUnit* unit,
                                                 TacticalTileIndex targetTileIndex) {
  TacticalTileIndex pathTiles[12];
  pathTiles[0] = targetTileIndex;
  int stepCount = SeekPath(targetTileIndex, 0, unit->tileIndex, pathTiles);
  if (stepCount == -1) {
    return;
  }

  // pathTiles[stepCount] is the unit's own tile; walk down to pathTiles[0] = target.
  bool stopped = 0;
  if (stepCount != 0) {
    int* pathCursor = &pathTiles[stepCount];
    do {
      if (stopped != 0) {
        break;
      }
      unit->AssertValid();
      LaMove(unit, pathCursor[0], pathCursor[-1], false);
      --pathCursor;
      --stepCount;
      stopped = CheckOpportunityFire(*pathCursor);
    } while (stepCount != 0);
  }

  unit->actionPoints -= tileMoveCostArray[pathTiles[stepCount]];
  if (battleView != 0) {
    battleView->InvalidateUnit(unit);
  }
  if (battleView != 0) {
    battleView->ForceRedraw();
  }

  // Logical column on the doubled-x hex grid (odd rows are staggered half a tile).
  TacticalTileIndex arrivedTile = pathTiles[stepCount];
  int exitColumn = (((arrivedTile / 29) & 1) + 2 * (arrivedTile % 29)) / 2;
  int side = unit->side;
  if ((side == 1 && exitColumn >= battlefieldColumnCount - 1) || (side == 0 && exitColumn == 0)) {
    bool unitMayLeave;
    if (unit->state1c == 1) {
      unitMayLeave = 1;
    } else if (battleView != 0) {
      TTacticalPlayer* sidePlayer = (side == 0) ? players[0] : players[1];
      unitMayLeave = sidePlayer->AlwaysTrueTacticalPredicate10(unit);
    }
    if (unitMayLeave != 0) {
      TacticalTileIndex exitTile = pathTiles[stepCount];
      unit->state1c = 2;
      unit->tileIndex = -2;
      tileGrid[exitTile].occupant = 0;
      CheckForVictory();
    }
  }

  CalculateMoveMap(unit);
  if (battleView != 0) {
    battleView->RefreshControl();
  }
}
IMPERIALISM_END_RETAIL_UNINITIALIZED_READ

// FUNCTION: IMPERIALISM 0x005a16e0
int TTacticalBattle::SeekPath(TacticalTileIndex walkTileIndex, int pathDepth,
                              TacticalTileIndex goalTileIndex, TacticalTileIndex* outPathTiles) {
  if (walkTileIndex == goalTileIndex) {
    outPathTiles[pathDepth] = walkTileIndex;
    return pathDepth;
  }
  TacticalTileIndex candidateTiles[6];
  TacticalTileIndex neighborTiles[6];
  int candidateCount = 0;
  int walkCost = tileMoveCostArray[walkTileIndex];
  GetNeighborList(walkTileIndex, neighborTiles);
  TacticalTileIndex* neighborCursor = neighborTiles;
  int* candidateCursor = candidateTiles;
  for (int remainingDirections = 0; remainingDirections < 6; ++remainingDirections) {
    TacticalTileIndex neighborTile = *neighborCursor;
    int neighborCost = tileMoveCostArray[neighborTile];
    if (neighborCost != -1 && neighborCost < walkCost) {
      *candidateCursor = neighborTile;
      ++candidateCount;
      ++candidateCursor;
    }
    ++neighborCursor;
  }
  if (candidateCount == 0) {
    return -1;
  }
  if (candidateCount > 1) {
    int* curSlot = candidateTiles;
    for (int outerRemaining = candidateCount - 1; outerRemaining > 0; --outerRemaining) {
      int* nextSlot = &candidateTiles[1];
      for (int innerRemaining = candidateCount - 1; innerRemaining > 0; --innerRemaining) {
        TacticalTileIndex nextTile = *nextSlot;
        TacticalTileIndex curTile = *curSlot;
        bool swapFlag = tileMoveCostArray[nextTile] < tileMoveCostArray[curTile];
        if (!swapFlag && tileMoveCostArray[nextTile] == tileMoveCostArray[curTile]) {
          char nextThreat = tileThreatLevelArray[nextTile];
          char curThreat = tileThreatLevelArray[curTile];
          if (nextThreat == 0) {
            if (curThreat != 0) {
              swapFlag = true;
            } else {
              swapFlag = (rand() & 1) != 0;
            }
          } else if (curThreat != 0) {
            swapFlag = (rand() & 1) != 0;
          }
        }
        if (swapFlag) {
          *curSlot = nextTile;
          *nextSlot = curTile;
        }
        ++nextSlot;
      }
      ++curSlot;
    }
  }
  if (candidateCount > 0) {
    int candidateSlot = 0;
    int* walkCursor = candidateTiles;
    while (candidateSlot < candidateCount) {
      int foundDepth = SeekPath(*walkCursor, pathDepth + 1, goalTileIndex, outPathTiles);
      if (foundDepth != -1) {
        outPathTiles[pathDepth] = walkTileIndex;
        return foundDepth;
      }
      ++candidateSlot;
      ++walkCursor;
    }
  }
  return -1;
}

// FUNCTION: IMPERIALISM 0x005a1910
void TTacticalBattle::LaMove(TTacticalUnit* unit, TacticalTileIndex fromTileIndex,
                             TacticalTileIndex toTileIndex, bool remoteFlag) {
  if (!remoteFlag) {
    bool multiplayerActive = g_pSimMgr->multiplayerSessionRole != kSessionRoleStandalone;
    if (multiplayerActive) {
      g_pGameFlowState->SendTacLa(kControlTagMove, unit, fromTileIndex, toTileIndex);
    }
  }
  if (battleView != 0) {
    battleView->InvalidateUnit(unit);
  }
  tileGrid[fromTileIndex].occupant = 0;
  if (battleView != 0) {
    battleView->KillSelectionBlink();
  }
  if (currentTacticalActionCode != 7) {
    if (battleView != 0) {
      battleView->GlideUnit(unit, fromTileIndex, toTileIndex);
    }
  }
  unit->tileIndex = toTileIndex;
  tileGrid[toTileIndex].occupant = unit;
  if (battleView != 0) {
    battleView->InvalidateUnit(unit);
  }
  if (battleView != 0) {
    battleView->InvalidateTile(toTileIndex);
  }
  if (battleView != 0) {
    battleView->UpdateSelectionBlink();
  }
}

// FUNCTION: IMPERIALISM 0x005a1a20
bool TTacticalBattle::CheckOpportunityFire(TacticalTileIndex tileIndex) {
  bool reactionFired = false;
  TTacticalUnit* occupant = tileGrid[tileIndex].occupant;
  TTacticalPlayer* reactingPlayer = (occupant->side == 0) ? players[1] : players[0];
  CIterator reactorIter(reactingPlayer->unitList);
  TTacticalUnit* reactor = static_cast<TTacticalUnit*>(reactorIter.Reset());
  // The original asserts the first record once before entering the loop.
  reactor->AssertValid();
  do {
    reactor->AssertValid();
    if (reactor->state1c == 0 && reactor->selectedFlag) {
      TacticalTileIndex reactorTileIndex = reactor->tileIndex;
      short categoryCode = g_awTacticalUnitCategoryCodeBySlot[reactor->unitType];
      if (IsTacticalTargetTileReachableForAction(
              reactorTileIndex, tileIndex,
              static_cast<char>(g_afTacticalDirectFireFlagByCategory[categoryCode]),
              reactor->GetUnitRange()) != 0) {
        FireOn(reactor, tileIndex);
        if (battleView != 0) {
          battleView->InvalidateUnit(reactor);
        }
        reactionFired = true;
      }
    }
    if (reactorIter.More()) {
      reactor = static_cast<TTacticalUnit*>(reactorIter.Advance());
    } else {
      reactor = 0;
    }
  } while (reactor != 0 && occupant->strength != 0);
  return reactionFired;
}

// FUNCTION: IMPERIALISM 0x005a1b50
bool TTacticalBattle::ValidMove() {
  TacticalTileIndex neighborTiles[6];
  GetNeighborList(selectedUnit->tileIndex, neighborTiles);
  for (int direction = 0; direction < 6; ++direction) {
    TacticalTileIndex neighborTile = neighborTiles[direction];
    if (neighborTile != -1) {
      short moveCost = tileMoveCostArray[neighborTile];
      if (moveCost != -1 && moveCost <= selectedUnit->actionPoints) {
        return true;
      }
    }
  }
  return false;
}

// FUNCTION: IMPERIALISM 0x005a1bd0
void TTacticalBattle::MoveAndCycle(TTacticalUnit* unit, TacticalTileIndex targetTileIndex) {
  MoveTacticalUnitTowardTile(unit, targetTileIndex);
  if (g_awTacticalUnitCategoryCodeBySlot[unit->unitType] == 7) {
    unit->selectedFlag = false;
  }
  if (unit->state1c == 0 && battleOutcome == kTacticalBattleInProgress) {
    if (unit->selectedFlag) {
      if (ValidTargets()) {
        return;
      }
    }
    TacticalTileIndex neighborTiles[6];
    GetNeighborList(selectedUnit->tileIndex, neighborTiles);
    int direction = 0;
    TacticalTileIndex* neighborCursor = neighborTiles;
    for (; direction < 6; ++direction, ++neighborCursor) {
      TacticalTileIndex neighborTile = *neighborCursor;
      if (neighborTile != -1) {
        short moveCost = tileMoveCostArray[neighborTile];
        if (moveCost != -1 && moveCost <= selectedUnit->actionPoints) {
          return; // the selected unit can still reach an adjacent tile
        }
      }
    }
  }
  FinishedMove();
}

// FUNCTION: IMPERIALISM 0x005a1ca0
void TTacticalBattle::FireAndCycle(TTacticalUnit* unit, TacticalTileIndex targetTileIndex) {
  FireOn(unit, targetTileIndex);
  short categoryCode = g_awTacticalUnitCategoryCodeBySlot[unit->unitType];
  if (categoryCode == 4 || categoryCode == 5) {
    TacticalTileIndex neighborTiles[6];
    GetNeighborList(selectedUnit->tileIndex, neighborTiles);
    int direction = 0;
    TacticalTileIndex* neighborCursor = neighborTiles;
    for (; direction < 6; ++direction, ++neighborCursor) {
      TacticalTileIndex neighborTile = *neighborCursor;
      if (neighborTile != -1) {
        short moveCost = tileMoveCostArray[neighborTile];
        if (moveCost != -1 && moveCost <= selectedUnit->actionPoints) {
          if (battleOutcome != kTacticalBattleInProgress) {
            FinishedMove();
          }
          return;
        }
      }
    }
    FinishedMove();
    return;
  }
  FinishedMove();
}

// FUNCTION: IMPERIALISM 0x005a1d70
bool TTacticalBattle::ValidTargets() {
  TTacticalUnit* selectedUnit = this->selectedUnit;
  short categoryCode = g_awTacticalUnitCategoryCodeBySlot[selectedUnit->unitType];
  if (categoryCode == 9) {
    TacticalTileIndex neighborTiles[6];
    GetNeighborList(selectedUnit->tileIndex, neighborTiles);
    int direction = 0;
    TacticalTileIndex* neighborCursor = neighborTiles;
    for (; direction < 6; ++direction, ++neighborCursor) {
      TacticalTileIndex neighborTile = *neighborCursor;
      if (neighborTile != -1) {
        TTacticalUnit* occupant = tileGrid[neighborTile].occupant;
        if (occupant != 0 && occupant->side == this->selectedUnit->side) {
          return true;
        }
      }
    }
    return false;
  }
  if (categoryCode == 8) {
    return false;
  }
  TTacticalPlayer* opposingPlayer = (selectedUnit->side == 0) ? players[1] : players[0];
  CIterator enemyIter(opposingPlayer->unitList);
  for (TTacticalUnit* enemyUnit = static_cast<TTacticalUnit*>(enemyIter.Reset()); enemyIter.More();
       enemyUnit = static_cast<TTacticalUnit*>(enemyIter.Advance())) {
    TacticalTileIndex enemyTile = enemyUnit->tileIndex;
    if (enemyTile >= 0) {
      unsigned char targetReachable;
      if (this->selectedUnit->selectedFlag) {
        short attackerCategory = g_awTacticalUnitCategoryCodeBySlot[this->selectedUnit->unitType];
        targetReachable = IsTacticalTargetTileReachableForAction(
            this->selectedUnit->tileIndex, enemyTile,
            static_cast<char>(g_afTacticalDirectFireFlagByCategory[attackerCategory]),
            this->selectedUnit->GetUnitRange());
      } else {
        targetReachable = 0;
      }
      if (targetReachable != 0) {
        return true;
      }
    }
  }
  return false;
}

// FUNCTION: IMPERIALISM 0x005a1ee0
void TTacticalBattle::FireOn(TTacticalUnit* attackerUnit, TacticalTileIndex targetTileIndex) {
  TTacticalUnit* defenderUnit = tileGrid[targetTileIndex].occupant;
  if (defenderUnit != 0) {
    defenderUnit->AssertValid();
  }

  bool fortWallTargeted;
  if (tileGrid[targetTileIndex].deployMark > 1 &&
      fortStrengthPoints[targetTileIndex / 29 / 2] > 0 && defenderUnit == 0) {
    fortWallTargeted = true;
  } else {
    fortWallTargeted = false;
  }

  int fortWallTileOnLine =
      FindFortWallTileCrossedByFiringLine(targetTileIndex, attackerUnit->tileIndex);

  bool meleeAdjacent = false;
  {
    TacticalTileIndex neighborTiles[6];
    GetNeighborList(attackerUnit->tileIndex, neighborTiles);
    int direction = 0;
    TacticalTileIndex* neighborCursor = neighborTiles;
    for (; direction < 6; ++direction, ++neighborCursor) {
      if (*neighborCursor == targetTileIndex) {
        meleeAdjacent = true;
        break;
      }
    }
  }
  if (fortWallTileOnLine != 0 && tileGrid[fortWallTileOnLine].deployMark > 1 &&
      fortStrengthPoints[fortWallTileOnLine / 29 / 2] > 0) {
    meleeAdjacent = false; // an intact wall section between the tiles blocks melee contact
  }

  short attackerCategory;
  float attackPower;
  {
    double strengthFactor = 1.0 - attackerUnit->qualityLevel * -0.1; // = 1 + 0.1*quality
    strengthFactor *= g_afTacticalBaseAttackPowerByUnitType[attackerUnit->unitType];
    if (meleeAdjacent) {
      strengthFactor = strengthFactor *
                       g_afTacticalMeleeMultiplierByCategory
                           [g_awTacticalUnitCategoryCodeBySlot[attackerUnit->unitType]];
    }
    attackerCategory = g_awTacticalUnitCategoryCodeBySlot[attackerUnit->unitType];
    attackPower =
        (float)(attackerUnit->strength * strengthFactor *
                g_afTacticalAttackTerrainModifierByCategory
                    [attackerCategory * 5 + tileGrid[attackerUnit->tileIndex].terrainType]);
  }

  if (fortWallTargeted) {
    // Wall attack: erode the wall's strength pool and play the hit effect.
    DamageFort(fortWallTileOnLine, (int)(0.001f * attackPower));
    if (battleView != 0) {
      battleView->MakeTileVisible(targetTileIndex);
      g_pSfxPlaybackSystem->PlaySoundEffect(
          g_awTacticalFireSfxTokenByUnitType[attackerUnit->unitType], 0, 1);
      RECT effectRect;
      battleView->Tile2Rect(&effectRect, targetTileIndex);
      effectRect.top -= 0x14;
      battleView->PlayAni(&effectRect, 0xf98, 6, targetTileIndex, 2);
    }
    return;
  }

  short defenderCategory = g_awTacticalUnitCategoryCodeBySlot[defenderUnit->unitType];
  float damage =
      g_afTacticalDefenseTerrainModifierByCategory[defenderCategory * 5 +
                                                   tileGrid[targetTileIndex].terrainType] *
      g_afTacticalDamageScaleByUnitType[defenderUnit->unitType] * attackPower;

  if (fortWallTileOnLine != 0 && tileGrid[fortWallTileOnLine].deployMark > 1 &&
      fortStrengthPoints[fortWallTileOnLine / 29 / 2] > 0) {
    if (g_afTacticalDirectFireFlagByCategory[attackerCategory] == 0.0f) {
      DamageFort(fortWallTileOnLine, (int)(0.001f * attackPower));
    }
    defenderCategory = g_awTacticalUnitCategoryCodeBySlot[defenderUnit->unitType];
    damage =
        damage * g_afTacticalCoverDamageModifierByCategory[defenderCategory * 5 +
                                                           tileGrid[fortWallTileOnLine].deployMark];
  }

  if (tileGrid[targetTileIndex].deployMark == 1) {
    int attackerRow = attackerUnit->tileIndex / 29;
    int attackerX = (attackerRow & 1) + attackerUnit->tileIndex % 29 * 2;
    int targetRow = targetTileIndex / 29;
    int targetX = (targetRow & 1) + targetTileIndex % 29 * 2;
    if (targetX < attackerX) {
      targetX = attackerX * 2 - targetX;
    }
    if (targetRow < attackerRow) {
      targetRow = attackerRow * 2 - targetRow;
    }
    int rowDelta = targetRow - attackerRow;
    int extraColumns = targetX - rowDelta - attackerX;
    int hexDistance = (extraColumns > 0) ? rowDelta + extraColumns / 2 : rowDelta;
    if (hexDistance > 1) {
      damage = damage * g_afTacticalCoverDamageModifierByCategory[defenderCategory * 5 + 1];
    }
  }

  float leaderMoraleMultiplier = 2.0f;
  {
    TTacticalPlayer* defenderPlayer = (defenderUnit->side == 0) ? players[0] : players[1];
    CIterator leaderIter(defenderPlayer->unitList);
    for (TTacticalUnit* leaderUnit = static_cast<TTacticalUnit*>(leaderIter.Reset());
         leaderIter.More(); leaderUnit = static_cast<TTacticalUnit*>(leaderIter.Advance())) {
      if (leaderUnit->unitType >= 0x1b && leaderUnit->state1c == 0) {
        double leaderValue = 2.0 - leaderUnit->qualityLevel * 0.2 - 0.2;
        if (leaderValue < leaderMoraleMultiplier) {
          leaderMoraleMultiplier = (float)leaderValue;
        }
      }
    }
  }
  float moraleDamage = leaderMoraleMultiplier * damage;

  bool captureEffectCode;
  short overrunDefenderCategory = g_awTacticalUnitCategoryCodeBySlot[defenderUnit->unitType];
  if (meleeAdjacent && (overrunDefenderCategory == 6 || overrunDefenderCategory == 7) &&
      g_awTacticalUnitCategoryCodeBySlot[attackerUnit->unitType] < 4 &&
      static_cast<TArmyTacUnit*>(defenderUnit)->morale < moraleDamage) {
    captureEffectCode = true;
  } else {
    captureEffectCode = false;
  }

  attackerUnit->AssertValid();
  LaFireOn(attackerUnit, defenderUnit, targetTileIndex, (int)damage, (int)moraleDamage,
           captureEffectCode, false);
  TTacticalPlayer* postActionPlayer = (defenderUnit->side == 0) ? players[0] : players[1];
  postActionPlayer->skipRequested = false;
}

// FUNCTION: IMPERIALISM 0x005a24a0
void TTacticalBattle::LaFireOn(TTacticalUnit* attackerUnit, TTacticalUnit* targetUnit,
                               TacticalTileIndex targetTileIndex, int damageA, int damageB,
                               char effectCode2C, bool remoteFlag) {
  if (!remoteFlag) {
    bool multiplayerActive = g_pSimMgr->multiplayerSessionRole != kSessionRoleStandalone;
    if (multiplayerActive) {
      g_pGameFlowState->SendTacLaEx(kControlTagFire, attackerUnit, targetUnit, damageA, damageB,
                                    effectCode2C);
    }
  }
  targetUnit->ApplyDamage(damageA, damageB);
  if (battleView != 0) {
    battleView->MakeTileVisible(targetTileIndex);
    short sfxToken = g_awTacticalFireSfxTokenByUnitType[attackerUnit->unitType];
    g_pSfxPlaybackSystem->PlaySoundEffect(sfxToken, 0, 1);
    short categoryCode = g_awTacticalUnitCategoryCodeBySlot[attackerUnit->unitType];
    if (categoryCode == 6 || categoryCode == 7 || attackerUnit->unitType == 0x15) {
      if (battleView != 0) {
        // effect-id + frame-count pair: 0xf6e/6 here, 0xf78/3 in the else branch (verified).
        battleView->PlayAni(targetTileIndex, 0xf6e, 6);
      }
    } else {
      if (battleView != 0) {
        battleView->PlayAni(targetTileIndex, 0xf78, 3);
      }
    }
    if (battleView != 0) {
      battleView->InvalidateTile(targetTileIndex);
    }
  }
  if (targetUnit->state1c == 3) {
    if (battleView != 0) {
      battleView->InvalidateTile(targetUnit->tileIndex);
    }
    if (battleView != 0) {
      battleView->InvalidateUnit(targetUnit);
    }
    tileGrid[targetUnit->tileIndex].occupant = 0;
    targetUnit->tileIndex = -1;
  }
  attackerUnit->selectedFlag = false;
  CheckForVictory();
}

// FUNCTION: IMPERIALISM 0x005a2630
float TTacticalBattle::FindMoraleBonus(unsigned char side) {
  float moraleBonus = 2.0f;
  CIterator unitIter((side == 0) ? players[0]->unitList : players[1]->unitList);
  for (TTacticalUnit* unit = static_cast<TTacticalUnit*>(unitIter.Reset()); unitIter.More();
       unit = static_cast<TTacticalUnit*>(unitIter.Advance())) {
    if (unit->unitType >= 0x1b && unit->state1c == 0) {
      float unitBonus = static_cast<float>(2.0 - unit->qualityLevel * 0.2 - 0.2);
      if (unitBonus < moraleBonus) {
        moraleBonus = unitBonus;
      }
    }
  }
  return moraleBonus;
}

// FUNCTION: IMPERIALISM 0x005a2700
void TTacticalBattle::TransferTacticalUnitToOpposingSide(TTacticalUnit* unit) {
  if (unit->side == 0) {
    TTacticalPlayer* receivingPlayer = players[1];
    players[0]->RemoveCapturedUnit(unit);
    receivingPlayer->AddCapturedUnit(unit);
  } else {
    TTacticalPlayer* receivingPlayer = players[0];
    players[1]->RemoveCapturedUnit(unit);
    receivingPlayer->AddCapturedUnit(unit);
  }
}

// FUNCTION: IMPERIALISM 0x005a2750
void TTacticalBattle::CheckForVictory() {
  unsigned char sideHasLiveUnit[2];
  sideHasLiveUnit[0] = 0;
  sideHasLiveUnit[1] = 0;
  CIterator unitIter(recordList);
  for (TTacticalUnit* unit = static_cast<TTacticalUnit*>(unitIter.Reset());
       unitIter.More() && (sideHasLiveUnit[0] == 0 || sideHasLiveUnit[1] == 0);
       unit = static_cast<TTacticalUnit*>(unitIter.Advance())) {
    unit->AssertValid();
    if (unit->state1c == 0 || unit->state1c == 1) {
      sideHasLiveUnit[unit->side] = 1;
    }
  }

  if (sideHasLiveUnit[0] != 0) {
    if (sideHasLiveUnit[1] != 0 && roundCounter < 0x23) {
      return; // both sides still have live units and the round limit is not reached
    }
  }
  if (sideHasLiveUnit[0] != 0 && roundCounter < 0x23) {
    battleOutcome = kTacticalBattleSide0Victory;
  } else {
    battleOutcome = kTacticalBattleSide1Victory;
  }

  if (battleView == 0) {
    return; // headless battle: outcome recorded, no summary dialog
  }

  bool localIsSide0Player = players[0]->IsPlayer();
  bool localSideWon;
  if ((battleOutcome == kTacticalBattleSide0Victory && players[0]->IsPlayer()) ||
      (battleOutcome == kTacticalBattleSide1Victory && players[1]->IsPlayer())) {
    localSideWon = true;
  } else {
    localSideWon = false;
  }

  g_pSfxPlaybackSystem->RequestAudioPresetChangeWithDeferredApply(localSideWon ? 9 : 10, false);

  TextStyle styleDescriptor;
  styleDescriptor.textColor = 0;
  TWindow* dialog = static_cast<TWindow*>(
      g_pAssetMgr->ResolveTurnEventDialogNodeByMessageContext(kTurnEventTacticalBattleResult));

  TPicture* headerPicture = static_cast<TPicture*>(dialog->FindSubView(kControlTagDialog));
  headerPicture->AssertValid();
  headerPicture->SetPictureRsrcID(g_pSimMgr->GetPlayerCountry() + (localSideWon ? 0xeed : 0xefb),
                                  0);

  TStaticText* titleControl =
      static_cast<TStaticText*>(headerPicture->FindSubView(kControlTagTitl));
  titleControl->AssertValid();
  {
    int titleMessageIndex;
    if (localIsSide0Player) {
      titleMessageIndex = localSideWon ? 3 : 1;
    } else {
      titleMessageIndex = localSideWon ? 6 : 4;
    }
    CString titleText;
    g_pSimMgr->GetString(0x273d, titleMessageIndex, &titleText);
    BuildUiTextStyleDescriptor(&styleDescriptor, 0, 0xc, 0x2b67);
    titleControl->InstallTextStyle(styleDescriptor, 0);
    titleControl->SetTextAndMaybeRefresh(&titleText, false);
  }

  TStaticText* locationControl =
      static_cast<TStaticText*>(headerPicture->FindSubView(kControlTagLoca));
  locationControl->AssertValid();
  {
    CString cityName;
    CString siteOwnerLabel;
    g_pGlobalMapState->AssignCityRecordDisplayName(battleSiteIndex, &cityName);
    g_apTerrainTypeDescriptorTable[g_pGlobalMapState->cityScoreTable[battleSiteIndex]
                                       .ownerNationCode]
        ->FormatOverlayTerrainLabelText(&siteOwnerLabel);
    CString locationTemplate;
    CString locationText;
    g_pSimMgr->GetString(0x273d, 7, &locationTemplate);
    scanBracketExpressions(g_pSimMgr, &locationText, static_cast<const char*>(locationTemplate),
                           static_cast<const char*>(cityName),
                           static_cast<const char*>(siteOwnerLabel));
    BuildUiTextStyleDescriptor(&styleDescriptor, 0, 0xa, 0x2b67);
    locationControl->InstallTextStyle(styleDescriptor, 0);
    locationControl->SetTextAndMaybeRefresh(&locationText, true);
  }

  TDeluxeText* infoControl = static_cast<TDeluxeText*>(headerPicture->FindSubView(kControlTagInfo));
  infoControl->AssertValid();
  {
    CString infoText;
    CString unusedTextA;
    CString casualtyTemplate;
    CString unusedTextB;
    infoText = CString(g_pszEmptyTextRef);
    BuildUiTextStyleDescriptor(&styleDescriptor, 0, 0xa, 0x2b67);

    int destroyedCountBySide[2];
    destroyedCountBySide[0] = 0;
    destroyedCountBySide[1] = 0;
    CIterator lossIter(recordList);
    for (TTacticalUnit* lossUnit = static_cast<TTacticalUnit*>(lossIter.Reset()); lossIter.More();
         lossUnit = static_cast<TTacticalUnit*>(lossIter.Advance())) {
      lossUnit->AssertValid();
      if (lossUnit->state1c == 3) {
        ++destroyedCountBySide[lossUnit->side];
      }
    }

    CString side0NationLabel;
    CString side1NationLabel;
    CString side0CountText;
    CString side1CountText;
    CString side0CasualtyLine;
    CString side1CasualtyLine;
    CString combinedCasualtyText;

    g_apTerrainTypeDescriptorTable[players[0]->nationIndex]->FormatOverlayTerrainLabelText(
        &side0NationLabel);
    if (destroyedCountBySide[0] > 1) {
      g_pSimMgr->GetString(0x273d, 0x24, &casualtyTemplate);
      side0CountText.Format(g_szDecimalFormat, destroyedCountBySide[0]);
      scanBracketExpressions(
          g_pSimMgr, &side0CasualtyLine, static_cast<const char*>(casualtyTemplate),
          static_cast<const char*>(side0NationLabel), static_cast<const char*>(side0CountText));
    } else {
      g_pSimMgr->GetString(0x273d, (destroyedCountBySide[0] == 1) ? 0x25 : 0x26, &casualtyTemplate);
      scanBracketExpressions(g_pSimMgr, &side0CasualtyLine,
                             static_cast<const char*>(casualtyTemplate),
                             static_cast<const char*>(side0NationLabel));
    }

    g_apTerrainTypeDescriptorTable[players[1]->nationIndex]->FormatOverlayTerrainLabelText(
        &side1NationLabel);
    if (destroyedCountBySide[1] > 1) {
      g_pSimMgr->GetString(0x273d, 0x24, &casualtyTemplate);
      side1CountText.Format(g_szDecimalFormat, destroyedCountBySide[1]);
      scanBracketExpressions(
          g_pSimMgr, &side1CasualtyLine, static_cast<const char*>(casualtyTemplate),
          static_cast<const char*>(side1NationLabel), static_cast<const char*>(side1CountText));
    } else {
      g_pSimMgr->GetString(0x273d, (destroyedCountBySide[1] == 1) ? 0x25 : 0x26, &casualtyTemplate);
      scanBracketExpressions(g_pSimMgr, &side1CasualtyLine,
                             static_cast<const char*>(casualtyTemplate),
                             static_cast<const char*>(side1NationLabel));
    }

    combinedCasualtyText = CString(side0CasualtyLine + s_szDoubleNewline + side1CasualtyLine);
    infoControl->SetTextStyle(styleDescriptor, false);
    infoControl->UpdateTextEntrySharedStringAndMaybeNotify(&combinedCasualtyText, false);
    infoControl->CenterVertically(false);
  }

  dialog->SetModality(true);
  TDialogBehavior* content = dialog->GetDialogBehavior();
  if (content != 0) {
    content->defaultCommandCode = kControlTagOkay; // 'okay'
  }
  dialog->PoseModally();
  dialog->Close();
  dialog->Free();
  battleView->ForceRedraw();
}

// FUNCTION: IMPERIALISM 0x005a3190
void TTacticalBattle::BeginDig(TArmyTacUnit* unit, TacticalTileIndex targetTileIndex) {
  TacticalTileIndex unitTileIndex = unit->tileIndex;
  tileGrid[unitTileIndex].mineRunState = 2;
  unit->AssertValid();
  unit->sapTargetTileIndex = targetTileIndex;
  if (battleView != 0) {
    battleView->InvalidateTile(unitTileIndex);
  }
  if (unit->actionPoints != 0) {
    unit->actionPoints = 0;
    return;
  }
  FinishedMove();
}

// FUNCTION: IMPERIALISM 0x005a3210
void TTacticalBattle::ContinueDig(TArmyTacUnit* unit) {
  TacticalTileIndex targetTileIndex = unit->sapTargetTileIndex;
  if (tileGrid[targetTileIndex].deployMark <= 1) {
    unit->sapTargetTileIndex = -1;
    return;
  }
  TacticalTileIndex runTileIndex = unit->tileIndex;
  if (runTileIndex != targetTileIndex) {
    do {
      if (tileGrid[runTileIndex].mineRunState == -1) {
        break;
      }
      runTileIndex -= tacticalTileStride;
    } while (runTileIndex != targetTileIndex);
  }
  if (runTileIndex == targetTileIndex) {
    if (battleView != 0) {
      battleView->PlayAni(runTileIndex, 0xf6e, 6);
    }
    tileGrid[unit->sapTargetTileIndex].deployMark = 0;
    if (battleView != 0) {
      battleView->InvalidateTile(unit->sapTargetTileIndex);
    }
    unit->sapTargetTileIndex = -1;
  } else if (((runTileIndex / tacticalTileStride) & 1) != 0) {
    tileGrid[runTileIndex].mineRunState = 0;
  } else {
    tileGrid[runTileIndex].mineRunState = 1;
  }
  if (unit->actionPoints == 0) {
    FinishedMove();
    return;
  }
  unit->actionPoints = 0;
}

// FUNCTION: IMPERIALISM 0x005a3320
void TTacticalBattle::ClearTunnel(TacticalTileIndex tileIndex) {
  TacticalTileIndex runTileIndex;
  for (runTileIndex = tileIndex; runTileIndex >= 0; runTileIndex -= tacticalTileStride) {
    int* runState = &tileGrid[runTileIndex].mineRunState;
    if (*runState == -1) {
      break;
    }
    *runState = -1;
    if (battleView != 0) {
      battleView->InvalidateTile(runTileIndex);
    }
  }
}

// FUNCTION: IMPERIALISM 0x005a3370
void TTacticalBattle::DispatchTacticalActionByHoverStateIndex(TacticalTileIndex tileIndex) {
  currentTacticalActionCode = GetTileCursor(tileIndex);
  switch (currentTacticalActionCode) {
  case 3:
    DeployUnit(selectedUnit, tileIndex);
    break;
  case 4:
    MoveAndCycle(selectedUnit, tileIndex);
    break;
  case 5:
  case 0xa:
    FireAndCycle(selectedUnit, tileIndex);
    break;
  case 6:
    FinishedMove();
    break;
  case 7:
    DigTunnel(selectedUnit, tileIndex);
    break;
  case 8: {
    TTacticalUnit* occupant = tileGrid[tileIndex].occupant;
    occupant->AssertValid();
    RallyUnit(selectedUnit, static_cast<TArmyTacUnit*>(occupant));
    break;
  }
  case 9:
    MineWall(selectedUnit, tileIndex);
    break;
  case 0xc: {
    TTacticalUnit* occupant = tileGrid[tileIndex].occupant;
    if (battleView != 0) {
      battleView->InvalidateUnit(occupant);
    }
    occupant->tileIndex = -2;
    tileGrid[tileIndex].occupant = 0;
    break;
  }
  }
}

// FUNCTION: IMPERIALISM 0x005a34d0
void TTacticalBattle::MineWall(TTacticalUnit* unit, TacticalTileIndex tileIndex) {
  int unitType = unit->unitType;
  int amount = static_cast<int>(rand()) % 400 + unitType * 250 - 5600;
  bool multiplayerActive = g_pSimMgr->multiplayerSessionRole != kSessionRoleStandalone;
  if (multiplayerActive) {
    g_pGameFlowState->SendTacLa(kControlTagMine, 0, tileIndex, amount);
  }
  DamageFort(tileIndex, amount);
  if (battleView != 0) {
    g_pSfxPlaybackSystem->PlaySoundEffect(0x3a9d, 0, 1);
    battleView->PlayAni(tileIndex, 0xf98, 6);
  }
  FinishedMove();
}

// FUNCTION: IMPERIALISM 0x005a35a0
void TTacticalBattle::LaMine(TacticalTileIndex tileIndex, int amount, bool remoteFlag) {
  if (!remoteFlag) {
    bool multiplayerActive = g_pSimMgr->multiplayerSessionRole != kSessionRoleStandalone;
    if (multiplayerActive) {
      g_pGameFlowState->SendTacLa(kControlTagMine, 0, tileIndex, amount);
    }
  }
  DamageFort(tileIndex, amount);
  if (battleView != 0) {
    g_pSfxPlaybackSystem->PlaySoundEffect(0x3a9d, 0, 1);
    battleView->PlayAni(tileIndex, 0xf98, 6);
  }
}

// FUNCTION: IMPERIALISM 0x005a3640
void TTacticalBattle::DigTunnel(TTacticalUnit* unit, TacticalTileIndex tileIndex) {
  unit->AssertValid();
  // Captured as a word before the dig/move mutate the unit.
  short actionPointsBefore = static_cast<short>(unit->actionPoints);
  LaDig(unit, tileIndex, false);
  MoveTacticalUnitTowardTile(unit, tileIndex);
  unit->actionPoints = actionPointsBefore - g_awUnitTypeBaseActionPointTable[unit->unitType] / 2;
  CalculateMoveMap(unit);
  if (unit->actionPoints == 0) {
    FinishedMove();
  }
}

// FUNCTION: IMPERIALISM 0x005a36d0
void TTacticalBattle::LaDig(TTacticalUnit* unit, TacticalTileIndex targetTileIndex,
                            bool remoteFlag) {
  TacticalTileIndex neighborTiles[6];
  if (!remoteFlag) {
    bool multiplayerActive = g_pSimMgr->multiplayerSessionRole != kSessionRoleStandalone;
    if (multiplayerActive) {
      g_pGameFlowState->SendTacLa(kControlTagDigg, unit, targetTileIndex, 0);
    }
  }
  TacticalTileIndex unitTileIndex = unit->tileIndex;
  GetNeighborList(unitTileIndex, neighborTiles);
  int direction = 0;
  TacticalTileIndex* neighborCursor = neighborTiles;
  do {
    if (*neighborCursor == targetTileIndex) {
      break;
    }
    ++direction;
    ++neighborCursor;
  } while (direction < 6);
  unsigned char srcMask = tileGrid[unitTileIndex].trenchMask;
  if (srcMask == 0) {
    tileGrid[unitTileIndex].trenchMask = 0x80;
  } else {
    tileGrid[unitTileIndex].trenchMask = srcMask & 0x7f;
    tileGrid[unitTileIndex].trenchMask |= 0x40;
  }
  tileGrid[unitTileIndex].trenchMask |= static_cast<unsigned char>(1 << direction);
  direction += 3;
  if (direction > 5) {
    direction -= 6;
  }
  unsigned char dstMask = tileGrid[targetTileIndex].trenchMask;
  if (dstMask != 0) {
    tileGrid[targetTileIndex].trenchMask = dstMask & 0x7f;
    tileGrid[targetTileIndex].trenchMask |= 0x40;
  }
  tileGrid[targetTileIndex].trenchMask |= static_cast<unsigned char>(1 << direction);
}

// FUNCTION: IMPERIALISM 0x005a3810
void TTacticalBattle::RallyUnit(TTacticalUnit* rallyingUnit, TArmyTacUnit* rallyTarget) {
  int newState = rallyTarget->state1c;
  int newMorale = rallyTarget->morale;
  if (newState == 0) {
    newMorale += rallyTarget->strength / 10 * (rallyingUnit->qualityLevel + 3);
  } else if (newState == 1) {
    int qualityLevel = rallyingUnit->qualityLevel;
    if (static_cast<int>(rand()) % 100 < (qualityLevel + 5) * 10) {
      newMorale = rallyTarget->strength / 10 + 20;
      newState = 0;
    }
  }
  LaRally(rallyTarget, newMorale, newState, false);
  FinishedMove();
}

// FUNCTION: IMPERIALISM 0x005a38e0
void TTacticalBattle::LaRally(TArmyTacUnit* unit, int newMorale, int newState, bool remoteFlag) {
  if (!remoteFlag) {
    bool multiplayerActive = g_pSimMgr->multiplayerSessionRole != kSessionRoleStandalone;
    if (multiplayerActive) {
      g_pGameFlowState->SendTacLa(kControlTagRaly, unit, newMorale, newState);
    }
  }
  int strength = unit->strength;
  unit->state1c = newState;
  if (newMorale > strength) {
    unit->morale = strength;
  } else {
    unit->morale = newMorale;
  }
  if (battleView != 0) {
    battleView->InvalidateUnit(unit);
  }
  if (battleView != 0) {
    g_pSfxPlaybackSystem->PlaySoundEffect(0x3aae, 0, 1);
  }
}

// FUNCTION: IMPERIALISM 0x005a3a70
TacticalTileIndex
TTacticalBattle::FindFortWallTileCrossedByFiringLine(TacticalTileIndex targetTileIndex,
                                                     TacticalTileIndex attackerTileIndex) {
  float wallX = (float)(2 * battlefieldColumnCount - 12);
  int lineX1 = 2 * (targetTileIndex % 29) + ((targetTileIndex / 29) & 1);
  int lineY1 = 2 * (targetTileIndex / 29);
  int lineX2 = 2 * (attackerTileIndex % 29) + ((attackerTileIndex / 29) & 1);
  int lineY2 = 2 * (attackerTileIndex / 29);
  if (lineX2 == lineX1) {
    return 0;
  }
  if (lineX2 > lineX1) {
    // Canonicalize so (lineX2, lineY2) is the left endpoint.
    int swapTemp = lineX2;
    lineX2 = lineX1;
    lineX1 = swapTemp;
    swapTemp = lineY2;
    lineY2 = lineY1;
    lineY1 = swapTemp;
  }
  float leftXF = (float)lineX2;
  if (leftXF > wallX) {
    return 0;
  }
  if ((float)lineX1 < wallX) {
    return 0;
  }
  if (lineY1 == lineY2) {
    return tacticalTileStride * lineY1 / 2 + battlefieldColumnCount - 6;
  }
  return battlefieldColumnCount -
         (int)(((float)lineY2 +
                (wallX - leftXF) * ((float)(lineY1 - lineY2) / (float)(lineX1 - lineX2))) *
               -0.5f) *
             tacticalTileStride -
         6;
}

// FUNCTION: IMPERIALISM 0x005a3c20
void TTacticalBattle::DamageFort(TacticalTileIndex tileIndex, int consumeAmount) {
  int poolIndex = tileIndex / 29 / 2;
  int remaining = fortStrengthPoints[poolIndex] - consumeAmount;
  fortStrengthPoints[poolIndex] = remaining;
  if (remaining < 0) {
    fortStrengthPoints[poolIndex] = 0;
    TacticalTileIndex poolTileIndex = battlefieldColumnCount + poolIndex * 58 - 6;
    if (battleView != 0) {
      battleView->InvalidateTile(poolTileIndex);
    }
    if (battleView != 0) {
      battleView->InvalidateTile(poolTileIndex + 1);
    }
    if (battleView != 0) {
      battleView->InvalidateTile(poolTileIndex + 29);
    }
  }
}

// FUNCTION: IMPERIALISM 0x005a3cc0
unsigned char TTacticalBattle::CanFireOn(TTacticalUnit* unit, TacticalTileIndex targetTileIndex) {
  TacticalTileIndex attackerTileIndex = unit->tileIndex;
  if (!unit->selectedFlag) {
    return 0;
  }
  int category = g_awTacticalUnitCategoryCodeBySlot[unit->unitType];
  int range = unit->GetUnitRange();
  int directFireFlag = static_cast<int>(g_afTacticalDirectFireFlagByCategory[category]);
  return IsTacticalTargetTileReachableForAction(attackerTileIndex, targetTileIndex,
                                                static_cast<char>(directFireFlag), range);
}

// FUNCTION: IMPERIALISM 0x005a3d30
unsigned char
TTacticalBattle::IsTacticalTargetTileReachableForAction(TacticalTileIndex attackerTileIndex,
                                                        TacticalTileIndex targetTileIndex,
                                                        char directFireFlag, int range) {
  int attackerRow = attackerTileIndex / 29;
  int attackerColumn = attackerTileIndex % 29;
  int attackerAxialX = (attackerRow & 1) + attackerColumn * 2;
  int targetRow = targetTileIndex / 29;
  int targetColumn = targetTileIndex % 29;
  int targetAxialX = (targetRow & 1) + targetColumn * 2;
  if (targetAxialX < attackerAxialX) {
    targetAxialX = attackerAxialX * 2 - targetAxialX;
  }
  if (targetRow < attackerRow) {
    targetRow = attackerRow * 2 - targetRow;
  }
  int rowDistance = targetRow - attackerRow;
  int diagonalOverhang = targetAxialX - rowDistance - attackerAxialX;
  int hexDistance;
  if (diagonalOverhang > 0) {
    hexDistance = diagonalOverhang / 2 + rowDistance;
  } else {
    hexDistance = rowDistance;
  }
  if (hexDistance > range) {
    return 0;
  }
  TacticalTileRecord* targetRecord = &tileGrid[targetTileIndex];
  TTacticalUnit* targetOccupant = targetRecord->occupant;
  if (targetOccupant != 0 && g_awTacticalUnitCategoryCodeBySlot[targetOccupant->unitType] == 8 &&
      targetRecord->trenchMask != 0) {
    TacticalTileIndex neighborTiles[6];
    GetNeighborList(attackerTileIndex, neighborTiles);
    int direction = 0;
    TacticalTileIndex* neighborCursor = neighborTiles;
    while (*neighborCursor != targetTileIndex) {
      ++direction;
      ++neighborCursor;
      if (direction >= 6) {
        return 0; // entrenched sapper: only adjacent attackers get through
      }
    }
  }
  if (directFireFlag == 0) {
    return 1;
  }
  TacticalTileIndex wallTileIndex =
      FindFortWallTileCrossedByFiringLine(targetTileIndex, attackerTileIndex);
  if (wallTileIndex == 0) {
    return 1;
  }
  if (tileGrid[wallTileIndex].deployMark <= 1) {
    return 1;
  }
  if (fortStrengthPoints[wallTileIndex / 29 / 2] <= 0) {
    return 1;
  }
  if (targetColumn <= battlefieldColumnCount - 5) {
    return 1;
  }
  if (attackerColumn == battlefieldColumnCount - 5) {
    return 1;
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x005a3f10
void TTacticalBattle::CycleTarget() {
  TTacticalUnit* selected = selectedUnit;
  TTacticalUnit* result = NULL;
  if (selected == NULL || battleView == NULL) {
    return;
  }
  TTacticalUnit* marker = selected->attackTarget;
  TList* list = players[selected->side == 0]->unitList;

  // Locate the current target's ordinal in the opposing list (0 if it is gone).
  int position = 0;
  if (marker != NULL) {
    int count = list->GetCount();
    for (int i = 1; i <= count; i++) {
      if (list->GetEntryByOrdinal(i) == marker) {
        position = i;
      }
      count = list->GetCount();
    }
    if (position == 0) {
      marker = NULL;
    }
  }

  // If the current target is still valid and reachable, recenter the view on it.
  if (marker != NULL && marker->state1c == 0) {
    char reachable;
    if (!selectedUnit->selectedFlag) {
      reachable = 0;
    } else {
      reachable = IsTacticalTargetTileReachableForAction(
          selectedUnit->tileIndex, marker->tileIndex,
          static_cast<char>(g_afTacticalDirectFireFlagByCategory
                                [g_awTacticalUnitCategoryCodeBySlot[selectedUnit->unitType]]),
          selectedUnit->GetUnitRange());
    }
    if (reachable != 0) {
      battleView->MakeTileVisible(marker->tileIndex);
    }
  }

  if (position == 0 || position == list->GetCount()) {
    position = 1;
  }

  int cursor = position;
  do {
    int next = cursor + 1;
    if (list->GetCount() < next) {
      next = 1;
    }
    TTacticalUnit* candidate = static_cast<TTacticalUnit*>(list->GetEntryByOrdinal(next));
    candidate->AssertValid();
    if (candidate->state1c == 0) {
      char reachable;
      if (!selectedUnit->selectedFlag) {
        reachable = 0;
      } else {
        reachable = IsTacticalTargetTileReachableForAction(
            selectedUnit->tileIndex, candidate->tileIndex,
            static_cast<char>(g_afTacticalDirectFireFlagByCategory
                                  [g_awTacticalUnitCategoryCodeBySlot[selectedUnit->unitType]]),
            selectedUnit->GetUnitRange());
      }
      if (reachable != 0) {
        if (marker == NULL) {
          battleView->MakeTileVisible(candidate->tileIndex);
          marker = candidate;
        } else {
          result = candidate;
        }
      }
    }
    cursor = next;
  } while (cursor != position && result == NULL);

  selectedUnit->attackTarget = result;
  if (result == NULL) {
    g_pSfxPlaybackSystem->PlaySoundEffect(0x1b5a, 0, 1);
  }
}

// FUNCTION: IMPERIALISM 0x005a41c0
bool TTacticalBattle::ApplyGridColumnSelectionGuard(TacticalTileIndex tileIndex) {
  int column = tileIndex % 29;
  if (tileIndex < 29) {
    return false;
  }
  TacticalTileRecord* record = &tileGrid[tileIndex];
  if (record->terrainType == 4) {
    return false;
  }
  if (record->occupant != 0) {
    return false;
  }
  if (currentSide == 0) {
    if (column < 3) {
      return false;
    }
    return column <= 5;
  }
  if (column > battlefieldColumnCount - 3) {
    return false;
  }
  return column >= battlefieldColumnCount - 5;
}

// FUNCTION: IMPERIALISM 0x005a4240
int TTacticalBattle::CountDeploymentTiles() {
  int freeTileCount = 0;
  int tileCount = tacticalTileCount;
  if (tileCount > 0) {
    for (TacticalTileIndex tileIndex = 0; tileIndex < tileCount; ++tileIndex) {
      int column = tileIndex % 29;
      bool tileFree = false;
      if (tileIndex >= 29) {
        TacticalTileRecord* record = &tileGrid[tileIndex];
        if (record->terrainType != 4 && record->occupant == 0) {
          if (currentSide == 0) {
            if (column >= 3 && column <= 5) {
              tileFree = true;
            }
          } else if (column <= battlefieldColumnCount - 3 && column >= battlefieldColumnCount - 5) {
            tileFree = true;
          }
        }
      }
      if (tileFree) {
        ++freeTileCount;
      }
    }
  }
  return freeTileCount;
}

// FUNCTION: IMPERIALISM 0x005a42e0
bool TTacticalBattle::HasFortWallGarrison(TacticalTileIndex tileIndex) {
  return tileGrid[tileIndex].deployMark > 1 && fortStrengthPoints[tileIndex / 0x3a] > 0;
}

// FUNCTION: IMPERIALISM 0x005a4330
bool TTacticalBattle::IsTacticalSideCategoryCoverageIncompleteOrFlagOff() {
  if (fortLevel == 0) {
    return true;
  }
  for (int poolIndex = 0; poolIndex < 8; ++poolIndex) {
    if (fortStrengthPoints[poolIndex] <= 0) {
      return true;
    }
  }
  return false;
}

// FUNCTION: IMPERIALISM 0x005a4370
void TTacticalBattle::LaDeploy(TArmyTacUnit* unit, TacticalTileIndex tileIndex, bool remoteFlag) {
  TacticalTileIndex neighborTiles[6];
  if (!remoteFlag) {
    bool multiplayerActive = g_pSimMgr->multiplayerSessionRole != kSessionRoleStandalone;
    if (multiplayerActive) {
      g_pGameFlowState->SendTacLa(kControlTagDepl, unit, tileIndex, 0);
    }
  }
  unit->tileIndex = tileIndex;
  tileGrid[tileIndex].occupant = unit;
  if (unit->flag3c != 0 && fortLevel == 0) {
    tileGrid[tileIndex].deployMark = 1;
    if (battleView != 0) {
      GetNeighborList(tileIndex, neighborTiles);
      TacticalTileIndex* neighborCursor = neighborTiles;
      for (int remaining = 0; remaining < 6; ++remaining) {
        if (*neighborCursor != -1) {
          battleView->InvalidateTile(*neighborCursor);
        }
        ++neighborCursor;
      }
    }
  }
  if (battleView != 0) {
    battleView->InvalidateUnit(unit);
  }
}

// FUNCTION: IMPERIALISM 0x005a4460
void TTacticalBattle::MakeRetreatMap(char ourSideFlag) {
  int fillIndex;
  for (fillIndex = 0; fillIndex < tacticalTileCount; ++fillIndex) {
    tileIntArray[fillIndex] = -1;
  }
  if (ourSideFlag != 0) {
    // Seed column 0 of each of the 15 grid rows.
    int rowStartA;
    for (rowStartA = 0; rowStartA < 0x1b3; rowStartA += 0x1d) {
      if (tileGrid[rowStartA].terrainType != 4) {
        tileIntArray[rowStartA] = 0;
      }
    }
  } else {
    // Seed the last playable column (battlefieldColumnCount - 1) of each row.
    int rowStartB;
    for (rowStartB = 0; rowStartB < 0x1b3; rowStartB += 0x1d) {
      TacticalTileIndex edgeTile = battlefieldColumnCount + rowStartB;
      if (tileGrid[edgeTile - 1].terrainType != 4) {
        tileIntArray[edgeTile - 1] = 0;
      }
    }
  }
  int distance = 0;
  bool anyTileExpanded;
  do {
    anyTileExpanded = false;
    int tile;
    for (tile = 0; tile < tacticalTileCount; ++tile) {
      if (tileIntArray[tile] != distance) {
        continue;
      }
      TacticalTileIndex neighborTiles[6];
      GetNeighborList(tile, neighborTiles);
      TacticalTileIndex* neighborCursor = neighborTiles;
      int direction;
      for (direction = 0; direction < 6; ++direction, ++neighborCursor) {
        TacticalTileIndex neighborTile = *neighborCursor;
        if (neighborTile == -1) {
          continue;
        }
        int* distanceCell = &tileIntArray[neighborTile];
        if (*distanceCell != -1) {
          continue;
        }
        TacticalTileRecord* record = &tileGrid[neighborTile];
        if (record->occupant != 0) {
          continue;
        }
        if (record->deployMark >= 2 && record->deployMark > 1) {
          int wallRow = neighborTile / 0x1d;
          if (fortStrengthPoints[wallRow / 2] > 0) {
            int doubledColumn = (wallRow & 1) + (neighborTile % 0x1d) * 2;
            if (wallRow != 5 && wallRow != 7 && wallRow != 9) {
              continue;
            }
            if (doubledColumn / 2 != battlefieldColumnCount - 6) {
              continue;
            }
            if (ourSideFlag != 0) {
              continue;
            }
            // Gun-slot gate: stays passable for the attacking side.
          }
        }
        if (record->terrainType != 4) {
          anyTileExpanded = true;
          *distanceCell = distance + 1;
        }
      }
    }
    ++distance;
  } while (anyTileExpanded);
}

// FUNCTION: IMPERIALISM 0x005a4690
bool TTacticalBattle::IsTacticalTileAtFortWallSectionSlot(TacticalTileIndex tileIndex) {
  int row = tileIndex / 0x1d;
  int doubledColumn = (row & 1) + (tileIndex % 0x1d) * 2;
  if (row == 5 || row == 7 || row == 9) {
    if (doubledColumn / 2 == battlefieldColumnCount - 6) {
      return true;
    }
  }
  return false;
}

// FUNCTION: IMPERIALISM 0x005a53e0
TArmyTacUnit* TTacticalBattle::SeekLinkedListCursorByNestedId(int nestedId) {
  if (nestedId == 0) {
    return 0;
  }
  CIterator unitIter(recordList);
  for (TArmyTacUnit* unit = static_cast<TArmyTacUnit*>(unitIter.Reset()); unitIter.More();
       unit = static_cast<TArmyTacUnit*>(unitIter.Advance())) {
    int foundId;
    if (unit != 0 && unit->sourceUnit != 0) {
      foundId = unit->sourceUnit->persistentUnitId;
    } else {
      foundId = 0;
    }
    if (nestedId == foundId) {
      return unit;
    }
  }
  return 0;
}
