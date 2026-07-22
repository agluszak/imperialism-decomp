#include "game/TAmbitApplication.h"
#include "game/TTacticalBattle.h"

#include <stdlib.h>

#include "game/CIterator.h"
#include "game/CString.h"
#include "game/hex_tile_distance.h"
#include "game/TAssetMgr.h"
#include "game/TControl.h"
#include "game/TCountry.h"
#include "game/TDeluxeText.h"
#include "game/TMapMgr.h"
#include "game/TPicture.h"
#include "game/TStaticText.h"
#include "game/mapped_flavor_text.h"
#include "game/quickdraw_rendering.h"
#include "game/turn_event_dialog_provisional.h"
#include "game/TArmyTacUnit.h"
#include "game/TList.h"
#include "game/TMilitaryUnit.h"
#include "game/TMultiplayerMgr.h"
#include "game/TApplication.h"
#include "game/TNextMoveCommand.h"
#include "game/TSimMgr.h"
#include "game/TSoundPlayer.h"
#include "game/TNavyPlayer.h"
#include "game/TTacticalBattleView.h"
#include "game/TTacticalPlayer.h"
#include "game/TTacticalToolbar.h"
#include "game/TViewMgr.h"
#include "game/global_data_tables.h"
#include "game/ui_control_tags.h"
#include "game/global_data_tables.h"
#include "game/ui_text_label_helpers_decls.h"

using turn_event_dialog::TurnEventDialogNode;

// Non-virtual action helpers dispatched above.

// Turn-order comparator (see the header note on the AX/short return).
// FUNCTION: IMPERIALISM 0x0059f610
short __cdecl CompareTacticalUnitsForTurnOrder(void* a, void* b, void* context) {
  (void)context;
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
  if (unitB->qualityLevel10 < unitA->qualityLevel10) {
    return -1;
  }
  if (unitB->qualityLevel10 > unitA->qualityLevel10) {
    return 1;
  }
  return (unitA->field24 <= unitB->field24) ? 1 : -1;
}
// SYNTHETIC: IMPERIALISM 0x0059f6d0
// TTacticalBattle::CreateObject

// FUNCTION: IMPERIALISM 0x0059f710
void TTacticalBattle::DeployTacticalUnitToTile(TTacticalUnit* unit, int tileIndex) {
  (void)unit;
  (void)tileIndex;
}

// FUNCTION: IMPERIALISM 0x0059f730
undefined TTacticalBattle::FinalizeTacticalBattleOutcome(int) {
  return 0;
}

// SYNTHETIC: IMPERIALISM 0x0059f750
// TTacticalBattle::GetRuntimeClass

IMPLEMENT_DYNCREATE(TTacticalBattle, TObject)

// Body assignments (not a member-init list) reproduce the original store order
// +4, +8, +0x24, +0x1c, +0x34, +0x74, +0x20, which does not follow declaration order.
// FUNCTION: IMPERIALISM 0x0059f770
TTacticalBattle::TTacticalBattle() {
  tileGrid4 = 0;
  battleView8 = 0;
  tileMoveCostArray24 = 0;
  selectedUnit1c = 0;
  battlefieldColumnCount34 = 0;
  roundCounter74 = 0;
  recordList20 = 0;
}

// SYNTHETIC: IMPERIALISM 0x0059f7a0
// TTacticalBattle::`scalar deleting destructor'
TTacticalBattle::~TTacticalBattle() {}

// Battle-state assembly (Mac oracle: InitTacticalBattle): links both players to the
// battle, tags each side's units (side20 = 0/1) with a random field24 seed and collects
// them into recordList20, seeds the selection from the +0x18 side, sizes battlefieldColumnCount34 from
// the longest unit range (+11), (re)allocates the per-tile work arrays and the hex tile
// grid, and publishes the battle to g_pActiveTacticalBattle.
// FUNCTION: IMPERIALISM 0x0059f890
void TTacticalBattle::BuildTacticalBattleStateFromBothSides(TTacticalPlayer* ourPlayer,
                                                            TTacticalPlayer* enemyPlayer) {
  tacticalPlayer14 = ourPlayer;
  tacticalPlayer18 = enemyPlayer;
  ourPlayer->battle14 = this;
  enemyPlayer->battle14 = this;

  {
    CIterator ourIter(ourPlayer->unitList4);
    for (TTacticalUnit* ourUnit = static_cast<TTacticalUnit*>(ourIter.Reset()); ourIter.More();
         ourUnit = static_cast<TTacticalUnit*>(ourIter.Advance())) {
      ourUnit->side20 = 0;
      ourUnit->field24 = static_cast<short>(rand());
      recordList20->AddTail(ourUnit);
    }
  }
  {
    CIterator enemyIter(enemyPlayer->unitList4);
    for (TTacticalUnit* enemyUnit = static_cast<TTacticalUnit*>(enemyIter.Reset());
         enemyIter.More(); enemyUnit = static_cast<TTacticalUnit*>(enemyIter.Advance())) {
      enemyUnit->side20 = 1;
      enemyUnit->field24 = static_cast<short>(rand());
      recordList20->AddTail(enemyUnit);
    }
  }

  battleLive10 = 0;
  currentSideC = 1;
  battleOutcomeCode44 = 0;
  selectedUnit1c = enemyPlayer->SelectNextTacticalUnitForDoneCommand();

  // battlefieldColumnCount34 = longest per-unit range across both sides + 11 (the original calls the
  // range virtual twice per improving unit).
  int maxUnitRange = 0;
  {
    CIterator rangeIter(recordList20);
    for (TTacticalUnit* rangeUnit = static_cast<TTacticalUnit*>(rangeIter.Reset());
         rangeIter.More(); rangeUnit = static_cast<TTacticalUnit*>(rangeIter.Advance())) {
      if (rangeUnit->GetUnitRange() > maxUnitRange) {
        maxUnitRange = rangeUnit->GetUnitRange();
      }
    }
  }
  battlefieldColumnCount34 = maxUnitRange + 11;

  tileMoveCostArray24 = new short[tacticalTileCount3c];
  for (int costIdx = 0; costIdx < tacticalTileCount3c; ++costIdx) {
    tileMoveCostArray24[costIdx] = -1;
  }
  tileThreatLevelArray28 = new char[tacticalTileCount3c];
  for (int threatIdx = 0; threatIdx < tacticalTileCount3c; ++threatIdx) {
    tileThreatLevelArray28[threatIdx] = 0;
  }
  tileIntArray2c = new int[tacticalTileCount3c];
  for (int workIdxA = 0; workIdxA < tacticalTileCount3c; ++workIdxA) {
    tileIntArray2c[workIdxA] = 0;
  }
  tileIntArray30 = new int[tacticalTileCount3c];
  for (int workIdxB = 0; workIdxB < tacticalTileCount3c; ++workIdxB) {
    tileIntArray30[workIdxB] = 0;
  }

  if (tileGrid4 != 0) {
    delete[] tileGrid4;
  }
  tileGrid4 = new TacticalTileRecord[tacticalTileCount3c];
  TacticalTileRecord* record = tileGrid4;
  for (int tile = 0; tile < tacticalTileCount3c; ++tile, ++record) {
    record->terrainType0 = 0;
    record->occupant4 = 0;
    record->deployMark8 = 0;
    record->mineRunStateC = -1;
    record->trenchMask10 = 0;
  }

  g_pActiveTacticalBattle = this;
}

// Tears the battle down: frees the owned scratch planes and the tile grid, empties
// and frees the record list and both side players, clears the live-battle global, and
// self-deletes. The recordList20->RemoveAll() dispatch is unguarded in the original
// (crashes on a null list), unlike every other member here.
// FUNCTION: IMPERIALISM 0x0059fb50
void TTacticalBattle::Free() {
  if (tileMoveCostArray24 != 0) {
    delete[] tileMoveCostArray24;
  }
  recordList20->RemoveAll();
  if (recordList20 != 0) {
    recordList20->Free();
  }
  if (tacticalPlayer14 != 0) {
    tacticalPlayer14->Free();
  }
  if (tacticalPlayer18 != 0) {
    tacticalPlayer18->Free();
  }
  if (tileGrid4 != 0) {
    delete[] tileGrid4;
  }
  if (tileThreatLevelArray28 != 0) {
    delete[] tileThreatLevelArray28;
  }
  if (tileIntArray2c != 0) {
    delete[] tileIntArray2c;
  }
  if (tileIntArray30 != 0) {
    delete[] tileIntArray30;
  }
  g_pActiveTacticalBattle = 0;
  delete this;
}

// FUNCTION: IMPERIALISM 0x0059fc20
void TTacticalBattle::StartBattle() {
  tacticalPlayer18->StartBattle();
}

// Round handover once the current side is done deploying; the 'retr' tag name is the
// command-dispatch label, not a retreat walk.
// FUNCTION: IMPERIALISM 0x0059fd10
void TTacticalBattle::HandleTacticalCommandTag_retr() {
  currentSideC = (currentSideC == 0);
  selectedUnit1c = (&tacticalPlayer14)[currentSideC]->SelectNextTacticalUnitForDoneCommand();
  if (battleView8 != 0) {
    TTacticalToolbar* toolbar = static_cast<TTacticalToolbar*>(
        battleView8->ownerContext->ResolveControlByTag(kControlTagTool));
    toolbar->AssertValid();
    toolbar->UpdateTacticalCurrentUnitControlAndDialogLabel(selectedUnit1c);
    toolbar->ForceRedraw();
  }
  TTacticalPlayer* incomingPlayer = (&tacticalPlayer14)[currentSideC];
  if (incomingPlayer->sideReadyFlag10 != 0) {
    FinalizeTacticalTurnStateAndQueueEvent232A();
    return;
  }
  incomingPlayer->StartBattle();
}

// FUNCTION: IMPERIALISM 0x0059fdb0
void TTacticalBattle::FinalizeTacticalTurnStateAndQueueEvent232A() {
  tacticalPlayer14->RetireUndeployedUnitsToReserveList();
  tacticalPlayer18->RetireUndeployedUnitsToReserveList();
  recordList20->SortBy(&CompareTacticalUnitsForTurnOrder, this);
  battleLive10 = 1;
  if (battleView8 != 0) {
    TTacticalToolbar* toolbar = static_cast<TTacticalToolbar*>(
        battleView8->ownerContext->ResolveControlByTag(kControlTagTool));
    toolbar->AssertValid();
    toolbar->ConfigureTacticalTargetDoneRetreatAutoControls(1);
  }
  // TSortedList ordinals are 1-based, so GetEntryByOrdinal(GetCount()) is the tail.
  selectedUnit1c =
      static_cast<TTacticalUnit*>(recordList20->GetEntryByOrdinal(recordList20->GetCount()));
  QueueTacticalEventPacket232A();
}

// Selection/UI helpers dispatched by the command family; bodies not yet ported.

// Applies a completed selection: records the unit, recomputes its reachable-tile cost
// map, pushes the unit into the 'tool' toolbar cluster, recenters the viewport on the
// unit's tile when it is on-grid, and refreshes the view + selection marker.
// FUNCTION: IMPERIALISM 0x0059fe40
void TTacticalBattle::ApplyTacticalDoneSelectionAndRefreshUi(TTacticalUnit* unit) {
  selectedUnit1c = unit;
  ComputeTacticalReachableTileCostsByUnitCategory(unit);
  if (battleView8 != 0) {
    TTacticalToolbar* toolbar = static_cast<TTacticalToolbar*>(
        battleView8->ownerContext->ResolveControlByTag(kControlTagTool));
    toolbar->AssertValid();
    toolbar->UpdateTacticalCurrentUnitControlAndDialogLabel(selectedUnit1c);
    int tileIndex = unit->tileIndex8;
    int row = tileIndex / 29;
    int column = ((row & 1) + tileIndex % 29 * 2) / 2;
    if (tileIndex >= 0 && row >= 0 && row < 15 && column >= 0 &&
        column < battlefieldColumnCount34) {
      battleView8->CenterViewportAroundGridIndexAndSnap(tileIndex);
    }
    battleView8->RefreshControl();
    battleView8->SpawnTacticalUiMarkerAtUnitTile();
  }
}

// Flood-fills tileMoveCostArray24 with the cheapest action-point cost for the unit to
// reach each tile (-1 = unreachable): seeds the unit's tile at 0, then sweeps the grid
// once per 10-point cost band, relaxing each tile's six hex neighbors through the
// per-category terrain move-cost table. A neighbor is rejected when occupied, in grid
// row 0, behind a live fort wall (deployMark8 > 1 with fort strength left -- except
// the gate column battlefieldColumnCount34 - 6 at rows 5/7/9 for the attacking side),
// over the action-point budget, worse than an already-found cost, flanked by an enemy
// on an adjacent ring neighbor, or in the opponent's entry column. Ends by rebuilding
// the threat plane for the unit.
// FUNCTION: IMPERIALISM 0x0059ff20
void TTacticalBattle::ComputeTacticalReachableTileCostsByUnitCategory(TTacticalUnit* unit) {
  int neighborTiles[6];
  int categoryCode = g_awTacticalUnitCategoryCodeBySlot[unit->unitTypeC];
  short* moveCosts = tileMoveCostArray24;
  int actionPoints = unit->actionPoints28;
  int fillIndex;
  for (fillIndex = 0; fillIndex < tacticalTileCount3c; ++fillIndex) {
    moveCosts[fillIndex] = -1;
  }
  int startTile = unit->tileIndex8;
  if (startTile < 0 || startTile >= tacticalTileCount3c) {
    return;
  }
  int edgeColumn;
  if (unit->side20 == 0) {
    edgeColumn = battlefieldColumnCount34 - 1;
  } else {
    edgeColumn = 0;
  }
  moveCosts[startTile] = 0;
  int costLevel;
  for (costLevel = 0; costLevel <= actionPoints; costLevel += 10) {
    int column = 0;
    short* costCursor = moveCosts + tacticalTileStride40;
    int tile;
    for (tile = tacticalTileStride40; tile < tacticalTileCount3c; ++tile) {
      if (column < battlefieldColumnCount34 && column != edgeColumn && *costCursor >= costLevel) {
        ComputeHexNeighborTileIndices_005A0420(tile, neighborTiles);
        int direction;
        int* neighborCursor = neighborTiles;
        for (direction = 0; direction < 6; ++direction, ++neighborCursor) {
          short neighborIndex = static_cast<short>(*neighborCursor);
          if (neighborIndex == -1) {
            continue;
          }
          TacticalTileRecord* record = &tileGrid4[neighborIndex];
          if (record->occupant4 != 0) {
            continue;
          }
          if (neighborIndex < tacticalTileStride40) {
            continue;
          }
          if (record->deployMark8 > 1 && fortStrengthPoints54[neighborIndex / 0x1d / 2] > 0) {
            int wallRow = neighborIndex / 0x1d;
            int wallColumn = neighborIndex % 0x1d;
            if (wallRow != 5 && wallRow != 7 && wallRow != 9) {
              continue;
            }
            if (((wallRow & 1) + wallColumn * 2) / 2 != battlefieldColumnCount34 - 6) {
              continue;
            }
            if (unit->side20 != 1) {
              continue;
            }
          }
          short newCost = static_cast<short>(
              g_awTacticalMoveCostByCategoryAndTerrain[categoryCode * 5 + record->terrainType0] +
              *costCursor);
          if (newCost > actionPoints) {
            continue;
          }
          short existingCost = moveCosts[neighborIndex];
          if (existingCost != -1 && existingCost <= newCost) {
            continue;
          }
          unsigned char blockedByAdjacentEnemy = 0;
          short prevDirection = static_cast<short>((direction > 0) ? direction - 1 : 5);
          int prevNeighbor = neighborTiles[prevDirection];
          if (prevNeighbor != -1) {
            TTacticalUnit* prevOccupant = tileGrid4[prevNeighbor].occupant4;
            if (prevOccupant != 0 && prevOccupant->side20 != unit->side20) {
              blockedByAdjacentEnemy = 1;
            }
          }
          // Transcribed as compiled: the original indexes neighborTiles[1] (or [0] when
          // direction >= 5), NOT [direction + 1]. The branchless codegen proves the
          // literal constants; likely an original bug for the intended "next ring
          // neighbor", kept literal for byte match ((4 < direction) - 1 & 1 == 0 for
          // direction >= 5, else 1).
          short nextDirection = static_cast<short>((direction >= 5) ? 0 : 1);
          int nextNeighbor = neighborTiles[nextDirection];
          if (nextNeighbor != -1) {
            TTacticalUnit* nextOccupant = tileGrid4[nextNeighbor].occupant4;
            if (nextOccupant != 0 && nextOccupant->side20 != unit->side20) {
              blockedByAdjacentEnemy = 1;
            }
          }
          if (blockedByAdjacentEnemy != 0) {
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
  PropagateTileAccessibilityStrengthLevels(unit);
}

// Rebuilds tileThreatLevelArray28 from the given unit's perspective: seeds each tile
// holding a live enemy (other side, state1c == 0) with that enemy's range + 1 and
// every other tile with 0, then decays the levels outward -- one pass per level from
// 19 down, spreading level - 1 onto any hex neighbor still below it.
// FUNCTION: IMPERIALISM 0x005a02e0
void TTacticalBattle::PropagateTileAccessibilityStrengthLevels(TTacticalUnit* unit) {
  int neighborTiles[6];
  char unitSide = static_cast<char>(unit->side20);
  char* threatLevels = tileThreatLevelArray28;
  int seedTile;
  for (seedTile = 0; seedTile < tacticalTileCount3c; ++seedTile) {
    TTacticalUnit* occupant = tileGrid4[seedTile].occupant4;
    if (occupant != 0 && occupant->side20 != unitSide && occupant->state1c == 0) {
      occupant->AssertValid();
      threatLevels[seedTile] = static_cast<char>(occupant->GetUnitRange() + 1);
    } else {
      threatLevels[seedTile] = 0;
    }
  }
  int level;
  for (level = 0x13; level > 0; --level) {
    char* levelCursor = tileThreatLevelArray28;
    int tile;
    for (tile = 0; tile < tacticalTileCount3c; ++tile, ++levelCursor) {
      if (*levelCursor == level) {
        ComputeHexNeighborTileIndices_005A0420(tile, neighborTiles);
        int neighborSlot;
        int* neighborCursor = neighborTiles;
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

// Six hex neighbors of tileIndex into outNeighborTiles6[0..5], -1 = off-grid.
// Order: [0] up-right, [1] right, [2] down-right, [3] down-left, [4] left, [5] up-left
// (odd/even rows of the 29-wide staggered grid use shifted column offsets).
// FUNCTION: IMPERIALISM 0x005a0420
void TTacticalBattle::ComputeHexNeighborTileIndices_005A0420(int tileIndex,
                                                             int* outNeighborTiles6) {
  if ((tileIndex / tacticalTileStride40) & 1) {
    outNeighborTiles6[0] = tileIndex - tacticalTileStride40 + 1;
    outNeighborTiles6[1] = tileIndex + 1;
    outNeighborTiles6[2] = tileIndex + tacticalTileStride40 + 1;
    outNeighborTiles6[3] = tileIndex + tacticalTileStride40;
    outNeighborTiles6[4] = tileIndex - 1;
    outNeighborTiles6[5] = tileIndex - tacticalTileStride40;
  } else {
    outNeighborTiles6[0] = tileIndex - tacticalTileStride40;
    outNeighborTiles6[1] = tileIndex + 1;
    outNeighborTiles6[2] = tileIndex + tacticalTileStride40;
    outNeighborTiles6[3] = tileIndex + tacticalTileStride40 - 1;
    outNeighborTiles6[4] = tileIndex - 1;
    outNeighborTiles6[5] = tileIndex - tacticalTileStride40 - 1;
  }
  if ((tileIndex + 1) % tacticalTileStride40 == 0) {
    // Right edge: no east neighbor; odd rows also lose both +1-column diagonals.
    outNeighborTiles6[1] = -1;
    if ((tileIndex / tacticalTileStride40) & 1) {
      outNeighborTiles6[0] = -1;
      outNeighborTiles6[2] = -1;
    }
  } else if (tileIndex % tacticalTileStride40 == 0) {
    // Left edge: no west neighbor; even rows also lose both -1-column diagonals.
    outNeighborTiles6[4] = -1;
    if (!((tileIndex / tacticalTileStride40) & 1)) {
      outNeighborTiles6[3] = -1;
      outNeighborTiles6[5] = -1;
    }
  }
  if (tileIndex >= tacticalTileCount3c - tacticalTileStride40) {
    // Bottom row: no southern neighbors.
    outNeighborTiles6[2] = -1;
    outNeighborTiles6[3] = -1;
  } else if (tileIndex < tacticalTileStride40) {
    // Top row: no northern neighbors.
    outNeighborTiles6[0] = -1;
    outNeighborTiles6[5] = -1;
  }
}

// FUNCTION: IMPERIALISM 0x005a0550
unsigned char TTacticalBattle::IsHexNeighborTileIndex(int tileIndex, int candidateTileIndex) {
  int neighbors[6];
  ComputeHexNeighborTileIndices_005A0420(tileIndex, neighbors);
  int direction;
  for (direction = 0; direction < 6; ++direction) {
    if (neighbors[direction] == candidateTileIndex) {
      return 1;
    }
  }
  return 0;
}

// Hover-cursor state for `tileIndex` relative to the current selection/side. Before the
// battle goes live: hovering the current side's own unit returns 0xc; otherwise a per-side
// deployment-zone column band (columns 3-5 for side 0, the mirrored band at the far edge for
// side 1) returns 3, everything else 2. Once live: checks the selected unit against the
// hovered tile for reachable move (4), manned fort wall (9), adjacent dig/mine target (7),
// adjacent rally target (8), ranged/fire attack target (5), adjacent melee attack target
// (0xa), or hovering the selection itself (6). 0 when nothing applies.
// FUNCTION: IMPERIALISM 0x005a05a0
int TTacticalBattle::ComputeTacticalHoverCursorStateIndex(int tileIndex) {
  TTacticalPlayer* currentSidePlayer = (&tacticalPlayer14)[currentSideC];
  if (!currentSidePlayer->IsTacticalControllerOwnedByActiveNation()) {
    return 1;
  }

  if (battleLive10 == 0) {
    TacticalTileRecord* tile = &tileGrid4[tileIndex];
    TTacticalUnit* occupant = tile->occupant4;
    if (occupant != 0 && occupant->side20 == currentSideC) {
      return 0xc;
    }

    int column = tileIndex % tacticalTileStride40;
    if (tileIndex >= tacticalTileStride40 && tile->terrainType0 != 4 && occupant == 0) {
      if (currentSideC == 0) {
        if (column > 2 && column < 6) {
          return 3;
        }
      } else if (column <= battlefieldColumnCount34 - 3 && column >= battlefieldColumnCount34 - 5) {
        return 3;
      }
    }
    return 2;
  }

  short unitCategoryCode0 = g_awTacticalUnitCategoryCodeBySlot[selectedUnit1c->unitTypeC];
  int state = 0;

  if (unitCategoryCode0 == 8) {
    int neighbors[6];
    ComputeHexNeighborTileIndices_005A0420(selectedUnit1c->tileIndex8, neighbors);
    bool tileIsNeighbor = false;
    for (int i = 0; i < 6; ++i) {
      if (neighbors[i] == tileIndex) {
        tileIsNeighbor = true;
        break;
      }
    }
    if (tileIsNeighbor) {
      TacticalTileRecord* tile = &tileGrid4[tileIndex];
      if (tile->deployMark8 > 1 && fortStrengthPoints54[tileIndex / tacticalTileStride40 / 2] > 0) {
        state = 9;
      } else if (selectedUnit1c->actionPoints28 >=
                     g_awUnitTypeBaseActionPointTable[selectedUnit1c->unitTypeC] / 2 &&
                 (tile->trenchMask10 & 0xc0) == 0 && tile->occupant4 == 0 &&
                 tile->terrainType0 != 4) {
        state = 7;
      }
    }
  } else if (unitCategoryCode0 == 9) {
    int neighbors[6];
    ComputeHexNeighborTileIndices_005A0420(selectedUnit1c->tileIndex8, neighbors);
    bool tileIsNeighbor = false;
    for (int i = 0; i < 6; ++i) {
      if (neighbors[i] == tileIndex) {
        tileIsNeighbor = true;
        break;
      }
    }
    if (tileIsNeighbor) {
      TTacticalUnit* occupant = tileGrid4[tileIndex].occupant4;
      if (occupant != 0 && occupant->side20 == selectedUnit1c->side20) {
        state = 8;
      }
    }
  }

  if (state == 0) {
    TacticalTileRecord* tile = &tileGrid4[tileIndex];
    if (tile->deployMark8 > 1 && fortStrengthPoints54[tileIndex / tacticalTileStride40 / 2] > 0) {
      // Manned fort wall: direct-fire units can't shoot over it at all; indirect-fire units
      // can if in range (the wall-crossing check inside IsTacticalTargetTileReachableForAction
      // is skipped by passing directFireFlag=0).
      short unitCategoryCode = g_awTacticalUnitCategoryCodeBySlot[selectedUnit1c->unitTypeC];
      if (g_afTacticalDirectFireFlagByCategory[unitCategoryCode] ==
          g_fTacticalRetreatQualityWeightDefault_00669EC0) {
        char reachable =
            selectedUnit1c->selectedFlag18 == 0
                ? 0
                : IsTacticalTargetTileReachableForAction(selectedUnit1c->tileIndex8, tileIndex, 0,
                                                         selectedUnit1c->GetUnitRange());
        if (reachable != 0) {
          return 5;
        }
      }
      if (tileMoveCostArray24[tileIndex] > 0 && tile->occupant4 == 0) {
        return 4;
      }
    } else {
      if (tileMoveCostArray24[tileIndex] > 0 && tile->occupant4 == 0) {
        return 4;
      }
      TTacticalUnit* occupant = tile->occupant4;
      if (occupant != 0 && occupant->side20 != currentSideC && unitCategoryCode0 != 8) {
        char reachable =
            selectedUnit1c->selectedFlag18 == 0
                ? 0
                : IsTacticalTargetTileReachableForAction(
                      selectedUnit1c->tileIndex8, tileIndex,
                      static_cast<char>(
                          g_afTacticalDirectFireFlagByCategory
                              [g_awTacticalUnitCategoryCodeBySlot[selectedUnit1c->unitTypeC]]),
                      selectedUnit1c->GetUnitRange());
        if (reachable != 0) {
          int neighbors[6];
          ComputeHexNeighborTileIndices_005A0420(selectedUnit1c->tileIndex8, neighbors);
          bool tileIsNeighbor = false;
          for (int i = 0; i < 6; ++i) {
            if (neighbors[i] == tileIndex) {
              tileIsNeighbor = true;
              break;
            }
          }
          return tileIsNeighbor ? 0xa : 5;
        }
      } else if (occupant == selectedUnit1c) {
        return 6;
      }
    }
  }
  return state;
}

// Maps the hover-state classifier to the cursor resource used by the tactical view. Enemy
// targets and intact fort sections refine the generic state with the actual reachability test.
// FUNCTION: IMPERIALISM 0x005a0a90
short TTacticalBattle::ResolveTacticalHoverCursorResourceId(int tileIndex) {
  short cursorsByHoverState[13] = {0,     0x402, 0x3f0, 0x3ec, 0x3ed, 0x3fc, 0x3f0,
                                   0x3ff, 0x41d, 0x3fe, 0x3fd, 0x403, 0x41c};
  int hoverState = ComputeTacticalHoverCursorStateIndex(tileIndex);
  TTacticalPlayer* player = (&tacticalPlayer14)[currentSideC];
  if (player->notWatchedFlagE != 0) {
    return 0x402;
  }

  if (selectedUnit1c != 0 && hoverState == 0) {
    TacticalTileRecord* tile = &tileGrid4[tileIndex];
    TTacticalUnit* occupant = tile->occupant4;
    short category = g_awTacticalUnitCategoryCodeBySlot[selectedUnit1c->unitTypeC];
    bool enemyTarget = occupant != 0 && occupant->side20 != currentSideC;
    bool intactFortSection = g_afTacticalDirectFireFlagByCategory[category] ==
                                 g_fTacticalRetreatQualityWeightDefault_00669EC0 &&
                             tile->deployMark8 > 1 && fortStrengthPoints54[tileIndex / 58] > 0 &&
                             selectedUnit1c->attackTarget30 == 0;
    if (enemyTarget || intactFortSection) {
      char directFire = static_cast<char>(g_afTacticalDirectFireFlagByCategory[category]);
      return IsTacticalTargetTileReachableForAction(selectedUnit1c->tileIndex8, tileIndex,
                                                    directFire, selectedUnit1c->GetUnitRange())
                 ? 0x403
                 : 0x400;
    }
  }
  return cursorsByHoverState[hoverState];
}

// Top-level tactical toolbar command dispatch for the current side. Ignored unless the side
// is human-watched; then routes the 4-char command tag to the matching handler.
// FUNCTION: IMPERIALISM 0x005a0c50
void TTacticalBattle::HandleTacticalBattleCommandTag(int commandTag) {
  TTacticalPlayer* player = (&tacticalPlayer14)[currentSideC];
  if (player->watchFlagD == 0) {
    return;
  }
  switch (commandTag) {
  case 0x646f6e65: // 'done'
    if (battleLive10 == 1) {
      QueueTacticalEventPacket232A();
      return;
    }
    ApplyTacticalDoneSelectionAndRefreshUi(player->SelectNextTacticalUnitForDoneCommand());
    return;
  case 0x6175746f: // 'auto'
    player->ProceedAfterBattleIntroAccepted();
    return;
  case 0x72657472: // 'retr'
    if (battleLive10 == 0) {
      HandleTacticalCommandTag_retr();
      return;
    }
    if (g_pUiRuntimeContext->ShowLocalizedUiPromptByGroupAndIndex(0x273d, 0x32, 1, 1)) {
      player = (&tacticalPlayer14)[currentSideC];
      player->fieldF = 1;
      player->ProceedAfterBattleIntroAccepted();
    }
    return;
  case 0x736b6970: // 'skip'
    player->HandleTacticalCommandTag_skip();
    return;
  case 0x74617267: // 'targ'
    HandleTacticalCommandTag_targ();
    return;
  }
}

// Ends the current action round: clears the follow-up latch and posts a 'next move'
// command (turn event 0x232a) carrying this battle to the UI root controller.
// FUNCTION: IMPERIALISM 0x005a0d60
void TTacticalBattle::QueueTacticalEventPacket232A() {
  pendingEndOfActionFlag48 = 0;
  TNextMoveCommand* command = new TNextMoveCommand();
  command->InitializeRangePair(0x232a, g_pGlobalUiRootController, 0, 0, 0);
  command->battle18 = this;
  g_pGlobalUiRootController->DispatchUiSelectionToHandler(command);
}

// FUNCTION: IMPERIALISM 0x005a0ea0
void TTacticalBattle::AdvanceToNextTacticalUnitTurnStep() {
  int position;
  if (selectedUnit1c == 0) {
    position = 1;
  } else {
    position = 1;
    CIterator cursor(recordList20);
    for (TTacticalUnit* unit = static_cast<TTacticalUnit*>(cursor.Reset()); cursor.More();
         unit = static_cast<TTacticalUnit*>(cursor.Advance())) {
      unit->AssertValid();
      if (unit == selectedUnit1c) {
        break;
      }
      ++position;
    }
  }

  TTacticalUnit* candidateUnit;
  for (;;) {
    int totalCount = recordList20->GetCount();
    if (position == totalCount) {
      ++roundCounter74;
      if (roundCounter74 >= 0x23) {
        EvaluateTacticalSideStateAndShowBattleSummaryDialog();
        QueueTacticalEventPacket232A();
        return;
      }
      position = 1;
    } else {
      ++position;
    }
    candidateUnit = static_cast<TTacticalUnit*>(recordList20->GetEntryByOrdinal(position));
    candidateUnit->AssertValid();
    if (candidateUnit->state1c != 3) {
      break;
    }
  }

  candidateUnit->AssertValid();
  SetCurrentTacticalUnitSelection(candidateUnit, 0);
  if (candidateUnit->state1c == 1) {
    ProcessTacticalUnitState1TurnStep(candidateUnit);
    return;
  }
  if (g_awTacticalUnitCategoryCodeBySlot[candidateUnit->unitTypeC] == 8 &&
      static_cast<TArmyTacUnit*>(candidateUnit)->sapTargetTileIndex40 != -1) {
    AdvanceOrResetTacticalTileStateRunAndMaybeDispatchPacket(
        static_cast<TArmyTacUnit*>(candidateUnit));
    return;
  }
  (&tacticalPlayer14)[currentSideC]->AdvanceTacticalTurnPulse();
}

// Tactical command family: each handler echoes the command to multiplayer when it
// originates locally (remoteFlag == 0), then applies it to the battle state. The
// 0x545940 turn-event dispatcher re-enters these with remoteFlag = 1.

// Selects a tactical unit: echoes a 'sele' command in multiplayer, flips the current
// side to match the unit, refreshes the action toolbar + old/new selection rects,
// refills the unit's action points, and applies the selection state.
// FUNCTION: IMPERIALISM 0x005a1010
void TTacticalBattle::SetCurrentTacticalUnitSelection(TTacticalUnit* unit, char remoteFlag) {
  if (remoteFlag == 0) {
    unsigned char multiplayerActive = g_pSimMgr->multiplayerSessionRole != 0;
    if (multiplayerActive != 0) {
      g_pGameFlowState->EmitTacticalCommandPacket(0x73656c65 /* 'sele' */, unit, 0, 0);
    }
  }
  if (unit->side20 != currentSideC) {
    currentSideC = currentSideC == 0;
  }
  if (battleView8 != 0) {
    battleView8->UpdateTacticalActionControlBitmapForCurrentUnit(static_cast<char>(unit->side20));
  }
  if (battleView8 != 0) {
    battleView8->InvalidateTacticalUnitTileRect(selectedUnit1c);
  }
  if (battleView8 != 0) {
    battleView8->InvalidateTacticalUnitTileRect(unit);
  }
  unit->actionPoints28 = unit->GetBaseActionPoints();
  unit->selectedFlag18 = 1;
  ApplyTacticalDoneSelectionAndRefreshUi(unit);
}

// FUNCTION: IMPERIALISM 0x005a10e0
void TTacticalBattle::ProcessTacticalUnitState1TurnStep(TTacticalUnit* unit) {
  int bestDistance = 999;
  int originalTile = unit->tileIndex8;
  BuildTacticalDistanceFieldForSide(unit->side20 == 0);

  int bestTile = originalTile;
  for (int i = 0; i < tacticalTileCount3c; ++i) {
    if (tileMoveCostArray24[i] != -1 && tileIntArray30[i] != -1 &&
        (tileIntArray30[i] < bestDistance ||
         (tileIntArray30[i] == bestDistance && (rand() & 1) != 0))) {
      bestDistance = tileIntArray30[i];
      bestTile = i;
    }
  }
  if (bestTile != unit->tileIndex8) {
    MoveTacticalUnitTowardTile(unit, bestTile);
  }

  if (unit->state1c == 1) {
    TList* sideUnitList =
        (unit->side20 == 0) ? tacticalPlayer18->unitList4 : tacticalPlayer14->unitList4;

    int nearbyThreshold = 0;
    CIterator cursor(sideUnitList);
    for (TTacticalUnit* candidate = static_cast<TTacticalUnit*>(cursor.Reset()); cursor.More();
         candidate = static_cast<TTacticalUnit*>(cursor.Advance())) {
      if (candidate->state1c != 0) {
        continue;
      }
      int distance = ComputeHexTileDistanceFromIndices(unit->tileIndex8, candidate->tileIndex8);
      if (distance < 3) {
        nearbyThreshold = static_cast<int>(candidate->GetBaseAttackPower() * candidate->strength4 +
                                           nearbyThreshold);
      }
    }

    int ownThreshold = static_cast<int>(unit->GetBaseAttackPower() * (unit->strength4 * 3));
    if (nearbyThreshold > ownThreshold) {
      nearbyThreshold = ownThreshold;
    }

    bool shouldDestroy = true;
    if (unit->tileIndex8 != originalTile) {
      shouldDestroy = false;
      if (nearbyThreshold > 0) {
        int remainder = rand() % nearbyThreshold;
        if (unit->GetBaseAttackPower() * unit->strength4 < static_cast<float>(remainder)) {
          shouldDestroy = true;
        }
      }
    }

    if (shouldDestroy) {
      if (battleView8 != 0) {
        battleView8->PlayTacticalTileEffect(unit->tileIndex8, 0xf8c, 10);
      }
      unit->ApplyTacticalDamage(unit->strength4, 0);
      tileGrid4[unit->tileIndex8].occupant4 = 0;
      unit->tileIndex8 = -1;
      if (battleView8 != 0) {
        battleView8->InvalidateTacticalUnitTileRect(unit);
      }
      EvaluateTacticalSideStateAndShowBattleSummaryDialog();
    }
  }
  QueueTacticalEventPacket232A();
}

// FUNCTION: IMPERIALISM 0x005a1400
unsigned char TTacticalBattle::HasEnemyUnitOnTilesFlankingHexDirection(int tileIndex,
                                                                       int hexDirection,
                                                                       char side) {
  int neighborTiles[6];
  unsigned char foundEnemy = 0;
  ComputeHexNeighborTileIndices_005A0420(tileIndex, neighborTiles);
  int clockwiseDirection = (hexDirection == 5) ? 0 : hexDirection + 1;
  int counterDirection = (hexDirection == 0) ? 5 : hexDirection - 1;
  int clockwiseTile = neighborTiles[clockwiseDirection];
  if (clockwiseTile != -1) {
    TTacticalUnit* clockwiseOccupant = tileGrid4[clockwiseTile].occupant4;
    if (clockwiseOccupant != 0 && clockwiseOccupant->side20 != side) {
      foundEnemy = 1;
    }
  }
  if (foundEnemy == 0) {
    int counterTile = neighborTiles[counterDirection];
    if (counterTile != -1) {
      TTacticalUnit* counterOccupant = tileGrid4[counterTile].occupant4;
      if (counterOccupant != 0 && counterOccupant->side20 != side) {
        foundEnemy = 1;
      }
    }
  }
  return foundEnemy;
}

// Listing 0x005a1520 reads the stack byte without initializing it on the headless,
// unbroken-morale path; preserve that retail behavior but keep the warning elsewhere.
IMPERIALISM_BEGIN_RETAIL_UNINITIALIZED_READ
// FUNCTION: IMPERIALISM 0x005a1520
void TTacticalBattle::MoveTacticalUnitTowardTile(TTacticalUnit* unit, int targetTileIndex) {
  int pathTiles[12];
  pathTiles[0] = targetTileIndex;
  int stepCount = BuildPathToTargetByDistanceField(targetTileIndex, 0, unit->tileIndex8, pathTiles);
  if (stepCount == -1) {
    return;
  }

  // pathTiles[stepCount] is the unit's own tile; walk down to pathTiles[0] = target.
  unsigned char stopped = 0;
  if (stepCount != 0) {
    int* pathCursor = &pathTiles[stepCount];
    do {
      if (stopped != 0) {
        break;
      }
      unit->AssertValid();
      MoveTacticalUnitBetweenTiles(unit, pathCursor[0], pathCursor[-1], 0);
      --pathCursor;
      --stepCount;
      stopped = ResolveTacticalReactionChecksForTile(*pathCursor);
    } while (stepCount != 0);
  }

  unit->actionPoints28 -= tileMoveCostArray24[pathTiles[stepCount]];
  if (battleView8 != 0) {
    battleView8->InvalidateTacticalUnitTileRect(unit);
  }
  if (battleView8 != 0) {
    battleView8->ForceRedraw();
  }

  // Logical column on the doubled-x hex grid (odd rows are staggered half a tile).
  int arrivedTile = pathTiles[stepCount];
  int exitColumn = (((arrivedTile / 29) & 1) + 2 * (arrivedTile % 29)) / 2;
  int side = unit->side20;
  if ((side == 1 && exitColumn >= battlefieldColumnCount34 - 1) || (side == 0 && exitColumn == 0)) {
    unsigned char unitMayLeave;
    if (unit->state1c == 1) {
      unitMayLeave = 1;
    } else if (battleView8 != 0) {
      TTacticalPlayer* sidePlayer = (side == 0) ? tacticalPlayer14 : tacticalPlayer18;
      unitMayLeave = sidePlayer->AlwaysTrueTacticalPredicate10(unit);
    }
    // Original bug (faithful): unitMayLeave is read uninitialized when the battle runs
    // headless (battleView8 == 0) and the unit's morale is unbroken -- the original omits
    // the else branch too.
    if (unitMayLeave != 0) {
      int exitTile = pathTiles[stepCount];
      unit->state1c = 2;
      unit->tileIndex8 = -2;
      tileGrid4[exitTile].occupant4 = 0;
      EvaluateTacticalSideStateAndShowBattleSummaryDialog();
    }
  }

  ComputeTacticalReachableTileCostsByUnitCategory(unit);
  if (battleView8 != 0) {
    battleView8->RefreshControl();
  }
}
IMPERIALISM_END_RETAIL_UNINITIALIZED_READ

// Recursive distance-field path builder: when the walk tile is the goal, records it
// and returns the depth; otherwise collects the neighbors whose move cost is known
// (!= -1) and strictly downhill, orders them (lower cost first; on ties a zero-threat
// tile wins, two equal-threat-class tiles coin-flip), and recurses into each candidate
// until one reaches the goal. Returns the found path depth or -1.
// FUNCTION: IMPERIALISM 0x005a16e0
int TTacticalBattle::BuildPathToTargetByDistanceField(int walkTileIndex, int pathDepth,
                                                      int goalTileIndex, int* outPathTiles) {
  if (walkTileIndex == goalTileIndex) {
    outPathTiles[pathDepth] = walkTileIndex;
    return pathDepth;
  }
  int candidateTiles[6];
  int neighborTiles[6];
  int candidateCount = 0;
  int walkCost = tileMoveCostArray24[walkTileIndex];
  ComputeHexNeighborTileIndices_005A0420(walkTileIndex, neighborTiles);
  int* neighborCursor = neighborTiles;
  int* candidateCursor = candidateTiles;
  int remainingDirections = 6;
  do {
    int neighborTile = *neighborCursor;
    // NOTE(faithful): a -1 neighbor indexes tileMoveCostArray24[-1] in the original
    // too (out-of-bounds word read); do not add a guard.
    int neighborCost = tileMoveCostArray24[neighborTile];
    if (neighborCost != -1 && neighborCost < walkCost) {
      *candidateCursor = neighborTile;
      ++candidateCount;
      ++candidateCursor;
    }
    ++neighborCursor;
    --remainingDirections;
  } while (remainingDirections != 0);
  if (candidateCount == 0) {
    return -1;
  }
  if (candidateCount > 1) {
    // Quirky original sort: the compare slot stays fixed per outer pass while the
    // scan cursor always restarts at candidateTiles[1] (not curSlot + 1).
    int* curSlot = candidateTiles;
    for (int outerRemaining = candidateCount - 1; outerRemaining > 0; --outerRemaining) {
      int* nextSlot = &candidateTiles[1];
      for (int innerRemaining = candidateCount - 1; innerRemaining > 0; --innerRemaining) {
        int nextTile = *nextSlot;
        int curTile = *curSlot;
        unsigned char swapFlag = static_cast<unsigned char>(tileMoveCostArray24[nextTile] <
                                                            tileMoveCostArray24[curTile]);
        if (swapFlag == 0 && tileMoveCostArray24[nextTile] == tileMoveCostArray24[curTile]) {
          char nextThreat = tileThreatLevelArray28[nextTile];
          char curThreat = tileThreatLevelArray28[curTile];
          // Tiebreak (truth table verified against the listing): exactly one zero-threat
          // side -> it sorts first; both zero / both nonzero -> coin flip.
          if (nextThreat == 0) {
            if (curThreat != 0) {
              swapFlag = 1;
            } else {
              swapFlag = static_cast<unsigned char>(rand() & 1);
            }
          } else if (curThreat != 0) {
            swapFlag = static_cast<unsigned char>(rand() & 1);
          }
        }
        if (swapFlag != 0) {
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
    do {
      int foundDepth =
          BuildPathToTargetByDistanceField(*walkCursor, pathDepth + 1, goalTileIndex, outPathTiles);
      if (foundDepth != -1) {
        outPathTiles[pathDepth] = walkTileIndex;
        return foundDepth;
      }
      ++candidateSlot;
      ++walkCursor;
    } while (candidateSlot < candidateCount);
  }
  return -1;
}

// Moves a unit from one battle-grid tile to another: multiplayer 'move' echo, clear the
// source tile's occupant, optionally animate (suppressed when moveAnimSuppressCode4c == 7), re-anchor
// the unit on the destination tile, and refresh the affected view rects/marker.
// FUNCTION: IMPERIALISM 0x005a1910
void TTacticalBattle::MoveTacticalUnitBetweenTiles(TTacticalUnit* unit, int fromTileIndex,
                                                   int toTileIndex, char remoteFlag) {
  if (remoteFlag == 0) {
    unsigned char multiplayerActive = g_pSimMgr->multiplayerSessionRole != 0;
    if (multiplayerActive != 0) {
      g_pGameFlowState->EmitTacticalCommandPacket(0x6d6f7665 /* 'move' */, unit, fromTileIndex,
                                                  toTileIndex);
    }
  }
  if (battleView8 != 0) {
    battleView8->InvalidateTacticalUnitTileRect(unit);
  }
  tileGrid4[fromTileIndex].occupant4 = 0;
  if (battleView8 != 0) {
    battleView8->TriggerTacticalUiUpdate2711();
  }
  if (currentTacticalActionCode4c != 7) {
    if (battleView8 != 0) {
      battleView8->AnimateTacticalUnitMoveBetweenTiles(unit, fromTileIndex, toTileIndex);
    }
  }
  unit->tileIndex8 = toTileIndex;
  tileGrid4[toTileIndex].occupant4 = unit;
  if (battleView8 != 0) {
    battleView8->InvalidateTacticalUnitTileRect(unit);
  }
  if (battleView8 != 0) {
    battleView8->InvalidateTacticalHexTileRect(toTileIndex);
  }
  if (battleView8 != 0) {
    battleView8->SpawnTacticalUiMarkerAtUnitTile();
  }
}

// Reaction/opportunity fire when a unit enters a tile: every unit of the opposing side
// that is unbroken (state1c == 0), still latched for action (selectedFlag18), and has
// the entered tile in range resolves its action against the tile's occupant. Stops
// early when the occupant's strength hits 0; returns whether any reaction fired.
// FUNCTION: IMPERIALISM 0x005a1a20
unsigned char TTacticalBattle::ResolveTacticalReactionChecksForTile(int tileIndex) {
  unsigned char reactionFired = 0;
  TTacticalUnit* occupant = tileGrid4[tileIndex].occupant4;
  TTacticalPlayer* reactingPlayer = (occupant->side20 == 0) ? tacticalPlayer18 : tacticalPlayer14;
  CIterator reactorIter(reactingPlayer->unitList4);
  TTacticalUnit* reactor = static_cast<TTacticalUnit*>(reactorIter.Reset());
  // The original asserts the first record once before entering the loop.
  reactor->AssertValid();
  do {
    reactor->AssertValid();
    if (reactor->state1c == 0 && reactor->selectedFlag18 != 0) {
      int reactorTileIndex = reactor->tileIndex8;
      short categoryCode = g_awTacticalUnitCategoryCodeBySlot[reactor->unitTypeC];
      if (IsTacticalTargetTileReachableForAction(
              reactorTileIndex, tileIndex,
              static_cast<char>(g_afTacticalDirectFireFlagByCategory[categoryCode]),
              reactor->GetUnitRange()) != 0) {
        EvaluateAndResolveTacticalActionAgainstTileOccupant(reactor, tileIndex);
        if (battleView8 != 0) {
          battleView8->InvalidateTacticalUnitTileRect(reactor);
        }
        reactionFired = 1;
      }
    }
    if (reactorIter.More()) {
      reactor = static_cast<TTacticalUnit*>(reactorIter.Advance());
    } else {
      reactor = 0;
    }
  } while (reactor != 0 && occupant->strength4 != 0);
  return reactionFired;
}

// Executes the move (pathing the unit toward the target tile), clears the follow-up
// selection latch for category-7 (siege-gun) units, then ends the action round: unless
// the unit is still alive, the battle undecided, and the selected unit either has a
// valid follow-up target or an adjacent tile still reachable within its remaining
// action points, queue the 0x232a follow-up command.
// FUNCTION: IMPERIALISM 0x005a1bd0
void TTacticalBattle::MoveTacticalUnitAndQueueEvent232AIfNoAdjacentReachableTarget(
    TTacticalUnit* unit, int targetTileIndex) {
  MoveTacticalUnitTowardTile(unit, targetTileIndex);
  if (g_awTacticalUnitCategoryCodeBySlot[unit->unitTypeC] == 7) {
    unit->selectedFlag18 = 0;
  }
  if (unit->state1c == 0 && battleOutcomeCode44 == 0) {
    if (unit->selectedFlag18 != 0) {
      if (HasValidTacticalFollowupTargetForCurrentAction() != 0) {
        return;
      }
    }
    int neighborTiles[6];
    ComputeHexNeighborTileIndices_005A0420(selectedUnit1c->tileIndex8, neighborTiles);
    int direction = 0;
    int* neighborCursor = neighborTiles;
    for (; direction < 6; ++direction, ++neighborCursor) {
      int neighborTile = *neighborCursor;
      if (neighborTile != -1) {
        short moveCost = tileMoveCostArray24[neighborTile];
        if (moveCost != -1 && moveCost <= selectedUnit1c->actionPoints28) {
          return; // the selected unit can still reach an adjacent tile
        }
      }
    }
  }
  QueueTacticalEventPacket232A();
}

// Resolves the action against the target tile (virtual slot 0x10), then ends the
// action round; category-4/5 (cavalry) attackers with an adjacent tile still reachable
// keep the round open unless the battle outcome (battleOutcomeCode44) is already decided.
// FUNCTION: IMPERIALISM 0x005a1ca0
void TTacticalBattle::ExecuteTacticalActionAndQueueEventIfNoAdjacentValidTarget(
    TTacticalUnit* unit, int targetTileIndex) {
  EvaluateAndResolveTacticalActionAgainstTileOccupant(unit, targetTileIndex);
  short categoryCode = g_awTacticalUnitCategoryCodeBySlot[unit->unitTypeC];
  if (categoryCode == 4 || categoryCode == 5) {
    int neighborTiles[6];
    ComputeHexNeighborTileIndices_005A0420(selectedUnit1c->tileIndex8, neighborTiles);
    int direction = 0;
    int* neighborCursor = neighborTiles;
    for (; direction < 6; ++direction, ++neighborCursor) {
      int neighborTile = *neighborCursor;
      if (neighborTile != -1) {
        short moveCost = tileMoveCostArray24[neighborTile];
        if (moveCost != -1 && moveCost <= selectedUnit1c->actionPoints28) {
          // The cavalry unit can still move on: only close the round when the battle
          // outcome is already decided.
          if (battleOutcomeCode44 != 0) {
            QueueTacticalEventPacket232A();
          }
          return;
        }
      }
    }
    QueueTacticalEventPacket232A();
    return;
  }
  QueueTacticalEventPacket232A();
}

// Whether the selected unit still has a valid follow-up target: category 9 (engineer)
// needs an adjacent friendly unit, category 8 never has one, and every other category
// needs any placed enemy unit whose tile is reachable for the current action (range
// scaled by the direct-fire flag of the attacker's category).
// FUNCTION: IMPERIALISM 0x005a1d70
unsigned char TTacticalBattle::HasValidTacticalFollowupTargetForCurrentAction() {
  TTacticalUnit* selectedUnit = selectedUnit1c;
  short categoryCode = g_awTacticalUnitCategoryCodeBySlot[selectedUnit->unitTypeC];
  if (categoryCode == 9) {
    int neighborTiles[6];
    ComputeHexNeighborTileIndices_005A0420(selectedUnit->tileIndex8, neighborTiles);
    int direction = 0;
    int* neighborCursor = neighborTiles;
    for (; direction < 6; ++direction, ++neighborCursor) {
      int neighborTile = *neighborCursor;
      if (neighborTile != -1) {
        TTacticalUnit* occupant = tileGrid4[neighborTile].occupant4;
        if (occupant != 0 && occupant->side20 == selectedUnit1c->side20) {
          return 1;
        }
      }
    }
    return 0;
  }
  if (categoryCode == 8) {
    return 0;
  }
  TTacticalPlayer* opposingPlayer =
      (selectedUnit->side20 == 0) ? tacticalPlayer18 : tacticalPlayer14;
  CIterator enemyIter(opposingPlayer->unitList4);
  for (TTacticalUnit* enemyUnit = static_cast<TTacticalUnit*>(enemyIter.Reset()); enemyIter.More();
       enemyUnit = static_cast<TTacticalUnit*>(enemyIter.Advance())) {
    int enemyTile = enemyUnit->tileIndex8;
    if (enemyTile >= 0) {
      unsigned char targetReachable;
      if (selectedUnit1c->selectedFlag18 != 0) {
        short attackerCategory = g_awTacticalUnitCategoryCodeBySlot[selectedUnit1c->unitTypeC];
        targetReachable = IsTacticalTargetTileReachableForAction(
            selectedUnit1c->tileIndex8, enemyTile,
            static_cast<char>(g_afTacticalDirectFireFlagByCategory[attackerCategory]),
            selectedUnit1c->GetUnitRange());
      } else {
        targetReachable = 0;
      }
      if (targetReachable != 0) {
        return 1;
      }
    }
  }
  return 0;
}

// Damage resolution for a fire/melee action from attackerUnit against targetTileIndex.
// Computes attack power from strength, quality (+10%/level), per-type base power, the
// melee multiplier when adjacent (unless an intact fort wall blocks contact), and the
// attacker-tile terrain modifier. Firing at an unoccupied intact wall tile erodes the
// wall (0.1% of attack power) and plays the hit effect. Otherwise damage is scaled by
// the defender's terrain/type modifiers, wall cover (indirect-fire categories 6/7 also
// erode a wall crossed by the firing line), and trench cover beyond hex distance 1;
// morale damage is additionally scaled by the defender side's best living leader
// (2.0 down to 1.8 - 0.2*quality). Melee against artillery (defender category 6/7) by
// category <4 attackers whose morale damage breaks the defender's morale sets the
// capture effect code. Ends by dispatching ApplyTacticalActionEffectsAndMaybeRemoveUnit
// and clearing the defender-side player's field20.
// FUNCTION: IMPERIALISM 0x005a1ee0
void TTacticalBattle::EvaluateAndResolveTacticalActionAgainstTileOccupant(
    TTacticalUnit* attackerUnit, int targetTileIndex) {
  TTacticalUnit* defenderUnit = tileGrid4[targetTileIndex].occupant4;
  if (defenderUnit != 0) {
    defenderUnit->AssertValid();
  }

  // Firing at an intact fort-wall tile (deployMark8 > 1 = wall state) with no occupant
  // attacks the wall itself.
  unsigned char fortWallTargeted;
  if (tileGrid4[targetTileIndex].deployMark8 > 1 &&
      fortStrengthPoints54[targetTileIndex / 29 / 2] > 0 && defenderUnit == 0) {
    fortWallTargeted = 1;
  } else {
    fortWallTargeted = 0;
  }

  int fortWallTileOnLine =
      FindFortWallTileCrossedByFiringLine(targetTileIndex, attackerUnit->tileIndex8);

  unsigned char meleeAdjacent = 0;
  {
    int neighborTiles[6];
    ComputeHexNeighborTileIndices_005A0420(attackerUnit->tileIndex8, neighborTiles);
    int direction = 0;
    int* neighborCursor = neighborTiles;
    for (; direction < 6; ++direction, ++neighborCursor) {
      if (*neighborCursor == targetTileIndex) {
        meleeAdjacent = 1;
        break;
      }
    }
  }
  if (fortWallTileOnLine != 0 && tileGrid4[fortWallTileOnLine].deployMark8 > 1 &&
      fortStrengthPoints54[fortWallTileOnLine / 29 / 2] > 0) {
    meleeAdjacent = 0; // an intact wall section between the tiles blocks melee contact
  }

  // Attack power. Original FP order: (1.0 - quality * -0.1) * basePower[type]
  // [* meleeMul[cat] when adjacent], then strength * that, then * terrainMod.
  short attackerCategory;
  float attackPower;
  {
    double strengthFactor = 1.0 - attackerUnit->qualityLevel10 * -0.1; // = 1 + 0.1*quality
    strengthFactor =
        strengthFactor * g_afTacticalBaseAttackPowerByUnitType[attackerUnit->unitTypeC];
    if (meleeAdjacent != 0) {
      strengthFactor = strengthFactor *
                       g_afTacticalMeleeMultiplierByCategory
                           [g_awTacticalUnitCategoryCodeBySlot[attackerUnit->unitTypeC]];
    }
    attackerCategory = g_awTacticalUnitCategoryCodeBySlot[attackerUnit->unitTypeC];
    attackPower =
        (float)(attackerUnit->strength4 * strengthFactor *
                g_afTacticalAttackTerrainModifierByCategory
                    [attackerCategory * 5 + tileGrid4[attackerUnit->tileIndex8].terrainType0]);
  }

  if (fortWallTargeted != 0) {
    // Wall attack: erode the wall's strength pool and play the hit effect.
    ConsumeFortStrengthPointsAndInvalidateIfDepleted(fortWallTileOnLine,
                                                     (int)(0.001f * attackPower));
    if (battleView8 != 0) {
      battleView8->CenterViewportAroundGridIndexAndSnap(targetTileIndex);
      g_pSfxPlaybackSystem->PlaySoundEffect(
          g_awTacticalFireSfxTokenByUnitType[attackerUnit->unitTypeC], 0, 1);
      RECT effectRect;
      battleView8->ComputeTacticalHexTileScreenRect(&effectRect, targetTileIndex);
      effectRect.top -= 0x14;
      battleView8->RunOneTimeAnimationModalWaitAndInvalidateCityDialog(&effectRect, 0xf98, 6,
                                                                       targetTileIndex, 2);
    }
    return;
  }

  short defenderCategory = g_awTacticalUnitCategoryCodeBySlot[defenderUnit->unitTypeC];
  float damage =
      g_afTacticalDefenseTerrainModifierByCategory[defenderCategory * 5 +
                                                   tileGrid4[targetTileIndex].terrainType0] *
      g_afTacticalDamageScaleByUnitType[defenderUnit->unitTypeC] * attackPower;

  if (fortWallTileOnLine != 0 && tileGrid4[fortWallTileOnLine].deployMark8 > 1 &&
      fortStrengthPoints54[fortWallTileOnLine / 29 / 2] > 0) {
    // Shot crosses an intact wall: indirect-fire categories (table value 0.0 for
    // categories 6/7) erode it; the defender gets wall cover (indexed by wall state).
    if (g_afTacticalDirectFireFlagByCategory[attackerCategory] == 0.0f) {
      ConsumeFortStrengthPointsAndInvalidateIfDepleted(fortWallTileOnLine,
                                                       (int)(0.001f * attackPower));
    }
    defenderCategory = g_awTacticalUnitCategoryCodeBySlot[defenderUnit->unitTypeC];
    damage = damage *
             g_afTacticalCoverDamageModifierByCategory[defenderCategory * 5 +
                                                       tileGrid4[fortWallTileOnLine].deployMark8];
  }

  if (tileGrid4[targetTileIndex].deployMark8 == 1) {
    // Trench cover applies beyond point-blank range (staggered-grid hex distance > 1;
    // x = doubled column + row parity).
    int attackerRow = attackerUnit->tileIndex8 / 29;
    int attackerX = (attackerRow & 1) + attackerUnit->tileIndex8 % 29 * 2;
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

  // Defender-side leadership: lowest (best) morale-damage multiplier from living
  // leader units (unit type >= 0x1b), default 2.0.
  float leaderMoraleMultiplier = 2.0f;
  {
    TTacticalPlayer* defenderPlayer =
        (defenderUnit->side20 == 0) ? tacticalPlayer14 : tacticalPlayer18;
    CIterator leaderIter(defenderPlayer->unitList4);
    for (TTacticalUnit* leaderUnit = static_cast<TTacticalUnit*>(leaderIter.Reset());
         leaderIter.More(); leaderUnit = static_cast<TTacticalUnit*>(leaderIter.Advance())) {
      if (leaderUnit->unitTypeC >= 0x1b && leaderUnit->state1c == 0) {
        double leaderValue = 2.0 - leaderUnit->qualityLevel10 * 0.2 - 0.2;
        if (leaderValue < leaderMoraleMultiplier) {
          leaderMoraleMultiplier = (float)leaderValue;
        }
      }
    }
  }
  float moraleDamage = leaderMoraleMultiplier * damage;

  // Melee overrun of artillery: adjacent attack, defender category 6/7, attacker
  // category < 4, and the morale damage breaks the defender's morale -> capture code.
  // (morale34 is on the army slice; this battle-side resolution path is the army branch.)
  unsigned char captureEffectCode;
  short overrunDefenderCategory = g_awTacticalUnitCategoryCodeBySlot[defenderUnit->unitTypeC];
  if (meleeAdjacent != 0 && (overrunDefenderCategory == 6 || overrunDefenderCategory == 7) &&
      g_awTacticalUnitCategoryCodeBySlot[attackerUnit->unitTypeC] < 4 &&
      static_cast<TArmyTacUnit*>(defenderUnit)->morale34 < moraleDamage) {
    captureEffectCode = 1;
  } else {
    captureEffectCode = 0;
  }

  attackerUnit->AssertValid();
  ApplyTacticalActionEffectsAndMaybeRemoveUnit(attackerUnit, defenderUnit, targetTileIndex,
                                               (int)damage, (int)moraleDamage, captureEffectCode,
                                               0);
  TTacticalPlayer* postActionPlayer =
      (defenderUnit->side20 == 0) ? tacticalPlayer14 : tacticalPlayer18;
  postActionPlayer->field20 = 0;
}

// Resolves a 'fire' action: multiplayer echo, virtual damage application on the target,
// camera snap + per-unit-type fire sfx + tile hit effect (big effect 0xf6e for category
// 6/7 or unit type 0x15, small 0xf78 otherwise), removal of a destroyed target from the
// grid, and end-of-battle evaluation.
// FUNCTION: IMPERIALISM 0x005a24a0
void TTacticalBattle::ApplyTacticalActionEffectsAndMaybeRemoveUnit(TTacticalUnit* attackerUnit,
                                                                   TTacticalUnit* targetUnit,
                                                                   int targetTileIndex, int damageA,
                                                                   int damageB, char effectCode2C,
                                                                   char remoteFlag) {
  if (remoteFlag == 0) {
    unsigned char multiplayerActive = g_pSimMgr->multiplayerSessionRole != 0;
    if (multiplayerActive != 0) {
      g_pGameFlowState->EmitTacticalFireCommandPacket(0x66697265 /* 'fire' */, attackerUnit,
                                                      targetUnit, damageA, damageB, effectCode2C);
    }
  }
  targetUnit->ApplyTacticalDamage(damageA, damageB);
  if (battleView8 != 0) {
    battleView8->CenterViewportAroundGridIndexAndSnap(targetTileIndex);
    short sfxToken = g_awTacticalFireSfxTokenByUnitType[attackerUnit->unitTypeC];
    g_pSfxPlaybackSystem->PlaySoundEffect(sfxToken, 0, 1);
    short categoryCode = g_awTacticalUnitCategoryCodeBySlot[attackerUnit->unitTypeC];
    if (categoryCode == 6 || categoryCode == 7 || attackerUnit->unitTypeC == 0x15) {
      if (battleView8 != 0) {
        // effect-id + frame-count pair: 0xf6e/6 here, 0xf78/3 in the else branch (verified).
        battleView8->PlayTacticalTileEffect(targetTileIndex, 0xf6e, 6);
      }
    } else {
      if (battleView8 != 0) {
        battleView8->PlayTacticalTileEffect(targetTileIndex, 0xf78, 3);
      }
    }
    if (battleView8 != 0) {
      battleView8->InvalidateTacticalHexTileRect(targetTileIndex);
    }
  }
  if (targetUnit->state1c == 3) {
    if (battleView8 != 0) {
      battleView8->InvalidateTacticalHexTileRect(targetUnit->tileIndex8);
    }
    if (battleView8 != 0) {
      battleView8->InvalidateTacticalUnitTileRect(targetUnit);
    }
    tileGrid4[targetUnit->tileIndex8].occupant4 = 0;
    targetUnit->tileIndex8 = -1;
  }
  attackerUnit->selectedFlag18 = 0;
  EvaluateTacticalSideStateAndShowBattleSummaryDialog();
}

// Moves a unit's record from its own side's player unit list onto the opposing side's
// list (artillery capture path; the unit's side20 itself is not touched here).
// FUNCTION: IMPERIALISM 0x005a2700
void TTacticalBattle::TransferTacticalUnitToOpposingSide(TTacticalUnit* unit) {
  if (unit->side20 == 0) {
    TTacticalPlayer* receivingPlayer = tacticalPlayer18;
    tacticalPlayer14->RemoveTacticalUnitFromUnitList(unit);
    receivingPlayer->AddTacticalUnitToUnitListHead(unit);
  } else {
    TTacticalPlayer* receivingPlayer = tacticalPlayer14;
    tacticalPlayer18->RemoveTacticalUnitFromUnitList(unit);
    receivingPlayer->AddTacticalUnitToUnitListHead(unit);
  }
}

// Post-round tactical evaluation: scan recordList20 for live units per side, decide
// the battle outcome code (battleOutcomeCode44: 1 = side 0 still standing before round 35,
// 2 = side 0 wiped out or round limit reached; battle continues while both sides
// live and roundCounter74 < 35), then -- only when a live battle view exists -- build and run
// the battle-summary turn-event dialog (message context 0xeed): per-nation header
// picture (0xeed victory / 0xefb defeat + nation id), 'titl' outcome line (group
// 0x273d idx 1/3/4/6), 'loca' site line (idx 7 expanded with city name + site-owner
// nation), and 'info' casualty lines per side (idx 0x24 with count / 0x25 one loss /
// 0x26 no losses) joined by a blank line.
// FUNCTION: IMPERIALISM 0x005a2750
void TTacticalBattle::EvaluateTacticalSideStateAndShowBattleSummaryDialog() {
  unsigned char sideHasLiveUnit[2];
  sideHasLiveUnit[0] = 0;
  sideHasLiveUnit[1] = 0;
  CIterator unitIter(recordList20);
  for (TTacticalUnit* unit = static_cast<TTacticalUnit*>(unitIter.Reset());
       unitIter.More() && (sideHasLiveUnit[0] == 0 || sideHasLiveUnit[1] == 0);
       unit = static_cast<TTacticalUnit*>(unitIter.Advance())) {
    unit->AssertValid();
    if (unit->state1c == 0 || unit->state1c == 1) {
      sideHasLiveUnit[unit->side20] = 1;
    }
  }

  if (sideHasLiveUnit[0] != 0) {
    if (sideHasLiveUnit[1] != 0 && roundCounter74 < 0x23) {
      return; // both sides still have live units and the round limit is not reached
    }
  }
  if (sideHasLiveUnit[0] != 0 && roundCounter74 < 0x23) {
    battleOutcomeCode44 = 1;
  } else {
    battleOutcomeCode44 = 2;
  }

  if (battleView8 == 0) {
    return; // headless battle: outcome recorded, no summary dialog
  }

  unsigned char localIsSide0Player = tacticalPlayer14->IsTacticalControllerOwnedByActiveNation();
  unsigned char localSideWon;
  if ((battleOutcomeCode44 == 1 &&
       tacticalPlayer14->IsTacticalControllerOwnedByActiveNation() != 0) ||
      (battleOutcomeCode44 == 2 &&
       tacticalPlayer18->IsTacticalControllerOwnedByActiveNation() != 0)) {
    localSideWon = 1;
  } else {
    localSideWon = 0;
  }

  g_pSfxPlaybackSystem->RequestAudioPresetChangeWithDeferredApply(localSideWon != 0 ? 9 : 10, 0);

  TextStyle styleDescriptor;
  styleDescriptor.textColor = 0;
  TurnEventDialogNode* dialog = static_cast<TurnEventDialogNode*>(
      g_pUiViewManager->ResolveTurnEventDialogNodeByMessageContext(0xeed));

  TPicture* headerPicture =
      static_cast<TPicture*>(dialog->ResolveControlByTag(0x444c4f47 /* 'DLOG' */));
  headerPicture->AssertValid();
  headerPicture->SetPictureResourceIdAndRefresh(
      g_pSimMgr->GetActiveNationId() + (localSideWon != 0 ? 0xeed : 0xefb), 0);

  TStaticText* titleControl =
      static_cast<TStaticText*>(headerPicture->ResolveControlByTag(0x7469746c /* 'titl' */));
  titleControl->AssertValid();
  {
    int titleMessageIndex;
    if (localIsSide0Player != 0) {
      titleMessageIndex = (localSideWon != 0) ? 3 : 1;
    } else {
      titleMessageIndex = (localSideWon != 0) ? 6 : 4;
    }
    CString titleText;
    g_pSimMgr->GetString(0x273d, titleMessageIndex, &titleText);
    BuildUiTextStyleDescriptor(&styleDescriptor, 0, 0xc, 0x2b67);
    titleControl->InstallTextStyle(styleDescriptor, 0);
    titleControl->SetTextAndMaybeRefresh(&titleText, 0);
  }

  TStaticText* locationControl =
      static_cast<TStaticText*>(headerPicture->ResolveControlByTag(0x6c6f6361 /* 'loca' */));
  locationControl->AssertValid();
  {
    CString cityName;
    CString siteOwnerLabel;
    g_pGlobalMapState->AssignCityRecordDisplayName(battleSiteIndex38, &cityName);
    g_apTerrainTypeDescriptorTable[g_pGlobalMapState->cityScoreTable[battleSiteIndex38]
                                       .ownerNationCode00]
        ->FormatOverlayTerrainLabelText(&siteOwnerLabel);
    CString locationTemplate;
    CString locationText;
    g_pSimMgr->GetString(0x273d, 7, &locationTemplate);
    scanBracketExpressions(g_pSimMgr, &locationText, static_cast<const char*>(locationTemplate),
                           static_cast<const char*>(cityName),
                           static_cast<const char*>(siteOwnerLabel));
    BuildUiTextStyleDescriptor(&styleDescriptor, 0, 0xa, 0x2b67);
    locationControl->InstallTextStyle(styleDescriptor, 0);
    locationControl->SetTextAndMaybeRefresh(&locationText, 1);
  }

  TDeluxeText* infoControl =
      static_cast<TDeluxeText*>(headerPicture->ResolveControlByTag(0x696e666f /* 'info' */));
  infoControl->AssertValid();
  {
    CString infoText;
    // Constructed and destroyed but never read/written in the original -- kept
    // faithfully (same dead-local shape as BuildUiTextStyleDescriptor's CString).
    CString unusedTextA;
    CString casualtyTemplate;
    CString unusedTextB;
    infoText = CString(g_pszEmptyTextRef_00669db8);
    BuildUiTextStyleDescriptor(&styleDescriptor, 0, 0xa, 0x2b67);

    int destroyedCountBySide[2];
    destroyedCountBySide[0] = 0;
    destroyedCountBySide[1] = 0;
    CIterator lossIter(recordList20);
    for (TTacticalUnit* lossUnit = static_cast<TTacticalUnit*>(lossIter.Reset()); lossIter.More();
         lossUnit = static_cast<TTacticalUnit*>(lossIter.Advance())) {
      lossUnit->AssertValid();
      if (lossUnit->state1c == 3) {
        ++destroyedCountBySide[lossUnit->side20];
      }
    }

    CString side0NationLabel;
    CString side1NationLabel;
    CString side0CountText;
    CString side1CountText;
    CString side0CasualtyLine;
    CString side1CasualtyLine;
    CString combinedCasualtyText;

    g_apTerrainTypeDescriptorTable[tacticalPlayer14->nationIndex1C]->FormatOverlayTerrainLabelText(
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

    g_apTerrainTypeDescriptorTable[tacticalPlayer18->nationIndex1C]->FormatOverlayTerrainLabelText(
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

    combinedCasualtyText =
        CString(side0CasualtyLine + s_szDoubleNewline_00699438 + side1CasualtyLine);
    infoControl->SetTextStyle(styleDescriptor, 0);
    infoControl->UpdateTextEntrySharedStringAndMaybeNotify(&combinedCasualtyText, 0);
    infoControl->CenterVertically(0);
  }

  dialog->ShowTurnEventDialog(1);
  void* content = dialog->QueryTurnEventContentObject();
  if (content != 0) {
    *reinterpret_cast<int*>(reinterpret_cast<char*>(content) + 0x14) = 0x6f6b6179; // 'okay'
  }
  dialog->RefreshTurnEventDialog();
  dialog->Close();
  dialog->Free();
  battleView8->ForceRedraw();
}

// Queues a sap/mine run for the unit: stamps the unit's own tile with run state 2,
// records the target wall tile on the unit, invalidates the unit tile in the view,
// then spends the unit's remaining action points -- or, when they were already spent,
// dispatches the 0x232a end-of-action event.
// FUNCTION: IMPERIALISM 0x005a3190
void TTacticalBattle::MarkTacticalTileStateQueuedAndMaybeDispatchPacket(TArmyTacUnit* unit,
                                                                        int targetTileIndex) {
  int unitTileIndex = unit->tileIndex8;
  tileGrid4[unitTileIndex].mineRunStateC = 2;
  unit->AssertValid();
  unit->sapTargetTileIndex40 = targetTileIndex;
  if (battleView8 != 0) {
    battleView8->InvalidateTacticalHexTileRect(unitTileIndex);
  }
  if (unit->actionPoints28 != 0) {
    unit->actionPoints28 = 0;
    return;
  }
  QueueTacticalEventPacket232A();
}

// Advances the unit's queued sap/mine run one step. If the target wall tile no longer
// carries a wall (deployMark8 <= 1) the run is dropped. Otherwise walks from the
// unit's tile toward the target one grid row (stride) at a time until the first
// unmarked (-1) run tile: reaching the target blows the wall (tile effect 0xf6e,
// deployMark8 cleared + tile invalidated, run reset), otherwise the unmarked tile is
// stamped with the row-parity marker (odd row -> 0, even row -> 1). Finally spends the
// unit's action points, or dispatches the 0x232a end-of-action event when already
// spent.
// FUNCTION: IMPERIALISM 0x005a3210
void TTacticalBattle::AdvanceOrResetTacticalTileStateRunAndMaybeDispatchPacket(TArmyTacUnit* unit) {
  int targetTileIndex = unit->sapTargetTileIndex40;
  if (tileGrid4[targetTileIndex].deployMark8 <= 1) {
    unit->sapTargetTileIndex40 = -1;
    return;
  }
  int runTileIndex = unit->tileIndex8;
  if (runTileIndex != targetTileIndex) {
    do {
      if (tileGrid4[runTileIndex].mineRunStateC == -1) {
        break;
      }
      runTileIndex -= tacticalTileStride40;
    } while (runTileIndex != targetTileIndex);
  }
  if (runTileIndex == targetTileIndex) {
    if (battleView8 != 0) {
      battleView8->PlayTacticalTileEffect(runTileIndex, 0xf6e, 6);
    }
    tileGrid4[unit->sapTargetTileIndex40].deployMark8 = 0;
    if (battleView8 != 0) {
      battleView8->InvalidateTacticalHexTileRect(unit->sapTargetTileIndex40);
    }
    unit->sapTargetTileIndex40 = -1;
  } else if (((runTileIndex / tacticalTileStride40) & 1) != 0) {
    tileGrid4[runTileIndex].mineRunStateC = 0;
  } else {
    tileGrid4[runTileIndex].mineRunStateC = 1;
  }
  if (unit->actionPoints28 == 0) {
    QueueTacticalEventPacket232A();
    return;
  }
  unit->actionPoints28 = 0;
}

// Clears a sap/mine run: walks from the given tile down one grid row (stride) per
// step, resetting each marked run tile back to -1 and invalidating it in the view,
// stopping at the first already-clear tile or when walking off the grid (index < 0).
// FUNCTION: IMPERIALISM 0x005a3320
void TTacticalBattle::ClearTacticalTileStateRunByStride(int tileIndex) {
  int runTileIndex;
  for (runTileIndex = tileIndex; runTileIndex >= 0; runTileIndex -= tacticalTileStride40) {
    int* runState = &tileGrid4[runTileIndex].mineRunStateC;
    if (*runState == -1) {
      break;
    }
    *runState = -1;
    if (battleView8 != 0) {
      battleView8->InvalidateTacticalHexTileRect(runTileIndex);
    }
  }
}

// Resolve the action represented by the current hover cursor and dispatch it through the
// battle's real virtual action slots. This is the common click path for army and navy battles.
// FUNCTION: IMPERIALISM 0x005a3370
void TTacticalBattle::DispatchTacticalActionByHoverStateIndex(int tileIndex) {
  currentTacticalActionCode4c = ComputeTacticalHoverCursorStateIndex(tileIndex);
  switch (currentTacticalActionCode4c) {
  case 3:
    DeployTacticalUnitToTile(selectedUnit1c, tileIndex);
    break;
  case 4:
    MoveTacticalUnitAndQueueEvent232AIfNoAdjacentReachableTarget(selectedUnit1c, tileIndex);
    break;
  case 5:
  case 0xa:
    ExecuteTacticalActionAndQueueEventIfNoAdjacentValidTarget(selectedUnit1c, tileIndex);
    break;
  case 6:
    QueueTacticalEventPacket232A();
    break;
  case 7:
    ExecuteTacticalDigActionAndConsumeUnitActionPoints(selectedUnit1c, tileIndex);
    break;
  case 8: {
    TTacticalUnit* occupant = tileGrid4[tileIndex].occupant4;
    occupant->AssertValid();
    ComputeRallyStrengthAndQueueTacticalRallyCommand(selectedUnit1c,
                                                     static_cast<TArmyTacUnit*>(occupant));
    break;
  }
  case 9:
    ExecuteTacticalMineActionAndQueuePacket(selectedUnit1c, tileIndex);
    break;
  case 0xc: {
    TTacticalUnit* occupant = tileGrid4[tileIndex].occupant4;
    if (battleView8 != 0) {
      battleView8->InvalidateTacticalUnitTileRect(occupant);
    }
    occupant->tileIndex8 = -2;
    tileGrid4[tileIndex].occupant4 = 0;
    break;
  }
  }
}

// Local 'mine' action for the acting unit against a fort tile: rolls the sap amount
// from the unit's type (type * 250 - 5600 + rand % 400), echoes a 'mine' command
// packet when multiplayer is active, consumes the tile's fort strength pool, plays the
// mining sfx + tile effect when a view is attached, then dispatches the 0x232a
// end-of-action event. (HandleTacticalCommandTag_mine at 0x5a35a0 is the remote-echo
// twin of the middle section.)
// FUNCTION: IMPERIALISM 0x005a34d0
void TTacticalBattle::ExecuteTacticalMineActionAndQueuePacket(TTacticalUnit* unit, int tileIndex) {
  int unitType = unit->unitTypeC;
  int amount = static_cast<int>(rand()) % 400 + unitType * 250 - 5600;
  unsigned char multiplayerActive = g_pSimMgr->multiplayerSessionRole != 0;
  if (multiplayerActive != 0) {
    g_pGameFlowState->EmitTacticalCommandPacket(0x6d696e65 /* 'mine' */, 0, tileIndex, amount);
  }
  ConsumeFortStrengthPointsAndInvalidateIfDepleted(tileIndex, amount);
  if (battleView8 != 0) {
    g_pSfxPlaybackSystem->PlaySoundEffect(0x3a9d, 0, 1);
    battleView8->PlayTacticalTileEffect(tileIndex, 0xf98, 6);
  }
  QueueTacticalEventPacket232A();
}

// 'mine' command: multiplayer echo (no unit), consume from the side resource pool for
// the tile, then mining sfx + tile effect when a view is attached.
// FUNCTION: IMPERIALISM 0x005a35a0
void TTacticalBattle::HandleTacticalCommandTag_mine(int tileIndex, int amount, char remoteFlag) {
  if (remoteFlag == 0) {
    unsigned char multiplayerActive = g_pSimMgr->multiplayerSessionRole != 0;
    if (multiplayerActive != 0) {
      g_pGameFlowState->EmitTacticalCommandPacket(0x6d696e65 /* 'mine' */, 0, tileIndex, amount);
    }
  }
  ConsumeFortStrengthPointsAndInvalidateIfDepleted(tileIndex, amount);
  if (battleView8 != 0) {
    g_pSfxPlaybackSystem->PlaySoundEffect(0x3a9d, 0, 1);
    battleView8->PlayTacticalTileEffect(tileIndex, 0xf98, 6);
  }
}

// 'digg' action wrapper: apply the trench dig locally (+ echo), walk the unit to the
// target tile, charge half the unit type's base action points against the pre-action
// balance, rebuild the reachable-cost plane, and close the round when the unit is spent.
// FUNCTION: IMPERIALISM 0x005a3640
void TTacticalBattle::ExecuteTacticalDigActionAndConsumeUnitActionPoints(TTacticalUnit* unit,
                                                                         int tileIndex) {
  unit->AssertValid();
  // Captured as a word before the dig/move mutate the unit.
  short actionPointsBefore = static_cast<short>(unit->actionPoints28);
  HandleTacticalCommandTag_digg(unit, tileIndex, 0);
  MoveTacticalUnitTowardTile(unit, tileIndex);
  unit->actionPoints28 = actionPointsBefore - g_awUnitTypeBaseActionPointTable[unit->unitTypeC] / 2;
  ComputeTacticalReachableTileCostsByUnitCategory(unit);
  if (unit->actionPoints28 == 0) {
    QueueTacticalEventPacket232A();
  }
}

// 'digg' command: digs a trench link between the unit's tile and an adjacent target
// tile -- finds the hex direction of the target among the unit tile's six neighbors,
// then sets the paired direction bits (and the 0x80 first-dig / 0x40 linked state
// bits) in both tiles' trench masks.
// FUNCTION: IMPERIALISM 0x005a36d0
void TTacticalBattle::HandleTacticalCommandTag_digg(TTacticalUnit* unit, int targetTileIndex,
                                                    char remoteFlag) {
  int neighborTiles[6];
  if (remoteFlag == 0) {
    unsigned char multiplayerActive = g_pSimMgr->multiplayerSessionRole != 0;
    if (multiplayerActive != 0) {
      g_pGameFlowState->EmitTacticalCommandPacket(0x64696767 /* 'digg' */, unit, targetTileIndex,
                                                  0);
    }
  }
  int unitTileIndex = unit->tileIndex8;
  ComputeHexNeighborTileIndices_005A0420(unitTileIndex, neighborTiles);
  int direction = 0;
  int* neighborCursor = neighborTiles;
  do {
    if (*neighborCursor == targetTileIndex) {
      break;
    }
    ++direction;
    ++neighborCursor;
  } while (direction < 6);
  unsigned char srcMask = tileGrid4[unitTileIndex].trenchMask10;
  if (srcMask == 0) {
    tileGrid4[unitTileIndex].trenchMask10 = 0x80;
  } else {
    tileGrid4[unitTileIndex].trenchMask10 = srcMask & 0x7f;
    tileGrid4[unitTileIndex].trenchMask10 |= 0x40;
  }
  tileGrid4[unitTileIndex].trenchMask10 |= static_cast<unsigned char>(1 << direction);
  direction += 3;
  if (direction > 5) {
    direction -= 6;
  }
  unsigned char dstMask = tileGrid4[targetTileIndex].trenchMask10;
  if (dstMask != 0) {
    tileGrid4[targetTileIndex].trenchMask10 = dstMask & 0x7f;
    tileGrid4[targetTileIndex].trenchMask10 |= 0x40;
  }
  tileGrid4[targetTileIndex].trenchMask10 |= static_cast<unsigned char>(1 << direction);
}

// Rally strength computation: an unbroken target (state1c == 0) gains
// strength/10 * (rallier quality + 3) morale; a broken one (state1c == 1) recovers to
// state 0 with strength/10 + 20 morale on a rand()%100 < (quality+5)*10 roll. Then the
// 'raly' command applies/echoes it and the 0x232a end-of-action event is queued.
// FUNCTION: IMPERIALISM 0x005a3810
undefined
TTacticalBattle::ComputeRallyStrengthAndQueueTacticalRallyCommand(TTacticalUnit* rallyingUnit,
                                                                  TArmyTacUnit* rallyTarget) {
  int newState = rallyTarget->state1c;
  int newMorale = rallyTarget->morale34;
  if (newState == 0) {
    newMorale += rallyTarget->strength4 / 10 * (rallyingUnit->qualityLevel10 + 3);
  } else if (newState == 1) {
    int qualityLevel = rallyingUnit->qualityLevel10;
    if (static_cast<int>(rand()) % 100 < (qualityLevel + 5) * 10) {
      newMorale = rallyTarget->strength4 / 10 + 20;
      newState = 0;
    }
  }
  HandleTacticalCommandTag_raly(rallyTarget, newMorale, newState, 0);
  QueueTacticalEventPacket232A();
  return 0;
}

// 'raly' command: multiplayer echo, sets the unit's state (rallying a broken unit) and
// restores morale to min(newMorale, strength), then refreshes the unit rect and plays
// the rally sfx.
// FUNCTION: IMPERIALISM 0x005a38e0
void TTacticalBattle::HandleTacticalCommandTag_raly(TArmyTacUnit* unit, int newMorale, int newState,
                                                    char remoteFlag) {
  if (remoteFlag == 0) {
    unsigned char multiplayerActive = g_pSimMgr->multiplayerSessionRole != 0;
    if (multiplayerActive != 0) {
      g_pGameFlowState->EmitTacticalCommandPacket(0x72616c79 /* 'raly' */, unit, newMorale,
                                                  newState);
    }
  }
  int strength = unit->strength4;
  unit->state1c = newState;
  if (newMorale > strength) {
    unit->morale34 = strength;
  } else {
    unit->morale34 = newMorale;
  }
  if (battleView8 != 0) {
    battleView8->InvalidateTacticalUnitTileRect(unit);
  }
  if (battleView8 != 0) {
    g_pSfxPlaybackSystem->PlaySoundEffect(0x3aae, 0, 1);
  }
}

// Fort-wall tile index where the firing line between the two tiles crosses the wall
// column x = 2*battlefieldColumnCount34 - 12 (doubled-x hex coordinates), 0 when the
// segment does not span that column.
// FUNCTION: IMPERIALISM 0x005a3a70
int TTacticalBattle::FindFortWallTileCrossedByFiringLine(int targetTileIndex,
                                                         int attackerTileIndex) {
  float wallX = (float)(2 * battlefieldColumnCount34 - 12);
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
    return tacticalTileStride40 * lineY1 / 2 + battlefieldColumnCount34 - 6;
  }
  // Interpolate the crossing row (y is doubled, hence the -0.5 scale; the wall column
  // itself sits at grid column battlefieldColumnCount34 - 6).
  return battlefieldColumnCount34 -
         (int)(((float)lineY2 +
                (wallX - leftXF) * ((float)(lineY1 - lineY2) / (float)(lineX1 - lineX2))) *
               -0.5f) *
             tacticalTileStride40 -
         6;
}

// Consumes fort strength from the per-row-pair pool (one slot per two grid rows,
// tile/58); when a pool runs dry it clamps to 0 and invalidates the three tiles where
// the fort section is drawn (column band anchored at battlefieldColumnCount34 - 6).
// FUNCTION: IMPERIALISM 0x005a3c20
void TTacticalBattle::ConsumeFortStrengthPointsAndInvalidateIfDepleted(int tileIndex,
                                                                       int consumeAmount) {
  int poolIndex = tileIndex / 29 / 2;
  int remaining = fortStrengthPoints54[poolIndex] - consumeAmount;
  fortStrengthPoints54[poolIndex] = remaining;
  if (remaining < 0) {
    fortStrengthPoints54[poolIndex] = 0;
    int poolTileIndex = battlefieldColumnCount34 + poolIndex * 58 - 6;
    if (battleView8 != 0) {
      battleView8->InvalidateTacticalHexTileRect(poolTileIndex);
    }
    if (battleView8 != 0) {
      battleView8->InvalidateTacticalHexTileRect(poolTileIndex + 1);
    }
    if (battleView8 != 0) {
      battleView8->InvalidateTacticalHexTileRect(poolTileIndex + 29);
    }
  }
}

// Range/line-of-fire test on the doubled-x hex grid. Distance uses axial x = 2*col +
// (row&1) with both deltas reflected positive; beyond `range` fails. An entrenched
// category-8 (sapper) target is only engageable from an adjacent tile. Direct-fire
// attacks are additionally blocked by an intact fort wall crossing the firing line,
// unless the target is not behind the wall band or the attacker stands on the wall
// column.
// FUNCTION: IMPERIALISM 0x005a3d30
unsigned char TTacticalBattle::IsTacticalTargetTileReachableForAction(int attackerTileIndex,
                                                                      int targetTileIndex,
                                                                      char directFireFlag,
                                                                      int range) {
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
  TacticalTileRecord* targetRecord = &tileGrid4[targetTileIndex];
  TTacticalUnit* targetOccupant = targetRecord->occupant4;
  if (targetOccupant != 0 && g_awTacticalUnitCategoryCodeBySlot[targetOccupant->unitTypeC] == 8 &&
      targetRecord->trenchMask10 != 0) {
    int neighborTiles[6];
    ComputeHexNeighborTileIndices_005A0420(attackerTileIndex, neighborTiles);
    int direction = 0;
    int* neighborCursor = neighborTiles;
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
  int wallTileIndex = FindFortWallTileCrossedByFiringLine(targetTileIndex, attackerTileIndex);
  if (wallTileIndex == 0) {
    return 1;
  }
  if (tileGrid4[wallTileIndex].deployMark8 <= 1) {
    return 1;
  }
  if (fortStrengthPoints54[wallTileIndex / 29 / 2] <= 0) {
    return 1;
  }
  if (targetColumn <= battlefieldColumnCount34 - 5) {
    return 1;
  }
  if (attackerColumn == battlefieldColumnCount34 - 5) {
    return 1;
  }
  return 0;
}

// "targ" command: cycles the selected unit's target to the next reachable enemy unit in the
// opposing side's list, starting after the current target (which is recentered if still
// valid), recentering the view on the first reachable candidate; sets the selected unit's
// target field, or plays a "no target" cue if none was found.
// FUNCTION: IMPERIALISM 0x005a3f10
void TTacticalBattle::HandleTacticalCommandTag_targ() {
  TTacticalUnit* selected = selectedUnit1c;
  TTacticalUnit* result = NULL;
  if (selected == NULL || battleView8 == NULL) {
    return;
  }
  TTacticalUnit* marker = selected->attackTarget30;
  TList* list = (&tacticalPlayer14)[selected->side20 == 0]->unitList4;

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
    if (selectedUnit1c->selectedFlag18 == 0) {
      reachable = 0;
    } else {
      reachable = IsTacticalTargetTileReachableForAction(
          selectedUnit1c->tileIndex8, marker->tileIndex8,
          static_cast<char>(g_afTacticalDirectFireFlagByCategory
                                [g_awTacticalUnitCategoryCodeBySlot[selectedUnit1c->unitTypeC]]),
          selectedUnit1c->GetUnitRange());
    }
    if (reachable != 0) {
      battleView8->CenterViewportAroundGridIndexAndSnap(marker->tileIndex8);
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
      if (selectedUnit1c->selectedFlag18 == 0) {
        reachable = 0;
      } else {
        reachable = IsTacticalTargetTileReachableForAction(
            selectedUnit1c->tileIndex8, candidate->tileIndex8,
            static_cast<char>(g_afTacticalDirectFireFlagByCategory
                                  [g_awTacticalUnitCategoryCodeBySlot[selectedUnit1c->unitTypeC]]),
            selectedUnit1c->GetUnitRange());
      }
      if (reachable != 0) {
        if (marker == NULL) {
          battleView8->CenterViewportAroundGridIndexAndSnap(candidate->tileIndex8);
          marker = candidate;
        } else {
          result = candidate;
        }
      }
    }
    cursor = next;
  } while (cursor != position && result == NULL);

  selectedUnit1c->attackTarget30 = result;
  if (result == NULL) {
    g_pSfxPlaybackSystem->PlaySoundEffect(0x1b5a, 0, 1);
  }
}

// Whether a tile is a legal deployment target for the current side: not in the first
// grid row, not water/impassable terrain (type 4), unoccupied, and inside the side's
// deployment column band (side 0: columns 3..5; side 1: columnCount-5..columnCount-3).
// FUNCTION: IMPERIALISM 0x005a41c0
unsigned char TTacticalBattle::ApplyGridColumnSelectionGuard(int tileIndex) {
  int column = tileIndex % 29;
  if (tileIndex < 29) {
    return 0;
  }
  TacticalTileRecord* record = &tileGrid4[tileIndex];
  if (record->terrainType0 == 4) {
    return 0;
  }
  if (record->occupant4 != 0) {
    return 0;
  }
  if (currentSideC == 0) {
    if (column < 3) {
      return 0;
    }
    if (column > 5) {
      return 0;
    }
    return 1;
  }
  if (column > battlefieldColumnCount34 - 3) {
    return 0;
  }
  if (column < battlefieldColumnCount34 - 5) {
    return 0;
  }
  return 1;
}

// FUNCTION: IMPERIALISM 0x005a4240
int TTacticalBattle::CountFreeDeploymentZoneTilesForCurrentSide() {
  int freeTileCount = 0;
  int tileCount = tacticalTileCount3c;
  if (tileCount > 0) {
    for (int tileIndex = 0; tileIndex < tileCount; ++tileIndex) {
      int column = tileIndex % 29;
      unsigned char tileFree = 0;
      if (tileIndex >= 29) {
        TacticalTileRecord* record = &tileGrid4[tileIndex];
        if (record->terrainType0 != 4 && record->occupant4 == 0) {
          if (currentSideC == 0) {
            if (column >= 3 && column <= 5) {
              tileFree = 1;
            }
          } else if (column <= battlefieldColumnCount34 - 3 &&
                     column >= battlefieldColumnCount34 - 5) {
            tileFree = 1;
          }
        }
      }
      if (tileFree != 0) {
        ++freeTileCount;
      }
    }
  }
  return freeTileCount;
}

// FUNCTION: IMPERIALISM 0x005a42e0
bool TTacticalBattle::HasFortWallGarrison(int tileIndex) {
  return tileGrid4[tileIndex].deployMark8 > 1 && fortStrengthPoints54[tileIndex / 0x3a] > 0;
}

// True when there is no fort (fortLevel49 == 0) or any of the eight per-row-pair fort
// strength pools is depleted (<= 0).
// FUNCTION: IMPERIALISM 0x005a4330
unsigned char TTacticalBattle::IsTacticalSideCategoryCoverageIncompleteOrFlagOff() {
  if (fortLevel49 == 0) {
    return 1;
  }
  for (int poolIndex = 0; poolIndex < 8; ++poolIndex) {
    if (fortStrengthPoints54[poolIndex] <= 0) {
      return 1;
    }
  }
  return 0;
}

// 'depl' command: places a unit on a battle-grid tile during deployment; for
// trench-capable units (flag3c) outside the fortLevel49 mode it marks the tile deployed
// and invalidates the six neighbor tiles, then refreshes the unit rect.
// FUNCTION: IMPERIALISM 0x005a4370
void TTacticalBattle::HandleTacticalCommandTag_depl(TArmyTacUnit* unit, int tileIndex,
                                                    char remoteFlag) {
  int neighborTiles[6];
  if (remoteFlag == 0) {
    unsigned char multiplayerActive = g_pSimMgr->multiplayerSessionRole != 0;
    if (multiplayerActive != 0) {
      g_pGameFlowState->EmitTacticalCommandPacket(0x6465706c /* 'depl' */, unit, tileIndex, 0);
    }
  }
  unit->tileIndex8 = tileIndex;
  tileGrid4[tileIndex].occupant4 = unit;
  if (unit->flag3c != 0 && fortLevel49 == 0) {
    tileGrid4[tileIndex].deployMark8 = 1;
    if (battleView8 != 0) {
      ComputeHexNeighborTileIndices_005A0420(tileIndex, neighborTiles);
      int* neighborCursor = neighborTiles;
      int remaining = 6;
      do {
        if (*neighborCursor != -1) {
          battleView8->InvalidateTacticalHexTileRect(*neighborCursor);
        }
        ++neighborCursor;
        --remaining;
      } while (remaining != 0);
    }
  }
  if (battleView8 != 0) {
    battleView8->InvalidateTacticalUnitTileRect(unit);
  }
}

// Builds the per-tile advance-distance field into tileIntArray30 for the given side:
// fills the plane with -1, seeds distance 0 along the side's entry column (column 0
// for ourSideFlag != 0, battlefieldColumnCount34 - 1 otherwise; water tiles with
// terrainType0 == 4 stay unseeded), then flood-expands ring by ring through the six
// hex neighbors. A neighbor is skipped when already reached, occupied, or behind an
// intact fort wall -- except the wall gun-slot tiles (rows 5/7/9 at wall column
// battlefieldColumnCount34 - 6), which stay passable for the attacking side only.
// FUNCTION: IMPERIALISM 0x005a4460
void TTacticalBattle::BuildTacticalDistanceFieldForSide(char ourSideFlag) {
  int fillIndex;
  for (fillIndex = 0; fillIndex < tacticalTileCount3c; ++fillIndex) {
    tileIntArray30[fillIndex] = -1;
  }
  if (ourSideFlag != 0) {
    // Seed column 0 of each of the 15 grid rows.
    int rowStartA;
    for (rowStartA = 0; rowStartA < 0x1b3; rowStartA += 0x1d) {
      if (tileGrid4[rowStartA].terrainType0 != 4) {
        tileIntArray30[rowStartA] = 0;
      }
    }
  } else {
    // Seed the last playable column (battlefieldColumnCount34 - 1) of each row.
    int rowStartB;
    for (rowStartB = 0; rowStartB < 0x1b3; rowStartB += 0x1d) {
      int edgeTile = battlefieldColumnCount34 + rowStartB;
      if (tileGrid4[edgeTile - 1].terrainType0 != 4) {
        tileIntArray30[edgeTile - 1] = 0;
      }
    }
  }
  int distance = 0;
  unsigned char anyTileExpanded;
  do {
    anyTileExpanded = 0;
    int tile;
    for (tile = 0; tile < tacticalTileCount3c; ++tile) {
      if (tileIntArray30[tile] != distance) {
        continue;
      }
      int neighborTiles[6];
      ComputeHexNeighborTileIndices_005A0420(tile, neighborTiles);
      int* neighborCursor = neighborTiles;
      int direction;
      for (direction = 0; direction < 6; ++direction, ++neighborCursor) {
        int neighborTile = *neighborCursor;
        if (neighborTile == -1) {
          continue;
        }
        int* distanceCell = &tileIntArray30[neighborTile];
        if (*distanceCell != -1) {
          continue;
        }
        TacticalTileRecord* record = &tileGrid4[neighborTile];
        if (record->occupant4 != 0) {
          continue;
        }
        // The original emits two consecutive compares here (jl 2, then jle 1), so the
        // source repeats the redundant wall-mark test; kept literally.
        if (record->deployMark8 >= 2 && record->deployMark8 > 1) {
          int wallRow = neighborTile / 0x1d;
          if (fortStrengthPoints54[wallRow / 2] > 0) {
            int doubledColumn = (wallRow & 1) + (neighborTile % 0x1d) * 2;
            if (wallRow != 5 && wallRow != 7 && wallRow != 9) {
              continue;
            }
            if (doubledColumn / 2 != battlefieldColumnCount34 - 6) {
              continue;
            }
            if (ourSideFlag != 0) {
              continue;
            }
            // Gun-slot gate: stays passable for the attacking side.
          }
        }
        if (record->terrainType0 != 4) {
          anyTileExpanded = 1;
          *distanceCell = distance + 1;
        }
      }
    }
    ++distance;
  } while (anyTileExpanded != 0);
}

// Whether the tile sits on a fort-wall gun-slot: grid rows 5/7/9 at the wall column
// battlefieldColumnCount34 - 6 (column compared in doubled-hex coordinates).
// FUNCTION: IMPERIALISM 0x005a4690
unsigned char TTacticalBattle::IsTacticalTileAtFortWallSectionSlot(int tileIndex) {
  int row = tileIndex / 0x1d;
  int doubledColumn = (row & 1) + (tileIndex % 0x1d) * 2;
  if (row == 5 || row == 7 || row == 9) {
    if (doubledColumn / 2 == battlefieldColumnCount34 - 6) {
      return 1;
    }
  }
  return 0;
}

// Walks recordList20 for the tactical unit whose source army unit's TUnit::field_20 id
// matches nestedId; 0 when nestedId is 0 or nothing matches.
// FUNCTION: IMPERIALISM 0x005a53e0
TArmyTacUnit* TTacticalBattle::SeekLinkedListCursorByNestedId(int nestedId) {
  if (nestedId == 0) {
    return 0;
  }
  CIterator unitIter(recordList20);
  for (TArmyTacUnit* unit = static_cast<TArmyTacUnit*>(unitIter.Reset()); unitIter.More();
       unit = static_cast<TArmyTacUnit*>(unitIter.Advance())) {
    int foundId;
    if (unit != 0 && unit->sourceUnit38 != 0) {
      foundId = unit->sourceUnit38->field_20;
    } else {
      foundId = 0;
    }
    if (nestedId == foundId) {
      return unit;
    }
  }
  return 0;
}

// Sets the current side's navy ship-panel display mode from the navy toolbar (hull/crew/sail).
// The players are TNavyPlayer in a sea battle, so the mode lands in the navy-slice field.
// FUNCTION: IMPERIALISM 0x005a5b90
void TTacticalBattle::SetCurrentSideNavyShipDisplayMode(int mode) {
  static_cast<TNavyPlayer*>((&tacticalPlayer14)[currentSideC])->shipDisplayMode2c = mode;
}
