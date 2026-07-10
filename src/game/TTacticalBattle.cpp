#include "game/TTacticalBattle.h"

#include "game/CIterator.h"
#include "game/CString.h"
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
#include "game/TSimMgr.h"
#include "game/TSoundPlayer.h"
#include "game/TTacticalBattleView.h"
#include "game/TTacticalPlayer.h"
#include "game/TTacticalToolbar.h"
#include "game/ui_control_tags.h"
#include "game/global_data_tables.h"

extern undefined4 GenerateThreadLocalRandom15(void);

using turn_event_dialog::TurnEventDialogNode;

undefined TTacticalBattle::OrphanRetStub_0059f710() {
  return 0;
}

undefined TTacticalBattle::CreateTTacticalBattleInstance() {
  return 0;
}
// SYNTHETIC: IMPERIALISM 0x0059f6d0
// TTacticalBattle::CreateObject

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
  field74 = 0;
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
      ourUnit->field24 = static_cast<short>(GenerateThreadLocalRandom15());
      recordList20->AddTail(ourUnit);
    }
  }
  {
    CIterator enemyIter(enemyPlayer->unitList4);
    for (TTacticalUnit* enemyUnit = static_cast<TTacticalUnit*>(enemyIter.Reset());
         enemyIter.More(); enemyUnit = static_cast<TTacticalUnit*>(enemyIter.Advance())) {
      enemyUnit->side20 = 1;
      enemyUnit->field24 = static_cast<short>(GenerateThreadLocalRandom15());
      recordList20->AddTail(enemyUnit);
    }
  }

  field10 = 0;
  currentSideC = 1;
  field44 = 0;
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
undefined TTacticalBattle::StartBattle() {
  return tacticalPlayer18->StartBattle();
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
          // neighbor". TODO(verify): keep literal for byte match.
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

// FUNCTION: IMPERIALISM 0x005a0d60
void TTacticalBattle::QueueTacticalEventPacket232A() {
  // TODO: port body @ 0x5a0d60 (clears field48, news a 0x1c-byte TCommand with vtable
  // 0x66a100, queues turn event 0x232a).
}

undefined TTacticalBattle::ExecuteTacticalDigActionAndConsumeUnitActionPoints(int* param_1,
                                                                              undefined4 param_2) {
  return 0;
}

undefined TTacticalBattle::ComputeRallyStrengthAndQueueTacticalRallyCommand(int param_1) {
  return 0;
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
    unsigned char multiplayerActive = g_pSimMgr->field44 != 0;
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

// Non-virtual action helpers dispatched above; bodies not yet ported.

// FUNCTION: IMPERIALISM 0x005a1520
void TTacticalBattle::MoveTacticalUnitTowardTile(TTacticalUnit* unit, int targetTileIndex) {
  // TODO: port body @ 0x5a1520.
  (void)unit;
  (void)targetTileIndex;
}

// Moves a unit from one battle-grid tile to another: multiplayer 'move' echo, clear the
// source tile's occupant, optionally animate (suppressed when field4c == 7), re-anchor
// the unit on the destination tile, and refresh the affected view rects/marker.
// FUNCTION: IMPERIALISM 0x005a1910
void TTacticalBattle::MoveTacticalUnitBetweenTiles(TTacticalUnit* unit, int fromTileIndex,
                                                   int toTileIndex, char remoteFlag) {
  if (remoteFlag == 0) {
    unsigned char multiplayerActive = g_pSimMgr->field44 != 0;
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
  if (field4c != 7) {
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
  if (unit->state1c == 0 && field44 == 0) {
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
// keep the round open unless the battle outcome (field44) is already decided.
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
          if (field44 != 0) {
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

// FUNCTION: IMPERIALISM 0x005a1d70
unsigned char TTacticalBattle::HasValidTacticalFollowupTargetForCurrentAction() {
  // TODO: port body @ 0x5a1d70.
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
    unsigned char multiplayerActive = g_pSimMgr->field44 != 0;
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
        // TODO(verify): 0xf6e/6 vs 0xf78/3 assumed effect-id + frame-count pair.
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
// the battle outcome code (field44: 1 = side 0 still standing before round 35,
// 2 = side 0 wiped out or round limit reached; battle continues while both sides
// live and field74 < 35), then -- only when a live battle view exists -- build and run
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
    if (sideHasLiveUnit[1] != 0 && field74 < 0x23) {
      return; // both sides still have live units and the round limit is not reached
    }
  }
  if (sideHasLiveUnit[0] != 0 && field74 < 0x23) {
    field44 = 1;
  } else {
    field44 = 2;
  }

  if (battleView8 == 0) {
    return; // headless battle: outcome recorded, no summary dialog
  }

  unsigned char localIsSide0Player = tacticalPlayer14->IsTacticalControllerOwnedByActiveNation();
  unsigned char localSideWon;
  if ((field44 == 1 && tacticalPlayer14->IsTacticalControllerOwnedByActiveNation() != 0) ||
      (field44 == 2 && tacticalPlayer18->IsTacticalControllerOwnedByActiveNation() != 0)) {
    localSideWon = 1;
  } else {
    localSideWon = 0;
  }

  g_pSfxPlaybackSystem->RequestAudioPresetChangeWithDeferredApply(localSideWon != 0 ? 9 : 10, 0);

  TControlPictureRectState styleDescriptor;
  styleDescriptor.styleRef6 = 0;
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
    titleControl->SetCityProductionDialogPictureRectAndMaybeRefresh(&styleDescriptor, 0);
    titleControl->AssignTextSharedRefIfChangedAndMaybeInvalidate(&titleText, 0);
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
    locationControl->SetCityProductionDialogPictureRectAndMaybeRefresh(&styleDescriptor, 0);
    locationControl->AssignTextSharedRefIfChangedAndMaybeInvalidate(&locationText, 1);
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
    infoControl->ApplyTextStyleDescriptorAndMaybeRefresh(&styleDescriptor, 0);
    infoControl->UpdateTextEntrySharedStringAndMaybeNotify(&combinedCasualtyText, 0);
    infoControl->RecenterTextFromMeasuredWidthAndMaybeInvalidate(0);
  }

  dialog->ShowTurnEventDialog(1);
  void* content = dialog->QueryTurnEventContentObject();
  if (content != 0) {
    *reinterpret_cast<int*>(reinterpret_cast<char*>(content) + 0x14) = 0x6f6b6179; // 'okay'
  }
  dialog->RefreshTurnEventDialog();
  dialog->CallVoidSlotA0();
  dialog->Free();
  battleView8->InvokeSlot13C();
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

// Local 'mine' action for the acting unit against a fort tile: rolls the sap amount
// from the unit's type (type * 250 - 5600 + rand % 400), echoes a 'mine' command
// packet when multiplayer is active, consumes the tile's fort strength pool, plays the
// mining sfx + tile effect when a view is attached, then dispatches the 0x232a
// end-of-action event. (HandleTacticalCommandTag_mine at 0x5a35a0 is the remote-echo
// twin of the middle section.)
// FUNCTION: IMPERIALISM 0x005a34d0
void TTacticalBattle::ExecuteTacticalMineActionAndQueuePacket(TTacticalUnit* unit, int tileIndex) {
  int unitType = unit->unitTypeC;
  int amount = static_cast<int>(GenerateThreadLocalRandom15()) % 400 + unitType * 250 - 5600;
  unsigned char multiplayerActive = g_pSimMgr->field44 != 0;
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
    unsigned char multiplayerActive = g_pSimMgr->field44 != 0;
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

// 'digg' command: digs a trench link between the unit's tile and an adjacent target
// tile -- finds the hex direction of the target among the unit tile's six neighbors,
// then sets the paired direction bits (and the 0x80 first-dig / 0x40 linked state
// bits) in both tiles' trench masks.
// FUNCTION: IMPERIALISM 0x005a36d0
void TTacticalBattle::HandleTacticalCommandTag_digg(TTacticalUnit* unit, int targetTileIndex,
                                                    char remoteFlag) {
  int neighborTiles[6];
  if (remoteFlag == 0) {
    unsigned char multiplayerActive = g_pSimMgr->field44 != 0;
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

// 'raly' command: multiplayer echo, sets the unit's state (rallying a broken unit) and
// restores morale to min(newMorale, strength), then refreshes the unit rect and plays
// the rally sfx.
// FUNCTION: IMPERIALISM 0x005a38e0
void TTacticalBattle::HandleTacticalCommandTag_raly(TArmyTacUnit* unit, int newMorale, int newState,
                                                    char remoteFlag) {
  if (remoteFlag == 0) {
    unsigned char multiplayerActive = g_pSimMgr->field44 != 0;
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

// FUNCTION: IMPERIALISM 0x005a3a70
int TTacticalBattle::FindFortWallTileCrossedByFiringLine(int targetTileIndex,
                                                         int attackerTileIndex) {
  // TODO: port body @ 0x5a3a70.
  (void)targetTileIndex;
  (void)attackerTileIndex;
  return 0;
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

// 'depl' command: places a unit on a battle-grid tile during deployment; for
// trench-capable units (flag3c) outside the fortLevel49 mode it marks the tile deployed
// and invalidates the six neighbor tiles, then refreshes the unit rect.
// FUNCTION: IMPERIALISM 0x005a4370
void TTacticalBattle::HandleTacticalCommandTag_depl(TArmyTacUnit* unit, int tileIndex,
                                                    char remoteFlag) {
  int neighborTiles[6];
  if (remoteFlag == 0) {
    unsigned char multiplayerActive = g_pSimMgr->field44 != 0;
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
