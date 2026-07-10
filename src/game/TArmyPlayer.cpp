#include "game/TArmyPlayer.h"

#include "game/CIterator.h"
#include "game/TArmyStack.h"
#include "game/TArmyTacUnit.h"
#include "game/TList.h"
#include "game/TAssetMgr.h"
#include "game/TMilitaryUnit.h"
#include "game/TTacticalBattle.h"
#include "game/TTacticalHolaPicture.h"
#include "game/global_data_tables.h"
#include "game/turn_event_dialog_provisional.h"
#include "game/ui_invalidation_guard.h"

extern undefined4 GenerateThreadLocalRandom15(void);

using turn_event_dialog::TurnEventDialogNode;

// Sort comparator for the auto-deploy strategies (0x59b070): compares the AI-class
// priority words of two tactical unit records. Body TODO.
// FUNCTION: IMPERIALISM 0x0059b070
int __cdecl CompareTacticalCursorEntriesByActionClassPriority(void* a, void* b) {
  // TODO: port body @ 0x59b070 (AssertValid both, priority {class 0: 1, class 2: 2,
  // others: 0}).
  (void)a;
  (void)b;
  return 0;
}
// SYNTHETIC: IMPERIALISM 0x0059b110
// TArmyPlayer::CreateObject

// SYNTHETIC: IMPERIALISM 0x0059b140
// TArmyPlayer::`scalar deleting destructor'
TArmyPlayer::~TArmyPlayer() {}

// SYNTHETIC: IMPERIALISM 0x0059b190
// TArmyPlayer::GetRuntimeClass

IMPLEMENT_DYNCREATE(TArmyPlayer, TTacticalPlayer)

// FUNCTION: IMPERIALISM 0x0059b1b0
void TArmyPlayer::InitializeTacticalSideFromArmyUnitList(TArmyStack* stack, int isOurSide,
                                                         char watchFlag, int nationIndex) {
  // Scatter-init of the side state, in the original store order.
  // TODO(verify): the asm only ever touches the low byte of `isOurSide` -- the
  // original param was likely char/BOOL.
  isOurSideFlagC = static_cast<char>(isOurSide);
  sideReadyFlag10 = 0;
  watchFlagD = watchFlag;
  nationIndex1C = nationIndex;
  cursorIndex18 = 0;
  fieldF = 0;
  field20 = 0;
  field24 = 0;

  unitList4 = new TList();
  sideReadyFlag10 = 0; // duplicate store present in the original
  secondaryList8 = new TList();

  // Walk the stack's embedded {TUnit*, next} chain. The original inlines the
  // TArmyStack::ResetCursorAndGetHeadUnit (0x4a3b70) / AdvanceCursorAndGetUnit
  // (0x4a3b90) bodies here (no calls emitted), so the walk is written out directly.
  stack->cursor18 = stack->head14;
  TUnit* unit;
  if (stack->head14 != 0) {
    unit = stack->head14->unit;
  } else {
    unit = 0;
  }
  while (unit != 0) {
    TArmyTacUnit* record = new TArmyTacUnit();
    record->ConstructTArmyTacUnitBaseState(static_cast<TMilitaryUnit*>(unit));
    unitList4->AddTail(record);
    if (static_cast<char>(isOurSide) == 0) {
      record->selectedFlag18 = 1; // TODO(verify): set only for the enemy side
    }
    TArmyStackUnitNode* node = stack->cursor18;
    if (node != 0) {
      node = node->next;
      stack->cursor18 = node;
      if (node != 0) {
        unit = node->unit;
      } else {
        unit = 0;
      }
    } else {
      unit = 0;
    }
  }

  armyStack28 = stack;
  cursorIndex18 = 0;      // duplicate store present in the original
  watchFlagD = watchFlag; // duplicate store present in the original
  notWatchedFlagE = (watchFlag == 0);
  field44 = -1;
  unsigned char coinFlip = static_cast<unsigned char>(GenerateThreadLocalRandom15() & 1);
  field4C = -1;
  randomParityByte50 = coinFlip;
  field51 = 0;
}

// Writes each record's surviving strength back to its source army unit's strength
// word and detaches (kills) units that ended the battle at zero strength, on both
// owned record lists.
// FUNCTION: IMPERIALISM 0x0059b3e0
void TArmyPlayer::CommitTacticalResultsToSourceUnits(int unused) {
  (void)unused;
  if (unitList4->GetCount() > 0) {
    CIterator unitIter(unitList4);
    for (TArmyTacUnit* record = static_cast<TArmyTacUnit*>(unitIter.Reset()); unitIter.More();
         record = static_cast<TArmyTacUnit*>(unitIter.Advance())) {
      record->sourceUnit38->field_34 = static_cast<short>(record->strength4);
      if (record->strength4 == 0) {
        record->sourceUnit38->DetachUnitOrderFromOwnerAndReset();
      }
    }
  }
  if (secondaryList8->GetCount() > 0) {
    CIterator secondaryIter(secondaryList8);
    for (TArmyTacUnit* secondaryRecord = static_cast<TArmyTacUnit*>(secondaryIter.Reset());
         secondaryIter.More();
         secondaryRecord = static_cast<TArmyTacUnit*>(secondaryIter.Advance())) {
      secondaryRecord->sourceUnit38->field_34 = static_cast<short>(secondaryRecord->strength4);
      if (secondaryRecord->strength4 == 0) {
        secondaryRecord->sourceUnit38->DetachUnitOrderFromOwnerAndReset();
      }
    }
  }
}

// FUNCTION: IMPERIALISM 0x0059b4f0
void TArmyPlayer::RemoveTacticalUnitFromUnitList(TTacticalUnit* unit) {
  // TODO: port body @ 0x59b4f0.
  (void)unit;
}

// FUNCTION: IMPERIALISM 0x0059b540
void TArmyPlayer::AddTacticalUnitToUnitListHead(TTacticalUnit* unit) {
  // TODO: port body @ 0x59b540.
  (void)unit;
}

// Kicks the side at battle start: unwatched (AI/remote) sides skip the intro dialog
// and auto-deploy; watched sides run the battle-intro ('hola', 0xf19) dialog and only
// proceed on 'okay'.
// FUNCTION: IMPERIALISM 0x0059b830
void TArmyPlayer::StartBattle() {
  if (notWatchedFlagE != 0) {
    SelectAndApplyTacticalCursorModeProfile(1);
    AutoDeploySideUnitsAndMarkReady();
    return;
  }
  unsigned char alreadyStarted = field24 == 2;
  if (alreadyStarted == 0) {
    TTacticalPlayer* opponent;
    if (isOurSideFlagC != 0) {
      opponent = battle14->tacticalPlayer18;
    } else {
      opponent = battle14->tacticalPlayer14;
    }
    int opposingNationIndex = opponent->nationIndex1C;

    // Battle-intro ("hola") dialog, id 0xf19.
    TurnEventDialogNode* dialog = static_cast<TurnEventDialogNode*>(
        g_pUiViewManager->ResolveTurnEventDialogNodeByMessageContext(0xf19));
    if (dialog == 0) {
      FailNilPointerWithAssert(s_SourcePathUTacPlayer_00699D84, 0x18d);
    }
    TTacticalHolaPicture* holaPicture =
        static_cast<TTacticalHolaPicture*>(dialog->ResolveControlByTag(0x444c4f47 /* 'DLOG' */));
    holaPicture->AssertValid();
    if (isOurSideFlagC != 0) {
      holaPicture->ConfigureBattleIntroCoatsAndSiteLabels(
          nationIndex1C, static_cast<short>(opposingNationIndex), isOurSideFlagC,
          battle14->battleSiteIndex38);
    } else {
      holaPicture->ConfigureBattleIntroCoatsAndSiteLabels(
          static_cast<short>(opposingNationIndex), nationIndex1C, 0, battle14->battleSiteIndex38);
    }
    int resultTag = dialog->RefreshTurnEventDialog();
    dialog->CallVoidSlotA0();
    dialog->Free();
    if (resultTag == 0x6f6b6179 /* 'okay' */) {
      ProceedAfterBattleIntroAccepted();
    }
  }
}

// FUNCTION: IMPERIALISM 0x0059b990
void TArmyPlayer::RecomputeTacticalCursorProjectionScoresAndPruneList(int maxUnitCount) {
  // TODO: port body @ 0x59b990.
  (void)maxUnitCount;
}

// Auto-deploys every unit of this side into the deployment zone (pruning the unit
// list first if it exceeds the free-tile capacity) and marks the side ready. Our side
// deploys by the zone score table; the enemy side deploys by the per-class selectors.
// FUNCTION: IMPERIALISM 0x0059bc80
void TArmyPlayer::AutoDeploySideUnitsAndMarkReady() {
  int freeDeployTileCount = battle14->CountFreeDeploymentZoneTilesForCurrentSide();
  if (unitList4->GetCount() > freeDeployTileCount) {
    RecomputeTacticalCursorProjectionScoresAndPruneList(freeDeployTileCount);
  }
  if (isOurSideFlagC != 0) {
    BuildTacticalActionPriorityBucketsWithGridGuard();
    sideReadyFlag10 = 1;
    return;
  }
  DispatchTacticalActionClassSelectionAcrossCursorList();
  sideReadyFlag10 = 1;
}

// Deploy strategy for our side: sorts the unit list by action-class priority, then
// places each unit on the best-scoring free deployment-zone tile (per-AI-class
// zone-cell score + distance-from-edge row bonus).
// FUNCTION: IMPERIALISM 0x0059bcf0
void TArmyPlayer::BuildTacticalActionPriorityBucketsWithGridGuard() {
  // Flat local score table; the lookup below indexes from entry 11, so cells decode
  // as [aiClass][col 5..3, odd/even row] for aiClass 0..4, column 3..5.
  // TODO(verify): a tile passing the guard with a column outside 3..5 indexes out of
  // this table in the original too.
  int zoneScoreByClassAndCell[30] = {
      10, 30, 10, 20, 10, 10, // aiClass 0
      10, 20, 30, 40, 50, 60, // aiClass 1
      60, 40, 50, 30, 20, 10, // aiClass 2
      10, 20, 30, 40, 50, 60, // aiClass 3
      10, 20, 30, 40, 50, 60, // aiClass 4
  };
  unitList4->SortEntriesWithComparator(&CompareTacticalCursorEntriesByActionClassPriority, 0);
  CIterator unitIter(unitList4);
  for (TTacticalUnit* unit = static_cast<TTacticalUnit*>(unitIter.Reset()); unitIter.More();
       unit = static_cast<TTacticalUnit*>(unitIter.Advance())) {
    int bestScore = 0;
    int bestTileIndex = -1;
    for (int tileIndex = 0; tileIndex < battle14->tacticalTileCount3c; ++tileIndex) {
      if (battle14->ApplyGridColumnSelectionGuard(tileIndex) != 0) {
        int row = tileIndex / 29;
        int column = tileIndex % 29;
        int aiClass = g_awTacticalUnitAiClassByUnitType_006693B8[unit->unitTypeC];
        int score = zoneScoreByClassAndCell[2 * (3 * aiClass - column) - (row & 1) + 11];
        if (row > 7) {
          row = 15 - row;
        }
        score += row;
        if (score > bestScore) {
          bestScore = score;
          bestTileIndex = tileIndex;
        }
      }
    }
    battle14->DeployTacticalUnitToTile(unit, bestTileIndex);
  }
}

// Deploy strategy for the enemy side: sorts by the same comparator, then asks the
// per-action-class tile selector for each unit's deployment tile.
// FUNCTION: IMPERIALISM 0x0059bf20
void TArmyPlayer::DispatchTacticalActionClassSelectionAcrossCursorList() {
  unitList4->SortEntriesWithComparator(&CompareTacticalCursorEntriesByActionClassPriority, 0);
  CIterator unitIter(unitList4);
  for (TTacticalUnit* unit = static_cast<TTacticalUnit*>(unitIter.Reset()); unitIter.More();
       unit = static_cast<TTacticalUnit*>(unitIter.Advance())) {
    int tileIndex;
    switch (g_awTacticalUnitAiClassByUnitType_006693B8[unit->unitTypeC]) {
    case 0:
      tileIndex = SelectTacticalTileByActionClassAdjacencyPriority();
      break;
    case 2:
      tileIndex = SelectTacticalTileIndexByColumnPriorityVariantA();
      break;
    default:
      tileIndex = SelectTacticalTileIndexByColumnPriorityVariantB();
      break;
    }
    battle14->DeployTacticalUnitToTile(unit, tileIndex);
  }
}

// FUNCTION: IMPERIALISM 0x0059bfe0
int TArmyPlayer::SelectTacticalTileIndexByColumnPriorityVariantA() {
  // TODO: port body @ 0x59bfe0.
  return -1;
}

// FUNCTION: IMPERIALISM 0x0059c140
int TArmyPlayer::SelectTacticalTileByActionClassAdjacencyPriority() {
  // TODO: port body @ 0x59c140.
  return -1;
}

// FUNCTION: IMPERIALISM 0x0059c2a0
int TArmyPlayer::SelectTacticalTileIndexByColumnPriorityVariantB() {
  // TODO: port body @ 0x59c2a0.
  return -1;
}

// FUNCTION: IMPERIALISM 0x0059c3c0
undefined TArmyPlayer::TArmyTacUnit_VtblSlot07() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x0059c440
void TArmyPlayer::SelectAndApplyTacticalCursorModeProfile(int cursorProfileMode) {
  // TODO: port body @ 0x59c440.
  (void)cursorProfileMode;
}

// FUNCTION: IMPERIALISM 0x0059d530
int TArmyPlayer::SelectBestTacticalTileByWeightedHeuristics(TTacticalUnit* unit,
                                                            int* heuristicWeights15) {
  // TODO: port body @ 0x59d530 (weights the fifteen tile-score heuristics at
  // 0x59d6b0..0x59e0d0).
  (void)unit;
  (void)heuristicWeights15;
  return -1;
}

// FUNCTION: IMPERIALISM 0x0059e110
int TArmyPlayer::SelectBestTacticalTargetTileByActionHeuristics(TTacticalUnit* unit, int flag) {
  // TODO: port body @ 0x59e110.
  (void)unit;
  (void)flag;
  return -1;
}

// FUNCTION: IMPERIALISM 0x0059e3e0
void TArmyPlayer::AdvanceTacticalTurnPulse() {
  // TODO: port body @ 0x59e3e0 (per-tick battle pump; runs the auto-turn controller
  // while notWatchedFlagE, with a GetAsyncKeyState(0x5c) cancel check).
}

// One full AI turn for the battle's currently selected unit: pick a destination by
// weighted tile heuristics (or hold position), march there, then act -- officers rally
// an adjacent damaged friendly, sappers mine the fort wall or dig in, everyone else
// fires on the best target (artillery may then advance) -- and finally hand the turn
// back via the 0x232a event.
// FUNCTION: IMPERIALISM 0x0059e4f0
void TArmyPlayer::RunTacticalAutoTurnControllerForActiveUnit() {
  TTacticalUnit* unit = battle14->selectedUnit1c;

  if (g_awTacticalUnitAiClassByUnitType_006693B8[unit->unitTypeC] != 2 || unit->side20 == 1) {
    SelectAndApplyTacticalCursorModeProfile(0);
  }

  int homeTileIndex = unit->tileIndex8;
  short categoryCode = g_awTacticalUnitCategoryCodeBySlot[unit->unitTypeC];

  // Phase 1: choose the destination tile.
  int targetTileIndex;
  if (categoryCode == 8 && unit->aiStateCode2c != 0xc) {
    // Sapper: assault row when the fort is gone or a wall section is breached;
    // otherwise hold if already entrenched or threatened, else seek a dig spot.
    if (battle14->IsTacticalSideCategoryCoverageIncompleteOrFlagOff() != 0) {
      targetTileIndex = SelectBestTacticalTileByWeightedHeuristics(
          unit, g_anTacticalTileHeuristicWeightsByAiState_00699500[12]);
    } else if (battle14->tileGrid4[homeTileIndex].trenchMask10 != 0) {
      targetTileIndex = homeTileIndex;
    } else if (battle14->tileThreatLevelArray28[homeTileIndex] != 0) {
      targetTileIndex = homeTileIndex;
    } else {
      targetTileIndex = SelectBestTacticalTileByWeightedHeuristics(
          unit, g_anTacticalTileHeuristicWeightsByAiState_00699500[13]);
    }
  } else if ((unit->aiStateCode2c == 5 || unit->aiStateCode2c == 2 || categoryCode == 4) &&
             battle14->field74 < 2) {
    targetTileIndex = homeTileIndex;
  } else if (categoryCode == 6 && battle14->field74 < 2) {
    targetTileIndex = SelectBestTacticalTileByWeightedHeuristics(
        unit, g_anTacticalTileHeuristicWeightsByAiState_00699500[18]);
  } else {
    targetTileIndex = SelectBestTacticalTileByWeightedHeuristics(
        unit, g_anTacticalTileHeuristicWeightsByAiState_00699500[unit->aiStateCode2c]);
  }
  if (targetTileIndex == -1) {
    targetTileIndex = unit->tileIndex8;
  }

  // Phase 2: march toward it, one echoed step at a time (guarded at 200 steps).
  if (targetTileIndex != unit->tileIndex8) {
    int moveGuard = 200;
    while (battle14->field48 != 0 && unit->state1c == 0 && unit->tileIndex8 != targetTileIndex) {
      if (moveGuard-- == 0) {
        break;
      }
      battle14->MoveTacticalUnitAndQueueEvent232AIfNoAdjacentReachableTarget(unit, targetTileIndex);
    }
  }

  // Phase 3: act from the reached tile.
  if (battle14->field48 != 0 && unit->state1c == 0) {
    if (unit->unitTypeC >= 0x1b) {
      // Officer types: rally the first adjacent friendly whose morale dropped below
      // its strength.
      int neighborTiles[6];
      battle14->ComputeHexNeighborTileIndices_005A0420(unit->tileIndex8, neighborTiles);
      TArmyTacUnit* rallyTarget = 0;
      for (int neighborIndex = 0; neighborIndex < 6 && rallyTarget == 0; ++neighborIndex) {
        int neighborTileIndex = neighborTiles[neighborIndex];
        if (neighborTileIndex != -1) {
          TArmyTacUnit* occupant =
              static_cast<TArmyTacUnit*>(battle14->tileGrid4[neighborTileIndex].occupant4);
          if (occupant != 0 && occupant->side20 == unit->side20 &&
              occupant->morale34 < occupant->strength4) {
            rallyTarget = occupant;
          }
        }
      }
      if (rallyTarget != 0) {
        battle14->ComputeRallyStrengthAndQueueTacticalRallyCommand(unit, rallyTarget);
      }
    } else if (g_awTacticalUnitCategoryCodeBySlot[unit->unitTypeC] == 8) {
      // Sapper that held position: mine the fort wall on the tile to its right, or dig
      // trenches there, while action points remain.
      if (unit->tileIndex8 == homeTileIndex) {
        while (unit->actionPoints28 >=
               g_awTacticalUnitActionPointCostByType_006693F8[unit->unitTypeC] / 2) {
          int wallTileIndex = unit->tileIndex8 + 1;
          TacticalTileRecord* wallTile = &battle14->tileGrid4[wallTileIndex];
          if (wallTile->deployMark8 > 1) {
            battle14->ExecuteTacticalMineActionAndQueuePacket(unit, wallTileIndex);
            return; // original returns here without queueing the 0x232a event
          }
          // TODO(verify): if the wall tile is occupied or already trenched the original
          // re-tests the unchanged condition -- faithful transcription.
          if (wallTile->occupant4 == 0 && wallTile->trenchMask10 == 0) {
            battle14->ExecuteTacticalDigActionAndConsumeUnitActionPoints(unit, wallTileIndex);
          }
        }
      }
    } else if (unit->selectedFlag18 != 0) {
      // Combat unit: fire on the best target; artillery-class units with an advance
      // stance then push toward the next weighted tile.
      int fireTileIndex = SelectBestTacticalTargetTileByActionHeuristics(unit, 1);
      TTacticalUnit* fireTarget = 0;
      if (fireTileIndex != -1) {
        fireTarget = battle14->tileGrid4[fireTileIndex].occupant4;
      }
      if (fireTarget != 0) {
        battle14->ExecuteTacticalActionAndQueueEventIfNoAdjacentValidTarget(unit,
                                                                            fireTarget->tileIndex8);
        if (battle14->field48 != 0 &&
            g_awTacticalUnitAiClassByUnitType_006693B8[unit->unitTypeC] == 1 &&
            unit->actionPoints28 != 0) {
          int aiState = unit->aiStateCode2c;
          if (aiState == 2 || aiState == 5 || aiState == 0xe) {
            int advanceTileIndex = SelectBestTacticalTileByWeightedHeuristics(
                unit, g_anTacticalTileHeuristicWeightsByAiState_00699500[aiState + 1]);
            if (advanceTileIndex != unit->tileIndex8) {
              int advanceGuard = 200;
              while (battle14->selectedUnit1c == unit && unit->state1c == 0 &&
                     unit->tileIndex8 != advanceTileIndex) {
                if (advanceGuard-- == 0) {
                  break;
                }
                battle14->MoveTacticalUnitAndQueueEvent232AIfNoAdjacentReachableTarget(
                    unit, advanceTileIndex);
              }
            }
          }
        }
      }
    }
  }

  // Hand the turn back.
  if (battle14->field48 != 0) {
    battle14->QueueTacticalEventPacket232A();
  }
}

// FUNCTION: IMPERIALISM 0x0059ea60
undefined TArmyPlayer::TArmyTacUnit_VtblSlot09() {
  return 0;
}

// After the battle-intro dialog is accepted: auto-deploy if this side has not
// deployed yet; otherwise (first acceptance on a watched side) mark the side as no
// longer watched-idle, apply cursor profile 0, and start the turn pump.
// FUNCTION: IMPERIALISM 0x0059eb40
void TArmyPlayer::ProceedAfterBattleIntroAccepted() {
  if (sideReadyFlag10 == 0) {
    AutoDeploySideUnitsAndMarkReady();
    return;
  }
  if (notWatchedFlagE == 0) {
    notWatchedFlagE = 1;
    SelectAndApplyTacticalCursorModeProfile(0);
    AdvanceTacticalTurnPulse();
  }
}
