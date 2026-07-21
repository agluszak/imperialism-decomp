#include "game/TArmyPlayer.h"

#include <stdlib.h>

#include "game/CIterator.h"
#include "game/map_overlay_geometry.h"
#include "game/TArmyStack.h"
#include "game/TArmyTacUnit.h"
#include "game/TList.h"
#include "game/TAssetMgr.h"
#include "game/TCountry.h"
#include "game/TMapMgr.h"
#include "game/TMilitaryUnit.h"
#include "game/TTacticalBattle.h"
#include "game/TTacticalHolaPicture.h"
#include "game/global_data_tables.h"
#include "game/turn_event_dialog_provisional.h"
#include "game/ui_invalidation_guard.h"

using turn_event_dialog::TurnEventDialogNode;

// FUNCTION: IMPERIALISM 0x005362c0
float __cdecl ComputeDistributionSimilarityScoreFromVectorAndReferenceProfile(
    float* vector, const short* referenceProfile, int count) {
  // Locals are double: the original keeps the whole computation on the FP stack with
  // no intermediate float rounding stores.
  double vectorSum = g_Recompute_Nation_Order_LookupTable_0065A9E8;
  int i;
  double difference;
  for (i = 0; i < count; ++i) {
    vectorSum += vector[i];
  }
  if (vectorSum == g_Recompute_Nation_Order_LookupTable_0065A9F0) {
    return g_Recompute_Nation_Order_LookupTable_0065A9E8;
  }
  double absoluteDifferenceSum = g_Recompute_Nation_Order_LookupTable_0065A9E8;
  for (i = 0; i < count; ++i) {
    difference =
        vector[i] / vectorSum - referenceProfile[i] * g_Recompute_Nation_Order_LookupTable_0065A9F8;
    if (difference <= g_Recompute_Nation_Order_LookupTable_0065A9F0) {
      difference = -difference;
    }
    absoluteDifferenceSum += difference;
  }
  return vectorSum * (g_Recompute_Nation_Order_LookupTable_0065AA08 -
                      absoluteDifferenceSum * g_Recompute_Nation_Order_LookupTable_0065AA00);
}

// Sort comparator for the auto-deploy strategies: melee (aiClass 0) first, artillery
// (aiClass 2) last, everything else in between.
// FUNCTION: IMPERIALISM 0x0059b070
short __cdecl CompareTacticalCursorEntriesByActionClassPriority(void* a, void* b, void* context) {
  (void)context;
  // The verdict is returned in AX only (short); the upper 16 bits are leftover garbage
  // in the original, matching the TSortedListCompareFunc comparator shape.
  short priorityByAiClass[5] = {1, 0, 2, 0, 0};
  TTacticalUnit* unitA = static_cast<TTacticalUnit*>(a);
  TTacticalUnit* unitB = static_cast<TTacticalUnit*>(b);
  unitA->AssertValid();
  unitB->AssertValid();
  short priorityA = priorityByAiClass[g_awTacticalUnitAiClassByUnitType_006693B8[unitA->unitTypeC]];
  short priorityB = priorityByAiClass[g_awTacticalUnitAiClassByUnitType_006693B8[unitB->unitTypeC]];
  if (priorityA < priorityB) {
    return 1;
  }
  return -(priorityA != priorityB); // neg/sbb idiom: -1 when priorityA > priorityB, else 0
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
  // The original only reads the low byte of `isOurSide` (a char/BOOL param).
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
      record->selectedFlag18 = 1; // set only for the enemy side (isOurSide == 0)
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
  lastAppliedCursorMode44 = -1;
  unsigned char coinFlip = static_cast<unsigned char>(rand() & 1);
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
  POSITION pos = unitList4->listState.Find(unit);
  if (pos != nullptr) {
    unitList4->listState.RemoveAt(pos);
  }
  armyStack28->RemoveUnitFromChain(static_cast<TArmyTacUnit*>(unit)->sourceUnit38);
}

// FUNCTION: IMPERIALISM 0x0059b540
void TArmyPlayer::AddTacticalUnitToUnitListHead(TTacticalUnit* unit) {
  unitList4->listState.AddHead(unit);
  unit->FlipUnitSideAffiliation();
  TMilitaryUnit* sourceUnit = static_cast<TArmyTacUnit*>(unit)->sourceUnit38;
  sourceUnit->field_18 = static_cast<short>(nationIndex1C);
  sourceUnit->VTableSlot10(battle14->battleSiteIndex38);
  armyStack28->AddUnitToChainHead(sourceUnit);
  static_cast<TArmyTacUnit*>(unit)->morale34 = unit->strength4;
}

// Rebuilds the side's projection metrics from the active records: sums the five-float
// projection vectors, tracks the max unit range (and the max skipping artillery), sets
// field51 when the side has any active artillery or sapper, then folds sums[0]/sums[1]
// into distribution-similarity scores vs the 0x697870 reference profiles (row 0
// baseline; row 1 = fort present, row 2 = open field).
// FUNCTION: IMPERIALISM 0x0059b5b0
void TArmyPlayer::AccumulateTacticalProjectionMetricsAndUnitRanges() {
  maxNonArtilleryUnitRange42 = 0;
  maxUnitRange40 = 0;
  // Zeroed through a base pointer in the original (lea + five dword stores).
  float* sums = projectionScoreSums2C;
  sums[0] = 0.0f;
  sums[1] = 0.0f;
  sums[2] = 0.0f;
  sums[3] = 0.0f;
  sums[4] = 0.0f;
  field51 = 0;

  CIterator unitIter(unitList4);
  for (TArmyTacUnit* record = static_cast<TArmyTacUnit*>(unitIter.Reset()); unitIter.More();
       record = static_cast<TArmyTacUnit*>(unitIter.Advance())) {
    if (record->state1c == 0) {
      record->ComputeTacticalProjectionScoreVector();

      // Pointer-walk countdown accumulate (fld/fadd/fstp loop in the original).
      float* sumCursor = projectionScoreSums2C;
      float* vectorCursor = &record->field44;
      int remaining;
      for (remaining = 5; remaining > 0; --remaining) {
        *sumCursor++ += *vectorCursor++;
      }

      // max()-macro form: the losing branch re-evaluates GetUnitRange().
      maxUnitRange40 = static_cast<short>(
          maxUnitRange40 > record->GetUnitRange() ? maxUnitRange40 : record->GetUnitRange());
      if (g_awTacticalUnitAiClassByUnitType_006693B8[record->unitTypeC] != 2) {
        maxNonArtilleryUnitRange42 = static_cast<short>(
            maxNonArtilleryUnitRange42 > record->GetUnitRange() ? maxNonArtilleryUnitRange42
                                                                : record->GetUnitRange());
      }
      if (g_awTacticalUnitAiClassByUnitType_006693B8[record->unitTypeC] == 2 ||
          g_awTacticalUnitCategoryCodeBySlot[record->unitTypeC] == 8) {
        field51 = 1;
      }
    }
  }

  // The row-0 score must be sampled before sums[1] is overwritten (both calls read the
  // live sums). Row select: fort present -> row 1, open field -> row 2.
  // Row sense here (fort -> 1, open -> 2) is inverted vs
  // RecomputeTacticalCursorProjectionScoresAndPruneList (fort -> 2, open -> 1); both are
  // faithful to their originals.
  float baselineProfileScore = ComputeDistributionSimilarityScoreFromVectorAndReferenceProfile(
      projectionScoreSums2C, g_awTacticalCompositionReferenceProfiles_00697870, 5);
  projectionScoreSums2C[1] = ComputeDistributionSimilarityScoreFromVectorAndReferenceProfile(
      projectionScoreSums2C,
      g_awTacticalCompositionReferenceProfiles_00697870 + 5 * (battle14->fortLevel49 != 0 ? 1 : 2),
      5);
  projectionScoreSums2C[0] = baselineProfileScore;
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
    dialog->Close();
    dialog->Free();
    if (resultTag == 0x6f6b6179 /* 'okay' */) {
      ProceedAfterBattleIntroAccepted();
    }
  }
}

// Prunes the side's unit list down to `maxUnitCount`: moves every record onto
// secondaryList8 (refreshing its projection-score vector), keeps the first category-9
// record plus the greedy best-scoring set by the distribution-similarity profile
// (row: enemy=0, attacker=1, attacker-vs-fort=2), and drops every pruned record from
// the battle's recordList20.
// FUNCTION: IMPERIALISM 0x0059b990
void TArmyPlayer::RecomputeTacticalCursorProjectionScoresAndPruneList(int maxUnitCount) {
  int profileRowIndex;
  if (isOurSideFlagC != 0) {
    profileRowIndex = (battle14->fortLevel49 != 0) + 1;
  } else {
    profileRowIndex = 0;
  }

  // Move every record onto secondaryList8, back to front (ordinals are 1-based).
  for (int ordinal = unitList4->GetCount(); ordinal > 0; --ordinal) {
    TArmyTacUnit* record = static_cast<TArmyTacUnit*>(unitList4->GetEntryByOrdinal(ordinal));
    record->AssertValid();
    unitList4->RemoveAtOrdinal(ordinal);
    secondaryList8->AddTail(record);
    record->ComputeTacticalProjectionScoreVector();
  }

  int remainingCapacity = maxUnitCount;
  unsigned char movedCategory9Record = 0;
  if (remainingCapacity != 0) {
    CIterator category9Iter(secondaryList8);
    TArmyTacUnit* category9Record = static_cast<TArmyTacUnit*>(category9Iter.Reset());
    while (category9Iter.More() != 0) {
      if (g_awTacticalUnitCategoryCodeBySlot[category9Record->unitTypeC] == 9) {
        POSITION category9Pos = secondaryList8->listState.Find(category9Record, 0);
        if (category9Pos != 0) {
          secondaryList8->listState.RemoveAt(category9Pos);
        }
        unitList4->AddTail(category9Record);
        movedCategory9Record = 1;
        --remainingCapacity;
      }
      category9Record = static_cast<TArmyTacUnit*>(category9Iter.Advance());
      if (movedCategory9Record != 0) {
        break; // original stops after the first category-9 record
      }
    }
  }

  float keptScoreVectorSum[5] = {0.0f, 0.0f, 0.0f, 0.0f, 0.0f};
  if (remainingCapacity != 0) {
    for (int passesLeft = remainingCapacity; passesLeft != 0; --passesLeft) {
      int bestOrdinal = 0;
      float bestScore = 0.0f;
      // Faithful off-by-one: the scan starts at ordinal 1 and stops before GetCount(),
      // so the last entry is never scored; with bestOrdinal left 0, GetEntryByOrdinal(0)
      // returns 0.
      for (int candidateOrdinal = 1; candidateOrdinal < secondaryList8->GetCount();
           ++candidateOrdinal) {
        TArmyTacUnit* candidate =
            static_cast<TArmyTacUnit*>(secondaryList8->GetEntryByOrdinal(candidateOrdinal));
        float* candidateVector = &candidate->field44;
        int addComponent;
        for (addComponent = 0; addComponent < 5; ++addComponent) {
          keptScoreVectorSum[addComponent] += candidateVector[addComponent];
        }
        float score = ComputeDistributionSimilarityScoreFromVectorAndReferenceProfile(
            keptScoreVectorSum,
            g_awTacticalCompositionReferenceProfiles_00697870 + profileRowIndex * 5, 5);
        if (score > bestScore) {
          bestScore = score;
          bestOrdinal = candidateOrdinal;
        }
        int subComponent;
        for (subComponent = 0; subComponent < 5; ++subComponent) {
          keptScoreVectorSum[subComponent] -= candidateVector[subComponent];
        }
      }
      TArmyTacUnit* keptRecord =
          static_cast<TArmyTacUnit*>(secondaryList8->GetEntryByOrdinal(bestOrdinal));
      secondaryList8->RemoveAtOrdinal(bestOrdinal);
      unitList4->AddTail(keptRecord);
      float* keptVector = &keptRecord->field44;
      int keptComponent;
      for (keptComponent = 0; keptComponent < 5; ++keptComponent) {
        keptScoreVectorSum[keptComponent] += keptVector[keptComponent];
      }
    }
  }

  // Every record still on secondaryList8 was pruned from the battle roster.
  CIterator prunedIter(secondaryList8);
  for (TArmyTacUnit* prunedRecord = static_cast<TArmyTacUnit*>(prunedIter.Reset());
       prunedIter.More(); prunedRecord = static_cast<TArmyTacUnit*>(prunedIter.Advance())) {
    POSITION prunedPos = battle14->recordList20->listState.Find(prunedRecord, 0);
    if (prunedPos != 0) {
      battle14->recordList20->listState.RemoveAt(prunedPos);
    }
  }
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
  // The guard does not bound the column, so a tile passing it with a column outside 3..5
  // indexes out of this table in the original too.
  int zoneScoreByClassAndCell[30] = {
      10, 30, 10, 20, 10, 10, // aiClass 0
      10, 20, 30, 40, 50, 60, // aiClass 1
      60, 40, 50, 30, 20, 10, // aiClass 2
      10, 20, 30, 40, 50, 60, // aiClass 3
      10, 20, 30, 40, 50, 60, // aiClass 4
  };
  unitList4->SortBy(&CompareTacticalCursorEntriesByActionClassPriority, 0);
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
  unitList4->SortBy(&CompareTacticalCursorEntriesByActionClassPriority, 0);
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

// Deploy-tile selector for artillery-class (aiClass 2) enemy units: zone-cell score by
// column distance from the playable-column edge (odd rows shifted half a cell), plus
// distance from the near board edge, plus 100 when any hex neighbor already holds an
// artillery-class unit (either side); writes each candidate's score into
// battle14->tileIntArray2c.
// FUNCTION: IMPERIALISM 0x0059bfe0
int TArmyPlayer::SelectTacticalTileIndexByColumnPriorityVariantA() {
  int bestScore = 0;
  int bestTileIndex = -1;
  for (int tileIndex = 0; tileIndex < battle14->tacticalTileCount3c; ++tileIndex) {
    if (battle14->ApplyGridColumnSelectionGuard(tileIndex) != 0) {
      int row = tileIndex / 29;
      int column = tileIndex % 29;
      int zoneCell = (row & 1) + 2 * (column - battle14->battlefieldColumnCount34) + 10;
      int score;
      if (zoneCell == 0) {
        score = 10;
      } else {
        score = (7 - zoneCell) * 10;
      }
      int rowDistance = row;
      if (rowDistance > 7) {
        rowDistance = 15 - rowDistance;
      }
      score += rowDistance;
      int neighborTiles[6];
      int adjacentArtilleryBonus = 0;
      battle14->ComputeHexNeighborTileIndices_005A0420(tileIndex, neighborTiles);
      for (int neighborIndex = 0; neighborIndex < 6; ++neighborIndex) {
        int neighborTileIndex = neighborTiles[neighborIndex];
        if (neighborTileIndex != -1) {
          TTacticalUnit* occupant = battle14->tileGrid4[neighborTileIndex].occupant4;
          if (occupant != 0 &&
              g_awTacticalUnitAiClassByUnitType_006693B8[occupant->unitTypeC] == 2) {
            adjacentArtilleryBonus = 0x64;
          }
        }
      }
      score += adjacentArtilleryBonus;
      battle14->tileIntArray2c[tileIndex] = score;
      if (score > bestScore) {
        bestScore = score;
        bestTileIndex = tileIndex;
      }
    }
  }
  return bestTileIndex;
}

// Deploy-tile selector for melee-class (aiClass 0) enemy units: cell score grows
// toward the playable-column edge, plus edge-row distance, plus an adjacency bonus
// (100 next to an artillery-class unit, else 10 next to any occupant).
// FUNCTION: IMPERIALISM 0x0059c140
int TArmyPlayer::SelectTacticalTileByActionClassAdjacencyPriority() {
  int bestScore = 0;
  int bestTileIndex = -1;
  for (int tileIndex = 0; tileIndex < battle14->tacticalTileCount3c; ++tileIndex) {
    if (battle14->ApplyGridColumnSelectionGuard(tileIndex) != 0) {
      int row = tileIndex / 29;
      int column = tileIndex % 29;
      int score = (2 * (battle14->battlefieldColumnCount34 - column) - (row & 1) - 3) * 10;
      int rowDistance = row;
      if (rowDistance > 7) {
        rowDistance = 15 - rowDistance;
      }
      score += rowDistance;
      int neighborTiles[6];
      int adjacencyBonus = 0;
      battle14->ComputeHexNeighborTileIndices_005A0420(tileIndex, neighborTiles);
      for (int neighborIndex = 0; neighborIndex < 6; ++neighborIndex) {
        int neighborTileIndex = neighborTiles[neighborIndex];
        if (neighborTileIndex != -1) {
          TTacticalUnit* occupant = battle14->tileGrid4[neighborTileIndex].occupant4;
          if (occupant != 0) {
            if (g_awTacticalUnitAiClassByUnitType_006693B8[occupant->unitTypeC] == 2) {
              adjacencyBonus = 0x64;
            } else if (adjacencyBonus == 0) {
              adjacencyBonus = 0xa;
            }
          }
        }
      }
      score += adjacencyBonus;
      if (score > bestScore) {
        bestScore = score;
        bestTileIndex = tileIndex;
      }
    }
  }
  return bestTileIndex;
}

// Deploy-tile selector for the remaining enemy action classes: a per-battle constant
// base (20 * (columnCount - 5)) plus edge-row distance, plus 10 when any hex neighbor
// is occupied (first hit stops the neighbor scan).
// FUNCTION: IMPERIALISM 0x0059c2a0
int TArmyPlayer::SelectTacticalTileIndexByColumnPriorityVariantB() {
  int bestScore = 0;
  int bestTileIndex = -1;
  for (int tileIndex = 0; tileIndex < battle14->tacticalTileCount3c; ++tileIndex) {
    if (battle14->ApplyGridColumnSelectionGuard(tileIndex) != 0) {
      int row = tileIndex / 29;
      int score = (battle14->battlefieldColumnCount34 - 5) * 20;
      if (row > 7) {
        row = 15 - row;
      }
      score += row;
      int neighborTiles[6];
      int occupiedNeighborBonus = 0;
      battle14->ComputeHexNeighborTileIndices_005A0420(tileIndex, neighborTiles);
      for (int neighborIndex = 0; occupiedNeighborBonus == 0 && neighborIndex < 6;
           ++neighborIndex) {
        int neighborTileIndex = neighborTiles[neighborIndex];
        if (neighborTileIndex != -1 && battle14->tileGrid4[neighborTileIndex].occupant4 != 0) {
          occupiedNeighborBonus = 0xa;
        }
      }
      score += occupiedNeighborBonus;
      if (score > bestScore) {
        bestScore = score;
        bestTileIndex = tileIndex;
      }
    }
  }
  return bestTileIndex;
}

// FUNCTION: IMPERIALISM 0x0059c3c0
void TArmyPlayer::DeploymentClick(int tileIndex) {
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

// Re-derives the side's AI cursor mode from both sides' aggregated projection metrics
// and applies the matching per-unit stance profile. The `cursorProfileMode` parameter
// is dead in the original (popped by ret 4, never read).
// FUNCTION: IMPERIALISM 0x0059c440
void TArmyPlayer::SelectAndApplyTacticalCursorModeProfile(int cursorProfileMode) {
  (void)cursorProfileMode;

  // Is the battle site this nation's capital city record?
  unsigned char siteIsHomeCapital =
      battle14->battleSiteIndex38 ==
      g_pGlobalMapState
          ->terrainStateTable[static_cast<short>(
              g_apTerrainTypeDescriptorTable[nationIndex1C]->homeRegionIndex)]
          .cityRecordIndex;

  // Army battles always pair two TArmyPlayers; the +0x2c metric slice lives on the
  // derived class.
  TArmyPlayer* opponent;
  if (isOurSideFlagC != 0) {
    opponent = static_cast<TArmyPlayer*>(battle14->tacticalPlayer18);
  } else {
    opponent = static_cast<TArmyPlayer*>(battle14->tacticalPlayer14);
  }

  AccumulateTacticalProjectionMetricsAndUnitRanges();
  opponent->AccumulateTacticalProjectionMetricsAndUnitRanges();

  // Pointer-walk countdown copy (the original emits an fld/fstp loop, not rep movsd).
  float opponentMetrics[5];
  float* metricsDst = opponentMetrics;
  const float* metricsSrc = opponent->projectionScoreSums2C;
  for (int remaining = 5; remaining > 0; --remaining) {
    *metricsDst++ = *metricsSrc++;
  }

  // Function-scope iterator: it stays live across the switch, so the block-scoped
  // iterators below (own-unit scan + case loops) pack into a second frame slot,
  // matching the original stack layout.
  unsigned char enemyHasActiveUnit = 0;
  CIterator scanIter(opponent->unitList4);
  for (TTacticalUnit* enemyRecord = static_cast<TTacticalUnit*>(scanIter.Reset()); scanIter.More();
       enemyRecord = static_cast<TTacticalUnit*>(scanIter.Advance())) {
    if (enemyRecord->state1c == 0) {
      enemyHasActiveUnit = 1;
    }
  }
  if (enemyHasActiveUnit == 0) {
    field48 = 1;
  } else {
    field48 = 0;
  }

  int cursorMode;
  if (isOurSideFlagC == 0) {
    // Defending side.
    if (enemyHasActiveUnit == 0) {
      cursorMode = 6;
    } else if (opponent->field51 == 0 &&
               battle14->IsTacticalSideCategoryCoverageIncompleteOrFlagOff() == 0) {
      cursorMode = 7;
    } else if (projectionScoreSums2C[1] / opponentMetrics[1] >
               g_dTacticalCursorStrongRatioThreshold_00669508) {
      if (battle14->IsTacticalSideCategoryCoverageIncompleteOrFlagOff() != 0) {
        cursorMode = 2;
      } else if (projectionScoreSums2C[1] / opponentMetrics[1] >
                 g_dTacticalCursorOverwhelmRatioThreshold_00669510) {
        cursorMode = 2;
      } else {
        cursorMode = 0;
      }
    } else if (projectionScoreSums2C[0] / opponentMetrics[1] <
                   g_dTacticalCursorWeakRatioThreshold_00669518 &&
               siteIsHomeCapital == 0) {
      cursorMode = 1;
    } else {
      // Branchless in the original (setl form): outranged defenders bombard.
      cursorMode = (maxUnitRange40 < opponent->maxUnitRange40) ? 2 : 0;
    }
  } else {
    // Attacking side.
    float strengthRatio = projectionScoreSums2C[1] / opponentMetrics[0];
    unsigned char haveActiveSapper = 0;
    unsigned char haveActiveArtillery = 0;
    CIterator unitIter(unitList4);
    for (TTacticalUnit* record = static_cast<TTacticalUnit*>(unitIter.Reset()); unitIter.More();
         record = static_cast<TTacticalUnit*>(unitIter.Advance())) {
      if (g_awTacticalUnitCategoryCodeBySlot[record->unitTypeC] == 8 && record->state1c == 0) {
        haveActiveSapper = 1;
      }
      if (g_awTacticalUnitAiClassByUnitType_006693B8[record->unitTypeC] == 2 &&
          record->state1c == 0) {
        haveActiveArtillery = 1;
      }
    }
    if (battle14->IsTacticalSideCategoryCoverageIncompleteOrFlagOff() == 0) {
      // Fort wall still intact.
      if (haveActiveSapper != 0) {
        cursorMode = 3;
      } else if (haveActiveArtillery == 0) {
        cursorMode = 1;
      } else if (projectionScoreSums2C[3] / opponentMetrics[3] <
                 g_dTacticalCursorArtilleryParityThreshold_00669520) {
        cursorMode = 1;
      } else {
        cursorMode = 3;
      }
    } else {
      // No fort, or a wall section is breached.
      if (enemyHasActiveUnit == 0) {
        cursorMode = 6;
      } else if (strengthRatio > g_dTacticalCursorStrongRatioThreshold_00669508) {
        cursorMode = 4;
      } else if (!(projectionScoreSums2C[3] / opponentMetrics[3] <
                   g_dTacticalCursorArtillerySuperiorityThreshold_00669528) &&
                 haveActiveArtillery != 0) {
        cursorMode = 3;
      } else if (!(strengthRatio < g_dTacticalCursorAssaultRatioThreshold_00669530)) {
        cursorMode = 4;
      } else if (strengthRatio < g_dTacticalCursorRetreatRatioThreshold_00669538 &&
                 siteIsHomeCapital == 0) {
        cursorMode = 1;
      } else {
        cursorMode = 5;
      }
    }
  }

  if (fieldF != 0) {
    cursorMode = 1;
  }
  if (cursorMode == 1) {
    field48 = cursorMode;
  }
  if (cursorMode == lastAppliedCursorMode44) {
    return; // mode unchanged since the last application
  }
  lastAppliedCursorMode44 = cursorMode;
  switch (cursorMode) {
  case 0:
    ApplyDefenderHoldLineStanceByActionClass();
    return;
  case 1: {
    // Retreat/fallback stance: non-category-0 units get state 0xc, category-0 get 7.
    CIterator retreatIter(unitList4);
    for (TTacticalUnit* retreatRecord = static_cast<TTacticalUnit*>(retreatIter.Reset());
         retreatIter.More(); retreatRecord = static_cast<TTacticalUnit*>(retreatIter.Advance())) {
      if (g_awTacticalUnitCategoryCodeBySlot[retreatRecord->unitTypeC] != 0) {
        retreatRecord->aiStateCode2c = 0xc;
      } else {
        retreatRecord->aiStateCode2c = 7;
      }
    }
    return;
  }
  case 2:
    ApplyDefenderBombardStanceByActionClass();
    return;
  case 3:
    ApplyAttackerSiegeStanceByActionClass();
    return;
  case 4:
    ApplyAttackerAssaultStanceByActionClass();
    return;
  case 5:
    ApplyAttackerStandoffStanceByActionClass();
    return;
  case 6:
    ApplyUnopposedAdvanceStanceByActionClass();
    return;
  case 7: {
    // Hold-fire garrison stance: every unit gets state 0x13.
    CIterator garrisonIter(unitList4);
    for (TTacticalUnit* garrisonRecord = static_cast<TTacticalUnit*>(garrisonIter.Reset());
         garrisonIter.More();
         garrisonRecord = static_cast<TTacticalUnit*>(garrisonIter.Advance())) {
      garrisonRecord->aiStateCode2c = 0x13;
    }
    return;
  }
  }
}

// Applies the per-unit stance profile for the side's already-selected cursor mode
// (this->lastAppliedCursorMode44). This is the standalone copy of the apply-switch that
// SelectAndApplyTacticalCursorModeProfile (0x59c440) inlines after deriving the mode:
// modes 0/2..6 delegate to the per-action-class appliers, modes 1 and 7 set aiStateCode2c
// inline (retreat: 0xc/7 by category; garrison: 0x13). Modes >7 are a no-op.
// FUNCTION: IMPERIALISM 0x0059c970
void TArmyPlayer::ApplyTacticalStanceProfileForCurrentCursorMode() {
  switch (lastAppliedCursorMode44) {
  case 0:
    ApplyDefenderHoldLineStanceByActionClass();
    return;
  case 1: {
    // Retreat/fallback stance: non-category-0 units get state 0xc, category-0 get 7.
    CIterator retreatIter(unitList4);
    for (TTacticalUnit* retreatRecord = static_cast<TTacticalUnit*>(retreatIter.Reset());
         retreatIter.More(); retreatRecord = static_cast<TTacticalUnit*>(retreatIter.Advance())) {
      if (g_awTacticalUnitCategoryCodeBySlot[retreatRecord->unitTypeC] != 0) {
        retreatRecord->aiStateCode2c = 0xc;
      } else {
        retreatRecord->aiStateCode2c = 7;
      }
    }
    return;
  }
  case 2:
    ApplyDefenderBombardStanceByActionClass();
    return;
  case 3:
    ApplyAttackerSiegeStanceByActionClass();
    return;
  case 4:
    ApplyAttackerAssaultStanceByActionClass();
    return;
  case 5:
    ApplyAttackerStandoffStanceByActionClass();
    return;
  case 6:
    ApplyUnopposedAdvanceStanceByActionClass();
    return;
  case 7: {
    // Hold-fire garrison stance: every unit gets state 0x13.
    CIterator garrisonIter(unitList4);
    for (TTacticalUnit* garrisonRecord = static_cast<TTacticalUnit*>(garrisonIter.Reset());
         garrisonIter.More();
         garrisonRecord = static_cast<TTacticalUnit*>(garrisonIter.Advance())) {
      garrisonRecord->aiStateCode2c = 0x13;
    }
    return;
  }
  }
}

// (unitType >= 27 -> 0xb, else 0xc). Skips broken/destroyed records.
// FUNCTION: IMPERIALISM 0x0059caf0
void TArmyPlayer::ApplyDefenderHoldLineStanceByActionClass() {
  int actionClassCounts[5] = {0, 0, 0, 0, 0};
  int engageAssignedCount = 0;
  CIterator countIter(unitList4);
  for (TTacticalUnit* countRecord = static_cast<TTacticalUnit*>(countIter.Reset());
       countIter.More(); countRecord = static_cast<TTacticalUnit*>(countIter.Advance())) {
    ++actionClassCounts[g_awTacticalUnitAiClassByUnitType_006693B8[countRecord->unitTypeC]];
  }

  CIterator applyIter(unitList4);
  for (TTacticalUnit* record = static_cast<TTacticalUnit*>(applyIter.Reset()); applyIter.More();
       record = static_cast<TTacticalUnit*>(applyIter.Advance())) {
    if (record->state1c != 0) {
      continue;
    }
    switch (g_awTacticalUnitAiClassByUnitType_006693B8[record->unitTypeC]) {
    case 0:
      record->aiStateCode2c = 0;
      break;
    case 2:
      record->aiStateCode2c = 9;
      break;
    case 1:
    case 3:
      // Faithful dead conditions: counts and the assigned counter are never negative, so
      // every class-1/3 unit gets 0xe (original-game dead code).
      if (actionClassCounts[0] < actionClassCounts[2] && actionClassCounts[0] < 0 &&
          engageAssignedCount < 0) {
        record->aiStateCode2c = 0;
        ++engageAssignedCount;
      } else {
        record->aiStateCode2c = 0xe;
      }
      break;
    case 4:
      if (record->unitTypeC >= 0x1b) {
        record->aiStateCode2c = 0xb;
      } else {
        record->aiStateCode2c = 0xc;
      }
      break;
    }
  }
}

// Mode 2 (defender bombard/outrange): artillery(class 2) gets 8, cavalry/flankers
// (classes 1,3) get 5, infantry(class 0) holds (7; the escort branch is dead),
// class 4 splits by unitType >= 27 (0xb vs 0xc). Skips broken/destroyed records.
// FUNCTION: IMPERIALISM 0x0059cd00
void TArmyPlayer::ApplyDefenderBombardStanceByActionClass() {
  int actionClassCounts[5] = {0, 0, 0, 0, 0};
  int engageAssignedCount = 0;
  int escortAssignedCount = 0;
  CIterator countIter(unitList4);
  for (TTacticalUnit* countRecord = static_cast<TTacticalUnit*>(countIter.Reset());
       countIter.More(); countRecord = static_cast<TTacticalUnit*>(countIter.Advance())) {
    ++actionClassCounts[g_awTacticalUnitAiClassByUnitType_006693B8[countRecord->unitTypeC]];
  }

  CIterator applyIter(unitList4);
  for (TTacticalUnit* record = static_cast<TTacticalUnit*>(applyIter.Reset()); applyIter.More();
       record = static_cast<TTacticalUnit*>(applyIter.Advance())) {
    if (record->state1c != 0) {
      continue;
    }
    switch (g_awTacticalUnitAiClassByUnitType_006693B8[record->unitTypeC]) {
    case 0:
      // Faithful dead conditions: engageAssignedCount stays 0, so every infantry unit
      // gets 7 (original-game dead code, kept literally).
      if (engageAssignedCount > 0 && escortAssignedCount < actionClassCounts[2]) {
        record->aiStateCode2c = 1;
        ++escortAssignedCount;
      } else if (engageAssignedCount < 0) {
        record->aiStateCode2c = 0;
        ++engageAssignedCount;
      } else {
        record->aiStateCode2c = 7;
      }
      break;
    case 2:
      record->aiStateCode2c = 8;
      break;
    case 1:
    case 3:
      record->aiStateCode2c = 5;
      break;
    case 4:
      if (record->unitTypeC >= 0x1b) {
        record->aiStateCode2c = 0xb;
      } else {
        record->aiStateCode2c = 0xc;
      }
      break;
    }
  }
}

// Mode 3 (attacker siege vs fort): sappers (category 8) target the wall (0xd while
// the wall record at tile 174 is intact, 0xc once breached); infantry(class 0)
// outranging the enemy's non-artillery reach snipes (0x11), cavalry-charge category 1
// hunts artillery when the enemy has deployed active artillery (0x10, else 0xa),
// otherwise engages (1); classes 1,3 screen (0xe); artillery(class 2) bombards
// (category 6 -> 0x11, else 8); class 4 remainder gets 0xb. No state1c filter.
// FUNCTION: IMPERIALISM 0x0059ce90
void TArmyPlayer::ApplyAttackerSiegeStanceByActionClass() {
  TArmyPlayer* opponent;
  if (isOurSideFlagC != 0) {
    opponent = static_cast<TArmyPlayer*>(battle14->tacticalPlayer18);
  } else {
    opponent = static_cast<TArmyPlayer*>(battle14->tacticalPlayer14);
  }
  short opponentMaxNonArtilleryRange = opponent->maxNonArtilleryUnitRange42;
  unsigned char enemyHasDeployedArtillery = OpponentHasDeployedActiveArtilleryUnit();

  CIterator applyIter(unitList4);
  for (TTacticalUnit* record = static_cast<TTacticalUnit*>(applyIter.Reset()); applyIter.More();
       record = static_cast<TTacticalUnit*>(applyIter.Advance())) {
    if (g_awTacticalUnitCategoryCodeBySlot[record->unitTypeC] == 8) {
      // Fort-wall reference tile (grid index 174 = row 6, column 0); deployMark8 > 1
      // is the standing wall level.
      if (battle14->tileGrid4[174].deployMark8 > 1) {
        record->aiStateCode2c = 0xd;
      } else {
        record->aiStateCode2c = 0xc;
      }
      continue;
    }
    switch (g_awTacticalUnitAiClassByUnitType_006693B8[record->unitTypeC]) {
    case 0:
      if (record->GetUnitRange() > opponentMaxNonArtilleryRange) {
        record->aiStateCode2c = 0x11;
      } else if (g_awTacticalUnitCategoryCodeBySlot[record->unitTypeC] == 1) {
        record->aiStateCode2c = enemyHasDeployedArtillery != 0 ? 0x10 : 0xa;
      } else {
        record->aiStateCode2c = 1;
      }
      break;
    case 1:
    case 3:
      record->aiStateCode2c = 0xe;
      break;
    case 2:
      if (g_awTacticalUnitCategoryCodeBySlot[record->unitTypeC] == 6) {
        record->aiStateCode2c = 0x11;
      } else {
        record->aiStateCode2c = 8;
      }
      break;
    case 4:
      record->aiStateCode2c = 0xb;
      break;
    }
  }
}

// Mode 4 (attacker assault): same class-0/class-2 logic as the siege profile but
// infantry defaults to hold (7), cavalry/flankers(classes 1,3) get 5, and class 4
// splits sapper (category 8 -> 0xc) vs 0xb. No state1c filter.
// FUNCTION: IMPERIALISM 0x0059d020
void TArmyPlayer::ApplyAttackerAssaultStanceByActionClass() {
  TArmyPlayer* opponent;
  if (isOurSideFlagC != 0) {
    opponent = static_cast<TArmyPlayer*>(battle14->tacticalPlayer18);
  } else {
    opponent = static_cast<TArmyPlayer*>(battle14->tacticalPlayer14);
  }
  short opponentMaxNonArtilleryRange = opponent->maxNonArtilleryUnitRange42;
  unsigned char enemyHasDeployedArtillery = OpponentHasDeployedActiveArtilleryUnit();

  CIterator applyIter(unitList4);
  for (TTacticalUnit* record = static_cast<TTacticalUnit*>(applyIter.Reset()); applyIter.More();
       record = static_cast<TTacticalUnit*>(applyIter.Advance())) {
    switch (g_awTacticalUnitAiClassByUnitType_006693B8[record->unitTypeC]) {
    case 0:
      if (record->GetUnitRange() > opponentMaxNonArtilleryRange) {
        record->aiStateCode2c = 0x11;
      } else if (g_awTacticalUnitCategoryCodeBySlot[record->unitTypeC] == 1) {
        record->aiStateCode2c = enemyHasDeployedArtillery != 0 ? 0x10 : 0xa;
      } else {
        record->aiStateCode2c = 7;
      }
      break;
    case 1:
    case 3:
      record->aiStateCode2c = 5;
      break;
    case 2:
      if (g_awTacticalUnitCategoryCodeBySlot[record->unitTypeC] == 6) {
        record->aiStateCode2c = 0x11;
      } else {
        record->aiStateCode2c = 8;
      }
      break;
    case 4:
      if (g_awTacticalUnitCategoryCodeBySlot[record->unitTypeC] == 8) {
        record->aiStateCode2c = 0xc;
      } else {
        record->aiStateCode2c = 0xb;
      }
      break;
    }
  }
}

// Mode 5 (attacker cautious/standoff): byte-for-byte the mode-4 profile except
// cavalry/flankers(classes 1,3) get 2 instead of 5.
// FUNCTION: IMPERIALISM 0x0059d1a0
void TArmyPlayer::ApplyAttackerStandoffStanceByActionClass() {
  TArmyPlayer* opponent;
  if (isOurSideFlagC != 0) {
    opponent = static_cast<TArmyPlayer*>(battle14->tacticalPlayer18);
  } else {
    opponent = static_cast<TArmyPlayer*>(battle14->tacticalPlayer14);
  }
  short opponentMaxNonArtilleryRange = opponent->maxNonArtilleryUnitRange42;
  unsigned char enemyHasDeployedArtillery = OpponentHasDeployedActiveArtilleryUnit();

  CIterator applyIter(unitList4);
  for (TTacticalUnit* record = static_cast<TTacticalUnit*>(applyIter.Reset()); applyIter.More();
       record = static_cast<TTacticalUnit*>(applyIter.Advance())) {
    switch (g_awTacticalUnitAiClassByUnitType_006693B8[record->unitTypeC]) {
    case 0:
      if (record->GetUnitRange() > opponentMaxNonArtilleryRange) {
        record->aiStateCode2c = 0x11;
      } else if (g_awTacticalUnitCategoryCodeBySlot[record->unitTypeC] == 1) {
        record->aiStateCode2c = enemyHasDeployedArtillery != 0 ? 0x10 : 0xa;
      } else {
        record->aiStateCode2c = 7;
      }
      break;
    case 1:
    case 3:
      record->aiStateCode2c = 2;
      break;
    case 2:
      if (g_awTacticalUnitCategoryCodeBySlot[record->unitTypeC] == 6) {
        record->aiStateCode2c = 0x11;
      } else {
        record->aiStateCode2c = 8;
      }
      break;
    case 4:
      if (g_awTacticalUnitCategoryCodeBySlot[record->unitTypeC] == 8) {
        record->aiStateCode2c = 0xc;
      } else {
        record->aiStateCode2c = 0xb;
      }
      break;
    }
  }
}

// Mode 6 (unopposed -- the enemy has no active unit left): fixed stance per class
// with no range/opponent checks: infantry 7, cavalry/flankers 5, artillery 8, class 4
// splits sapper (category 8 -> 0xc) vs 0xb. No state1c filter.
// FUNCTION: IMPERIALISM 0x0059d320
void TArmyPlayer::ApplyUnopposedAdvanceStanceByActionClass() {
  CIterator applyIter(unitList4);
  for (TTacticalUnit* record = static_cast<TTacticalUnit*>(applyIter.Reset()); applyIter.More();
       record = static_cast<TTacticalUnit*>(applyIter.Advance())) {
    switch (g_awTacticalUnitAiClassByUnitType_006693B8[record->unitTypeC]) {
    case 0:
      record->aiStateCode2c = 7;
      break;
    case 1:
    case 3:
      record->aiStateCode2c = 5;
      break;
    case 2:
      record->aiStateCode2c = 8;
      break;
    case 4:
      if (g_awTacticalUnitCategoryCodeBySlot[record->unitTypeC] == 8) {
        record->aiStateCode2c = 0xc;
      } else {
        record->aiStateCode2c = 0xb;
      }
      break;
    }
  }
}

// Blanket hold-fire stance: sets every unit's aiStateCode2c to 0x13. The standalone
// sibling of ApplyTacticalStanceProfileForCurrentCursorMode's mode-7 inline loop.
// FUNCTION: IMPERIALISM 0x0059d400
void TArmyPlayer::SetAllUnitAiStateCodesTo13() {
  CIterator iter(unitList4);
  for (TTacticalUnit* record = static_cast<TTacticalUnit*>(iter.Reset()); iter.More();
       record = static_cast<TTacticalUnit*>(iter.Advance())) {
    record->aiStateCode2c = 0x13;
  }
}

// Whether the opposing side has a deployed (tileIndex8 >= 0), still-active
// (state1c == 0) artillery-class (aiClass 2) unit.
// FUNCTION: IMPERIALISM 0x0059d470
unsigned char TArmyPlayer::OpponentHasDeployedActiveArtilleryUnit() {
  TList* opponentUnitList;
  if (isOurSideFlagC != 0) {
    opponentUnitList = battle14->tacticalPlayer18->unitList4;
  } else {
    opponentUnitList = battle14->tacticalPlayer14->unitList4;
  }
  CIterator enemyIter(opponentUnitList);
  for (TTacticalUnit* record = static_cast<TTacticalUnit*>(enemyIter.Reset()); enemyIter.More();
       record = static_cast<TTacticalUnit*>(enemyIter.Advance())) {
    if (record->tileIndex8 >= 0 &&
        g_awTacticalUnitAiClassByUnitType_006693B8[record->unitTypeC] == 2 &&
        record->state1c == 0) {
      return 1;
    }
  }
  return 0;
}

// Weighted tile chooser for the auto-turn controller: builds the distance field when
// the advance heuristic (column 8) is weighted, then scores every reachable tile as
// sum(weight[i] * heuristic[i](unit, tile)), tie-breaking on lower move cost, and
// writes the per-tile score into battle14->tileIntArray2c.
// FUNCTION: IMPERIALISM 0x0059d530
int TArmyPlayer::SelectBestTacticalTileByWeightedHeuristics(TTacticalUnit* unit,
                                                            int* heuristicWeights15) {
  int bestTileIndex = -1;
  int bestScore = -99999;
  char distanceFieldBuilt = 0;
  if (heuristicWeights15[8] > 0) {
    battle14->BuildTacticalDistanceFieldForSide(isOurSideFlagC);
    distanceFieldBuilt = 1;
  }
  for (int tileIndex = 0; tileIndex < battle14->tacticalTileCount3c; ++tileIndex) {
    int column = tileIndex % 29;
    if (battle14->tileMoveCostArray24[tileIndex] == -1) {
      battle14->tileIntArray2c[tileIndex] = 0;
      continue;
    }
    if (distanceFieldBuilt == 0) {
      // Without the distance field, never pick the outer edge columns.
      if (column == 0 || column == battle14->battlefieldColumnCount34 - 1) {
        battle14->tileIntArray2c[tileIndex] = 0;
        continue;
      }
    }
    int score = 0;
    for (int heuristicIndex = 0; heuristicIndex < 15; ++heuristicIndex) {
      if (heuristicWeights15[heuristicIndex] != 0) {
        score +=
            (this->*g_apfnTacticalTileHeuristicScorers_006994C0[heuristicIndex])(unit, tileIndex) *
            heuristicWeights15[heuristicIndex];
      }
    }
    if (score > bestScore ||
        (score == bestScore &&
         battle14->tileMoveCostArray24[tileIndex] < battle14->tileMoveCostArray24[bestTileIndex])) {
      // Faithful: on the first tie bestTileIndex is still -1, so the original reads the
      // move-cost word one slot before the array too (tileMoveCostArray24[-1]).
      bestTileIndex = tileIndex;
      bestScore = score;
    }
    battle14->tileIntArray2c[tileIndex] = score;
  }
  return bestTileIndex;
}

// Heuristic [0]: 100 for the tile the unit already stands on (hold position).
// FUNCTION: IMPERIALISM 0x0059d6b0
int TArmyPlayer::ScoreTacticalTileHoldPositionBonus(TTacticalUnit* unit, int tileIndex) {
  return (unit->tileIndex8 == tileIndex) ? 0x64 : 0;
}

// Heuristic [1]: 50 when some (active, or morale-broken in field48==1 mode) enemy is
// engageable from the tile, plus 50-minus-distance toward the current best target tile
// (skipped for artillery that can already engage).
// FUNCTION: IMPERIALISM 0x0059d6e0
int TArmyPlayer::ScoreTacticalTileFireOpportunityAndTargetApproach(TTacticalUnit* unit,
                                                                   int tileIndex) {
  // Dead call in the original: the result is discarded, but the compiler fetched the
  // vtable slot into a stack temp and re-called it inside the loop.
  unit->GetUnitRange();
  int score = 0;
  for (int scanTileIndex = 0; score == 0 && scanTileIndex < battle14->tacticalTileCount3c;
       ++scanTileIndex) {
    TTacticalUnit* occupant = battle14->tileGrid4[scanTileIndex].occupant4;
    if (occupant != 0 && occupant->side20 != unit->side20 &&
        (occupant->state1c == 0 || field48 == 1)) {
      short categoryCode = g_awTacticalUnitCategoryCodeBySlot[unit->unitTypeC];
      if (battle14->IsTacticalTargetTileReachableForAction(
              tileIndex, scanTileIndex,
              static_cast<char>(static_cast<int>(
                  g_afTacticalDirectFireFlagByCategoryCode_00669390[categoryCode])),
              unit->GetUnitRange()) != 0) {
        score = 0x32;
      }
    }
  }
  int targetTileIndex = SelectBestTacticalTargetTileByActionHeuristics(unit, 0);
  if (targetTileIndex != -1) {
    if (g_awTacticalUnitAiClassByUnitType_006693B8[unit->unitTypeC] != 2 || score == 0) {
      score += 0x32 - ComputeHexTileDistanceFromIndices(tileIndex, targetTileIndex);
    }
  }
  return score;
}

// Heuristic [2]: sapper wall-approach cell -- only column 6 scores: 80 (100 when the
// tile carries a deploy/wall mark), minus 20 for each friendly on the row-neighbor
// tiles left and right.
// FUNCTION: IMPERIALISM 0x0059d810
int TArmyPlayer::ScoreTacticalTileSapperWallApproachColumn(TTacticalUnit* unit, int tileIndex) {
  if (tileIndex % 29 != 6) {
    return 0;
  }
  TacticalTileRecord* tile = &battle14->tileGrid4[tileIndex];
  int score = ((tile->deployMark8 != 0) ? 0x14 : 0) + 0x50;
  TTacticalUnit* rightOccupant = tile[1].occupant4;
  if (rightOccupant != 0 && rightOccupant->side20 == unit->side20) {
    score -= 0x14;
  }
  TTacticalUnit* leftOccupant = tile[-1].occupant4;
  if (leftOccupant != 0 && leftOccupant->side20 == unit->side20) {
    score -= 0x14;
  }
  return score;
}

// Heuristic [3]: 100 when an enemy unit (active, or morale-broken in field48==1 mode)
// occupies one of the six hex neighbors of the tile.
// FUNCTION: IMPERIALISM 0x0059d8a0
int TArmyPlayer::ScoreTacticalTileAdjacentEnemyContact(TTacticalUnit* unit, int tileIndex) {
  int neighborTiles[6];
  battle14->ComputeHexNeighborTileIndices_005A0420(tileIndex, neighborTiles);
  for (int neighborIndex = 0; neighborIndex < 6; ++neighborIndex) {
    int neighborTileIndex = neighborTiles[neighborIndex];
    if (neighborTileIndex != -1) {
      TTacticalUnit* occupant = battle14->tileGrid4[neighborTileIndex].occupant4;
      if (occupant != 0 && occupant->side20 != unit->side20 &&
          (occupant->state1c == 0 || field48 == 1)) {
        return 0x64;
      }
    }
  }
  return 0;
}

// Heuristic [4]: how many deployed enemy units could engage this tile.
// FUNCTION: IMPERIALISM 0x0059d940
int TArmyPlayer::ScoreTacticalTileEnemyEngagementExposureCount(TTacticalUnit* unit, int tileIndex) {
  (void)unit;
  int exposureCount = 0;
  TList* enemyList;
  if (isOurSideFlagC != 0) {
    enemyList = battle14->tacticalPlayer18->unitList4;
  } else {
    enemyList = battle14->tacticalPlayer14->unitList4;
  }
  CIterator enemyIter(enemyList);
  for (TTacticalUnit* record = static_cast<TTacticalUnit*>(enemyIter.Reset()); enemyIter.More();
       record = static_cast<TTacticalUnit*>(enemyIter.Advance())) {
    if (record->tileIndex8 >= 0) {
      short categoryCode = g_awTacticalUnitCategoryCodeBySlot[record->unitTypeC];
      if (battle14->IsTacticalTargetTileReachableForAction(
              tileIndex, record->tileIndex8,
              static_cast<char>(static_cast<int>(
                  g_afTacticalDirectFireFlagByCategoryCode_00669390[categoryCode])),
              record->GetUnitRange()) != 0) {
        ++exposureCount;
      }
    }
  }
  return exposureCount;
}

// Heuristic [5]: proximity to this side's home/retreat edge row -- which edge is home
// was coin-flipped into randomParityByte50 at side init; 100 within two rows of it,
// tapering by (50 * rows-from-far-edge / 15) elsewhere.
// FUNCTION: IMPERIALISM 0x0059da20
int TArmyPlayer::ScoreTacticalTileRetreatEdgeRowProximity(TTacticalUnit* unit, int tileIndex) {
  (void)unit;
  int row = tileIndex / 29;
  if (randomParityByte50 != 0) {
    if (row <= 1) {
      return 0x64;
    }
    return (0xf - row) * 50 / 15;
  }
  if (row >= 0xd) {
    return 0x64;
  }
  return row * 50 / 15;
}

// Heuristic [6]: 100 on cover terrain (terrain codes 1 and 2).
// FUNCTION: IMPERIALISM 0x0059dac0
int TArmyPlayer::ScoreTacticalTileCoverTerrainBonus(TTacticalUnit* unit, int tileIndex) {
  (void)unit;
  int terrainType = battle14->tileGrid4[tileIndex].terrainType0;
  if (terrainType == 1 || terrainType == 2) {
    return 0x64;
  }
  return 0;
}

// Heuristic [7]: 100 when a friendly whose morale dropped below its strength occupies
// one of the tile's hex neighbors (officer rally magnet).
// FUNCTION: IMPERIALISM 0x0059db00
int TArmyPlayer::ScoreTacticalTileAdjacentRallyTargetBonus(TTacticalUnit* unit, int tileIndex) {
  int neighborTiles[6];
  battle14->ComputeHexNeighborTileIndices_005A0420(tileIndex, neighborTiles);
  for (int neighborIndex = 0; neighborIndex < 6; ++neighborIndex) {
    int neighborTileIndex = neighborTiles[neighborIndex];
    if (neighborTileIndex != -1) {
      TArmyTacUnit* occupant =
          static_cast<TArmyTacUnit*>(battle14->tileGrid4[neighborTileIndex].occupant4);
      if (occupant != 0 && occupant->side20 == unit->side20 &&
          occupant->morale34 < occupant->strength4) {
        return 0x64;
      }
    }
  }
  return 0;
}

// Heuristic [8]: advance along the distance field built by
// BuildTacticalDistanceFieldForSide (100 minus the tile's field value).
// FUNCTION: IMPERIALISM 0x0059dba0
int TArmyPlayer::ScoreTacticalTileDistanceFieldAdvance(TTacticalUnit* unit, int tileIndex) {
  (void)unit;
  int fieldValue = battle14->tileIntArray30[tileIndex];
  if (fieldValue != -1) {
    return 0x64 - fieldValue;
  }
  return 0;
}

// Heuristic [9]: stay near (but not within 2 tiles of) our own artillery -- 0
// immediately if any friendly artillery is within distance 2, else the best
// 100-minus-10*distance over all friendly artillery.
// FUNCTION: IMPERIALISM 0x0059dbe0
int TArmyPlayer::ScoreTacticalTileFriendlyArtillerySpacing(TTacticalUnit* unit, int tileIndex) {
  (void)unit;
  int bestScore = 0;
  CIterator friendIter(unitList4);
  for (TTacticalUnit* record = static_cast<TTacticalUnit*>(friendIter.Reset()); friendIter.More();
       record = static_cast<TTacticalUnit*>(friendIter.Advance())) {
    if (g_awTacticalUnitAiClassByUnitType_006693B8[record->unitTypeC] == 2) {
      int distance = ComputeHexTileDistanceFromIndices(tileIndex, record->tileIndex8);
      if (distance <= 2) {
        return 0;
      }
      int score = 0x64 - distance * 100 / 10;
      if (score > bestScore) {
        bestScore = score;
      }
    }
  }
  return bestScore;
}

// Heuristic [10]: artillery firing-lane column -- score equals the column index when
// the tile is unthreatened, at or left of the fort-wall column, and no blocking
// terrain (code 4) sits between the tile and that column on its row.
// FUNCTION: IMPERIALISM 0x0059dcd0
int TArmyPlayer::ScoreTacticalTileArtilleryFiringLaneColumn(TTacticalUnit* unit, int tileIndex) {
  (void)unit;
  int column = tileIndex % 29;
  int wallColumn = battle14->battlefieldColumnCount34 - 6;
  if (column < wallColumn) {
    TacticalTileRecord* scanTile = &battle14->tileGrid4[tileIndex];
    for (int scanColumn = column; scanColumn < wallColumn; ++scanColumn, ++scanTile) {
      if (scanTile->terrainType0 == 4) {
        return 0;
      }
    }
  }
  if (battle14->tileThreatLevelArray28[tileIndex] != 0) {
    return 0;
  }
  if (column > wallColumn) {
    return 0;
  }
  return column;
}

// Heuristic [11]: how many deployed enemy artillery units could engage this tile.
// FUNCTION: IMPERIALISM 0x0059dd40
int TArmyPlayer::ScoreTacticalTileEnemyArtilleryExposureCount(TTacticalUnit* unit, int tileIndex) {
  (void)unit;
  int exposureCount = 0;
  TList* enemyList;
  if (isOurSideFlagC != 0) {
    enemyList = battle14->tacticalPlayer18->unitList4;
  } else {
    enemyList = battle14->tacticalPlayer14->unitList4;
  }
  CIterator enemyIter(enemyList);
  for (TTacticalUnit* record = static_cast<TTacticalUnit*>(enemyIter.Reset()); enemyIter.More();
       record = static_cast<TTacticalUnit*>(enemyIter.Advance())) {
    if (record->tileIndex8 >= 0 &&
        g_awTacticalUnitAiClassByUnitType_006693B8[record->unitTypeC] == 2) {
      short categoryCode = g_awTacticalUnitCategoryCodeBySlot[record->unitTypeC];
      if (battle14->IsTacticalTargetTileReachableForAction(
              tileIndex, record->tileIndex8,
              static_cast<char>(static_cast<int>(
                  g_afTacticalDirectFireFlagByCategoryCode_00669390[categoryCode])),
              record->GetUnitRange()) != 0) {
        ++exposureCount;
      }
    }
  }
  return exposureCount;
}

// Heuristic [12]: standoff scorer -- 50 plus the distance to the NEAREST active enemy
// engageable from the tile (+5 when the current best target tile is also engageable);
// when nothing is engageable, 50 minus the distance to the best target tile.
// FUNCTION: IMPERIALISM 0x0059de30
int TArmyPlayer::ScoreTacticalTileEngageableEnemyStandoff(TTacticalUnit* unit, int tileIndex) {
  int range = unit->GetUnitRange();
  int score = 0;
  int targetTileIndex = SelectBestTacticalTargetTileByActionHeuristics(unit, 0);
  for (int scanTileIndex = 0; scanTileIndex < battle14->tacticalTileCount3c; ++scanTileIndex) {
    TTacticalUnit* occupant = battle14->tileGrid4[scanTileIndex].occupant4;
    if (occupant != 0 && occupant->side20 != unit->side20 && occupant->state1c == 0) {
      short categoryCode = g_awTacticalUnitCategoryCodeBySlot[unit->unitTypeC];
      if (battle14->IsTacticalTargetTileReachableForAction(
              tileIndex, scanTileIndex,
              static_cast<char>(static_cast<int>(
                  g_afTacticalDirectFireFlagByCategoryCode_00669390[categoryCode])),
              range) != 0) {
        int candidateScore = ComputeHexTileDistanceFromIndices(tileIndex, scanTileIndex) + 0x32;
        if (score == 0 || candidateScore < score) {
          score = candidateScore;
        }
      }
    }
  }
  if (score > 0) {
    short bonusCategoryCode = g_awTacticalUnitCategoryCodeBySlot[unit->unitTypeC];
    if (battle14->IsTacticalTargetTileReachableForAction(
            tileIndex, targetTileIndex,
            static_cast<char>(static_cast<int>(
                g_afTacticalDirectFireFlagByCategoryCode_00669390[bonusCategoryCode])),
            range) != 0) {
      score += 5;
    }
    if (score > 0) {
      return score;
    }
  }
  if (targetTileIndex != -1) {
    return 0x32 - ComputeHexTileDistanceFromIndices(tileIndex, targetTileIndex);
  }
  return 0;
}

// Heuristic [13]: 100 when some active enemy artillery unit is engageable from the
// tile (artillery-hunt magnet).
// FUNCTION: IMPERIALISM 0x0059dfe0
int TArmyPlayer::ScoreTacticalTileEnemyArtilleryHuntBonus(TTacticalUnit* unit, int tileIndex) {
  int range = unit->GetUnitRange();
  for (int scanTileIndex = 0; scanTileIndex < battle14->tacticalTileCount3c; ++scanTileIndex) {
    TTacticalUnit* occupant = battle14->tileGrid4[scanTileIndex].occupant4;
    if (occupant != 0 && occupant->side20 != unit->side20 && occupant->state1c == 0 &&
        g_awTacticalUnitAiClassByUnitType_006693B8[occupant->unitTypeC] == 2) {
      short categoryCode = g_awTacticalUnitCategoryCodeBySlot[unit->unitTypeC];
      if (battle14->IsTacticalTargetTileReachableForAction(
              tileIndex, scanTileIndex,
              static_cast<char>(static_cast<int>(
                  g_afTacticalDirectFireFlagByCategoryCode_00669390[categoryCode])),
              range) != 0) {
        return 0x64;
      }
    }
  }
  return 0;
}

// Heuristic [14]: 100 inside the enemy-edge column zone (column beyond
// battlefieldColumnCount34 - 5).
// FUNCTION: IMPERIALISM 0x0059e0d0
int TArmyPlayer::ScoreTacticalTileEnemyEdgeColumnZoneBonus(TTacticalUnit* unit, int tileIndex) {
  (void)unit;
  return (tileIndex % 29 > battle14->battlefieldColumnCount34 - 5) ? 0x64 : 0;
}

// Picks the tile of the most valuable enemy target: base value by unit category, plus
// (strength, or 500-minus-morale in field48==1 mode), doubled for adjacent entrenched
// targets and again for adjacent targets of aiClass-1 attackers. When no target exists
// and this attacker-side unit is indirect-fire with the fort still intact, falls back
// to a cached random fort-wall-column bombardment tile (field4C), rerolled off the
// wall gun-slot rows.
// FUNCTION: IMPERIALISM 0x0059e110
int TArmyPlayer::SelectBestTacticalTargetTileByActionHeuristics(TTacticalUnit* unit, int flag) {
  int bestTargetTileIndex = -1;
  int bestTargetScore = 0;
  TList* enemyList;
  if (isOurSideFlagC != 0) {
    enemyList = battle14->tacticalPlayer18->unitList4;
  } else {
    enemyList = battle14->tacticalPlayer14->unitList4;
  }
  int neighborTiles[6];
  battle14->ComputeHexNeighborTileIndices_005A0420(unit->tileIndex8, neighborTiles);

  CIterator enemyIter(enemyList);
  for (TArmyTacUnit* record = static_cast<TArmyTacUnit*>(enemyIter.Reset()); enemyIter.More();
       record = static_cast<TArmyTacUnit*>(enemyIter.Advance())) {
    // Valid targets: active units, plus morale-broken ones in field48==1 mode.
    if (!(field48 == 1 && record->state1c == 1) && record->state1c != 0) {
      continue;
    }
    if (flag != 0) { // read as a byte (char) in the original
      short reachCategoryCode = g_awTacticalUnitCategoryCodeBySlot[unit->unitTypeC];
      if (battle14->IsTacticalTargetTileReachableForAction(
              unit->tileIndex8, record->tileIndex8,
              static_cast<char>(static_cast<int>(
                  g_afTacticalDirectFireFlagByCategoryCode_00669390[reachCategoryCode])),
              unit->GetUnitRange()) == 0) {
        continue;
      }
    }
    int targetValueByCategoryCode[10] = {0x1f4, 0x1f4, 0x1f4, 0x1f4, 0x258,
                                         0x2bc, 0x320, 0x384, 0x64,  0x190};
    int score = targetValueByCategoryCode[g_awTacticalUnitCategoryCodeBySlot[record->unitTypeC]];
    if (field48 == 1) {
      score += 0x1f4 - record->morale34;
    } else {
      score += record->strength4;
    }
    int recordTileIndex = record->tileIndex8;
    char adjacent = 0;
    for (int neighborIndex = 0; neighborIndex < 6; ++neighborIndex) {
      if (recordTileIndex == neighborTiles[neighborIndex]) {
        adjacent = 1;
      }
    }
    if (adjacent != 0) {
      if (battle14->tileGrid4[recordTileIndex].deployMark8 == 1) {
        score += score; // entrenched adjacent target: double
      }
      if (g_awTacticalUnitAiClassByUnitType_006693B8[unit->unitTypeC] == 1) {
        score += score; // aiClass-1 attacker prefers adjacent targets: double again
      }
    }
    if (bestTargetTileIndex == -1 || score > bestTargetScore) {
      bestTargetTileIndex = recordTileIndex;
      bestTargetScore = score;
    }
  }

  if (bestTargetTileIndex == -1 && unit->side20 == 0 &&
      g_afTacticalDirectFireFlagByCategoryCode_00669390
              [g_awTacticalUnitCategoryCodeBySlot[unit->unitTypeC]] == 0.0f &&
      battle14->IsTacticalSideCategoryCoverageIncompleteOrFlagOff() == 0) {
    if (field4C == -1) {
      // Roll a fort-wall-column tile (rows 1..13; column = columnCount-6 + one full
      // row stride), rerolling while it lands on a wall gun-slot row (5/7/9).
      int rolledTileIndex;
      do {
        rolledTileIndex =
            (static_cast<int>(rand()) % 0xd) * 29 + battle14->battlefieldColumnCount34 + 0x17;
        field4C = rolledTileIndex;
      } while (battle14->IsTacticalTileAtFortWallSectionSlot(rolledTileIndex) != 0);
    }
    bestTargetTileIndex = field4C;
  }
  return bestTargetTileIndex;
}

// Per-tick battle pump. In the field20 phase it waits on an active sapper record:
// once the battle's selection has moved off the sapper it queues the 0x232a hand-back
// event, and when the sapper is selected (or none remains active) it clears the phase.
// Otherwise an unwatched side runs one auto-turn step, with a right-Windows-key
// cancel check for watched-then-released sides.
// FUNCTION: IMPERIALISM 0x0059e3e0
void TArmyPlayer::AdvanceTacticalTurnPulse() {
  if (field20 != 0) {
    CIterator unitIter(unitList4);
    TTacticalUnit* record = static_cast<TTacticalUnit*>(unitIter.Reset());
    while (unitIter.More() != 0) {
      if (g_awTacticalUnitCategoryCodeBySlot[record->unitTypeC] == 8 && record->state1c == 0) {
        if (g_awTacticalUnitCategoryCodeBySlot[battle14->selectedUnit1c->unitTypeC] != 8) {
          battle14->QueueTacticalEventPacket232A();
          return;
        }
        field20 = 0;
        return;
      }
      record = static_cast<TTacticalUnit*>(unitIter.Advance());
    }
    field20 = 0;
    return;
  }
  if (notWatchedFlagE != 0) {
    if (watchFlagD != 0) {
      if (GetAsyncKeyState(0x5c /* VK_RWIN */) & 0x8000) {
        notWatchedFlagE = 0;
        return;
      }
    }
    RunTacticalAutoTurnControllerForActiveUnit();
  }
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
             battle14->roundCounter74 < 2) {
    targetTileIndex = homeTileIndex;
  } else if (categoryCode == 6 && battle14->roundCounter74 < 2) {
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
    while (battle14->pendingEndOfActionFlag48 != 0 && unit->state1c == 0 &&
           unit->tileIndex8 != targetTileIndex) {
      if (moveGuard-- == 0) {
        break;
      }
      battle14->MoveTacticalUnitAndQueueEvent232AIfNoAdjacentReachableTarget(unit, targetTileIndex);
    }
  }

  // Phase 3: act from the reached tile.
  if (battle14->pendingEndOfActionFlag48 != 0 && unit->state1c == 0) {
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
          // If the wall tile is occupied or already trenched, neither branch runs and the
          // action points are unchanged, so the original re-tests the same loop condition
          // (a potential infinite loop in the original game code) -- faithful transcription.
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
        if (battle14->pendingEndOfActionFlag48 != 0 &&
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
  if (battle14->pendingEndOfActionFlag48 != 0) {
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
