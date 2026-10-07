#include "game/tactical/TArmyPlayer.h"
#include "game/ui_core/TWindow.h"
#include "game/ui_tags_common.h"

#include <stdlib.h>

#include "game/ui_core/CIterator.h"
#include "game/map/map_overlay_geometry.h"
#include "game/military/TArmyStack.h"
#include "game/tactical/TArmyTacUnit.h"
#include "game/TList.h"
#include "game/assets/TAssetMgr.h"
#include "game/city_ui/TCountry.h"
#include "game/map/TMapMgr.h"
#include "game/military/TMilitaryUnit.h"
#include "game/tactical/TTacticalBattle.h"
#include "game/tactical_ui/TTacticalHolaPicture.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/ui_core/TViewMgr.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"
#include "game/globals/tactical_globals.h"
#include "game/gfx/ui_invalidation_guard.h"

// FUNCTION: IMPERIALISM 0x005362c0
float __cdecl ComputeDistributionSimilarityScoreFromVectorAndReferenceProfile(
    float* vector, const short* referenceProfile, int count) {
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

// FUNCTION: IMPERIALISM 0x0059b070
short __cdecl CompareTacticalCursorEntriesByActionClassPriority(void* a, void* b, void* context) {
  (void)context;
  short priorityByAiClass[5] = {1, 0, 2, 0, 0};
  TTacticalUnit* unitA = static_cast<TTacticalUnit*>(a);
  TTacticalUnit* unitB = static_cast<TTacticalUnit*>(b);
  unitA->AssertValid();
  unitB->AssertValid();
  short priorityA = priorityByAiClass[g_awTacticalUnitAiClassByUnitType_006693B8[unitA->unitType]];
  short priorityB = priorityByAiClass[g_awTacticalUnitAiClassByUnitType_006693B8[unitB->unitType]];
  if (priorityA < priorityB) {
    return 1;
  }
  // Explicitly cross from the logical comparison into the integer comparator domain.
  return static_cast<short>(-static_cast<int>(priorityA != priorityB));
}

IMPLEMENT_DYNCREATE(TArmyPlayer, TTacticalPlayer)

// FUNCTION: IMPERIALISM 0x0059b1b0
void TArmyPlayer::IArmyPlayer(TArmyStack* stack, bool isOurSide, unsigned char watchFlag,
                              int nationIndex) {
  isOurSideFlag = static_cast<char>(isOurSide);
  sideReadyFlag = false;
  this->watchFlag = watchFlag;
  this->nationIndex = nationIndex;
  cursorIndex = 0;
  retreatOrdered = false;
  field20 = false;
  field24 = 0;

  unitList = new TList();
  sideReadyFlag = false; // duplicate store present in the original
  secondaryList = new TList();

  for (TMilitaryUnit* unit = stack->ResetCursorAndGetHeadUnit(); unit != 0;
       unit = stack->AdvanceCursorAndGetUnit()) {
    TArmyTacUnit* record = new TArmyTacUnit();
    record->IArmyTacUnit(unit);
    unitList->AddTail(record);
    if (static_cast<char>(isOurSide) == 0) {
      record->selectedFlag = 1; // set only for the enemy side (isOurSide == 0)
    }
  }

  armyStack = stack;
  cursorIndex = 0;             // duplicate store present in the original
  this->watchFlag = watchFlag; // duplicate store present in the original
  notWatchedFlag = (watchFlag == 0);
  lastAppliedCursorMode = -1;
  unsigned char coinFlip = static_cast<unsigned char>(rand() & 1);
  cachedFortBombardmentTargetTile = -1;
  randomParityByte50 = coinFlip;
  hasArtilleryOrSappers = false;
}

// FUNCTION: IMPERIALISM 0x0059b3e0
void TArmyPlayer::ApplyChanges(unsigned char sideWonFlag) {
  (void)sideWonFlag;
  if (unitList->GetCount() > 0) {
    CIterator unitIter(unitList);
    for (TArmyTacUnit* record = static_cast<TArmyTacUnit*>(unitIter.Reset()); unitIter.More();
         record = static_cast<TArmyTacUnit*>(unitIter.Advance())) {
      record->sourceUnit->strength = static_cast<short>(record->strength);
      if (record->strength == 0) {
        record->sourceUnit->Vaporize();
      }
    }
  }
  if (secondaryList->GetCount() > 0) {
    CIterator secondaryIter(secondaryList);
    for (TArmyTacUnit* secondaryRecord = static_cast<TArmyTacUnit*>(secondaryIter.Reset());
         secondaryIter.More();
         secondaryRecord = static_cast<TArmyTacUnit*>(secondaryIter.Advance())) {
      secondaryRecord->sourceUnit->strength = static_cast<short>(secondaryRecord->strength);
      if (secondaryRecord->strength == 0) {
        secondaryRecord->sourceUnit->Vaporize();
      }
    }
  }
}

// FUNCTION: IMPERIALISM 0x0059b4f0
void TArmyPlayer::RemoveTacticalUnitFromUnitList(TTacticalUnit* unit) {
  POSITION pos = unitList->listState.Find(unit);
  if (pos != nullptr) {
    unitList->listState.RemoveAt(pos);
  }
  armyStack->RemoveUnitFromChain(static_cast<TArmyTacUnit*>(unit)->sourceUnit);
}

// FUNCTION: IMPERIALISM 0x0059b540
void TArmyPlayer::AddTacticalUnitToUnitListHead(TTacticalUnit* unit) {
  unitList->listState.AddHead(unit);
  unit->FlipUnitSideAffiliation();
  TMilitaryUnit* sourceUnit = static_cast<TArmyTacUnit*>(unit)->sourceUnit;
  sourceUnit->ownerNationSlot = static_cast<short>(nationIndex);
  sourceUnit->MoveTo(battle->battleSiteIndex);
  armyStack->AddUnitToChainHead(sourceUnit);
  static_cast<TArmyTacUnit*>(unit)->morale = unit->strength;
}

// FUNCTION: IMPERIALISM 0x0059b5b0
void TArmyPlayer::AccumulateTacticalProjectionMetricsAndUnitRanges() {
  maxNonArtilleryUnitRange = 0;
  maxUnitRange = 0;
  for (int component = 0; component < 5; ++component) {
    projectionMetrics[component] = 0.0f;
  }
  hasArtilleryOrSappers = false;

  CIterator unitIter(unitList);
  for (TArmyTacUnit* record = static_cast<TArmyTacUnit*>(unitIter.Reset()); unitIter.More();
       record = static_cast<TArmyTacUnit*>(unitIter.Advance())) {
    if (record->state1c == 0) {
      record->ComputeTacticalProjectionScoreVector();

      for (int component = 0; component < 5; ++component) {
        projectionMetrics[component] += record->projectionScores[component];
      }

      // max()-macro form: the losing branch re-evaluates GetUnitRange().
      maxUnitRange = static_cast<short>(
          maxUnitRange > record->GetUnitRange() ? maxUnitRange : record->GetUnitRange());
      if (g_awTacticalUnitAiClassByUnitType_006693B8[record->unitType] != 2) {
        maxNonArtilleryUnitRange = static_cast<short>(
            maxNonArtilleryUnitRange > record->GetUnitRange() ? maxNonArtilleryUnitRange
                                                              : record->GetUnitRange());
      }
      if (g_awTacticalUnitAiClassByUnitType_006693B8[record->unitType] == 2 ||
          g_awTacticalUnitCategoryCodeBySlot[record->unitType] == 8) {
        hasArtilleryOrSappers = true;
      }
    }
  }

  float baselineProfileScore = ComputeDistributionSimilarityScoreFromVectorAndReferenceProfile(
      projectionMetrics, g_awTacticalCompositionReferenceProfiles_00697870, 5);
  projectionMetrics[1] = ComputeDistributionSimilarityScoreFromVectorAndReferenceProfile(
      projectionMetrics,
      g_awTacticalCompositionReferenceProfiles_00697870 + 5 * (battle->fortLevel != 0 ? 1 : 2), 5);
  projectionMetrics[0] = baselineProfileScore;
}

// FUNCTION: IMPERIALISM 0x0059b830
void TArmyPlayer::StartBattle() {
  if (notWatchedFlag) {
    SelectAndApplyTacticalCursorModeProfile(1);
    AutoDeploySideUnitsAndMarkReady();
    return;
  }
  bool alreadyStarted = field24 == 2;
  if (!alreadyStarted) {
    TTacticalPlayer* opponent;
    if (isOurSideFlag != 0) {
      opponent = battle->players[1];
    } else {
      opponent = battle->players[0];
    }
    int opposingNationIndex = opponent->nationIndex;

    // Battle-intro ("hola") dialog, id 0xf19.
    TWindow* dialog = static_cast<TWindow*>(
        g_pAssetMgr->ResolveTurnEventDialogNodeByMessageContext(kTurnEventTacticalDeployChoice));
    if (dialog == 0) {
      FailNilPointerWithAssert(s_SourcePathUTacPlayer_00699D84, 0x18d);
    }
    TTacticalHolaPicture* holaPicture =
        static_cast<TTacticalHolaPicture*>(dialog->ResolveControlByTag(kControlTagDialog));
    holaPicture->AssertValid();
    if (isOurSideFlag != 0) {
      holaPicture->StuffValues(nationIndex, static_cast<short>(opposingNationIndex), isOurSideFlag,
                               battle->battleSiteIndex);
    } else {
      holaPicture->StuffValues(static_cast<short>(opposingNationIndex), nationIndex, 0,
                               battle->battleSiteIndex);
    }
    int resultTag = dialog->PoseModally();
    dialog->Close();
    dialog->Free();
    if (resultTag == kControlTagOkay) {
      ProceedAfterBattleIntroAccepted();
    }
  }
}

// FUNCTION: IMPERIALISM 0x0059b990
void TArmyPlayer::RecomputeTacticalCursorProjectionScoresAndPruneList(int maxUnitCount) {
  int profileRowIndex;
  if (isOurSideFlag != 0) {
    profileRowIndex = (battle->fortLevel != 0) + 1;
  } else {
    profileRowIndex = 0;
  }

  // Move every record onto secondaryList, back to front (ordinals are 1-based).
  for (int ordinal = unitList->GetCount(); ordinal > 0; --ordinal) {
    TArmyTacUnit* record = static_cast<TArmyTacUnit*>(unitList->GetEntryByOrdinal(ordinal));
    record->AssertValid();
    unitList->RemoveAtOrdinal(ordinal);
    secondaryList->AddTail(record);
    record->ComputeTacticalProjectionScoreVector();
  }

  int remainingCapacity = maxUnitCount;
  bool movedCategory9Record = false;
  if (remainingCapacity != 0) {
    CIterator category9Iter(secondaryList);
    TArmyTacUnit* category9Record = static_cast<TArmyTacUnit*>(category9Iter.Reset());
    while (category9Iter.More() != 0) {
      if (g_awTacticalUnitCategoryCodeBySlot[category9Record->unitType] == 9) {
        POSITION category9Pos = secondaryList->listState.Find(category9Record, 0);
        if (category9Pos != 0) {
          secondaryList->listState.RemoveAt(category9Pos);
        }
        unitList->AddTail(category9Record);
        movedCategory9Record = true;
        --remainingCapacity;
      }
      category9Record = static_cast<TArmyTacUnit*>(category9Iter.Advance());
      if (movedCategory9Record) {
        break; // original stops after the first category-9 record
      }
    }
  }

  float keptScoreVectorSum[5] = {0.0f, 0.0f, 0.0f, 0.0f, 0.0f};
  if (remainingCapacity != 0) {
    for (int passesLeft = remainingCapacity; passesLeft != 0; --passesLeft) {
      int bestOrdinal = 0;
      float bestScore = 0.0f;
      for (int candidateOrdinal = 1; candidateOrdinal < secondaryList->GetCount();
           ++candidateOrdinal) {
        TArmyTacUnit* candidate =
            static_cast<TArmyTacUnit*>(secondaryList->GetEntryByOrdinal(candidateOrdinal));
        int component;
        for (component = 0; component < 5; ++component) {
          keptScoreVectorSum[component] += candidate->projectionScores[component];
        }
        float score = ComputeDistributionSimilarityScoreFromVectorAndReferenceProfile(
            keptScoreVectorSum,
            g_awTacticalCompositionReferenceProfiles_00697870 + profileRowIndex * 5, 5);
        if (score > bestScore) {
          bestScore = score;
          bestOrdinal = candidateOrdinal;
        }
        for (component = 0; component < 5; ++component) {
          keptScoreVectorSum[component] -= candidate->projectionScores[component];
        }
      }
      TArmyTacUnit* keptRecord =
          static_cast<TArmyTacUnit*>(secondaryList->GetEntryByOrdinal(bestOrdinal));
      secondaryList->RemoveAtOrdinal(bestOrdinal);
      unitList->AddTail(keptRecord);
      for (int component = 0; component < 5; ++component) {
        keptScoreVectorSum[component] += keptRecord->projectionScores[component];
      }
    }
  }

  // Every record still on secondaryList was pruned from the battle roster.
  CIterator prunedIter(secondaryList);
  for (TArmyTacUnit* prunedRecord = static_cast<TArmyTacUnit*>(prunedIter.Reset());
       prunedIter.More(); prunedRecord = static_cast<TArmyTacUnit*>(prunedIter.Advance())) {
    POSITION prunedPos = battle->recordList->listState.Find(prunedRecord, 0);
    if (prunedPos != 0) {
      battle->recordList->listState.RemoveAt(prunedPos);
    }
  }
}

// FUNCTION: IMPERIALISM 0x0059bc80
void TArmyPlayer::AutoDeploySideUnitsAndMarkReady() {
  int freeDeployTileCount = battle->CountFreeDeploymentZoneTilesForCurrentSide();
  if (unitList->GetCount() > freeDeployTileCount) {
    RecomputeTacticalCursorProjectionScoresAndPruneList(freeDeployTileCount);
  }
  if (isOurSideFlag != 0) {
    BuildTacticalActionPriorityBucketsWithGridGuard();
    sideReadyFlag = true;
    return;
  }
  DispatchTacticalActionClassSelectionAcrossCursorList();
  sideReadyFlag = true;
}

// FUNCTION: IMPERIALISM 0x0059bcf0
void TArmyPlayer::BuildTacticalActionPriorityBucketsWithGridGuard() {
  int zoneScoreByClassAndCell[30] = {
      10, 30, 10, 20, 10, 10, // aiClass 0
      10, 20, 30, 40, 50, 60, // aiClass 1
      60, 40, 50, 30, 20, 10, // aiClass 2
      10, 20, 30, 40, 50, 60, // aiClass 3
      10, 20, 30, 40, 50, 60, // aiClass 4
  };
  unitList->SortBy(&CompareTacticalCursorEntriesByActionClassPriority, 0);
  CIterator unitIter(unitList);
  for (TTacticalUnit* unit = static_cast<TTacticalUnit*>(unitIter.Reset()); unitIter.More();
       unit = static_cast<TTacticalUnit*>(unitIter.Advance())) {
    int bestScore = 0;
    TacticalTileIndex bestTileIndex = -1;
    for (TacticalTileIndex tileIndex = 0; tileIndex < battle->tacticalTileCount; ++tileIndex) {
      if (battle->ApplyGridColumnSelectionGuard(tileIndex) != 0) {
        int row = tileIndex / 29;
        int column = tileIndex % 29;
        int aiClass = g_awTacticalUnitAiClassByUnitType_006693B8[unit->unitType];
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
    battle->DeployUnit(unit, bestTileIndex);
  }
}

// FUNCTION: IMPERIALISM 0x0059bf20
void TArmyPlayer::DispatchTacticalActionClassSelectionAcrossCursorList() {
  unitList->SortBy(&CompareTacticalCursorEntriesByActionClassPriority, 0);
  CIterator unitIter(unitList);
  for (TTacticalUnit* unit = static_cast<TTacticalUnit*>(unitIter.Reset()); unitIter.More();
       unit = static_cast<TTacticalUnit*>(unitIter.Advance())) {
    TacticalTileIndex tileIndex;
    switch (g_awTacticalUnitAiClassByUnitType_006693B8[unit->unitType]) {
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
    battle->DeployUnit(unit, tileIndex);
  }
}

// FUNCTION: IMPERIALISM 0x0059bfe0
int TArmyPlayer::SelectTacticalTileIndexByColumnPriorityVariantA() {
  int bestScore = 0;
  TacticalTileIndex bestTileIndex = -1;
  for (TacticalTileIndex tileIndex = 0; tileIndex < battle->tacticalTileCount; ++tileIndex) {
    if (battle->ApplyGridColumnSelectionGuard(tileIndex) != 0) {
      int row = tileIndex / 29;
      int column = tileIndex % 29;
      int zoneCell = (row & 1) + 2 * (column - battle->battlefieldColumnCount) + 10;
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
      TacticalTileIndex neighborTiles[6];
      int adjacentArtilleryBonus = 0;
      battle->GetNeighborList(tileIndex, neighborTiles);
      for (int neighborIndex = 0; neighborIndex < 6; ++neighborIndex) {
        TacticalTileIndex neighborTileIndex = neighborTiles[neighborIndex];
        if (neighborTileIndex != -1) {
          TTacticalUnit* occupant = battle->tileGrid[neighborTileIndex].occupant;
          if (occupant != 0 &&
              g_awTacticalUnitAiClassByUnitType_006693B8[occupant->unitType] == 2) {
            adjacentArtilleryBonus = 0x64;
          }
        }
      }
      score += adjacentArtilleryBonus;
      battle->tileCandidateScorePlane[tileIndex] = score;
      if (score > bestScore) {
        bestScore = score;
        bestTileIndex = tileIndex;
      }
    }
  }
  return bestTileIndex;
}

// FUNCTION: IMPERIALISM 0x0059c140
int TArmyPlayer::SelectTacticalTileByActionClassAdjacencyPriority() {
  int bestScore = 0;
  TacticalTileIndex bestTileIndex = -1;
  for (TacticalTileIndex tileIndex = 0; tileIndex < battle->tacticalTileCount; ++tileIndex) {
    if (battle->ApplyGridColumnSelectionGuard(tileIndex) != 0) {
      int row = tileIndex / 29;
      int column = tileIndex % 29;
      int score = (2 * (battle->battlefieldColumnCount - column) - (row & 1) - 3) * 10;
      int rowDistance = row;
      if (rowDistance > 7) {
        rowDistance = 15 - rowDistance;
      }
      score += rowDistance;
      TacticalTileIndex neighborTiles[6];
      int adjacencyBonus = 0;
      battle->GetNeighborList(tileIndex, neighborTiles);
      for (int neighborIndex = 0; neighborIndex < 6; ++neighborIndex) {
        TacticalTileIndex neighborTileIndex = neighborTiles[neighborIndex];
        if (neighborTileIndex != -1) {
          TTacticalUnit* occupant = battle->tileGrid[neighborTileIndex].occupant;
          if (occupant != 0) {
            if (g_awTacticalUnitAiClassByUnitType_006693B8[occupant->unitType] == 2) {
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

// FUNCTION: IMPERIALISM 0x0059c2a0
int TArmyPlayer::SelectTacticalTileIndexByColumnPriorityVariantB() {
  int bestScore = 0;
  TacticalTileIndex bestTileIndex = -1;
  for (TacticalTileIndex tileIndex = 0; tileIndex < battle->tacticalTileCount; ++tileIndex) {
    if (battle->ApplyGridColumnSelectionGuard(tileIndex) != 0) {
      int row = tileIndex / 29;
      int score = (battle->battlefieldColumnCount - 5) * 20;
      if (row > 7) {
        row = 15 - row;
      }
      score += row;
      TacticalTileIndex neighborTiles[6];
      int occupiedNeighborBonus = 0;
      battle->GetNeighborList(tileIndex, neighborTiles);
      for (int neighborIndex = 0; occupiedNeighborBonus == 0 && neighborIndex < 6;
           ++neighborIndex) {
        TacticalTileIndex neighborTileIndex = neighborTiles[neighborIndex];
        if (neighborTileIndex != -1 && battle->tileGrid[neighborTileIndex].occupant != 0) {
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
void TArmyPlayer::DeploymentClick(TacticalTileIndex tileIndex) {
  int ordinal = 1;
  TTacticalUnit* unit;
  while (true) {
    unit = static_cast<TTacticalUnit*>(unitList->GetEntryByOrdinal(ordinal));
    ++ordinal;
    if (unit->tileIndex == -2) {
      break;
    }
    if (ordinal > unitList->GetCount()) {
      break;
    }
  }

  if (ordinal > unitList->GetCount()) {
    sideReadyFlag = true;
  } else {
    battle->DeployUnit(unit, tileIndex);
  }
}

// FUNCTION: IMPERIALISM 0x0059c440
void TArmyPlayer::SelectAndApplyTacticalCursorModeProfile(int cursorProfileMode) {
  (void)cursorProfileMode;

  // Is the battle site this nation's capital city record?
  bool siteIsHomeCapital = battle->battleSiteIndex ==
                           g_pGlobalMapState
                               ->terrainStateTable[static_cast<short>(
                                   g_apTerrainTypeDescriptorTable[nationIndex]->homeTileIndex)]
                               .cityRecordIndex;

  TArmyPlayer* opponent;
  if (isOurSideFlag != 0) {
    opponent = static_cast<TArmyPlayer*>(battle->players[1]);
  } else {
    opponent = static_cast<TArmyPlayer*>(battle->players[0]);
  }

  AccumulateTacticalProjectionMetricsAndUnitRanges();
  opponent->AccumulateTacticalProjectionMetricsAndUnitRanges();

  float opponentMetrics[5];
  for (int component = 0; component < 5; ++component) {
    opponentMetrics[component] = opponent->projectionMetrics[component];
  }

  bool enemyHasActiveUnit = false;
  CIterator scanIter(opponent->unitList);
  for (TTacticalUnit* enemyRecord = static_cast<TTacticalUnit*>(scanIter.Reset()); scanIter.More();
       enemyRecord = static_cast<TTacticalUnit*>(scanIter.Advance())) {
    if (enemyRecord->state1c == 0) {
      enemyHasActiveUnit = true;
    }
  }
  if (!enemyHasActiveUnit) {
    field48 = 1;
  } else {
    field48 = 0;
  }

  int cursorMode;
  if (isOurSideFlag == 0) {
    // Defending side.
    if (!enemyHasActiveUnit) {
      cursorMode = 6;
    } else if (!opponent->hasArtilleryOrSappers &&
               battle->IsTacticalSideCategoryCoverageIncompleteOrFlagOff() == 0) {
      cursorMode = 7;
    } else if (projectionMetrics[1] / opponentMetrics[1] >
               g_dTacticalCursorStrongRatioThreshold_00669508) {
      if (battle->IsTacticalSideCategoryCoverageIncompleteOrFlagOff() != 0) {
        cursorMode = 2;
      } else if (projectionMetrics[1] / opponentMetrics[1] >
                 g_dTacticalCursorOverwhelmRatioThreshold_00669510) {
        cursorMode = 2;
      } else {
        cursorMode = 0;
      }
    } else if (projectionMetrics[0] / opponentMetrics[1] <
                   g_dTacticalCursorWeakRatioThreshold_00669518 &&
               !siteIsHomeCapital) {
      cursorMode = 1;
    } else {
      // Branchless in the original (setl form): outranged defenders bombard.
      cursorMode = (maxUnitRange < opponent->maxUnitRange) ? 2 : 0;
    }
  } else {
    // Attacking side.
    float strengthRatio = projectionMetrics[1] / opponentMetrics[0];
    bool haveActiveSapper = false;
    bool haveActiveArtillery = false;
    CIterator unitIter(unitList);
    for (TTacticalUnit* record = static_cast<TTacticalUnit*>(unitIter.Reset()); unitIter.More();
         record = static_cast<TTacticalUnit*>(unitIter.Advance())) {
      if (g_awTacticalUnitCategoryCodeBySlot[record->unitType] == 8 && record->state1c == 0) {
        haveActiveSapper = true;
      }
      if (g_awTacticalUnitAiClassByUnitType_006693B8[record->unitType] == 2 &&
          record->state1c == 0) {
        haveActiveArtillery = true;
      }
    }
    if (battle->IsTacticalSideCategoryCoverageIncompleteOrFlagOff() == 0) {
      // Fort wall still intact.
      if (haveActiveSapper) {
        cursorMode = 3;
      } else if (!haveActiveArtillery) {
        cursorMode = 1;
      } else if (projectionMetrics[3] / opponentMetrics[3] <
                 g_dTacticalCursorArtilleryParityThreshold_00669520) {
        cursorMode = 1;
      } else {
        cursorMode = 3;
      }
    } else {
      // No fort, or a wall section is breached.
      if (!enemyHasActiveUnit) {
        cursorMode = 6;
      } else if (strengthRatio > g_dTacticalCursorStrongRatioThreshold_00669508) {
        cursorMode = 4;
      } else if (!(projectionMetrics[3] / opponentMetrics[3] <
                   g_dTacticalCursorArtillerySuperiorityThreshold_00669528) &&
                 haveActiveArtillery) {
        cursorMode = 3;
      } else if (!(strengthRatio < g_dTacticalCursorAssaultRatioThreshold_00669530)) {
        cursorMode = 4;
      } else if (strengthRatio < g_dTacticalCursorRetreatRatioThreshold_00669538 &&
                 !siteIsHomeCapital) {
        cursorMode = 1;
      } else {
        cursorMode = 5;
      }
    }
  }

  if (retreatOrdered) {
    cursorMode = 1;
  }
  if (cursorMode == 1) {
    field48 = cursorMode;
  }
  if (cursorMode == lastAppliedCursorMode) {
    return; // mode unchanged since the last application
  }
  lastAppliedCursorMode = cursorMode;
  switch (cursorMode) {
  case 0:
    ApplyDefenderHoldLineStanceByActionClass();
    return;
  case 1: {
    // Retreat/fallback stance: non-category-0 units get state 0xc, category-0 get 7.
    CIterator retreatIter(unitList);
    for (TTacticalUnit* retreatRecord = static_cast<TTacticalUnit*>(retreatIter.Reset());
         retreatIter.More(); retreatRecord = static_cast<TTacticalUnit*>(retreatIter.Advance())) {
      if (g_awTacticalUnitCategoryCodeBySlot[retreatRecord->unitType] != 0) {
        retreatRecord->aiStateCode = 0xc;
      } else {
        retreatRecord->aiStateCode = 7;
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
    CIterator garrisonIter(unitList);
    for (TTacticalUnit* garrisonRecord = static_cast<TTacticalUnit*>(garrisonIter.Reset());
         garrisonIter.More();
         garrisonRecord = static_cast<TTacticalUnit*>(garrisonIter.Advance())) {
      garrisonRecord->aiStateCode = 0x13;
    }
    return;
  }
  }
}

// FUNCTION: IMPERIALISM 0x0059c970
void TArmyPlayer::ApplyTacticalStanceProfileForCurrentCursorMode() {
  switch (lastAppliedCursorMode) {
  case 0:
    ApplyDefenderHoldLineStanceByActionClass();
    return;
  case 1: {
    // Retreat/fallback stance: non-category-0 units get state 0xc, category-0 get 7.
    CIterator retreatIter(unitList);
    for (TTacticalUnit* retreatRecord = static_cast<TTacticalUnit*>(retreatIter.Reset());
         retreatIter.More(); retreatRecord = static_cast<TTacticalUnit*>(retreatIter.Advance())) {
      if (g_awTacticalUnitCategoryCodeBySlot[retreatRecord->unitType] != 0) {
        retreatRecord->aiStateCode = 0xc;
      } else {
        retreatRecord->aiStateCode = 7;
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
    CIterator garrisonIter(unitList);
    for (TTacticalUnit* garrisonRecord = static_cast<TTacticalUnit*>(garrisonIter.Reset());
         garrisonIter.More();
         garrisonRecord = static_cast<TTacticalUnit*>(garrisonIter.Advance())) {
      garrisonRecord->aiStateCode = 0x13;
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
  CIterator countIter(unitList);
  for (TTacticalUnit* countRecord = static_cast<TTacticalUnit*>(countIter.Reset());
       countIter.More(); countRecord = static_cast<TTacticalUnit*>(countIter.Advance())) {
    ++actionClassCounts[g_awTacticalUnitAiClassByUnitType_006693B8[countRecord->unitType]];
  }

  CIterator applyIter(unitList);
  for (TTacticalUnit* record = static_cast<TTacticalUnit*>(applyIter.Reset()); applyIter.More();
       record = static_cast<TTacticalUnit*>(applyIter.Advance())) {
    if (record->state1c != 0) {
      continue;
    }
    switch (g_awTacticalUnitAiClassByUnitType_006693B8[record->unitType]) {
    case 0:
      record->aiStateCode = 0;
      break;
    case 2:
      record->aiStateCode = 9;
      break;
    case 1:
    case 3:
      if (actionClassCounts[0] < actionClassCounts[2] && actionClassCounts[0] < 0 &&
          engageAssignedCount < 0) {
        record->aiStateCode = 0;
        ++engageAssignedCount;
      } else {
        record->aiStateCode = 0xe;
      }
      break;
    case 4:
      if (record->unitType >= 0x1b) {
        record->aiStateCode = 0xb;
      } else {
        record->aiStateCode = 0xc;
      }
      break;
    }
  }
}

// FUNCTION: IMPERIALISM 0x0059cc70
void TArmyPlayer::AssignJobsByZeroCategory() {
  CIterator iter(unitList);
  for (TTacticalUnit* unit = static_cast<TTacticalUnit*>(iter.Reset()); iter.More();
       unit = static_cast<TTacticalUnit*>(iter.Advance())) {
    if (g_awTacticalUnitCategoryCodeBySlot[unit->unitType] != 0) {
      unit->aiStateCode = 0xc;
    } else {
      unit->aiStateCode = 7;
    }
  }
}

// FUNCTION: IMPERIALISM 0x0059cd00
void TArmyPlayer::ApplyDefenderBombardStanceByActionClass() {
  int actionClassCounts[5] = {0, 0, 0, 0, 0};
  int engageAssignedCount = 0;
  int escortAssignedCount = 0;
  CIterator countIter(unitList);
  for (TTacticalUnit* countRecord = static_cast<TTacticalUnit*>(countIter.Reset());
       countIter.More(); countRecord = static_cast<TTacticalUnit*>(countIter.Advance())) {
    ++actionClassCounts[g_awTacticalUnitAiClassByUnitType_006693B8[countRecord->unitType]];
  }

  CIterator applyIter(unitList);
  for (TTacticalUnit* record = static_cast<TTacticalUnit*>(applyIter.Reset()); applyIter.More();
       record = static_cast<TTacticalUnit*>(applyIter.Advance())) {
    if (record->state1c != 0) {
      continue;
    }
    switch (g_awTacticalUnitAiClassByUnitType_006693B8[record->unitType]) {
    case 0:
      if (engageAssignedCount > 0 && escortAssignedCount < actionClassCounts[2]) {
        record->aiStateCode = 1;
        ++escortAssignedCount;
      } else if (engageAssignedCount < 0) {
        record->aiStateCode = 0;
        ++engageAssignedCount;
      } else {
        record->aiStateCode = 7;
      }
      break;
    case 2:
      record->aiStateCode = 8;
      break;
    case 1:
    case 3:
      record->aiStateCode = 5;
      break;
    case 4:
      if (record->unitType >= 0x1b) {
        record->aiStateCode = 0xb;
      } else {
        record->aiStateCode = 0xc;
      }
      break;
    }
  }
}

// FUNCTION: IMPERIALISM 0x0059ce90
void TArmyPlayer::ApplyAttackerSiegeStanceByActionClass() {
  TArmyPlayer* opponent;
  if (isOurSideFlag != 0) {
    opponent = static_cast<TArmyPlayer*>(battle->players[1]);
  } else {
    opponent = static_cast<TArmyPlayer*>(battle->players[0]);
  }
  short opponentMaxNonArtilleryRange = opponent->maxNonArtilleryUnitRange;
  unsigned char enemyHasDeployedArtillery = OpponentHasDeployedActiveArtilleryUnit();

  CIterator applyIter(unitList);
  for (TTacticalUnit* record = static_cast<TTacticalUnit*>(applyIter.Reset()); applyIter.More();
       record = static_cast<TTacticalUnit*>(applyIter.Advance())) {
    if (g_awTacticalUnitCategoryCodeBySlot[record->unitType] == 8) {
      if (battle->tileGrid[174].deployMark > 1) {
        record->aiStateCode = 0xd;
      } else {
        record->aiStateCode = 0xc;
      }
      continue;
    }
    switch (g_awTacticalUnitAiClassByUnitType_006693B8[record->unitType]) {
    case 0:
      if (record->GetUnitRange() > opponentMaxNonArtilleryRange) {
        record->aiStateCode = 0x11;
      } else if (g_awTacticalUnitCategoryCodeBySlot[record->unitType] == 1) {
        record->aiStateCode = enemyHasDeployedArtillery != 0 ? 0x10 : 0xa;
      } else {
        record->aiStateCode = 1;
      }
      break;
    case 1:
    case 3:
      record->aiStateCode = 0xe;
      break;
    case 2:
      if (g_awTacticalUnitCategoryCodeBySlot[record->unitType] == 6) {
        record->aiStateCode = 0x11;
      } else {
        record->aiStateCode = 8;
      }
      break;
    case 4:
      record->aiStateCode = 0xb;
      break;
    }
  }
}

// FUNCTION: IMPERIALISM 0x0059d020
void TArmyPlayer::ApplyAttackerAssaultStanceByActionClass() {
  TArmyPlayer* opponent;
  if (isOurSideFlag != 0) {
    opponent = static_cast<TArmyPlayer*>(battle->players[1]);
  } else {
    opponent = static_cast<TArmyPlayer*>(battle->players[0]);
  }
  short opponentMaxNonArtilleryRange = opponent->maxNonArtilleryUnitRange;
  unsigned char enemyHasDeployedArtillery = OpponentHasDeployedActiveArtilleryUnit();

  CIterator applyIter(unitList);
  for (TTacticalUnit* record = static_cast<TTacticalUnit*>(applyIter.Reset()); applyIter.More();
       record = static_cast<TTacticalUnit*>(applyIter.Advance())) {
    switch (g_awTacticalUnitAiClassByUnitType_006693B8[record->unitType]) {
    case 0:
      if (record->GetUnitRange() > opponentMaxNonArtilleryRange) {
        record->aiStateCode = 0x11;
      } else if (g_awTacticalUnitCategoryCodeBySlot[record->unitType] == 1) {
        record->aiStateCode = enemyHasDeployedArtillery != 0 ? 0x10 : 0xa;
      } else {
        record->aiStateCode = 7;
      }
      break;
    case 1:
    case 3:
      record->aiStateCode = 5;
      break;
    case 2:
      if (g_awTacticalUnitCategoryCodeBySlot[record->unitType] == 6) {
        record->aiStateCode = 0x11;
      } else {
        record->aiStateCode = 8;
      }
      break;
    case 4:
      if (g_awTacticalUnitCategoryCodeBySlot[record->unitType] == 8) {
        record->aiStateCode = 0xc;
      } else {
        record->aiStateCode = 0xb;
      }
      break;
    }
  }
}

// FUNCTION: IMPERIALISM 0x0059d1a0
void TArmyPlayer::ApplyAttackerStandoffStanceByActionClass() {
  TArmyPlayer* opponent;
  if (isOurSideFlag != 0) {
    opponent = static_cast<TArmyPlayer*>(battle->players[1]);
  } else {
    opponent = static_cast<TArmyPlayer*>(battle->players[0]);
  }
  short opponentMaxNonArtilleryRange = opponent->maxNonArtilleryUnitRange;
  unsigned char enemyHasDeployedArtillery = OpponentHasDeployedActiveArtilleryUnit();

  CIterator applyIter(unitList);
  for (TTacticalUnit* record = static_cast<TTacticalUnit*>(applyIter.Reset()); applyIter.More();
       record = static_cast<TTacticalUnit*>(applyIter.Advance())) {
    switch (g_awTacticalUnitAiClassByUnitType_006693B8[record->unitType]) {
    case 0:
      if (record->GetUnitRange() > opponentMaxNonArtilleryRange) {
        record->aiStateCode = 0x11;
      } else if (g_awTacticalUnitCategoryCodeBySlot[record->unitType] == 1) {
        record->aiStateCode = enemyHasDeployedArtillery != 0 ? 0x10 : 0xa;
      } else {
        record->aiStateCode = 7;
      }
      break;
    case 1:
    case 3:
      record->aiStateCode = 2;
      break;
    case 2:
      if (g_awTacticalUnitCategoryCodeBySlot[record->unitType] == 6) {
        record->aiStateCode = 0x11;
      } else {
        record->aiStateCode = 8;
      }
      break;
    case 4:
      if (g_awTacticalUnitCategoryCodeBySlot[record->unitType] == 8) {
        record->aiStateCode = 0xc;
      } else {
        record->aiStateCode = 0xb;
      }
      break;
    }
  }
}

// FUNCTION: IMPERIALISM 0x0059d320
void TArmyPlayer::ApplyUnopposedAdvanceStanceByActionClass() {
  CIterator applyIter(unitList);
  for (TTacticalUnit* record = static_cast<TTacticalUnit*>(applyIter.Reset()); applyIter.More();
       record = static_cast<TTacticalUnit*>(applyIter.Advance())) {
    switch (g_awTacticalUnitAiClassByUnitType_006693B8[record->unitType]) {
    case 0:
      record->aiStateCode = 7;
      break;
    case 1:
    case 3:
      record->aiStateCode = 5;
      break;
    case 2:
      record->aiStateCode = 8;
      break;
    case 4:
      if (g_awTacticalUnitCategoryCodeBySlot[record->unitType] == 8) {
        record->aiStateCode = 0xc;
      } else {
        record->aiStateCode = 0xb;
      }
      break;
    }
  }
}

// FUNCTION: IMPERIALISM 0x0059d400
void TArmyPlayer::SetAllUnitAiStateCodesTo13() {
  CIterator iter(unitList);
  for (TTacticalUnit* record = static_cast<TTacticalUnit*>(iter.Reset()); iter.More();
       record = static_cast<TTacticalUnit*>(iter.Advance())) {
    record->aiStateCode = 0x13;
  }
}

// FUNCTION: IMPERIALISM 0x0059d470
unsigned char TArmyPlayer::OpponentHasDeployedActiveArtilleryUnit() {
  TList* opponentUnitList;
  if (isOurSideFlag != 0) {
    opponentUnitList = battle->players[1]->unitList;
  } else {
    opponentUnitList = battle->players[0]->unitList;
  }
  CIterator enemyIter(opponentUnitList);
  for (TTacticalUnit* record = static_cast<TTacticalUnit*>(enemyIter.Reset()); enemyIter.More();
       record = static_cast<TTacticalUnit*>(enemyIter.Advance())) {
    if (record->tileIndex >= 0 &&
        g_awTacticalUnitAiClassByUnitType_006693B8[record->unitType] == 2 && record->state1c == 0) {
      return 1;
    }
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x0059d530
int TArmyPlayer::FindBestMove(TTacticalUnit* unit, int* heuristicWeights15) {
  TacticalTileIndex bestTileIndex = -1;
  int bestScore = -99999;
  bool distanceFieldBuilt = false;
  if (heuristicWeights15[8] > 0) {
    battle->MakeRetreatMap(isOurSideFlag);
    distanceFieldBuilt = true;
  }
  for (TacticalTileIndex tileIndex = 0; tileIndex < battle->tacticalTileCount; ++tileIndex) {
    int column = tileIndex % 29;
    if (battle->tileMoveCostArray[tileIndex] == -1) {
      battle->tileCandidateScorePlane[tileIndex] = 0;
      continue;
    }
    if (!distanceFieldBuilt) {
      // Without the distance field, never pick the outer edge columns.
      if (column == 0 || column == battle->battlefieldColumnCount - 1) {
        battle->tileCandidateScorePlane[tileIndex] = 0;
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
    if (score > bestScore || (score == bestScore && battle->tileMoveCostArray[tileIndex] <
                                                        battle->tileMoveCostArray[bestTileIndex])) {
      bestTileIndex = tileIndex;
      bestScore = score;
    }
    battle->tileCandidateScorePlane[tileIndex] = score;
  }
  return bestTileIndex;
}

// Heuristic [0]: 100 for the tile the unit already stands on (hold position).
// FUNCTION: IMPERIALISM 0x0059d6b0
int TArmyPlayer::ScoreTacticalTileHoldPositionBonus(TTacticalUnit* unit,
                                                    TacticalTileIndex tileIndex) {
  return (unit->tileIndex == tileIndex) ? 0x64 : 0;
}

// FUNCTION: IMPERIALISM 0x0059d6e0
int TArmyPlayer::ScoreTacticalTileFireOpportunityAndTargetApproach(TTacticalUnit* unit,
                                                                   TacticalTileIndex tileIndex) {
  unit->GetUnitRange();
  int score = 0;
  for (TacticalTileIndex scanTileIndex = 0; score == 0 && scanTileIndex < battle->tacticalTileCount;
       ++scanTileIndex) {
    TTacticalUnit* occupant = battle->tileGrid[scanTileIndex].occupant;
    if (occupant != 0 && occupant->side != unit->side && (occupant->state1c == 0 || field48 == 1)) {
      short categoryCode = g_awTacticalUnitCategoryCodeBySlot[unit->unitType];
      if (battle->IsTacticalTargetTileReachableForAction(
              tileIndex, scanTileIndex,
              static_cast<char>(static_cast<int>(
                  g_afTacticalDirectFireFlagByCategoryCode_00669390[categoryCode])),
              unit->GetUnitRange()) != 0) {
        score = 0x32;
      }
    }
  }
  TacticalTileIndex targetTileIndex = SelectBestTacticalTargetTileByActionHeuristics(unit, 0);
  if (targetTileIndex != -1) {
    if (g_awTacticalUnitAiClassByUnitType_006693B8[unit->unitType] != 2 || score == 0) {
      score += 0x32 - ComputeHexTileDistanceFromIndices(tileIndex, targetTileIndex);
    }
  }
  return score;
}

// FUNCTION: IMPERIALISM 0x0059d810
int TArmyPlayer::ScoreTacticalTileSapperWallApproachColumn(TTacticalUnit* unit,
                                                           TacticalTileIndex tileIndex) {
  if (tileIndex % 29 != 6) {
    return 0;
  }
  TacticalTileRecord* tile = &battle->tileGrid[tileIndex];
  int score = ((tile->deployMark != 0) ? 0x14 : 0) + 0x50;
  TTacticalUnit* rightOccupant = tile[1].occupant;
  if (rightOccupant != 0 && rightOccupant->side == unit->side) {
    score -= 0x14;
  }
  TTacticalUnit* leftOccupant = tile[-1].occupant;
  if (leftOccupant != 0 && leftOccupant->side == unit->side) {
    score -= 0x14;
  }
  return score;
}

// FUNCTION: IMPERIALISM 0x0059d8a0
int TArmyPlayer::ScoreTacticalTileAdjacentEnemyContact(TTacticalUnit* unit,
                                                       TacticalTileIndex tileIndex) {
  TacticalTileIndex neighborTiles[6];
  battle->GetNeighborList(tileIndex, neighborTiles);
  for (int neighborIndex = 0; neighborIndex < 6; ++neighborIndex) {
    TacticalTileIndex neighborTileIndex = neighborTiles[neighborIndex];
    if (neighborTileIndex != -1) {
      TTacticalUnit* occupant = battle->tileGrid[neighborTileIndex].occupant;
      if (occupant != 0 && occupant->side != unit->side &&
          (occupant->state1c == 0 || field48 == 1)) {
        return 0x64;
      }
    }
  }
  return 0;
}

// Heuristic [4]: how many deployed enemy units could engage this tile.
// FUNCTION: IMPERIALISM 0x0059d940
int TArmyPlayer::ScoreTacticalTileEnemyEngagementExposureCount(TTacticalUnit* unit,
                                                               TacticalTileIndex tileIndex) {
  (void)unit;
  int exposureCount = 0;
  TList* enemyList;
  if (isOurSideFlag != 0) {
    enemyList = battle->players[1]->unitList;
  } else {
    enemyList = battle->players[0]->unitList;
  }
  CIterator enemyIter(enemyList);
  for (TTacticalUnit* record = static_cast<TTacticalUnit*>(enemyIter.Reset()); enemyIter.More();
       record = static_cast<TTacticalUnit*>(enemyIter.Advance())) {
    if (record->tileIndex >= 0) {
      short categoryCode = g_awTacticalUnitCategoryCodeBySlot[record->unitType];
      if (battle->IsTacticalTargetTileReachableForAction(
              tileIndex, record->tileIndex,
              static_cast<char>(static_cast<int>(
                  g_afTacticalDirectFireFlagByCategoryCode_00669390[categoryCode])),
              record->GetUnitRange()) != 0) {
        ++exposureCount;
      }
    }
  }
  return exposureCount;
}

// FUNCTION: IMPERIALISM 0x0059da20
int TArmyPlayer::ScoreTacticalTileRetreatEdgeRowProximity(TTacticalUnit* unit,
                                                          TacticalTileIndex tileIndex) {
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
int TArmyPlayer::ScoreTacticalTileCoverTerrainBonus(TTacticalUnit* unit,
                                                    TacticalTileIndex tileIndex) {
  (void)unit;
  int terrainType = battle->tileGrid[tileIndex].terrainType;
  if (terrainType == 1 || terrainType == 2) {
    return 0x64;
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x0059db00
int TArmyPlayer::ScoreTacticalTileAdjacentRallyTargetBonus(TTacticalUnit* unit,
                                                           TacticalTileIndex tileIndex) {
  TacticalTileIndex neighborTiles[6];
  battle->GetNeighborList(tileIndex, neighborTiles);
  for (int neighborIndex = 0; neighborIndex < 6; ++neighborIndex) {
    TacticalTileIndex neighborTileIndex = neighborTiles[neighborIndex];
    if (neighborTileIndex != -1) {
      TArmyTacUnit* occupant =
          static_cast<TArmyTacUnit*>(battle->tileGrid[neighborTileIndex].occupant);
      if (occupant != 0 && occupant->side == unit->side && occupant->morale < occupant->strength) {
        return 0x64;
      }
    }
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x0059dba0
int TArmyPlayer::ScoreTacticalTileDistanceFieldAdvance(TTacticalUnit* unit,
                                                       TacticalTileIndex tileIndex) {
  (void)unit;
  int fieldValue = battle->tileIntArray[tileIndex];
  if (fieldValue != -1) {
    return 0x64 - fieldValue;
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x0059dbe0
int TArmyPlayer::ScoreTacticalTileFriendlyArtillerySpacing(TTacticalUnit* unit,
                                                           TacticalTileIndex tileIndex) {
  (void)unit;
  int bestScore = 0;
  CIterator friendIter(unitList);
  for (TTacticalUnit* record = static_cast<TTacticalUnit*>(friendIter.Reset()); friendIter.More();
       record = static_cast<TTacticalUnit*>(friendIter.Advance())) {
    if (g_awTacticalUnitAiClassByUnitType_006693B8[record->unitType] == 2) {
      int distance = ComputeHexTileDistanceFromIndices(tileIndex, record->tileIndex);
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

// FUNCTION: IMPERIALISM 0x0059dcd0
int TArmyPlayer::ScoreTacticalTileArtilleryFiringLaneColumn(TTacticalUnit* unit,
                                                            TacticalTileIndex tileIndex) {
  (void)unit;
  int column = tileIndex % 29;
  int wallColumn = battle->battlefieldColumnCount - 6;
  if (column < wallColumn) {
    TacticalTileRecord* scanTile = &battle->tileGrid[tileIndex];
    for (int scanColumn = column; scanColumn < wallColumn; ++scanColumn, ++scanTile) {
      if (scanTile->terrainType == 4) {
        return 0;
      }
    }
  }
  if (battle->tileThreatLevelArray[tileIndex] != 0) {
    return 0;
  }
  if (column > wallColumn) {
    return 0;
  }
  return column;
}

// Heuristic [11]: how many deployed enemy artillery units could engage this tile.
// FUNCTION: IMPERIALISM 0x0059dd40
int TArmyPlayer::ScoreTacticalTileEnemyArtilleryExposureCount(TTacticalUnit* unit,
                                                              TacticalTileIndex tileIndex) {
  (void)unit;
  int exposureCount = 0;
  TList* enemyList;
  if (isOurSideFlag != 0) {
    enemyList = battle->players[1]->unitList;
  } else {
    enemyList = battle->players[0]->unitList;
  }
  CIterator enemyIter(enemyList);
  for (TTacticalUnit* record = static_cast<TTacticalUnit*>(enemyIter.Reset()); enemyIter.More();
       record = static_cast<TTacticalUnit*>(enemyIter.Advance())) {
    if (record->tileIndex >= 0 &&
        g_awTacticalUnitAiClassByUnitType_006693B8[record->unitType] == 2) {
      short categoryCode = g_awTacticalUnitCategoryCodeBySlot[record->unitType];
      if (battle->IsTacticalTargetTileReachableForAction(
              tileIndex, record->tileIndex,
              static_cast<char>(static_cast<int>(
                  g_afTacticalDirectFireFlagByCategoryCode_00669390[categoryCode])),
              record->GetUnitRange()) != 0) {
        ++exposureCount;
      }
    }
  }
  return exposureCount;
}

// FUNCTION: IMPERIALISM 0x0059de30
int TArmyPlayer::ScoreTacticalTileEngageableEnemyStandoff(TTacticalUnit* unit,
                                                          TacticalTileIndex tileIndex) {
  int range = unit->GetUnitRange();
  int score = 0;
  TacticalTileIndex targetTileIndex = SelectBestTacticalTargetTileByActionHeuristics(unit, 0);
  for (TacticalTileIndex scanTileIndex = 0; scanTileIndex < battle->tacticalTileCount;
       ++scanTileIndex) {
    TTacticalUnit* occupant = battle->tileGrid[scanTileIndex].occupant;
    if (occupant != 0 && occupant->side != unit->side && occupant->state1c == 0) {
      short categoryCode = g_awTacticalUnitCategoryCodeBySlot[unit->unitType];
      if (battle->IsTacticalTargetTileReachableForAction(
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
    short bonusCategoryCode = g_awTacticalUnitCategoryCodeBySlot[unit->unitType];
    if (battle->IsTacticalTargetTileReachableForAction(
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

// FUNCTION: IMPERIALISM 0x0059dfe0
int TArmyPlayer::ScoreTacticalTileEnemyArtilleryHuntBonus(TTacticalUnit* unit,
                                                          TacticalTileIndex tileIndex) {
  int range = unit->GetUnitRange();
  for (TacticalTileIndex scanTileIndex = 0; scanTileIndex < battle->tacticalTileCount;
       ++scanTileIndex) {
    TTacticalUnit* occupant = battle->tileGrid[scanTileIndex].occupant;
    if (occupant != 0 && occupant->side != unit->side && occupant->state1c == 0 &&
        g_awTacticalUnitAiClassByUnitType_006693B8[occupant->unitType] == 2) {
      short categoryCode = g_awTacticalUnitCategoryCodeBySlot[unit->unitType];
      if (battle->IsTacticalTargetTileReachableForAction(
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

// FUNCTION: IMPERIALISM 0x0059e0d0
int TArmyPlayer::ScoreTacticalTileEnemyEdgeColumnZoneBonus(TTacticalUnit* unit,
                                                           TacticalTileIndex tileIndex) {
  (void)unit;
  return (tileIndex % 29 > battle->battlefieldColumnCount - 5) ? 0x64 : 0;
}

// FUNCTION: IMPERIALISM 0x0059e110
int TArmyPlayer::SelectBestTacticalTargetTileByActionHeuristics(TTacticalUnit* unit, int flag) {
  TacticalTileIndex bestTargetTileIndex = -1;
  int bestTargetScore = 0;
  TList* enemyList;
  if (isOurSideFlag != 0) {
    enemyList = battle->players[1]->unitList;
  } else {
    enemyList = battle->players[0]->unitList;
  }
  TacticalTileIndex neighborTiles[6];
  battle->GetNeighborList(unit->tileIndex, neighborTiles);

  CIterator enemyIter(enemyList);
  for (TArmyTacUnit* record = static_cast<TArmyTacUnit*>(enemyIter.Reset()); enemyIter.More();
       record = static_cast<TArmyTacUnit*>(enemyIter.Advance())) {
    // Valid targets: active units, plus morale-broken ones in field48==1 mode.
    if (!(field48 == 1 && record->state1c == 1) && record->state1c != 0) {
      continue;
    }
    if (flag != 0) { // read as a byte (char) in the original
      short reachCategoryCode = g_awTacticalUnitCategoryCodeBySlot[unit->unitType];
      if (battle->IsTacticalTargetTileReachableForAction(
              unit->tileIndex, record->tileIndex,
              static_cast<char>(static_cast<int>(
                  g_afTacticalDirectFireFlagByCategoryCode_00669390[reachCategoryCode])),
              unit->GetUnitRange()) == 0) {
        continue;
      }
    }
    int targetValueByCategoryCode[10] = {0x1f4, 0x1f4, 0x1f4, 0x1f4, 0x258,
                                         0x2bc, 0x320, 0x384, 0x64,  0x190};
    int score = targetValueByCategoryCode[g_awTacticalUnitCategoryCodeBySlot[record->unitType]];
    if (field48 == 1) {
      score += 0x1f4 - record->morale;
    } else {
      score += record->strength;
    }
    TacticalTileIndex recordTileIndex = record->tileIndex;
    bool adjacent = false;
    for (int neighborIndex = 0; neighborIndex < 6; ++neighborIndex) {
      if (recordTileIndex == neighborTiles[neighborIndex]) {
        adjacent = true;
      }
    }
    if (adjacent) {
      if (battle->tileGrid[recordTileIndex].deployMark == 1) {
        score += score; // entrenched adjacent target: double
      }
      if (g_awTacticalUnitAiClassByUnitType_006693B8[unit->unitType] == 1) {
        score += score; // aiClass-1 attacker prefers adjacent targets: double again
      }
    }
    if (bestTargetTileIndex == -1 || score > bestTargetScore) {
      bestTargetTileIndex = recordTileIndex;
      bestTargetScore = score;
    }
  }

  if (bestTargetTileIndex == -1 && unit->side == 0 &&
      g_afTacticalDirectFireFlagByCategoryCode_00669390
              [g_awTacticalUnitCategoryCodeBySlot[unit->unitType]] == 0.0f &&
      battle->IsTacticalSideCategoryCoverageIncompleteOrFlagOff() == 0) {
    if (cachedFortBombardmentTargetTile == -1) {
      TacticalTileIndex rolledTileIndex;
      do {
        rolledTileIndex =
            (static_cast<int>(rand()) % 0xd) * 29 + battle->battlefieldColumnCount + 0x17;
        cachedFortBombardmentTargetTile = rolledTileIndex;
      } while (battle->IsTacticalTileAtFortWallSectionSlot(rolledTileIndex) != 0);
    }
    bestTargetTileIndex = cachedFortBombardmentTargetTile;
  }
  return bestTargetTileIndex;
}

// FUNCTION: IMPERIALISM 0x0059e3e0
void TArmyPlayer::NextMove() {
  if (field20) {
    CIterator unitIter(unitList);
    TTacticalUnit* record = static_cast<TTacticalUnit*>(unitIter.Reset());
    while (unitIter.More() != 0) {
      if (g_awTacticalUnitCategoryCodeBySlot[record->unitType] == 8 && record->state1c == 0) {
        if (g_awTacticalUnitCategoryCodeBySlot[battle->selectedUnit->unitType] != 8) {
          battle->FinishTacticalActionAndPostNextMoveCommand();
          return;
        }
        field20 = false;
        return;
      }
      record = static_cast<TTacticalUnit*>(unitIter.Advance());
    }
    field20 = false;
    return;
  }
  if (notWatchedFlag) {
    if (watchFlag != 0) {
      if (GetAsyncKeyState(0x5c /* VK_RWIN */) & 0x8000) {
        notWatchedFlag = false;
        return;
      }
    }
    RunTacticalAutoTurnControllerForActiveUnit();
  }
}

// FUNCTION: IMPERIALISM 0x0059e4f0
void TArmyPlayer::RunTacticalAutoTurnControllerForActiveUnit() {
  TTacticalUnit* unit = battle->selectedUnit;

  if (g_awTacticalUnitAiClassByUnitType_006693B8[unit->unitType] != 2 || unit->side == 1) {
    SelectAndApplyTacticalCursorModeProfile(0);
  }

  TacticalTileIndex homeTileIndex = unit->tileIndex;
  short categoryCode = g_awTacticalUnitCategoryCodeBySlot[unit->unitType];

  // Phase 1: choose the destination tile.
  TacticalTileIndex targetTileIndex;
  if (categoryCode == 8 && unit->aiStateCode != 0xc) {
    if (battle->IsTacticalSideCategoryCoverageIncompleteOrFlagOff() != 0) {
      targetTileIndex = FindBestMove(unit, g_anTacticalTileHeuristicWeightsByAiState_00699500[12]);
    } else if (battle->tileGrid[homeTileIndex].trenchMask != 0) {
      targetTileIndex = homeTileIndex;
    } else if (battle->tileThreatLevelArray[homeTileIndex] != 0) {
      targetTileIndex = homeTileIndex;
    } else {
      targetTileIndex = FindBestMove(unit, g_anTacticalTileHeuristicWeightsByAiState_00699500[13]);
    }
  } else if ((unit->aiStateCode == 5 || unit->aiStateCode == 2 || categoryCode == 4) &&
             battle->roundCounter < 2) {
    targetTileIndex = homeTileIndex;
  } else if (categoryCode == 6 && battle->roundCounter < 2) {
    targetTileIndex = FindBestMove(unit, g_anTacticalTileHeuristicWeightsByAiState_00699500[18]);
  } else {
    targetTileIndex =
        FindBestMove(unit, g_anTacticalTileHeuristicWeightsByAiState_00699500[unit->aiStateCode]);
  }
  if (targetTileIndex == -1) {
    targetTileIndex = unit->tileIndex;
  }

  // Phase 2: march toward it, one echoed step at a time (guarded at 200 steps).
  if (targetTileIndex != unit->tileIndex) {
    int moveGuard = 200;
    while (battle->pendingEndOfActionFlag != 0 && unit->state1c == 0 &&
           unit->tileIndex != targetTileIndex) {
      if (moveGuard-- == 0) {
        break;
      }
      battle->MoveTacticalUnitAndQueueEvent232AIfNoAdjacentReachableTarget(unit, targetTileIndex);
    }
  }

  // Phase 3: act from the reached tile.
  if (battle->pendingEndOfActionFlag != 0 && unit->state1c == 0) {
    if (unit->unitType >= 0x1b) {
      TacticalTileIndex neighborTiles[6];
      battle->GetNeighborList(unit->tileIndex, neighborTiles);
      TArmyTacUnit* rallyTarget = 0;
      for (int neighborIndex = 0; neighborIndex < 6 && rallyTarget == 0; ++neighborIndex) {
        TacticalTileIndex neighborTileIndex = neighborTiles[neighborIndex];
        if (neighborTileIndex != -1) {
          TArmyTacUnit* occupant =
              static_cast<TArmyTacUnit*>(battle->tileGrid[neighborTileIndex].occupant);
          if (occupant != 0 && occupant->side == unit->side &&
              occupant->morale < occupant->strength) {
            rallyTarget = occupant;
          }
        }
      }
      if (rallyTarget != 0) {
        battle->RallyUnit(unit, rallyTarget);
      }
    } else if (g_awTacticalUnitCategoryCodeBySlot[unit->unitType] == 8) {
      if (unit->tileIndex == homeTileIndex) {
        while (unit->actionPoints >=
               g_awTacticalUnitActionPointCostByType_006693F8[unit->unitType] / 2) {
          TacticalTileIndex wallTileIndex = unit->tileIndex + 1;
          TacticalTileRecord* wallTile = &battle->tileGrid[wallTileIndex];
          if (wallTile->deployMark > 1) {
            battle->ExecuteTacticalMineActionAndQueuePacket(unit, wallTileIndex);
            return; // original returns here without queueing the 0x232a event
          }
          if (wallTile->occupant == 0 && wallTile->trenchMask == 0) {
            battle->ExecuteTacticalDigActionAndConsumeUnitActionPoints(unit, wallTileIndex);
          }
        }
      }
    } else if (unit->selectedFlag != 0) {
      TacticalTileIndex fireTileIndex = SelectBestTacticalTargetTileByActionHeuristics(unit, 1);
      TTacticalUnit* fireTarget = 0;
      if (fireTileIndex != -1) {
        fireTarget = battle->tileGrid[fireTileIndex].occupant;
      }
      if (fireTarget != 0) {
        battle->ExecuteTacticalActionAndQueueEventIfNoAdjacentValidTarget(unit,
                                                                          fireTarget->tileIndex);
        if (battle->pendingEndOfActionFlag != 0 &&
            g_awTacticalUnitAiClassByUnitType_006693B8[unit->unitType] == 1 &&
            unit->actionPoints != 0) {
          int aiState = unit->aiStateCode;
          if (aiState == 2 || aiState == 5 || aiState == 0xe) {
            TacticalTileIndex advanceTileIndex =
                FindBestMove(unit, g_anTacticalTileHeuristicWeightsByAiState_00699500[aiState + 1]);
            if (advanceTileIndex != unit->tileIndex) {
              int advanceGuard = 200;
              while (battle->selectedUnit == unit && unit->state1c == 0 &&
                     unit->tileIndex != advanceTileIndex) {
                if (advanceGuard-- == 0) {
                  break;
                }
                battle->MoveTacticalUnitAndQueueEvent232AIfNoAdjacentReachableTarget(
                    unit, advanceTileIndex);
              }
            }
          }
        }
      }
    }
  }

  // Hand the turn back.
  if (battle->pendingEndOfActionFlag != 0) {
    battle->FinishTacticalActionAndPostNextMoveCommand();
  }
}

// FUNCTION: IMPERIALISM 0x0059e8a0
unsigned int
TArmyPlayer::BuildTacticalActionClassAndPositionFlags(TacticalTileIndex referenceTileIndex,
                                                      TTacticalUnit* unit) {
  TacticalTileIndex tileIndex = unit->tileIndex;
  unsigned int flags = 0;
  switch (g_awTacticalUnitAiClassByUnitType_006693B8[unit->unitType]) {
  case 0:
    flags = 1;
    break;
  case 1:
  case 3:
    flags = 2;
    break;
  case 2:
  case 4:
    flags = 4;
    break;
  }

  if (battle->AreNeighbors(tileIndex, referenceTileIndex) != 0) {
    flags |= 0x10;
  }
  if (g_awTacticalUnitAiClassByUnitType_006693B8[unit->unitType] == 0 &&
      battle->tileGrid[tileIndex].deployMark != 0) {
    flags |= 0x20;
  } else {
    flags |= 0x40;
  }

  int row = tileIndex / 29;
  int column = ((row & 1) + (tileIndex % 29) * 2) / 2;
  if (column > 6) {
    flags |= 0x80;
  }
  if (row == 14 || row == 13) {
    flags |= 0x100;
  }
  return flags;
}

// FUNCTION: IMPERIALISM 0x0059e9c0
int TArmyPlayer::GetMinimumActiveUnitRangeForStates2Or4() {
  int minimumActionPoints = 1000;
  CIterator iter(unitList);
  for (TTacticalUnit* unit = static_cast<TTacticalUnit*>(iter.Reset()); iter.More();
       unit = static_cast<TTacticalUnit*>(iter.Advance())) {
    if (unit->state1c == 0 && (unit->aiStateCode == 4 || unit->aiStateCode == 2) &&
        unit->GetBaseActionPoints() < minimumActionPoints) {
      minimumActionPoints = unit->GetBaseActionPoints();
    }
  }
  return minimumActionPoints;
}

// FUNCTION: IMPERIALISM 0x0059ea60
unsigned char TArmyPlayer::SwitchToAutoPlay() {
  if (notWatchedFlag) {
    CString message;
    g_pSimMgr->GetString(0x273d, 0, &message);
    return g_pViewMgr->ModalMessage(message, g_ptTacticalAutoPlayModalMessage, 1, 1);
  }
  return 1;
}

// FUNCTION: IMPERIALISM 0x0059eb40
void TArmyPlayer::ProceedAfterBattleIntroAccepted() {
  if (!sideReadyFlag) {
    AutoDeploySideUnitsAndMarkReady();
    return;
  }
  if (!notWatchedFlag) {
    notWatchedFlag = true;
    SelectAndApplyTacticalCursorModeProfile(0);
    NextMove();
  }
}
