// TGreatPower: the nation object for the seven great powers (Mac UCountry.cpp).

#include "game/nation_domain_types.h"
#include "game/map_domain_types.h"
#include <math.h>
#include "game/ui_tags_common.h"
#include "game/resource_domain_types.h"
#include <stddef.h>
#include <string.h>

#include "decomp_types.h"
#include <stdlib.h>

#include "game/ui_core/CIterator.h"
#include "game/core/CString.h"
#include "game/GameAssert.h"
#include "game/globals/global_types.h"
#include "game/globals/nation_globals.h"
#include "game/globals/tactical_globals.h"
#include "game/globals/shared_globals.h"
#include "game/mfc.h"
#include "game/nation_stream_serialization.h"
#include "game/ui_core/quickdraw_rendering.h"
#include "game/navy/TAdmiral.h"
#include "game/city/TCity.h"
#include "game/city/TPopulationMgr.h"
#include "game/city_ui/TCityInteriorMinister.h"
#include "game/military/TCivUnit.h"
#include "game/city_ui/TCountry.h"
#include "game/military/TDefendProvinceMission.h"
#include "game/military_ui/TDefenseMinister.h"
#include "game/military_ui/TDiplomacyMgr.h"
#include "game/nation/TForeignMinister.h"
#include "game/map/TMapMgr.h"
#include "game/nation/TGreatPower.h"
#include "game/nation/TGreatPower_internal.h"
#include "game/ui_core/THelpMgr.h"
#include "game/ui_screens/TNewsMgr.h"
#include "game/map/TMinister.h"
#include "game/military/TMilitaryUnit.h"
#include "game/military/mapped_flavor_text.h"
#include "game/city_ui/TProvinceDesirabilityList.h"
#include "game/nation/TMinor.h"
#include "game/map/TMission.h"
#include "game/net/TMultiplayerMgr.h"
#include "game/ui_widgets/TTradeMgr.h"
#include "game/navy/TNavyMgr.h"
#include "game/map/TNavyMission.h"
#include "game/app/TObject.h"
#include "game/navy/TOcean.h"
#include "game/city/TProductionOrder.h"
#include "game/navy/TShip.h"
#include "game/navy_order.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/military_ui/TSortedByRelationshipList.h"
#include "game/ui_core/TSortedList.h"
#include "game/ui_core/TPtrList.h"
#include "game/ui_widgets/TSoundPlayer.h"
#include "game/core/TStream.h"
#include "game/city/TTown.h"
#include "game/military/TUnit.h"
#include "game/ui_screens/turn_flow_cooldown.h"
#include "game/ui_core/TViewMgr.h"
#include "game/map/TZone.h"
#include "game/gfx/ui_invalidation_guard.h"

char __stdcall IsSpecialNationInteractionResource(short resourceIndex);

static const int kAidAllocationRowCount = 0x10;
static const int kAidAllocationColumnCount = kNationSlotCount;
static const int kDiplomacyTrackedSlotCount = 0x11;

static const float kOne = 1.0f;

static int SumMilitaryUnitPowerWeightsForScore(TSortedList* unitList) {
  int powerSum = 0;
  CIterator unitIter(unitList);
  for (TMilitaryUnit* unit = static_cast<TMilitaryUnit*>(unitIter.Reset()); unitIter.More();
       unit = static_cast<TMilitaryUnit*>(unitIter.Advance())) {
    powerSum += g_aUnitOrderCostProfileByAbilityId[unit->orderType][2];
  }
  return powerSum;
}

static float SumAlliedArmyScoreFactorsForScore(int targetNation) {
  float allySum = 0.0f;
  int allyIndex = 0;
  if (g_pDiplomacyTurnStateManager->GetNumAllies(targetNation) > 0) {
    do {
      int allyNation = g_pDiplomacyTurnStateManager->GetAllyNumber(allyIndex, targetNation);
      allySum += g_apNationStates[allyNation]->GetMilitaryPower();
      ++allyIndex;
    } while (allyIndex < g_pDiplomacyTurnStateManager->GetNumAllies(targetNation));
  }
  return allySum;
}

static float SumAlliedNavyScoreFactorsForScore(int targetNation) {
  float allySum = 0.0f;
  int allyIndex = 0;
  if (g_pDiplomacyTurnStateManager->GetNumAllies(targetNation) > 0) {
    do {
      int allyNation = g_pDiplomacyTurnStateManager->GetAllyNumber(allyIndex, targetNation);
      allySum += g_apNationStates[allyNation]->GetTotalNavalForce();
      ++allyIndex;
    } while (allyIndex < g_pDiplomacyTurnStateManager->GetNumAllies(targetNation));
  }
  return allySum;
}

static short* GetRelationStandingRowForScore(short nationSlot) {
  return &g_pDiplomacyTurnStateManager->relationStandingScores[nationSlot * kNationSlotCount];
}

static int GetClampedQuarterYearTermForScore() {
  int yearTerm = static_cast<short>(g_pSimMgr->economicTurn / 4);
  if (yearTerm >= 0x3c) {
    yearTerm = 0x3c;
  }
  return yearTerm;
}

struct TrackedSlotEntryPacket {
  short kind;
  short targetNation;
  short value;
  short eligibility;
  int payload;
};

ASSERT_OFFSET(TGreatPower, nationSlot, 0x0c);
ASSERT_OFFSET(TGreatPower, homeTileIndex, 0x88);
ASSERT_OFFSET(TGreatPower, ownedRegionList, 0x90);
ASSERT_OFFSET(TGreatPower, diplomacyPolicyByNation, 0xb2);
ASSERT_OFFSET(TGreatPower, aidAllocationMatrix, 0x280);
ASSERT_OFFSET(TGreatPower, city, 0x894);
ASSERT_OFFSET(TGreatPower, gameScoreRows, 0x930);
static_assert(offsetof(TGreatPower, gameScoreRows) + TGreatPower::kGameScoreTotal * sizeof(int) ==
                  0x95c,
              "TGreatPower game score total has wrong offset");
ASSERT_SIZE(TGreatPower, 0x964);

// FUNCTION: IMPERIALISM 0x004db7d0
void TGreatPower::TraceSupplyRoutes(char** outInfluenceMap) {
  if (city == 0) {
    return;
  }
  char* influenceMap = new char[kStrategicTileCount];
  if (influenceMap == 0) {
    FailNilPointerWithAssert(g_szUCountrySourcePath, 0xa0e);
  }
  memset(influenceMap, 0, kStrategicTileCount);

  CIterator markerCursor(townMarkerList);
  TTown* marker = static_cast<TTown*>(markerCursor.Reset());
  while (markerCursor.More() != 0 && static_cast<int>(marker->tileIndex) != homeTileIndex) {
    marker = static_cast<TTown*>(markerCursor.Advance());
  }
  int homeLinked = marker->IsUnblockedPort();
  if (homeLinked == 0) {
    TraceRail(influenceMap, marker->tileIndex);
    marker = static_cast<TTown*>(markerCursor.Reset());
    while (markerCursor.More() != 0 && homeLinked == 0) {
      if (influenceMap[marker->tileIndex] != 0 && marker->IsUnblockedPort() != 0) {
        homeLinked = 1;
      }
      marker = static_cast<TTown*>(markerCursor.Advance());
    }
  }
  marker = static_cast<TTown*>(markerCursor.Reset());
  while (markerCursor.More() != 0) {
    if (marker->IsUnblockedPort() != 0 && homeLinked != 0 && marker->activeFlag &&
        influenceMap[marker->tileIndex] == 0) {
      TraceRail(influenceMap, marker->tileIndex);
    }
    marker = static_cast<TTown*>(markerCursor.Advance());
  }
  marker = static_cast<TTown*>(markerCursor.Reset());
  while (markerCursor.More() != 0) {
    marker->transportLinked = !((influenceMap[marker->tileIndex] == 0 || !marker->activeFlag) &&
                                (marker->IsUnblockedPort() == 0 || homeLinked == 0));
    marker = static_cast<TTown*>(markerCursor.Advance());
  }
  if (outInfluenceMap != 0) {
    marker = static_cast<TTown*>(markerCursor.Reset());
    while (markerCursor.More() != 0) {
      if (marker->IsUnblockedPort() != 0 && homeLinked != 0) {
        influenceMap[marker->tileIndex] = 1;
      }
      marker = static_cast<TTown*>(markerCursor.Advance());
    }
    *outInfluenceMap = influenceMap;
    return;
  }
  delete[] influenceMap;
}

// FUNCTION: IMPERIALISM 0x004dbac0
void TGreatPower::TraceRail(char* regionMap, short regionId) {
  short nextRegion;
  do {
    regionMap[regionId] = 1;
    nextRegion = 0;
    char adjacencyBits = g_pGlobalMapState->terrainStateTable[regionId].adjacencyBits;
    for (short direction = 0; direction < 6; ++direction) {
      if ((adjacencyBits & (1 << direction)) != 0) {
        short neighbor = TMapMgr::GetNeighborTileID(regionId, direction);
        if (static_cast<short>(g_pGlobalMapState->terrainStateTable[neighbor].ownerNationTag) ==
                nationSlot &&
            regionMap[neighbor] == 0) {
          if (nextRegion != 0) {
            TraceRail(regionMap, neighbor);
          } else {
            nextRegion = neighbor;
          }
        }
      }
    }
    regionId = nextRegion;
  } while (nextRegion != 0 && regionMap[nextRegion] == 0);
}

// FUNCTION: IMPERIALISM 0x004dbbb0
char* TGreatPower::MakeConnectionMap() {
  TraceSupplyRoutes(NULL);

  char* influenceByTile = new char[kStrategicTileCount];
  memset(influenceByTile, 0, kStrategicTileCount);

  CIterator townIter(townMarkerList);
  for (TTown* town = static_cast<TTown*>(townIter.Reset()); townIter.More();
       town = static_cast<TTown*>(townIter.Advance())) {
    if (town != NULL && town->transportLinked) {
      char influence = (town->enabledFlag != 0) + 1;
      influenceByTile[town->tileIndex] = influence;

      short neighbors[6];
      TMapMgr::GetNeighborTileIDArray(town->tileIndex, neighbors,
                                      g_pGlobalMapState->hexNeighborWrapHorizontally);
      for (int direction = 0; direction < 6; ++direction) {
        short neighbor = neighbors[direction];
        if (neighbor != -1) {
          TTerrainStateRecord& tile = g_pGlobalMapState->terrainStateTable[neighbor];
          if ((static_cast<short>(tile.ownerNationTag) == nationSlot || tile.gateFlag == 0) &&
              influenceByTile[neighbor] < influence) {
            influenceByTile[neighbor] = influence;
          }
        }
      }
    }
  }
  return influenceByTile;
}

// FUNCTION: IMPERIALISM 0x004dbd20
void TGreatPower::RebuildNationResourceYieldCountersAndDevelopmentTargets(void) {
  const int kMapRegionSlotCount = kStrategicTileCount;

  short* currentNeedByType = needCurrentByType;
  short* developmentByType = &needCurrentByType[7]; // +0x11c overlays this runtime array.
  short* targetNeedByType = needTargetByType;
  short& controlledRegionCount = needCurrentByType[0x13];
  for (int i = 0; i < kNationSlotCount; ++i) {
    currentNeedByType[i] = 0;
  }

  char* influenceByRegion = MakeConnectionMap();
  char* influenceBuffer = influenceByRegion;
  TMapMgr* globalMapState = g_pGlobalMapState;
  TTerrainStateRecord* terrainTable = globalMapState->terrainStateTable;
  Province* cityTable = globalMapState->cityScoreTable;
  int regionIndex = 0;
  while (static_cast<short>(regionIndex) < kMapRegionSlotCount) {
    char influence = *influenceByRegion;
    if (influence != 0) {
      TTerrainStateRecord* terrainRecord = &terrainTable[regionIndex];
      if (terrainRecord->gateFlag == 0) {
        if (influence == 2) {
          ++controlledRegionCount;
        }
      } else {
        for (int edgeIndex = 0; edgeIndex < 2; ++edgeIndex) {
          short resourceType = terrainRecord->resourceTypeByEdge[edgeIndex];
          if (resourceType != -1) {
            char contribution = globalMapState->GetResourceAmtAt(regionIndex, edgeIndex);
            currentNeedByType[resourceType] = static_cast<short>(currentNeedByType[resourceType] +
                                                                 static_cast<short>(contribution));
          }
        }

        if (terrainRecord->riverSpriteCode != kRiverSpriteCodeNone && influence == 2) {
          ++controlledRegionCount;
        }

        int cityIndex = terrainRecord->cityRecordIndex;
        Province* cityRecord = &cityTable[cityIndex];
        if (cityRecord->cityTileIndex == static_cast<short>(regionIndex)) {
          for (int devIdx = 0; devIdx < 10; ++devIdx) {
            developmentByType[devIdx] = static_cast<short>(
                developmentByType[devIdx] + cityRecord->resourceDevelopmentCounts[devIdx]);
          }
        }
      }
    }

    ++regionIndex;
    ++influenceByRegion;
  }

  delete[] influenceBuffer;

  for (int typeIndex = 0; typeIndex < kNationSlotCount; ++typeIndex) {
    if (currentNeedByType[typeIndex] < targetNeedByType[typeIndex]) {
      UpdateNeedTargetAndAccumulateOverCap(typeIndex, currentNeedByType[typeIndex]);
    }
  }
}

// FUNCTION: IMPERIALISM 0x004dbf00
void TGreatPower::AdvanceOwnedRegionDevelopmentCountersAndHandleEvents(void) {
  TLongintList* regionList = ownedRegionList;
  int totalRegions = regionList->GetSize();
  int regionOrdinal = 1;
  while (regionOrdinal <= totalRegions) {
    short regionId = static_cast<short>(regionList->At(regionOrdinal));
    unsigned char pendingStage = 0;
    bool needsRedraw = false;

    TMapMgr* globalMapState = g_pGlobalMapState;
    TSimMgr* simMgr = g_pSimMgr;
    Province* cityTable = globalMapState->cityScoreTable;
    TTerrainStateRecord* terrainTable = globalMapState->terrainStateTable;
    Province* cityRecord = cityTable + regionId;
    short homeTileIndex = this->homeTileIndex;
    if (cityRecord->cityTileIndex != homeTileIndex) {
      unsigned int turnDelta = static_cast<unsigned int>(
          static_cast<int>(simMgr->GetEconomicTurn()) - static_cast<int>(cityRecord->lastTurnTick));

      if (turnDelta > 4) {
        int resourceSums[kNationSlotCount];
        int i = 0;
        while (i < kNationSlotCount) {
          resourceSums[i] = 0;
          ++i;
        }

        int linkedCount = cityRecord->linkedRegionCount;
        int linkedIndex = 0;
        while (linkedIndex < linkedCount) {
          short linkedRegion = cityRecord->linkedTileIndices[linkedIndex];
          int edge = 0;
          while (edge < 2) {
            signed char resourceType = terrainTable[linkedRegion].resourceTypeByEdge[edge];
            if (resourceType != -1) {
              resourceSums[resourceType] +=
                  static_cast<int>(globalMapState->GetResourceAmtAt(linkedRegion, edge));
            }
            ++edge;
          }
          ++linkedIndex;
        }

        short* stage1CounterA = &cityRecord->resourceDevelopmentCounts[1];
        short* stage1CounterB = &cityRecord->resourceDevelopmentCounts[2];
        short* stage1CounterC = &cityRecord->resourceDevelopmentCounts[4];
        short* stage1CounterD = &cityRecord->resourceDevelopmentCounts[5];
        short* stage2CounterA = &cityRecord->resourceDevelopmentCounts[6];
        short* stage2CounterB = &cityRecord->resourceDevelopmentCounts[7];
        short* stage2CounterC = &cityRecord->resourceDevelopmentCounts[8];

        if ((turnDelta & 1U) == 0) {
          int sum01 = resourceSums[0] + resourceSums[1];
          if (sum01 != 0) {
            int prod = city->GetBuildingType(1);
            int prodLimit = prod / 4;
            if (static_cast<int>(*stage1CounterA) < prodLimit &&
                static_cast<int>(*stage1CounterA) < sum01 / 2) {
              pendingStage = 1;
              *stage1CounterA = static_cast<short>(*stage1CounterA + 1);
              needsRedraw = true;
            }
          }

          if (resourceSums[2] != 0) {
            int prod = city->GetBuildingType(5);
            int prodLimit = prod / 4;
            if (static_cast<int>(*stage1CounterB) < prodLimit &&
                static_cast<int>(*stage1CounterB) < resourceSums[2] / 2) {
              pendingStage = 1;
              *stage1CounterB = static_cast<short>(*stage1CounterB + 1);
              needsRedraw = true;
            }
          }

          if (resourceSums[3] != 0) {
            int prod = city->GetBuildingType(3);
            int prodLimit = prod / 4;
            if (static_cast<int>(*stage1CounterC) < prodLimit &&
                static_cast<int>(*stage1CounterC) < resourceSums[3] / 2) {
              pendingStage = 1;
              *stage1CounterC = static_cast<short>(*stage1CounterC + 1);
              needsRedraw = true;
            }
          }

          TTechMgr* orderCapabilityState = g_pTechMgr;
          int capabilityScore = resourceSums[6];
          if (capabilityScore != 0 &&
              orderCapabilityState->perTechUnlockFlag[TTechMgr::kProductionOrderTechId] != 0) {
            if (static_cast<int>(*stage1CounterD) < capabilityScore / 2) {
              pendingStage = 1;
              *stage1CounterD = static_cast<short>(*stage1CounterD + 1);
              needsRedraw = true;
            }
          }
        }

        if (turnDelta > 9 && (turnDelta & 1U) != 0) {
          GetMerchantCapacity();

          if (*stage1CounterA != 0 &&
              static_cast<int>(*stage2CounterA) < static_cast<int>(*stage1CounterA) / 2) {
            pendingStage = 2;
            *stage2CounterA = static_cast<short>(*stage2CounterA + 1);
            needsRedraw = true;
          }
          if (*stage1CounterB != 0 &&
              static_cast<int>(*stage2CounterB) < static_cast<int>(*stage1CounterB) / 2) {
            pendingStage = 2;
            *stage2CounterB = static_cast<short>(*stage2CounterB + 1);
            needsRedraw = true;
          }
          if (*stage1CounterC != 0 &&
              static_cast<int>(*stage2CounterC) < static_cast<int>(*stage1CounterC) / 2) {
            pendingStage = 2;
            *stage2CounterC = static_cast<short>(*stage2CounterC + 1);
            needsRedraw = true;
          }
        }

        if (cityRecord->developmentStage < pendingStage) {
          g_pGlobalMapState->SetTownSize(regionId, pendingStage);
          if (pendingStage == 2) {
            SetNationPendingActionStateAndPayload(4, regionId);
          } else {
            SetNationPendingActionStateAndPayload(3, regionId);
            if (pendingActionStatus.byAction[8] < 0x33) {
              SetNationPendingActionStateAndPayload(8, -1);
            }
          }
        }
      }

      if (simMgr->multiplayerSessionRole != kSessionRoleStandalone && needsRedraw) {
        g_pGameFlowState->DispatchCityRedrawInvalidateEvent(regionId);
      }
    }

    ++regionOrdinal;
  }
}

// FUNCTION: IMPERIALISM 0x004dc3f0
bool TGreatPower::AnyNeedCurrentExceedsTargetWhenCapMismatch(void) {
  bool result = false;
  if (transportCapacity != reservedTransportCapacity) {
    short needIndex = 0;
    while (needCurrentByType[needIndex] <= needTargetByType[needIndex]) {
      ++needIndex;
      if (needIndex > 0x16) {
        return result;
      }
    }
    result = true;
  }
  return result;
}

// FUNCTION: IMPERIALISM 0x004dc440
bool TGreatPower::HasAnyCommodityRecordBelowStepValue(void) {
  TCity* tradeCity = city;
  if (tradeCity->productionSummary->strength <= 1) {
    return false;
  }
  for (int recordIndex = 8; recordIndex < 0xd; ++recordIndex) {
    TProductionOrder* record = city->orderSlots[static_cast<short>(recordIndex)];
    short controlValue = record->quantity;
    if (record->MaxOrder() > controlValue) {
      return true;
    }
  }
  return false;
}

// FUNCTION: IMPERIALISM 0x004dc4c0
short TGreatPower::ComputeTreasuryStatusPromptCode(void) {
  int dispatchCounter = g_pDiplomacyTurnStateManager->lastDiplomaticEffortTurn;
  short promptCode = 0;
  int turnTick = g_pSimMgr->GetEconomicTurn();
  if (dispatchCounter == 0 && turnTick == 3) {
    promptCode = 0x25;
    return promptCode;
  }
  if (dispatchCounter - turnTick > 4 && treasuryValue >= 10000) {
    promptCode = 0x27;
  }
  return promptCode;
}

// FUNCTION: IMPERIALISM 0x004dc540
bool TGreatPower::IsCapitolThreatened(int mode) {
  if (mode == 0) {
    int nodeContext = GetCapitolProvince();
    float localScore = TDefendProvinceMission::ComputeLocalSupportVectorScore(nodeContext);
    float crossNationScore =
        TDefendProvinceMission::ComputeCrossNationSupportVectorScore(nodeContext);
    return localScore < crossNationScore;
  } else {
    TZone* portZoneContext = g_pActiveMapOrderContext->GetPortZone(nationSlot);

    TZone* firstEntry = portZoneContext->primaryNeighbors[0];

    float exactSourceScore =
        TNavyMission::ComputeOrderDistributionSimilarityScoreForExactSourceNation(nationSlot,
                                                                                  firstEntry);
    float diplomacyFilteredScore =
        TNavyMission::ComputeOrderDistributionSimilarityScoreWithDiplomacyFilter(nationSlot,
                                                                                 firstEntry);
    return exactSourceScore < diplomacyFilteredScore;
  }
}

// FUNCTION: IMPERIALISM 0x004dc660
bool TGreatPower::BuildGreatPowerMapContextTriggeredNationEventMessages(CString* outMessageText) {
  bool anyMessage = false;
  bool found = false;
  int nationSlot;
  for (nationSlot = 0; nationSlot < kMajorNationCount; ++nationSlot) {
    if (g_pDiplomacyTurnStateManager->AreAtWar(nationSlot, this->nationSlot) &&
        g_pSimMgr->ReallyInTheGame(nationSlot)) {
      found = true;
    }
    if (found) {
      break;
    }
  }
  if (found) {
    TZone* contextEntry = g_pMapActionContextListHead;
    while (contextEntry != 0) {
      contextEntry->GetContextOrdinalOrInvalid();
      found = false;
      if (contextEntry->IsAdjacentToCountry(this->nationSlot)) {
        short candidate;
        for (candidate = 0; candidate < 7; ++candidate) {
          if (candidate != this->nationSlot &&
              g_pDiplomacyTurnStateManager->AreAtWar(this->nationSlot, candidate)) {
            unsigned char candidateMask = 1 << candidate;
            if ((contextEntry->nationKeyMask & candidateMask) != 0) {
              unsigned char selfMask = 1 << this->nationSlot;
              if ((contextEntry->nationKeyMask & selfMask) == 0) {
                CString zoneName;
                contextEntry->AssignZoneDisplayNameToOutputRef(&zoneName);
                *outMessageText += "\n     " + zoneName;
                anyMessage = true;
                found = true;
              }
            }
          }
          if (found) {
            break;
          }
        }
      }
      contextEntry = contextEntry->prev18;
    }
  }
  return anyMessage;
}

// FUNCTION: IMPERIALISM 0x004dc840
bool TGreatPower::BuildGreatPowerEligibleNationEventMessagesFromLinkedList(
    CString* outMessageText) {
  bool found = false;
  bool anyMessage = false;
  int nationSlot;
  for (nationSlot = 0; nationSlot < kMajorNationCount; ++nationSlot) {
    if (g_pDiplomacyTurnStateManager->AreAtWar(nationSlot, this->nationSlot) &&
        g_pSimMgr->ReallyInTheGame(nationSlot)) {
      found = true;
    }
    if (found) {
      break;
    }
  }
  if (found) {
    CIterator cursor(townMarkerList);
    TTown* town = static_cast<TTown*>(cursor.Reset());
    while (cursor.More()) {
      if (town->enabledFlag != 0 && !town->transportLinked) {
        anyMessage = true;
        CString townName;
        g_pGlobalMapState->AssignCityRecordDisplayName(
            g_pGlobalMapState->terrainStateTable[town->tileIndex].cityRecordIndex, &townName);
        *outMessageText += "\n     " + townName;
      }
      town = static_cast<TTown*>(cursor.Advance());
    }
  }
  return anyMessage;
}

// FUNCTION: IMPERIALISM 0x004dc9f0
void TGreatPower::FinishCityPhase(void) {
  if (city == 0) {
    return;
  }

  RebuildNationResourceYieldCountersAndDevelopmentTargets();
  AdvanceOwnedRegionDevelopmentCountersAndHandleEvents();
  AddCreatedItems();
  SellStockToCoverDebt();
  city->EndCityPhase();
  NoOpNationPendingActionHook();
}

// FUNCTION: IMPERIALISM 0x004dca60
void TGreatPower::CalculatePotentials(void) {
  TCity* cityPtr = city;
  if (cityPtr != 0) {
    cityPtr->PredictedNeeds();
  }
}

// FUNCTION: IMPERIALISM 0x004dca80
void TGreatPower::UpdateCountryStockpile(short* needVector) {}

// FUNCTION: IMPERIALISM 0x004dcaa0
unsigned int TGreatPower::GetUnreservedMerchantCapacity(int proposalCode) {
  if (foreignMinister->purchasePriorityByResource[4] != 0) {
    if (g_pTradeMgr->GetAmtOffered(4) != 0) {
      if (static_cast<short>(proposalCode) == 4) {
        return static_cast<unsigned short>(availableMerchantCapacity);
      }
      short resolvedCode = g_pTradeMgr->WhoTradesFirst(proposalCode, 4);
      if (resolvedCode == static_cast<short>(proposalCode)) {
        int reducedCounter = static_cast<int>(availableMerchantCapacity) - 2;
        return reducedCounter & (static_cast<int>(reducedCounter < 1) - 1);
      }
      return static_cast<unsigned short>(availableMerchantCapacity);
    }
  }
  if (foreignMinister->purchasePriorityByResource[5] != 0) {
    if (g_pTradeMgr->GetAmtOffered(5) != 0) {
      if (static_cast<short>(proposalCode) == 5) {
        return static_cast<unsigned short>(availableMerchantCapacity);
      }
      short resolvedCode = g_pTradeMgr->WhoTradesFirst(proposalCode, 5);
      if (resolvedCode == static_cast<short>(proposalCode)) {
        int reducedCounter = static_cast<int>(availableMerchantCapacity) - 2;
        return reducedCounter & (static_cast<int>(reducedCounter < 1) - 1);
      }
      return static_cast<unsigned short>(availableMerchantCapacity);
    }
  }
  if (foreignMinister->purchasePriorityByResource[3] != 0 && g_pTradeMgr->GetAmtOffered(3) != 0) {
    if (static_cast<short>(proposalCode) != 3) {
      short resolvedCode = g_pTradeMgr->WhoTradesFirst(proposalCode, 3);
      if (resolvedCode == static_cast<short>(proposalCode)) {
        int reducedCounter = static_cast<int>(availableMerchantCapacity) - 2;
        return reducedCounter & (static_cast<int>(reducedCounter < 1) - 1);
      }
      if (static_cast<short>(proposalCode) != 3) {
        return static_cast<unsigned short>(availableMerchantCapacity);
      }
    }
    if (foreignMinister->purchasePriorityByResource[4] != 0) {
      int reducedCounter = static_cast<int>(availableMerchantCapacity) - 1;
      return reducedCounter & (static_cast<int>(reducedCounter < 1) - 1);
    }
  }
  return static_cast<unsigned short>(availableMerchantCapacity);
}

// FUNCTION: IMPERIALISM 0x004dcc30
void TGreatPower::FillInteriorMinisterOrders(void) {}

// FUNCTION: IMPERIALISM 0x004dcc50
void TGreatPower::AddTransportedItems(void) {
  for (short resourceKind = 0; resourceKind < kResourceKindCount; ++resourceKind) {
    AddToStockpile(resourceKind, transportedItemsByResource[resourceKind]);
    transportedItemsByResource[resourceKind] = 0;
  }
}

// FUNCTION: IMPERIALISM 0x004dcca0
void TGreatPower::AddPurchasedItems(void) {
  for (short resourceKind = 0; resourceKind < kResourceKindCount; ++resourceKind) {
    AddToStockpile(resourceKind, purchasedItemsByResource[resourceKind]);
    if (rememberedTradeOffersByResource[resourceKind] == -1 &&
        purchasedItemsByResource[resourceKind] == 0) {
      unfilledTradeTurnCountsByResource[resourceKind] =
          static_cast<short>(unfilledTradeTurnCountsByResource[resourceKind] + 1);
    } else {
      unfilledTradeTurnCountsByResource[resourceKind] = 0;
    }
    purchasedItemsByResource[resourceKind] = 0;
  }
}

// FUNCTION: IMPERIALISM 0x004dcd10
void TGreatPower::AddCreatedItems(void) {
  AddToTreasury(static_cast<int>(needTargetByType[0x15]) * 500);

  TCity* cityPtr = city;
  cityPtr->stockByType[kResourceGems] = 0;
  cityPtr->VerifyStocks();

  AddToTreasury(static_cast<int>(needTargetByType[0x16]) * 200);

  cityPtr->stockByType[kResourceGold] = 0;
  cityPtr->VerifyStocks();

  for (int needIndex = 0; static_cast<short>(needIndex) < kNationSlotCount; ++needIndex) {
    AddToStockpile(static_cast<short>(needIndex), needTargetByType[needIndex]);
  }
}

// FUNCTION: IMPERIALISM 0x004dcdd0
void TGreatPower::UpdateNeedTargetAndAccumulateOverCap(short needIndex, short value) {
  short* target = &needTargetByType[needIndex];
  reservedTransportCapacity = static_cast<short>(reservedTransportCapacity + (value - *target));
  *target = value;
}

// FUNCTION: IMPERIALISM 0x004dce10
void TGreatPower::SetNationResourceNeedCurrentByType(int needType, int currentValue) {
  short needIndex = needType;
  needCurrentByType[needIndex] = static_cast<short>(currentValue);
}

// FUNCTION: IMPERIALISM 0x004dce40
bool TGreatPower::IsNeedTargetEqualCurrent(short needIndex) {
  bool result = false;
  if (needTargetByType[needIndex] == needCurrentByType[needIndex]) {
    result = true;
  }
  return result;
}

// FUNCTION: IMPERIALISM 0x004dce70
short TGreatPower::GetNeedTargetByType(short needIndex) {
  return needTargetByType[needIndex];
}

// FUNCTION: IMPERIALISM 0x004dce90
void TGreatPower::TryIncrementNationResourceNeedTargetTowardCurrent(int needType) {
  short needIndex = needType;
  short targetValue = needTargetByType[needIndex];
  short currentValue = needCurrentByType[needIndex];
  if (targetValue < currentValue) {
    UpdateNeedTargetAndAccumulateOverCap(needType, static_cast<int>(targetValue) + 1);
  }
}

// FUNCTION: IMPERIALISM 0x004dcf10
bool TGreatPower::IsTransportCapacityExceeded(void) {
  int sumCurrentNeeds = 0;
  for (int needIndex = 0; needIndex < kNationSlotCount; ++needIndex) {
    sumCurrentNeeds += static_cast<int>(needCurrentByType[needIndex]);
  }

  return sumCurrentNeeds > static_cast<int>(transportCapacity);
}

// FUNCTION: IMPERIALISM 0x004dcf60
bool TGreatPower::IncreaseRollingStock(void) {
  if (GetStockpile(kResourceLumber) != 0) {
    if (GetStockpile(kResourceSteel) != 0) {
      AddToStockpile(9, -1);
      AddToStockpile(0xb, -1);
      transportCapacity = static_cast<short>(transportCapacity + 1);
      return true;
    }
  }
  return false;
}

// FUNCTION: IMPERIALISM 0x004dcfd0
bool TGreatPower::IncreaseMerchantMarine(void) {
  if (GetStockpile(kResourceLumber) > 2) {
    if (GetStockpile(kResourceFabric) != 0) {
      AddToStockpile(9, -3);
      AddToStockpile(8, -1);
      merchantCapacity = static_cast<short>(merchantCapacity + 1);
      return true;
    }
  }
  return false;
}

// FUNCTION: IMPERIALISM 0x004dd040
void TGreatPower::SetTradePolicyTo(NationSlot targetNationSlot, short tradePolicy) {
  short nation = targetNationSlot;
  if (nation != nationSlot && tradePolicy != tradePolicyByNation[nation]) {
    tradePolicyByNation[nation] = tradePolicy;
  }
  if (diplomacyEligibility != 0) {
    g_pHelpMgr->DiplomacyMsg(-1, targetNationSlot, 1);
  }
  if (tradePolicy == 300) {
    SetGrantPolicyTo(targetNationSlot, -1);
  }
}

// FUNCTION: IMPERIALISM 0x004dd0c0
void TGreatPower::TellColoniesToBoycott(int targetNationSlot, int isBoycottEnabled) {
  unsigned char boycottFlag = isBoycottEnabled;
  int policyValue = boycottFlag ? kTradePolicyBoycott : kTradePolicyNormal;
  colonyBoycottFlags[targetNationSlot] = boycottFlag;

  for (int secondarySlot = kMajorNationCount; secondarySlot < kNationSlotCount; ++secondarySlot) {
    TMinor* secondaryState = g_apSecondaryNationStateSlots[secondarySlot];
    bool hasNationFlag = secondaryState->IsColonyOf(nationSlot);
    if (hasNationFlag != 0) {
      secondaryState->SetTradePolicyTo(static_cast<NationSlot>(targetNationSlot),
                                       static_cast<short>(policyValue));
    }
  }
}

// FUNCTION: IMPERIALISM 0x004dd140
void TGreatPower::RecomputeDiplomacyAidBudgetScoreFromResourceWeights(void) {
  int total = 0;
  for (int resourceType = 0; resourceType < kIndustryActionSlotCount; ++resourceType) {
    total += TShip::GetTypeCargoHold(resourceType) * city->orderCountByType[resourceType];
  }

  merchantCapacity = static_cast<short>(total);
  availableMerchantCapacity = static_cast<short>(total);
}

// FUNCTION: IMPERIALISM 0x004dd1b0
void TGreatPower::InitializeTradeStatus(void) {
  RecomputeDiplomacyAidBudgetScoreFromResourceWeights();

  unfilledTradeOfferCount = 0;
  budgetPoolDelta = 0;
  budgetPoolBase = 0;

  for (int nationIndex = 0; nationIndex < kNationSlotCount; ++nationIndex) {
    short snapshotValue = rememberedTradeOffersByResource[nationIndex];
    if (snapshotValue == -1) {
      ++unfilledTradeOfferCount;
    }
    itemPotentials[nationIndex] = snapshotValue;

    short needScore = GetStockpile(nationIndex);
    if (needScore < itemPotentials[nationIndex]) {
      itemPotentials[nationIndex] = GetStockpile(nationIndex);
    }

    for (int rowIndex = 0; rowIndex < kAidAllocationRowCount; ++rowIndex) {
      aidAllocationMatrix[rowIndex * kAidAllocationColumnCount + nationIndex] = 0;
    }
  }
}

// FUNCTION: IMPERIALISM 0x004dd270
void TGreatPower::RecallTradeBids(void) {
  for (int nationIndex = 0; nationIndex < kNationSlotCount; ++nationIndex) {
    short snapshotValue = rememberedTradeOffersByResource[nationIndex];
    if (snapshotValue == -1) {
      ++unfilledTradeOfferCount;
    }
    itemPotentials[nationIndex] = snapshotValue;

    short needScore = GetStockpile(nationIndex);
    if (needScore < itemPotentials[nationIndex]) {
      itemPotentials[nationIndex] = GetStockpile(nationIndex);
    }

    for (int rowIndex = 0; rowIndex < kAidAllocationRowCount; ++rowIndex) {
      aidAllocationMatrix[rowIndex * kAidAllocationColumnCount + nationIndex] = 0;
    }
  }
}

// FUNCTION: IMPERIALISM 0x004dd310
void TGreatPower::InitializeDealBook(void) {
  for (int listIndex = 0; listIndex < kDiplomacyTrackedSlotCount; ++listIndex) {
    diplomacyTrackedSlots[listIndex]->DeleteAll();
  }
}

// FUNCTION: IMPERIALISM 0x004dd340
void TGreatPower::AddOverseasProfitFrom(int amount, short columnIndex, short rowIndex) {
  AddToTreasury(amount);
  aidAllocationMatrix[rowIndex * kAidAllocationColumnCount + columnIndex -
                      7 * kAidAllocationColumnCount] += amount;
  aidAllocationTotal += amount;
}

// FUNCTION: IMPERIALISM 0x004dd3b0
int TGreatPower::GetOverseasProfitFrom(NationSlot targetNationSlot) {
  int total = 0;
  int rowIndex = 0;
  while (rowIndex < kAidAllocationRowCount) {
    int matrixIndex = rowIndex * kAidAllocationColumnCount + static_cast<int>(targetNationSlot);
    total += aidAllocationMatrix[matrixIndex];
    ++rowIndex;
  }
  return total;
}

// FUNCTION: IMPERIALISM 0x004dd3f0
int TGreatPower::GetTotalOverseasProfits(void) {
  int total = 0;
  int rowIndex = 0;
  while (rowIndex < kAidAllocationRowCount) {
    int columnIndex = 0;
    while (columnIndex < kAidAllocationColumnCount) {
      int matrixIndex = rowIndex * kAidAllocationColumnCount + columnIndex;
      total += aidAllocationMatrix[matrixIndex];
      ++columnIndex;
    }
    ++rowIndex;
  }
  return total;
}

// FUNCTION: IMPERIALISM 0x004dd430
int TGreatPower::ComputeRemainingDiplomacyAidBudget(void) {
  int outstandingCommitments = pendingCommitmentCost;
  int militaryExpenses = this->militaryExpenses;
  int baseBudget = GetTotalOverseasProfits();
  return baseBudget + budgetPoolBase + budgetPoolDelta - militaryExpenses - outstandingCommitments;
}

// FUNCTION: IMPERIALISM 0x004dd470
void TGreatPower::SetTradeBids(void) {
  TSimMgr* simMgr = g_pSimMgr;
  if (simMgr->difficultyLevel != kDifficultyIntroductory || simMgr->mode != kGamePhaseStartGame) {
    return;
  }

  SetItemPotentials(kResourceFood, -1);
  SetItemPotentials(kResourceCotton, -1);
  SetItemPotentials(kResourceWool, -1);
  SetItemPotentials(kResourceTimber, -1);
  RememberTradeBids();
}

// FUNCTION: IMPERIALISM 0x004dd4e0
void TGreatPower::AssignFallbackNationsToUnfilledDiplomacyNeedSlots(void) {
  const int kNeedSlotStart = 7;
  const int kNeedSlotEndExclusive = 12;
  const int kNeedSlotFallback = 5;

  if (diplomacyEligibility == 0) {
    foreignMinister->ArrangeMaterialsOffers();
    return;
  }

  TDiplomacyMgr* diplomacyManager = g_pDiplomacyTurnStateManager;
  bool hasUnfilledNeedSlot = false;
  for (int needSlot = kNeedSlotStart; needSlot < kNeedSlotEndExclusive; ++needSlot) {
    if (GetTradeOffersFor(needSlot) < 0) {
      hasUnfilledNeedSlot = true;
    }
  }

  if (hasUnfilledNeedSlot) {
    short selectedNation = -1;
    TSortedByRelationshipList* relationshipList = new TSortedByRelationshipList;
    relationshipList->ISortedByRelationshipList();
    diplomacyManager->BuildRelationshipList(nationSlot, 1, relationshipList);

    for (int needSlot = kNeedSlotStart; needSlot < kNeedSlotEndExclusive; ++needSlot) {
      if (GetTradeOffersFor(needSlot) < 0) {
        int listIndex = relationshipList->GetSize();
        if (selectedNation < 0) {
          while (listIndex >= 1) {
            short* rankedNation =
                static_cast<short*>(relationshipList->GetPtrListEntryByOneBasedIndex(listIndex));
            selectedNation = *rankedNation;
            --listIndex;
            TGreatPower* candidateState = g_apNationStates[selectedNation];
            if (candidateState->diplomacyEligibility != 0) {
              selectedNation = -1;
            }
            if (selectedNation >= 0) {
              break;
            }
          }
        }

        if (selectedNation >= 0) {
          TGreatPower* selectedNationState = g_apNationStates[selectedNation];
          selectedNationState->SetTradeOffersFor(needSlot, nationSlot);
        }
      }
    }

    if (relationshipList != 0) {
      relationshipList->FreeList();
    }
  }

  if (GetTradeOffersFor(kNeedSlotFallback) == -1) {
    bool foundFallbackNation = false;
    int fallbackNationSlot = -1;
    while (!foundFallbackNation) {
      fallbackNationSlot = rand() % 7;
      if (g_pSimMgr->ReallyInTheGame(fallbackNationSlot) &&
          !g_pDiplomacyTurnStateManager->AreAtWar(fallbackNationSlot, nationSlot) &&
          fallbackNationSlot != nationSlot) {
        foundFallbackNation = true;
      }
    }

    TGreatPower* fallbackNationState = g_apNationStates[fallbackNationSlot];
    fallbackNationState->SetTradeOffersFor(kNeedSlotFallback, nationSlot);
  }
}

// FUNCTION: IMPERIALISM 0x004dd740
short TGreatPower::GetStockpile(short resourceKind) {
  TCity* cityPtr = city;
  if (cityPtr == 0) {
    return 0;
  }
  return cityPtr->stockByType[resourceKind];
}

// FUNCTION: IMPERIALISM 0x004dd770
void TGreatPower::SetStockpile(short targetSlot, short value) {
  TCity* cityPtr = city;
  cityPtr->stockByType[targetSlot] = value;
  cityPtr->VerifyStocks();
}

// FUNCTION: IMPERIALISM 0x004dd7b0
void TGreatPower::AddToStockpile(short targetSlot, short value) {
  TCity* cityPtr = city;
  cityPtr->stockByType[targetSlot] = static_cast<short>(cityPtr->stockByType[targetSlot] + value);
  cityPtr->VerifyStocks();
}

// FUNCTION: IMPERIALISM 0x004dd7f0
unsigned int TGreatPower::ComputeProductionMetricForOrderKind(short orderKind) {
  switch (orderKind) {
  case 0:
  case 1: {
    int production = this->city->GetBuildingType(0);
    return production + production;
  }
  case 2: {
    int production = this->city->GetBuildingType(4);
    return production + production;
  }
  case 3:
  case 4:
    return this->city->GetBuildingType(2);
  case 6: {
    int production = this->city->GetBuildingType(6);
    return production + production;
  }
  case 8: {
    int production = this->city->GetBuildingType(1);
    return production + production;
  }
  case 9:
  case 10: {
    int production = this->city->GetBuildingType(5);
    return production + production;
  }
  case 0xb: {
    int production = this->city->GetBuildingType(3);
    return production + production;
  }
  case 0xc: {
    int production = this->city->GetBuildingType(0xb);
    return production + production;
  }
  case 7: {
    short* summary = this->city->GetUnmetNeeds();
    TCity* city = this->city;
    short available = static_cast<short>(
        ((((summary[0x14] + summary[0x12] + summary[0x11]) - city->stockByType[kResourceFood]) -
          city->stockByType[kResourceLivestock]) -
         city->stockByType[kResourceGrain]) -
        city->stockByType[kResourceFruit]);
    if (available >= 0) {
      return static_cast<unsigned short>(available);
    }
    return 0;
  }
  case 5:
  case 0xd:
  case 0xe:
  case 0xf:
  case 0x10:
    return 0;
  default:
    return orderKind;
  }
}

// FUNCTION: IMPERIALISM 0x004dda20
void TGreatPower::DeliverItem(short amount) {
  availableMerchantCapacity = static_cast<short>(availableMerchantCapacity - amount);
}

// FUNCTION: IMPERIALISM 0x004dda40
void TGreatPower::ConsumeMerchantCapacityForPurchase(int delta) {
  availableMerchantCapacity =
      static_cast<short>(availableMerchantCapacity - static_cast<short>(delta));
}

// FUNCTION: IMPERIALISM 0x004dda60
short TGreatPower::GetAmtUnsold(short resourceKind) {
  return static_cast<short>(itemPotentials[resourceKind] + purchasedItemsByResource[resourceKind]);
}

// FUNCTION: IMPERIALISM 0x004dda90
void TGreatPower::SetTradeOffersFor(short resourceKind, short offerContext) {
  g_pNewsMgr->AddShortageEvent(nationSlot, offerContext, resourceKind, false);
}

// FUNCTION: IMPERIALISM 0x004ddad0
bool TGreatPower::WereAllOfferedGoodsSold(void) {
  bool result = true;
  short nationSlot = 0xd;
  do {
    if (nationSlot > 0x10) {
      return result;
    }
    short state = itemPotentials[nationSlot];
    if (state > 0 && purchasedItemsByResource[nationSlot] + state > 0) {
      result = false;
    }
    ++nationSlot;
  } while (result);
  return result;
}

// FUNCTION: IMPERIALISM 0x004ddb20
short TGreatPower::GetTradeOffersFor(short resourceKind) {
  return itemPotentials[resourceKind];
}

// FUNCTION: IMPERIALISM 0x004ddb40
void TGreatPower::SetItemPotentials(short resourceKind, short value) {
  if (resourceKind != -10) {
    short clamped = merchantCapacity;
    if (value <= merchantCapacity) {
      clamped = value;
    }
    itemPotentials[resourceKind] = clamped;
  }
}

// FUNCTION: IMPERIALISM 0x004ddb80
void TGreatPower::RememberTradeBids(void) {
  for (int nationSlot = 0; nationSlot < kNationSlotCount; ++nationSlot) {
    rememberedTradeOffersByResource[nationSlot] = itemPotentials[nationSlot];
  }
}

// FUNCTION: IMPERIALISM 0x004ddbb0
bool TGreatPower::ReplyToTradeOffer(NationSlot targetNationSlot, short amount, short price,
                                    ResourceKindStorage resourceKind) {
  if (StillBuyingItem(resourceKind)) {
    TViewMgr* uiRuntimeContext = g_pViewMgr;
    uiRuntimeContext->ShowOfferSheet(nationSlot, targetNationSlot, amount, price, resourceKind);
    return true;
  }

  AddToDealBook(1, targetNationSlot, 0, resourceKind, 0);
  return false;
}

// FUNCTION: IMPERIALISM 0x004ddc30
void TGreatPower::PurchaseItem(short resourceKind, short amount, short price) {
  short index = resourceKind;
  short deltaWord = amount;
  purchasedItemsByResource[index] = static_cast<short>(purchasedItemsByResource[index] + deltaWord);

  int deltaInt = deltaWord;
  short multiplierWord = price;
  int scaledDelta = static_cast<int>(multiplierWord) * deltaInt;
  AddToTreasury(-scaledDelta);

  if (deltaWord > 0) {
    ConsumeMerchantCapacityForPurchase(amount);
    budgetPoolDelta -= scaledDelta;
    return;
  }

  budgetPoolBase -= scaledDelta;
  if (IsSpecialNationInteractionResource(index) != 0) {
    specialResourceTradeBalance -= deltaInt;
  }
}

// FUNCTION: IMPERIALISM 0x004ddcf0
void TGreatPower::AddPurchasedItemAmount(short index, short delta) {
  purchasedItemsByResource[index] = static_cast<short>(purchasedItemsByResource[index] + delta);
}

// FUNCTION: IMPERIALISM 0x004ddd20
void TGreatPower::ClearTradeOfferForResource(short targetSlot) {
  itemPotentials[targetSlot] = 0;
}

// FUNCTION: IMPERIALISM 0x004ddd50
bool TGreatPower::StillBuyingItem(ResourceKindStorage resourceKind) {
  bool result = true;
  if (GetMerchantCapacity() <= 0 || itemPotentials[resourceKind] >= 0) {
    result = false;
  }
  return result;
}

// FUNCTION: IMPERIALISM 0x004ddd90
void TGreatPower::AddToDealBook(short kind, NationSlot targetNation, short value, short slotIndex,
                                int payload) {
  TrackedSlotEntryPacket packet;
  packet.payload = payload;
  packet.kind = kind;
  packet.targetNation = targetNation;
  packet.value = value;
  if (kind == kTrackedSlotOfferEntry ||
      (kind == kTrackedSlotAcceptEntry &&
       !g_pDiplomacyTurnStateManager->IsGreatPower(targetNation))) {
    packet.eligibility = 1;
  } else {
    packet.eligibility = 0;
  }
  diplomacyTrackedSlots[slotIndex]->Insert(&packet);
}

// FUNCTION: IMPERIALISM 0x004dde30
bool TGreatPower::WasItemDeclined(short targetSlot) {
  bool found = false;
  for (short entryIndex = 1; !found; ++entryIndex) {
    TPtrList* trackedSlot = diplomacyTrackedSlots[targetSlot];
    if (entryIndex > trackedSlot->GetSize()) {
      return found;
    }
    TrackedSlotEntryPacket* entry = static_cast<TrackedSlotEntryPacket*>(
        trackedSlot->GetPtrListEntryByOneBasedIndex(entryIndex));
    if (entry->value == 0) {
      found = true;
    }
  }
  return found;
}

// FUNCTION: IMPERIALISM 0x004dde80
short TGreatPower::GetNumDealsIn(short targetSlot) {
  return diplomacyTrackedSlots[targetSlot]->GetSize();
}

// FUNCTION: IMPERIALISM 0x004ddeb0
void TGreatPower::GetDealInfo(short slotIndex, short ordinal, short* outKind, short* outValue,
                              short* outTargetNation, int* outPayload) {
  TrackedSlotEntryPacket* entry = static_cast<TrackedSlotEntryPacket*>(
      diplomacyTrackedSlots[slotIndex]->GetPtrListEntryByOneBasedIndex(ordinal));
  *outKind = entry->kind;
  *outTargetNation = entry->targetNation;
  *outValue = entry->value;
  *outPayload = entry->payload;
}

// FUNCTION: IMPERIALISM 0x004ddf20
void TGreatPower::DealInterupted(int targetSlot, int matchKey, int payload) {
  bool matched = false;
  for (int entryIndex = 1; !matched; ++entryIndex) {
    TPtrList* trackedSlot = diplomacyTrackedSlots[targetSlot];
    if (entryIndex > trackedSlot->GetSize()) {
      return;
    }
    TrackedSlotEntryPacket* entry = static_cast<TrackedSlotEntryPacket*>(
        trackedSlot->GetPtrListEntryByOneBasedIndex(entryIndex));
    if (entry->targetNation == matchKey) {
      matched = true;
      entry->payload = payload;
      entry->value = 0;
    }
  }
}

// FUNCTION: IMPERIALISM 0x004ddf90
void TGreatPower::ClearTradeOffers(void) {
  memset(itemPotentials, 0, sizeof(itemPotentials));
}

// FUNCTION: IMPERIALISM 0x004ddfc0
bool TGreatPower::SetDiplomacyPolicyTo(short targetClass, short policyCode) {
  const short kPolicyClear = -1;
  const short kPolicyRequiresCompatibilityStart = kDiplomacyProposalJoinEmpire;
  const short kPolicyTreasurySmall = 0x133;
  const short kPolicyTreasuryLarge = 0x134;

  bool shouldApply = true;

  if (policyCode < kPolicyRequiresCompatibilityStart) {
    if (policyCode == kPolicyClear) {
      short previousPolicy = diplomacyPolicyByNation[targetClass];
      if (previousPolicy == kPolicyTreasurySmall) {
        AddToTreasury(500);
      } else if (previousPolicy == kPolicyTreasuryLarge) {
        AddToTreasury(5000);
      }
    }
  } else if (policyCode == kPolicyRequiresCompatibilityStart) {
    if (g_pDiplomacyTurnStateManager->GetEmbassyStatus(nationSlot, targetClass) != 2) {
      shouldApply = false;
    }
  } else
    switch (policyCode - (kPolicyRequiresCompatibilityStart + 1)) {
    case 0:
    case 1:
      if (g_pDiplomacyTurnStateManager->GetEmbassyStatus(nationSlot, targetClass) != 2) {
        shouldApply = false;
      }
      break;

    case 3: {
      TSimMgr* simMgr = g_pSimMgr;
      if (simMgr != 0 && simMgr->mode == kGamePhaseDiplomacy) {
        DeclareWarOn(targetClass, 4, -1);
      }

      TDiplomacyMgr* diplomacyManager = g_pDiplomacyTurnStateManager;
      DiplomacyRelationshipStorage relationship =
          g_pDiplomacyTurnStateManager->GetTreatyStatus(targetClass, nationSlot);
      if (relationship == kDiplomacyRelationshipAlliance) {
        g_pDiplomacyTurnStateManager->TerminateAlliance(nationSlot, targetClass, 1);
      }

      TCountry* terrainDescriptor = g_apTerrainTypeDescriptorTable[targetClass];
      bool isClientNation = terrainDescriptor->encodedNationSlot >= 200;
      if (isClientNation) {
        short encodedNationSlot = terrainDescriptor->encodedNationSlot;
        short resolvedNationSlot;
        if (encodedNationSlot >= 200) {
          resolvedNationSlot = static_cast<short>(encodedNationSlot - 200);
        } else if (encodedNationSlot >= 100) {
          resolvedNationSlot = static_cast<short>(encodedNationSlot - 100);
        } else {
          resolvedNationSlot = terrainDescriptor->nationSlot;
        }

        if (!g_pDiplomacyTurnStateManager->AreAtWar(nationSlot, resolvedNationSlot)) {
          terrainDescriptor = g_apTerrainTypeDescriptorTable[targetClass];
          encodedNationSlot = terrainDescriptor->encodedNationSlot;
          if (encodedNationSlot >= 200) {
            resolvedNationSlot = static_cast<short>(encodedNationSlot - 200);
          } else if (encodedNationSlot >= 100) {
            resolvedNationSlot = static_cast<short>(encodedNationSlot - 100);
          } else {
            resolvedNationSlot = terrainDescriptor->nationSlot;
          }
          SetDiplomacyPolicyTo(resolvedNationSlot, kDiplomacyProposalDeclareWar);
        }
      }

      if (diplomacyEligibility != 0) {
        SetGrantPolicyTo(targetClass, -1);
      }
      break;
    }

    case 5:
      if (CanAfford(500)) {
        AddToTreasury(0xFFFFFE0C);
      } else {
        shouldApply = false;
      }
      break;

    case 6:
      if (CanAfford(5000)) {
        AddToTreasury(0xFFFFEC78);
      } else {
        shouldApply = false;
      }
      break;

    default:
      break;
    }

  if (shouldApply) {
    diplomacyPolicyByNation[targetClass] = policyCode;
  }
  if (diplomacyEligibility != 0) {
    g_pHelpMgr->DiplomacyMsg(static_cast<int>(policyCode), static_cast<int>(targetClass),
                             shouldApply);
  }
  return shouldApply;
}

// FUNCTION: IMPERIALISM 0x004de2b0
void TGreatPower::SetDiplomacyPolicies() {}

// FUNCTION: IMPERIALISM 0x004de2d0
void TGreatPower::ResetPolicies(void) {
  const unsigned short kResetValue = 0xFFFF;
  const unsigned short kRecurringGrantMask = 0x4000;

  int targetNation = 0;
  while (static_cast<short>(targetNation) < kNationSlotCount) {
    diplomacyPolicyByNation[targetNation] = static_cast<short>(kResetValue);

    unsigned short grantEntry = static_cast<unsigned short>(diplomacyGrantByNation[targetNation]);
    diplomacyGrantByNation[targetNation] = static_cast<short>(kResetValue);
    if (grantEntry != kResetValue && (grantEntry & kRecurringGrantMask) != 0) {
      SetGrantPolicyTo(targetNation, grantEntry);
    }

    ++targetNation;
  }
}

// FUNCTION: IMPERIALISM 0x004de340
bool TGreatPower::SetGrantPolicyTo(int targetNationArg, int grantValue) {
  const unsigned short kGrantClear = 0xFFFF;
  const unsigned short kGrantMask = 0x3FFF;
  const short kInfluenceAlertThreshold = 0x00FA;

  short targetNation = targetNationArg;
  int targetIndex = targetNation;
  unsigned short oldGrantRaw = static_cast<unsigned short>(diplomacyGrantByNation[targetIndex]);
  unsigned short newGrantRaw = grantValue;
  bool accepted = true;

  if (newGrantRaw != oldGrantRaw) {
    if (newGrantRaw != kGrantClear && !CanAffordGrantTo(targetNation, newGrantRaw)) {
      accepted = false;
    } else {
      if (oldGrantRaw != kGrantClear) {
        int oldGrantValue = static_cast<short>(oldGrantRaw & kGrantMask);
        grantTotalCost -= oldGrantValue;
        AddToTreasury(oldGrantValue);
      }

      if (newGrantRaw != kGrantClear) {
        int newGrantValue = static_cast<short>(newGrantRaw & kGrantMask);
        grantTotalCost += newGrantValue;
        AddToTreasury(-newGrantValue);
      }

      diplomacyGrantByNation[targetIndex] = static_cast<short>(newGrantRaw);
    }
  }

  if (diplomacyEligibility != 0) {
    g_pHelpMgr->DiplomacyMsg(static_cast<short>(newGrantRaw), static_cast<int>(targetNation),
                             accepted ? 1 : 0);

    if (accepted && newGrantRaw != kGrantClear && targetNation > 6) {
      bool shouldDispatchAlert = false;
      int majorNation = 0;
      while (majorNation < kMajorNationCount) {
        if (majorNation != nationSlot) {
          short relationValue =
              g_pDiplomacyTurnStateManager
                  ->relationStandingScores[majorNation * kNationSlotCount + targetIndex];
          if (relationValue >= kInfluenceAlertThreshold) {
            shouldDispatchAlert = true;
            break;
          }
        }
        ++majorNation;
      }

      if (shouldDispatchAlert) {
        CString alertHeaderRef;
        CString alertTextRef;
        g_pSimMgr->GetString(0x2753, 0x44, &alertHeaderRef);
        g_pSimMgr->GetString(0x2753, 0x45, &alertTextRef);
        g_pViewMgr->ModalMessage(5, alertHeaderRef, alertTextRef, g_ptGreatPowerModalMessage, 0, 0);
      }
    }
  }
  return accepted;
}

// FUNCTION: IMPERIALISM 0x004de5e0
void TGreatPower::GiveGrantTo(int targetNationSlot) {
  short targetNation = targetNationSlot;
  short grantValue = static_cast<short>(
      static_cast<unsigned short>(diplomacyGrantByNation[targetNation]) & 0x3FFF);
  if (grantValue <= 0) {
    return;
  }

  g_apTerrainTypeDescriptorTable[targetNation]->AddToTreasury(grantValue);

  grantTotalCost -= grantValue;

  if (g_pDiplomacyTurnStateManager->GetEmbassyStatus(targetNation, nationSlot) != 2) {
    return;
  }

  int sourceNation = nationSlot;
  int relationCode = static_cast<int>(
      g_pDiplomacyTurnStateManager
          ->relationStandingScores[(sourceNation)*kNationSlotCount + (targetNation)]);
  int relationDelta;
  switch (grantValue) {
  case 1000:
    relationDelta = 2;
    break;
  case 3000:
    relationDelta = 4;
    break;
  case 5000:
    relationDelta = 6;
    break;
  case 10000:
    relationDelta = 10;
    break;
  default:
    relationDelta = 0;
    break;
  }
  g_pDiplomacyTurnStateManager->SetRelationship(sourceNation, targetNation,
                                                relationCode + relationDelta);
}

// FUNCTION: IMPERIALISM 0x004de700
bool TGreatPower::CanAffordGrantTo(NationSlot targetNationSlot, unsigned short proposedGrantEntry) {
  int proposedGrantValue = static_cast<short>(proposedGrantEntry & 0x3FFF);
  if (proposedGrantValue < 0) {
    return true;
  }

  short currentGrantEntry = diplomacyGrantByNation[targetNationSlot];
  int currentGrant = 0;
  if (currentGrantEntry > 0) {
    currentGrant = static_cast<short>(currentGrantEntry & 0x3FFF);
  }

  int availableBudget = ComputeAvailableDiplomacyBudget();
  int remainingBudget = currentGrant - proposedGrantValue + availableBudget;
  bool canAfford = static_cast<char>(remainingBudget >= 0);
  return canAfford;
}

// FUNCTION: IMPERIALISM 0x004de790
bool TGreatPower::CanAfford(short additionalCost) {
  int availableBudget = ComputeAvailableDiplomacyBudget();
  int remainingBudget = availableBudget - grantTotalCost - static_cast<int>(additionalCost);
  bool canAfford = static_cast<char>(remainingBudget >= 0);
  return canAfford;
}

// FUNCTION: IMPERIALISM 0x004de7e0
void TGreatPower::FinishDiplomacyPhase(void) {
  if (city != 0 && foreignMinister != 0) {
    foreignMinister->FinishDiplomacyPhase();
  }
}

// FUNCTION: IMPERIALISM 0x004de810
void TGreatPower::ClearCivilianOrders(void) {
  int remaining = trackedObjectList->GetCount();
  if (remaining != 0) {
    do {
      TUnit* order = static_cast<TUnit*>(trackedObjectList->GetEntryByOrdinal(remaining));
      order->Vaporize();
      order->Free();
      --remaining;
    } while (remaining != 0);
  }
}

// FUNCTION: IMPERIALISM 0x004de860
void TGreatPower::BecomeProtectorateOf(int targetNationSlot) {
  const int kResetDiplomacyLevel = 100;
  const int kResetPolicyCode = -1;
  const DiplomacyRelationship kResetRelationship = kDiplomacyRelationshipWar;
  const int kDipFlagPolicy = 0x31;

  g_pNewsMgr->AddTreatyEvent(kInterNationEventNationTransferred, this->nationSlot, 7, false);
  g_pDiplomacyTurnStateManager->RebuildMinorNationDispositionLookupTables(this->nationSlot);

  encodedNationSlot = static_cast<short>(targetNationSlot + 100);

  int nationSlot;
  for (nationSlot = 0; nationSlot < kNationSlotCount; ++nationSlot) {
    if (g_pSimMgr->ReallyInTheGame(nationSlot) && nationSlot != this->nationSlot &&
        nationSlot != targetNationSlot) {
      g_apTerrainTypeDescriptorTable[nationSlot]->NewStatusFor(this->nationSlot,
                                                               kResetDiplomacyLevel);
    }
  }

  g_pDiplomacyTurnStateManager->ResetTerrainAdjacencyMatrixRowAndSymmetricLink(this->nationSlot);

  treasuryValue = 0;

  if (foreignMinister != 0) {
    foreignMinister->Free();
    foreignMinister = 0;
  }
  if (interiorMinister != 0) {
    interiorMinister->Free();
    interiorMinister = 0;
  }
  if (defenseMinister != 0) {
    defenseMinister->Free();
    defenseMinister = 0;
  }

  availableMerchantCapacity = 0;
  merchantCapacity = 0;
  transportCapacity = 0;
  reservedTransportCapacity = 0;
  grantTotalCost = 0;
  unfilledTradeOfferCount = 0;

  unsigned char* enemyFlags = this->enemyFlags;
  short* tradePolicyByNation = this->tradePolicyByNation;

  int idx;
  for (idx = 0; idx < kNationSlotCount; ++idx) {
    diplomacyPolicyByNation[idx] = -1;
    diplomacyGrantByNation[idx] = -1;
    enemyFlags[idx] = 0;
    tradePolicyByNation[idx] = 100;
  }

  for (idx = 0; idx < kNationSlotCount; ++idx) {
    needCurrentByType[idx] = 0;
    needTargetByType[idx] = 0;
    relationDeltaCurrent[idx] = 0;
    purchasedItemsByResource[idx] = 0;
    itemPotentials[idx] = 0;
    unfilledTradeTurnCountsByResource[idx] = 0;
    transportedItemsByResource[idx] = 0;
    rememberedTradeOffersByResource[idx] = 0;
    int col;
    for (col = 0; col < kAidAllocationRowCount; ++col) {
      int matrixIndex = col * kAidAllocationColumnCount + idx;
      aidAllocationMatrix[matrixIndex] = 0;
    }
  }

  budgetPoolBase = 0;
  budgetPoolDelta = 0;

  if (proposalQueue != 0) {
    proposalQueue->DeleteAll();
  }
  if (turnEventQueue != 0) {
    turnEventQueue->DeleteAll();
  }

  InitializeDealBook();

  if (city != 0) {
    city->Free();
  }
  city = 0;

  ClearCivilianOrders();

  for (nationSlot = 0; nationSlot < kMajorNationCount; ++nationSlot) {
    if (nationSlot != this->nationSlot && g_pSimMgr->ReallyInTheGame(nationSlot)) {
      g_pDiplomacyTurnStateManager->SetTreatyStatus(this->nationSlot, nationSlot,
                                                    kResetRelationship, 0);
      g_pDiplomacyTurnStateManager->SetRelationship(this->nationSlot, nationSlot, kDipFlagPolicy);
      TGreatPower* nationState = g_apNationStates[nationSlot];
      if (nationState->diplomacyEligibility == 0) {
        nationState->AddNoticeFrom(this->nationSlot, kDiplomacyProposalDeclareWar);
      }
      SetTradePolicyTo(static_cast<NationSlot>(nationSlot), kResetDiplomacyLevel);
      SetGrantPolicyTo(nationSlot, kResetPolicyCode);
    }
  }

  int secondarySlot;
  for (secondarySlot = kMajorNationCount; secondarySlot < kNationSlotCount; ++secondarySlot) {
    TMinor* secondaryState = g_apSecondaryNationStateSlots[secondarySlot];
    bool directReset = true;
    short encodedOwnerNation = secondaryState->encodedNationSlot;
    if (encodedOwnerNation >= 200) {
      short ownerNation = secondaryState->DecodeOwnerNationSlot();
      directReset = ownerNation == this->nationSlot;
    }

    if (!directReset) {
      g_pDiplomacyTurnStateManager->SetTreatyStatus(this->nationSlot, secondarySlot,
                                                    kResetRelationship, 0);
      g_pDiplomacyTurnStateManager->SetRelationship(this->nationSlot, secondarySlot,
                                                    kDipFlagPolicy);
    } else {
      g_pDiplomacyTurnStateManager->SetRelationship(this->nationSlot, secondarySlot, 0x6e);
      g_pDiplomacyTurnStateManager->SetNationPairDiplomacyRelationCodeFinal(
          this->nationSlot, secondarySlot, kDiplomacyRelationshipPeace);
    }

    SetTradePolicyTo(static_cast<NationSlot>(secondarySlot), kResetDiplomacyLevel);
    SetGrantPolicyTo(secondarySlot, kResetPolicyCode);

    if (g_apTerrainTypeDescriptorTable[secondarySlot] != 0) {
      secondaryState->SetTradePolicyTo(this->nationSlot, kResetDiplomacyLevel);
    }
  }

  g_pNavyOrderManager->RemoveOrdersByNationFromPrimarySecondaryAndTaskForceLists(this->nationSlot);
  g_pGlobalMapState->ApplyJoinEmpireMode0GlobalDiplomacyReset(this->nationSlot);

  if (g_pSimMgr->multiplayerSessionRole != kSessionRoleStandalone) {
    g_pGameFlowState->SendGameControl(kControlTagName, this->nationSlot, 0xfffffffd);
  }
}

// FUNCTION: IMPERIALISM 0x004deca0
void TGreatPower::ImproveTradePolicyTo(NationSlot nationSlot) {
  short* tradePolicy = &tradePolicyByNation[nationSlot];
  switch (*tradePolicy) {
  case 0x4b:
    if (treasuryValue > 10000) {
      *tradePolicy = 0x32;
    }
    break;
  case 0x5a:
    *tradePolicy = 0x4b;
    return;
  case 0x5f:
    *tradePolicy = 0x5a;
    return;
  case 100:
    *tradePolicy = 0x5f;
    return;
  }
}

// FUNCTION: IMPERIALISM 0x004dedf0
void TGreatPower::AddNoticeFrom(short sourceNation, short actionCode) {
  DiplomacyProposalCodeStorage proposalCode = static_cast<DiplomacyProposalCodeStorage>(actionCode);

  if (diplomacyEligibility != 0) {
    int packedCode = (static_cast<int>(static_cast<unsigned short>(sourceNation)) << 16) |
                     static_cast<unsigned short>(actionCode);
    turnEventQueue->Insert(&packedCode);

    NewsEvent payload;
    payload.marker0 = 1;
    payload.subjectNationMask = 1 << (static_cast<unsigned char>(this->nationSlot) & 0x1F);
    payload.marker8 = 1;
    payload.targetNationMask = 1 << (static_cast<unsigned char>(sourceNation) & 0x1F);

    bool immediateDispatch = IsRemote();
    if (!immediateDispatch) {
      g_pNewsMgr->AddEvent(static_cast<int>(this->nationSlot), &payload, false);
    } else {
      g_pGameFlowState->SendNewsEvent(static_cast<int>(this->nationSlot), &payload);
    }
  }

  TDiplomacyMgr* diplomacyState = g_pDiplomacyTurnStateManager;
  int nationSlot = this->nationSlot;

  if (proposalCode == kDiplomacyProposalPeaceTreaty &&
      g_pDiplomacyTurnStateManager->IsGreatPower(sourceNation)) {
    for (int slot = 0; slot < kMajorNationCount; ++slot) {
      if (!g_pSimMgr->ReallyInTheGame(slot)) {
        continue;
      }

      DiplomacyRelationshipStorage relationship =
          g_pDiplomacyTurnStateManager->GetTreatyStatus(nationSlot, slot);
      if (relationship != kDiplomacyRelationshipAlliance) {
        continue;
      }

      if (g_pDiplomacyTurnStateManager->AreAtWar(slot, sourceNation)) {
        g_pDiplomacyTurnStateManager->TerminateAlliance(nationSlot, slot, 1);
      }
    }
  }

  if (proposalCode != kDiplomacyProposalAlliance) {
    return;
  }

  for (int slot = 0; slot < kMajorNationCount; ++slot) {
    if (!g_pSimMgr->ReallyInTheGame(slot)) {
      continue;
    }

    if (!g_pDiplomacyTurnStateManager->AreAtWar(slot, sourceNation)) {
      continue;
    }

    if (!g_pDiplomacyTurnStateManager->AreAtWar(slot, nationSlot)) {
      DeclareWarOn(slot, 2, sourceNation);
    }
  }
}

// FUNCTION: IMPERIALISM 0x004defd0
void TGreatPower::AddOfferFrom(NationSlot sourceNationSlot,
                               DiplomacyProposalCodeStorage proposalCode) {
  struct DiplomacyProposalRecord {
    DiplomacyProposalCodeStorage proposalCode;
    NationSlot sourceNationSlot;
  };

  DiplomacyProposalRecord proposalRecord;
  proposalRecord.proposalCode = proposalCode;
  proposalRecord.sourceNationSlot = sourceNationSlot;

  proposalQueue->Insert(&proposalRecord);
}

// FUNCTION: IMPERIALISM 0x004df010
void TGreatPower::AcceptOffer(short proposalIndex) {
  struct DiplomacyProposalRecord {
    DiplomacyProposalCodeStorage proposalCode;
    NationSlot sourceNationSlot;
  };

  CString tmp0;
  CString tmp1;
  CString tmp2;

  DiplomacyProposalRecord* proposal = static_cast<DiplomacyProposalRecord*>(
      proposalQueue->GetPtrListEntryByOneBasedIndex(proposalIndex));

  switch (proposal->proposalCode) {
  case kDiplomacyProposalJoinEmpire:
    ChangeMaster(static_cast<int>(proposal->sourceNationSlot), 1);
    g_pNewsMgr->AddTreatyEvent(kInterNationEventJoinEmpireAccepted, this->nationSlot,
                               static_cast<int>(proposal->sourceNationSlot), false);
    break;

  case kDiplomacyProposalAlliance: {
    g_pDiplomacyTurnStateManager->SetNationPairDiplomacyRelationCodeFinal(
        this->nationSlot, proposal->sourceNationSlot, kDiplomacyRelationshipAlliance);
    g_pNewsMgr->AddTreatyEvent(kInterNationEventAllianceAccepted, this->nationSlot,
                               static_cast<int>(proposal->sourceNationSlot), false);
    for (int nationSlot = 0; nationSlot < kMajorNationCount; ++nationSlot) {
      if (g_pDiplomacyTurnStateManager->AreAtWar(nationSlot,
                                                 static_cast<int>(proposal->sourceNationSlot)) &&
          !g_pDiplomacyTurnStateManager->AreAtWar(this->nationSlot, nationSlot)) {
        DeclareWarOn(nationSlot, kDiplomacyRelationshipAlliance,
                     static_cast<int>(proposal->sourceNationSlot));
      }
    }
    break;
  }

  case kDiplomacyProposalNonAggressionPact:
    g_pDiplomacyTurnStateManager->SetNationPairDiplomacyRelationCodeFinal(
        this->nationSlot, proposal->sourceNationSlot, kDiplomacyRelationshipNonAggressionPact);
    g_pNewsMgr->AddTreatyEvent(kInterNationEventNonAggressionPactAccepted, this->nationSlot,
                               static_cast<int>(proposal->sourceNationSlot), false);
    break;

  case kDiplomacyProposalPeaceTreaty: {
    g_pDiplomacyTurnStateManager->SetNationPairDiplomacyRelationCodeFinal(
        this->nationSlot, proposal->sourceNationSlot, kDiplomacyRelationshipPeace);
    g_pNewsMgr->AddTreatyEvent(kInterNationEventPeaceTreatyAccepted, this->nationSlot,
                               static_cast<int>(proposal->sourceNationSlot), false);
    if (g_pDiplomacyTurnStateManager->IsGreatPower(proposal->sourceNationSlot)) {
      for (int nationSlot = 0; nationSlot < kMajorNationCount; ++nationSlot) {
        if (g_pSimMgr->ReallyInTheGame(nationSlot) &&
            g_pDiplomacyTurnStateManager->GetTreatyStatus(this->nationSlot, nationSlot) ==
                kDiplomacyRelationshipAlliance &&
            g_pDiplomacyTurnStateManager->AreAtWar(nationSlot,
                                                   static_cast<int>(proposal->sourceNationSlot))) {
          g_pDiplomacyTurnStateManager->TerminateAlliance(this->nationSlot, nationSlot, 1);
        }
      }
    }
    break;
  }

  case kDiplomacyProposalJoinEmpireWithWarEntanglements: {
    g_apTerrainTypeDescriptorTable[static_cast<int>(proposal->sourceNationSlot)]->ChangeMaster(
        this->nationSlot, 1);
    g_pNewsMgr->AddTreatyEvent(kInterNationEventJoinEmpireAccepted,
                               static_cast<int>(proposal->sourceNationSlot), this->nationSlot,
                               false);
    break;
  }

  default:
    break;
  }

  if (g_pDiplomacyTurnStateManager->IsGreatPower(proposal->sourceNationSlot) &&
      g_pSimMgr->ReallyInTheGame(static_cast<int>(proposal->sourceNationSlot))) {
    g_apNationStates[static_cast<int>(proposal->sourceNationSlot)]->AddNoticeFrom(
        this->nationSlot, proposal->proposalCode);
  }
}

// FUNCTION: IMPERIALISM 0x004df370
void TGreatPower::RejectOffer(short proposalQueueIndex) {
  TPtrList* queue = proposalQueue;
  int queueOrdinal = proposalQueueIndex;
  if (queueOrdinal > queue->GetSize()) {
    return;
  }

  short* proposalEntry = static_cast<short*>(queue->GetPtrListEntryByOneBasedIndex(queueOrdinal));
  DiplomacyProposalCodeStorage proposalCode = proposalEntry[0];
  short targetNation = proposalEntry[1];

  TDiplomacyMgr* diplomacyManager = g_pDiplomacyTurnStateManager;
  if (diplomacyManager->IsGreatPower(targetNation)) {
    TGreatPower* nationState = g_apNationStates[targetNation];
    if (nationState != 0) {
      nationState->AddNoticeFrom(nationSlot, -proposalCode);
    }
  }

  switch (proposalCode) {
  case kDiplomacyProposalJoinEmpire:
    g_pNewsMgr->AddTreatyEvent(kInterNationEventJoinEmpireRejected, targetNation, nationSlot,
                               false);
    return;
  case kDiplomacyProposalAlliance:
    g_pNewsMgr->AddTreatyEvent(kInterNationEventAllianceRejected, targetNation, nationSlot, false);
    return;
  case kDiplomacyProposalNonAggressionPact:
    g_pNewsMgr->AddTreatyEvent(kInterNationEventNonAggressionPactRejected, targetNation, nationSlot,
                               false);
    return;
  case kDiplomacyProposalPeaceTreaty:
    g_pNewsMgr->AddTreatyEvent(kInterNationEventPeaceTreatyRejected, targetNation, nationSlot,
                               false);
    return;
  default:
    return;
  }
}

// FUNCTION: IMPERIALISM 0x004df4b0
bool TGreatPower::IsDiplomacyProposalAllowedForRelationship(
    DiplomacyProposalCodeStorage proposalCode, int targetNation) {
  bool allowed = false;
  DiplomacyRelationshipStorage relationship =
      g_pDiplomacyTurnStateManager->GetTreatyStatus(nationSlot, targetNation);
  switch (relationship) {
  case kDiplomacyRelationshipAlliance:
    if (proposalCode != kDiplomacyProposalPeaceTreaty &&
        proposalCode != kDiplomacyProposalNonAggressionPact &&
        proposalCode != kDiplomacyProposalAlliance) {
      return true;
    }
    break;
  case kDiplomacyRelationshipNonAggressionPact:
    if (proposalCode != kDiplomacyProposalPeaceTreaty &&
        proposalCode != kDiplomacyProposalNonAggressionPact) {
      return true;
    }
    break;
  case kDiplomacyRelationshipPeace:
    if (proposalCode != kDiplomacyProposalPeaceTreaty) {
      return true;
    }
    break;
  case kDiplomacyRelationshipWar:
    if (proposalCode == kDiplomacyProposalPeaceTreaty) {
      allowed = true;
    }
    break;
  }
  return allowed;
}

// FUNCTION: IMPERIALISM 0x004df580
void TGreatPower::InitializeDiplomacyOffers(void) {
  proposalQueue->DeleteAll();
}

// FUNCTION: IMPERIALISM 0x004df5a0
void TGreatPower::InitializeDiplomacyNotices(void) {
  turnEventQueue->DeleteAll();
}

// FUNCTION: IMPERIALISM 0x004df5c0
void TGreatPower::ShowNewspaperForRecordNation(void) {
  TViewMgr* uiRuntimeContext = g_pViewMgr;
  uiRuntimeContext->DispatchTurnEvent(EncodeTurnEventCode(kTurnEventNewspaperStatus), nationSlot);
}

// FUNCTION: IMPERIALISM 0x004df5f0
void TGreatPower::ReplyToDiplomacyOffers(void) {
  CString proposalSummaryRef;
  CString proposalScratchRef;
  int proposalIndex = 0;
  int queueIndex = 0;

  TPtrList* queue = proposalQueue;
  short proposalCount = queue->GetSize();
  if (proposalCount != 0 && proposalCount > 0) {
    proposalIndex = 1;
    queueIndex = 1;
    TDiplomacyMgr* diplomacyManager = g_pDiplomacyTurnStateManager;
    TViewMgr* uiRuntimeContext = g_pViewMgr;

    do {
      short* proposalEntry = static_cast<short*>(queue->GetPtrListEntryByOneBasedIndex(queueIndex));
      DiplomacyProposalCodeStorage proposalCode = proposalEntry[0];
      short targetNation = proposalEntry[1];
      bool shouldApplyProposal;

      if (!IsTurnFlowCooldownActiveAndResetExpiredState()) {
        if (diplomacyPolicyByNation[targetNation] == proposalCode) {
          shouldApplyProposal = 1;
        } else if (proposalCode == kDiplomacyProposalAlliance) {
          if (g_pDiplomacyTurnStateManager->GetTreatyStatus(nationSlot, targetNation) !=
              kDiplomacyRelationshipPeace) {
            shouldApplyProposal = 0;
          } else {
            shouldApplyProposal = uiRuntimeContext->MakeDiplomacyOfferDialog(
                nationSlot, targetNation, kDiplomacyProposalAlliance);
          }
        } else {
          shouldApplyProposal =
              uiRuntimeContext->MakeDiplomacyOfferDialog(nationSlot, targetNation, proposalCode);
        }

        if (shouldApplyProposal == 0) {
          RejectOffer(proposalIndex);
        } else if (proposalCode == kDiplomacyProposalJoinEmpireWithWarEntanglements) {
          for (int checkNation = 0; checkNation < kMajorNationCount; ++checkNation) {
            if (g_pDiplomacyTurnStateManager->AreAtWar(targetNation, checkNation) &&
                !g_pDiplomacyTurnStateManager->AreAtWar(nationSlot, checkNation)) {
              DeclareWarOn(checkNation, kDiplomacyProposalJoinEmpireWithWarEntanglements,
                           targetNation);
            }
          }
        } else {
          AcceptOffer(proposalIndex);
        }
      } else {
        RejectOffer(proposalIndex);
      }

      ++proposalIndex;
      ++queueIndex;
    } while (static_cast<short>(proposalIndex) <= proposalCount);
  }

  ResetPolicies();
}

// FUNCTION: IMPERIALISM 0x004df810
void TGreatPower::ApplyScenarioRelationPresetAndSpawnFrogCity(TCity* mgr) {
  TPopulationMgr* notifySink = mgr->productionSummary;
  int presetLevel;
  if (diplomacyEligibility == 0) {
    presetLevel = 2;
  } else {
    presetLevel = g_pSimMgr->difficultyLevel;
  }
  const short* presetRow = g_Rebuild_Primary_Nation_Value[presetLevel];
  for (int needIndex = 0; needIndex < 0x17; ++needIndex) {
    mgr->stockByType[static_cast<short>(needIndex)] = presetRow[needIndex];
    mgr->VerifyStocks();
  }
  mgr->productionAccum[8] += 999 - mgr->productionOrderTable[8];
  mgr->productionOrderTable[8] = 999;
  mgr->productionAccum[10] += 999 - mgr->productionOrderTable[10];
  mgr->productionOrderTable[10] = 999;
  mgr->productionAccum[9] += 999 - mgr->productionOrderTable[9];
  mgr->productionOrderTable[9] = 999;
  mgr->productionAccum[7] += 999 - mgr->productionOrderTable[7];
  mgr->productionOrderTable[7] = 999;
  mgr->productionAccum[14] += 999 - mgr->productionOrderTable[14];
  mgr->productionOrderTable[14] = 999;
  mgr->productionAccum[13] += 999 - mgr->productionOrderTable[13];
  mgr->productionOrderTable[13] = 999;
  if (presetLevel == 0) {
    notifySink->SetPopulation(2, 3, 2);
  } else {
    notifySink->SetPopulation(4, 2, 1);
  }
  TSimMgr* simMgr = g_pSimMgr;
  if (diplomacyEligibility == 0 || simMgr->difficultyLevel < kDifficultyNormal ||
      simMgr->scenarioMapIndexPlusOne != 0) {
    if (!IsRemote() || simMgr->scenarioMapIndexPlusOne != 0) {
      CreateFrogCityAtHomeRegionAndAttach(mgr);
      return;
    }
  }
  CreateFrogCityTownMarkerAndAttach(mgr);
}

// FUNCTION: IMPERIALISM 0x004dfa20
void TGreatPower::CreateFrogCityTownMarkerAndAttach(void* receiver) {
  TTown* marker = new TTown();
  marker->ITown("Frog City", 0, true, nationSlot);
  static_cast<TCity*>(receiver)->SetSelectedTownMarker(marker);
  marker->activeFlag = true;
  townMarkerList->AddTail(marker);
}

// FUNCTION: IMPERIALISM 0x004dfae0
void TGreatPower::CreateFrogCityAtHomeRegionAndAttach(void* receiver) {
  TSimMgr* simMgr = g_pSimMgr;
  int homeTileIndex = -1;
  if (simMgr->scenarioMapIndexPlusOne == 0) {
    homeTileIndex = interiorMinister->SelectCitySite();
  } else {
    TTerrainStateRecord* terrainTable = g_pGlobalMapState->terrainStateTable;
    for (int tileIndex = 0; tileIndex < kStrategicTileCount; ++tileIndex) {
      if (static_cast<short>(terrainTable[static_cast<short>(tileIndex)].ownerNationTag) ==
              nationSlot &&
          (terrainTable[static_cast<short>(tileIndex)].activeFlags & 1) != 0) {
        homeTileIndex = tileIndex;
      }
    }
    if (static_cast<short>(homeTileIndex) == -1) {
      CString message;
      {
        CString prefix("GP#");
        message = prefix;
      }
      message += static_cast<char>('0' + static_cast<char>(nationSlot));
      message += " is missing capitol site";
      g_pViewMgr->ModalMessage(message, g_ptGreatPowerModalMessage);
    }
  }
  this->homeTileIndex = static_cast<short>(homeTileIndex);
  TTown* marker = new TTown();
  marker->ITown("FrogCity", homeTileIndex, true, nationSlot);
  static_cast<TCity*>(receiver)->SetSelectedTownMarker(marker);
  marker->activeFlag = true;
  townMarkerList->AddTail(marker);
  g_pGlobalMapState->PlaceCity(marker->tileIndex, nationSlot);
  if (diplomacyEligibility == 0 && interiorMinister != 0) {
    interiorMinister->MakeNewCity(static_cast<TCity*>(receiver));
  }
}

// Retail begins with TEST ESI,ESI and preserves this retail null-this path.
IMPERIALISM_BEGIN_RETAIL_NULL_THIS_CHECK
// FUNCTION: IMPERIALISM 0x004dfd30
void TGreatPower::PlaceCity(short homeTileIndex, char* cityName) {
  TCity* city = this ? this->city : 0;
  TTown* homeTown = city->homeTownMarker;

  if (homeTileIndex != -1) {
    homeTown->tileIndex = homeTileIndex;
  }

  short regionIndex;
  if (city->homeTownMarker) {
    regionIndex = city->homeTownMarker->tileIndex;
  } else {
    regionIndex = 1;
  }
  this->homeTileIndex = regionIndex;

  if (cityName) {
    CString nameStr(cityName);
    short cityRecordIndex = g_pGlobalMapState->terrainStateTable[regionIndex].cityRecordIndex;
    g_pGlobalMapState->SetProvinceName(cityRecordIndex, &nameStr);
    homeTown->SetName(nameStr);
  }

  RebuildNationResourceYieldCountersAndDevelopmentTargets();

  if (interiorMinister) {
    interiorMinister->SetCityPolicies();
  }

  if (g_pSimMgr->scenarioMapIndexPlusOne == 0) {
    short result1 = g_pGlobalMapState->FindReachableRecruitSpawnTileWithVisitedReset(
        this->homeTileIndex, false);
    TCivUnit* civ1 = new TCivUnit();
    civ1->ICivUnit(kCivilianUnitProspector, result1, nationSlot);

    short result2 =
        g_pGlobalMapState->FindReachableRecruitSpawnTileWithVisitedReset(this->homeTileIndex, true);
    TCivUnit* civ2 = new TCivUnit();
    civ2->ICivUnit(kCivilianUnitEngineer, result2, nationSlot);

    city->orderCountByType[1] += 2;

    if (g_pSimMgr->difficultyLevel == kDifficultyIntroductory && diplomacyEligibility) {
      city->orderCountByType[1] += 6;

      short result3 = g_pGlobalMapState->FindReachableRecruitSpawnTileWithVisitedReset(
          this->homeTileIndex, false);
      TCivUnit* civ3 = new TCivUnit();
      civ3->ICivUnit(kCivilianUnitProspector, result3, nationSlot);

      short result4 = g_pGlobalMapState->FindReachableRecruitSpawnTileWithVisitedReset(
          this->homeTileIndex, false);
      TCivUnit* civ4 = new TCivUnit();
      civ4->ICivUnit(kCivilianUnitMiner, result4, nationSlot);

      short result5 = g_pGlobalMapState->FindReachableRecruitSpawnTileWithVisitedReset(
          this->homeTileIndex, false);
      TCivUnit* civ5 = new TCivUnit();
      civ5->ICivUnit(kCivilianUnitFarmer, result5, nationSlot);
    }
  }

  g_pDiplomacyTurnStateManager->SetRelationship(nationSlot, nationSlot, 0x100);

  InitialMilitia();
}
IMPERIALISM_END_RETAIL_NULL_THIS_CHECK

// FUNCTION: IMPERIALISM 0x004e00d0
void TGreatPower::DispatchGreatPowerQuarterlyStatusMessageLevel2(CString* message) {
  int quarterTick = g_pSimMgr->economicTurn;
  if (static_cast<short>(quarterTick / 4) == 0) {
    return;
  }
  g_pViewMgr->ModalMessage(*message, g_ptGreatPowerModalMessage, 2, 0);
}

// FUNCTION: IMPERIALISM 0x004e0140
void TGreatPower::DispatchGreatPowerQuarterlyStatusMessageLevel1(CString* message) {
  int quarterTick = g_pSimMgr->economicTurn;
  if (static_cast<short>(quarterTick / 4) == 0) {
    return;
  }
  g_pViewMgr->ModalMessage(*message, g_ptGreatPowerModalMessage, 1, 0);
}

// FUNCTION: IMPERIALISM 0x004e01b0
void TGreatPower::DispatchGreatPowerQuarterlyStatusMessageLevel0(CString* message) {
  int quarterTick = g_pSimMgr->economicTurn;
  if (static_cast<short>(quarterTick / 4) == 0) {
    return;
  }
  g_pViewMgr->ModalMessage(*message, g_ptGreatPowerModalMessage, 0, 0);
}

// FUNCTION: IMPERIALISM 0x004e0220
void TGreatPower::ContinueCivilianOrders(void) {
  CIterator orderIter(trackedObjectList);
  for (TUnit* order = static_cast<TUnit*>(orderIter.Reset()); orderIter.More();
       order = static_cast<TUnit*>(orderIter.Advance())) {
    order->ContinueOrders();
  }
}

// FUNCTION: IMPERIALISM 0x004e0290
void TGreatPower::SortTrackedOrdersByTypePriority(void) {
  short orderCount = trackedObjectList->GetCount();
  int total = orderCount;
  for (int outer = 1; outer < total; ++outer) {
    void* entryOuter = trackedObjectList->GetEntryByOrdinal(outer);
    short outerPriority =
        g_anTrackedOrderSortPriorityByType[static_cast<TUnit*>(entryOuter)->orderType];
    for (int inner = outer + 1; inner <= total; ++inner) {
      void* entryInner = trackedObjectList->GetEntryByOrdinal(inner);
      short innerPriority =
          g_anTrackedOrderSortPriorityByType[static_cast<TUnit*>(entryInner)->orderType];
      if (innerPriority < outerPriority) {
        trackedObjectList->SetAtOrdinal(outer, &entryInner, 1);
        trackedObjectList->SetAtOrdinal(inner, &entryOuter, 1);
        entryOuter = entryInner;
        outerPriority = innerPriority;
      }
    }
  }
}

// FUNCTION: IMPERIALISM 0x004e03a0
void TGreatPower::MoveCivilians(void) {
  ContinueCivilianOrders();
  SortTrackedOrdersByTypePriority();
}

// FUNCTION: IMPERIALISM 0x004e03d0
void TGreatPower::MoveArmy(void) {
  armyTransportRemaining = transportCapacity / 5;
}

// FUNCTION: IMPERIALISM 0x004e0400
bool TGreatPower::HasEnemy() {
  return false;
}

// FUNCTION: IMPERIALISM 0x004e0420
void TGreatPower::SetEnemy(int targetNation) {}

// FUNCTION: IMPERIALISM 0x004e0440
void TGreatPower::StopBeingEnemiesWith(int targetNation) {}

// FUNCTION: IMPERIALISM 0x004e0460
int TGreatPower::GetNavalForceIn(TZone* zone) {
  int sum = 0;
  for (TShip* node = TShip::GetFirst(); node != 0; node = node->next) {
    if (node->nation == nationSlot && node->location == zone) {
      sum += node->GetStudliness();
    }
  }
  return sum;
}

// FUNCTION: IMPERIALISM 0x004e04b0
int TGreatPower::SumNavyOrderPriorityForNation() {
  int sum = 0;
  for (TShip* node = TShip::GetFirst(); node != 0; node = node->next) {
    if (node->nation == nationSlot) {
      sum += node->GetStudliness();
    }
  }
  return sum;
}

// FUNCTION: IMPERIALISM 0x004e0500
int TGreatPower::GetArmsInNavy(void) {
  int prioritySum = 0;
  for (TShip* node = TShip::GetFirst(); node != 0; node = node->next) {
    if (node->nation == nationSlot) {
      prioritySum += GetIndustryActionCostWeightByResourceType(node->type);
    }
  }
  return prioritySum;
}

// FUNCTION: IMPERIALISM 0x004e0550
int TGreatPower::CountMapActionContextNodesWithNationBit(void) {
  int count = 0;
  TZone* node = g_pMapActionContextListHead;
  if (node != 0) {
    int nationSlot = this->nationSlot;
    unsigned char nationBit = 1;
    nationBit <<= nationSlot;
    do {
      if ((static_cast<unsigned char>(node->nationKeyMask) & nationBit) != 0) {
        ++count;
      }
      node = node->prev18;
    } while (node != 0);
  }
  return count;
}

// FUNCTION: IMPERIALISM 0x004e0590
double TGreatPower::GetWarNumber(void) {
  return g_afWarNumberByForeignMinister[foreignMinister->skillIndex] +
         g_afWarNumberByDefenseMinister[defenseMinister->skillIndex];
}

// FUNCTION: IMPERIALISM 0x004e05d0
double TGreatPower::GetSeekAllianceNumber(void) {
  return g_afSeekAllianceByDefenseMinister[defenseMinister->skillIndex] +
         g_afSeekAllianceByForeignMinister[foreignMinister->skillIndex];
}

// FUNCTION: IMPERIALISM 0x004e0610
double TGreatPower::GetAcceptAllianceNumber(void) {
  return g_afAcceptAllianceByDefenseMinister[defenseMinister->skillIndex] +
         g_afAcceptAllianceByForeignMinister[foreignMinister->skillIndex];
}

// FUNCTION: IMPERIALISM 0x004e0650
double TGreatPower::GetSeekPeaceNumber(void) {
  return g_afSeekPeaceByForeignMinister[foreignMinister->skillIndex] +
         g_afSeekPeaceByDefenseMinister[defenseMinister->skillIndex];
}

// FUNCTION: IMPERIALISM 0x004e0690
double TGreatPower::GetAcceptPeaceNumber(void) {
  return g_afAcceptPeaceByForeignMinister[foreignMinister->skillIndex] +
         g_afAcceptPeaceByDefenseMinister[defenseMinister->skillIndex];
}

// FUNCTION: IMPERIALISM 0x004e06d0
int TGreatPower::SumCommodityRecordAccumulatedValues(void) {
  TCity* province = city;
  int total = 0;
  if (province != 0) {
    total = province->orderSlots[12]->accumulatedValue +
            province->orderSlots[11]->accumulatedValue + province->orderSlots[9]->accumulatedValue +
            province->orderSlots[10]->accumulatedValue + province->orderSlots[8]->accumulatedValue;
  }
  return total;
}

// FUNCTION: IMPERIALISM 0x004e0740
int TGreatPower::GetBuildingCapacity(short buildingSlot) {
  if (city != 0) {
    return static_cast<short>(city->GetBuildingType(buildingSlot));
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x004e0770
short TGreatPower::ComputeNationRuntimeAdvisoryMetricCase6() {
  TCity* nationCity = city;
  if (nationCity != 0) {
    TPopulationMgr* summary = nationCity->productionSummary;
    TLaborPool* bucket = summary->productionSlots;
    short folded = bucket->highSkillCount * 2 + bucket->mediumSkillCount;
    folded *= 2 + bucket->lowSkillCount;
    return folded + summary->extraAt1e;
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x004e07b0
int TGreatPower::GetReinforcementPotential(void) {
  if (city == 0) {
    return 0;
  }
  TPopulationMgr* scenario = city->productionSummary;
  short scenarioCap = scenario->strength;
  short productionCap = scenario->productionSlots->lowSkillCount;
  if (scenarioCap < productionCap) {
    productionCap = scenarioCap;
  }
  int budget = productionCap;
  short metricCap = GetStockpile(kResourceArms);
  if (static_cast<int>(metricCap) <= budget) {
    budget = metricCap;
  }
  int armyPower = SumMilitaryUnitPowerWeightsForScore(militaryUnitList);
  if (armyPower / 2 <= budget) {
    budget = armyPower / 2;
  }
  return budget;
}

// FUNCTION: IMPERIALISM 0x004e0890
float TGreatPower::GetMilitaryPower(void) {
  int armyPower = SumMilitaryUnitPowerWeightsForScore(militaryUnitList);
  float armyPowerF = static_cast<float>(armyPower);
  float commitBudgetF = static_cast<float>(GetReinforcementPotential());
  int production = GetBuildingCapacity(3);
  int poweredCap = static_cast<int>(armyPowerF * g_Iterate_Linked_List_Value);
  int productionTerm = static_cast<int>(static_cast<float>(production));
  if (productionTerm >= poweredCap) {
    productionTerm = poweredCap;
  }
  return armyPowerF + commitBudgetF + static_cast<float>(productionTerm);
}

// FUNCTION: IMPERIALISM 0x004e09a0
float TGreatPower::GetTotalNavalForce(void) {
  TTechMgr* capabilityState = g_pTechMgr;
  int shipProduction;
  if (capabilityState->resourceTypeEnabled[0xb] != 0) {
    shipProduction = GetBuildingCapacity(2);
  } else if (capabilityState->resourceTypeEnabled[8] != 0) {
    shipProduction = (GetBuildingCapacity(4) + GetBuildingCapacity(2)) / 2;
  } else {
    shipProduction = GetBuildingCapacity(4);
  }
  float shipProductionF = static_cast<float>(shipProduction);
  float navyPriorityF = static_cast<float>(GetArmsInNavy());
  int navyPriorityInt = static_cast<int>(navyPriorityF);
  int productionTerm = static_cast<int>(shipProductionF);
  if (productionTerm >= navyPriorityInt) {
    productionTerm = navyPriorityInt;
  }
  float productionTermF = static_cast<float>(productionTerm);
  int fleetPower = SumMilitaryUnitPowerWeightsForScore(militaryUnitList);
  int priorityCap = static_cast<int>(navyPriorityF * g_Compute_City_Order_Value);
  if (priorityCap >= fleetPower) {
    priorityCap = fleetPower;
  }
  return static_cast<float>(priorityCap) + navyPriorityF + productionTermF;
}

// FUNCTION: IMPERIALISM 0x004e0b20
float TGreatPower::ComputeArmyScoreRatioVsNation(int targetNation) {
  float selfScore = GetMilitaryPower();
  float targetScore = g_apNationStates[targetNation]->GetMilitaryPower();
  float allySum = SumAlliedArmyScoreFactorsForScore(targetNation);
  float denominator = targetScore - allySum * (-0.25f);
  if (denominator == 0.0f) {
    return selfScore;
  }
  return selfScore / denominator;
}

// FUNCTION: IMPERIALISM 0x004e0c10
float TGreatPower::ComputeArmyScoreStandingRatioVsNation(int targetNation) {
  float selfScore = GetMilitaryPower();
  float targetScore = g_apNationStates[targetNation]->GetMilitaryPower();
  float allySum = SumAlliedArmyScoreFactorsForScore(targetNation);
  int yearTerm = GetClampedQuarterYearTermForScore();
  short* standingRow = GetRelationStandingRowForScore(nationSlot);
  float denominator =
      (static_cast<float>(standingRow[static_cast<short>(targetNation)]) - allySum * (-0.25f)) +
      targetScore;
  float numerator = (static_cast<float>(yearTerm) + selfScore) - (-90.0f);
  if (denominator == 0.0f) {
    return numerator;
  }
  return numerator / denominator;
}

// FUNCTION: IMPERIALISM 0x004e0d80
float TGreatPower::ComputeNavyScoreRatioVsNation(int targetNation) {
  float selfScore = GetTotalNavalForce();
  float targetScore = g_apNationStates[targetNation]->GetTotalNavalForce();
  float allySum = SumAlliedNavyScoreFactorsForScore(targetNation);
  float denominator = targetScore - allySum * (-0.25f);
  if (denominator == 0.0f) {
    return selfScore;
  }
  return selfScore / denominator;
}

// FUNCTION: IMPERIALISM 0x004e0e70
float TGreatPower::ComputeNavyScoreStandingRatioVsNation(int targetNation) {
  float selfScore = GetTotalNavalForce();
  float targetScore = g_apNationStates[targetNation]->GetTotalNavalForce();
  float allySum = SumAlliedNavyScoreFactorsForScore(targetNation);
  int yearTerm = GetClampedQuarterYearTermForScore();
  short* standingRow = GetRelationStandingRowForScore(nationSlot);
  float denominator =
      (static_cast<float>(standingRow[static_cast<short>(targetNation)]) - allySum * (-0.25f)) +
      targetScore;
  float numerator = (static_cast<float>(yearTerm) + selfScore) - (-90.0f);
  if (denominator == 0.0f) {
    return numerator;
  }
  return numerator / denominator;
}

// FUNCTION: IMPERIALISM 0x004e0fe0
float TGreatPower::ComputeArmyScoreRatioVsNationWithSecondary(int targetNation, int secondarySlot) {
  float selfScore = GetMilitaryPower();
  int secondaryPower = SumMilitaryUnitPowerWeightsForScore(
      g_apSecondaryNationStateSlots[secondarySlot]->militaryUnitList);
  float combinedScore = static_cast<float>(secondaryPower) + selfScore;
  bool borderLinked = g_pGlobalMapState->AreNationsBorderLinked(targetNation, secondarySlot);
  float targetScore;
  if (borderLinked != 0) {
    targetScore = g_apNationStates[targetNation]->GetMilitaryPower();
  } else {
    targetScore = g_apNationStates[targetNation]->GetTotalNavalForce();
  }
  float allySum = SumAlliedArmyScoreFactorsForScore(targetNation);
  float denominator = targetScore - allySum * (-0.25f);
  if (denominator == 0.0f) {
    return selfScore;
  }
  return selfScore / denominator;
}

// FUNCTION: IMPERIALISM 0x004e1170
float TGreatPower::ComputeArmyScoreStandingRatioVsNationPair(int targetNation, int partnerNation) {
  float selfScore = GetMilitaryPower();
  bool borderLinked = g_pGlobalMapState->AreNationsBorderLinked(targetNation, partnerNation);
  float targetScore;
  if (borderLinked != 0) {
    targetScore = g_apNationStates[targetNation]->GetMilitaryPower();
  } else {
    targetScore = g_apNationStates[targetNation]->GetTotalNavalForce();
  }
  float allySum = SumAlliedArmyScoreFactorsForScore(targetNation);
  short* standingRow = GetRelationStandingRowForScore(nationSlot);
  float denominator =
      (static_cast<float>(standingRow[static_cast<short>(targetNation)]) - allySum * (-0.25f)) +
      targetScore;
  if (denominator == 0.0f) {
    return static_cast<float>(standingRow[static_cast<short>(partnerNation)]) + selfScore;
  }
  return (static_cast<float>(standingRow[static_cast<short>(partnerNation)]) + selfScore) /
         denominator;
}

// FUNCTION: IMPERIALISM 0x004e1300
float TGreatPower::ComputeNavyScoreRatioVsNationWithSecondary(int targetNation, int secondarySlot) {
  float selfScore = GetTotalNavalForce();
  int secondaryPower = SumMilitaryUnitPowerWeightsForScore(
      g_apSecondaryNationStateSlots[secondarySlot]->militaryUnitList);
  float combinedScore = static_cast<float>(secondaryPower) + selfScore;
  bool borderLinked = g_pGlobalMapState->AreNationsBorderLinked(targetNation, secondarySlot);
  float targetScore;
  if (borderLinked != 0) {
    targetScore = g_apNationStates[targetNation]->GetMilitaryPower();
  } else {
    targetScore = g_apNationStates[targetNation]->GetTotalNavalForce();
  }
  float allySum = SumAlliedNavyScoreFactorsForScore(targetNation);
  float denominator = targetScore - allySum * (-0.25f);
  if (denominator == 0.0f) {
    return selfScore;
  }
  return selfScore / denominator;
}

// FUNCTION: IMPERIALISM 0x004e1490
float TGreatPower::ComputeNavyScoreStandingRatioVsNationPair(int targetNation, int partnerNation) {
  float selfScore = GetTotalNavalForce();
  bool borderLinked = g_pGlobalMapState->AreNationsBorderLinked(targetNation, partnerNation);
  float targetScore;
  if (borderLinked != 0) {
    targetScore = g_apNationStates[targetNation]->GetMilitaryPower();
  } else {
    targetScore = g_apNationStates[targetNation]->GetTotalNavalForce();
  }
  float allySum = SumAlliedNavyScoreFactorsForScore(targetNation);
  short* standingRow = GetRelationStandingRowForScore(nationSlot);
  float denominator =
      (static_cast<float>(standingRow[static_cast<short>(targetNation)]) - allySum * (-0.25f)) +
      targetScore;
  if (denominator == 0.0f) {
    return static_cast<float>(standingRow[static_cast<short>(partnerNation)]) + selfScore;
  }
  return (static_cast<float>(standingRow[static_cast<short>(partnerNation)]) + selfScore) /
         denominator;
}

// FUNCTION: IMPERIALISM 0x004e1620
float TGreatPower::ComputeArmyScoreRatioForNationPair(int nationA, int nationB, char swapRoles) {
  int opponentNation = nationA;
  int partnerNation = nationB;
  if (swapRoles != 0) {
    opponentNation = nationB;
    partnerNation = nationA;
  }
  float selfScore = GetMilitaryPower();
  float opponentScore = g_apNationStates[opponentNation]->GetMilitaryPower();
  float partnerScore = g_apNationStates[partnerNation]->GetMilitaryPower();
  float allySum = SumAlliedArmyScoreFactorsForScore(opponentNation);
  float denominator = opponentScore - allySum * (-0.25f);
  float numerator;
  if (swapRoles == 0) {
    numerator = selfScore - partnerScore * g_Compute_Advisory_Peer_LookupTable;
  } else {
    numerator = selfScore - partnerScore * (-0.25f);
  }
  if (denominator != 0.0f) {
    numerator = numerator / denominator;
  }
  return numerator;
}

// FUNCTION: IMPERIALISM 0x004e1750
float TGreatPower::ComputeArmyScoreStandingRatioForNationPair(int nationA, int nationB,
                                                              char swapRoles) {
  int opponentNation = nationA;
  int partnerNation = nationB;
  if (swapRoles != 0) {
    opponentNation = nationB;
    partnerNation = nationA;
  }
  float selfScore = GetMilitaryPower();
  float opponentScore = g_apNationStates[opponentNation]->GetMilitaryPower();
  float partnerScore = g_apNationStates[partnerNation]->GetMilitaryPower();
  float allySum = SumAlliedArmyScoreFactorsForScore(opponentNation);
  short* standingRow = GetRelationStandingRowForScore(nationSlot);
  float denominator =
      (static_cast<float>(standingRow[static_cast<short>(opponentNation)]) - allySum * (-0.25f)) +
      opponentScore;
  float numerator;
  if (swapRoles == 0) {
    numerator = (static_cast<float>(standingRow[static_cast<short>(partnerNation)]) -
                 partnerScore * g_Compute_Advisory_Peer_LookupTable) +
                selfScore;
  } else {
    numerator = (static_cast<float>(standingRow[static_cast<short>(partnerNation)]) -
                 partnerScore * (-0.25f)) +
                selfScore;
  }
  if (denominator != 0.0f) {
    numerator = numerator / denominator;
  }
  return numerator;
}

// FUNCTION: IMPERIALISM 0x004e1910
float TGreatPower::ComputeNavyScoreRatioForNationPair(int nationA, int nationB, char swapRoles) {
  int opponentNation = nationA;
  int partnerNation = nationB;
  if (swapRoles != 0) {
    opponentNation = nationB;
    partnerNation = nationA;
  }
  float selfScore = GetTotalNavalForce();
  float opponentScore = g_apNationStates[opponentNation]->GetTotalNavalForce();
  float partnerScore = g_apNationStates[partnerNation]->GetTotalNavalForce();
  float allySum = SumAlliedNavyScoreFactorsForScore(opponentNation);
  float denominator = opponentScore - allySum * (-0.25f);
  float numerator;
  if (swapRoles == 0) {
    numerator = selfScore - partnerScore * g_Compute_Advisory_Peer_LookupTable;
  } else {
    numerator = selfScore - partnerScore * (-0.25f);
  }
  if (denominator != 0.0f) {
    numerator = numerator / denominator;
  }
  return numerator;
}

// FUNCTION: IMPERIALISM 0x004e1a40
float TGreatPower::ComputeNavyScoreStandingRatioForNationPair(int nationA, int nationB,
                                                              char swapRoles) {
  int opponentNation = nationA;
  int partnerNation = nationB;
  if (swapRoles != 0) {
    opponentNation = nationB;
    partnerNation = nationA;
  }
  float selfScore = GetTotalNavalForce();
  float opponentScore = g_apNationStates[opponentNation]->GetTotalNavalForce();
  float partnerScore = g_apNationStates[partnerNation]->GetTotalNavalForce();
  float allySum = SumAlliedNavyScoreFactorsForScore(opponentNation);
  short* standingRow = GetRelationStandingRowForScore(nationSlot);
  float denominator =
      (static_cast<float>(standingRow[static_cast<short>(opponentNation)]) - allySum * (-0.25f)) +
      opponentScore;
  float numerator;
  if (swapRoles == 0) {
    numerator = (static_cast<float>(standingRow[static_cast<short>(partnerNation)]) -
                 partnerScore * g_Compute_Advisory_Peer_LookupTable) +
                selfScore;
  } else {
    numerator = (static_cast<float>(standingRow[static_cast<short>(partnerNation)]) -
                 partnerScore * (-0.25f)) +
                selfScore;
  }
  if (denominator != 0.0f) {
    numerator = numerator / denominator;
  }
  return numerator;
}

// FUNCTION: IMPERIALISM 0x004e1c00
bool TGreatPower::PassesDiplomacyStrengthThresholdForTarget(int targetNation) {
  return false;
}

// FUNCTION: IMPERIALISM 0x004e1c20
bool TGreatPower::EvaluateJoinWarAgainstNationAndQueueEvent(int targetNation) {
  // Result intentionally ignored in the original; keep the call for its side effects.
  g_pDiplomacyTurnStateManager->AreAtWar(nationSlot, targetNation);
  bool joinsWar = false;
  TGreatPower* targetState = g_apNationStates[targetNation];
  if (!targetState->IsCapitolThreatened(0) && !targetState->IsCapitolThreatened(1)) {
    float warThreshold = GetPeaceThreat(targetNation);
    if (GetAcceptPeaceNumber() < warThreshold) {
      joinsWar = true;
      for (int otherNation = 0; otherNation < kMajorNationCount; ++otherNation) {
        if (g_pSimMgr->ReallyInTheGame(otherNation) &&
            g_pDiplomacyTurnStateManager->GetTreatyStatus(nationSlot, otherNation) ==
                kDiplomacyRelationshipAlliance &&
            g_pDiplomacyTurnStateManager->AreAtWar(otherNation, targetNation)) {
          g_pDiplomacyTurnStateManager->TerminateAlliance(nationSlot, otherNation, 1);
        }
      }
    }
  }
  if (joinsWar) {
    g_pNewsMgr->AddTreatyEvent(kInterNationEventNationJoinedWar, targetNation, nationSlot, false);
  }
  return joinsWar;
}

// FUNCTION: IMPERIALISM 0x004e1d50
int TGreatPower::ConsiderWarOfIntervention(int targetNation, int sourceNation) {
  char result = 0;
  TViewMgr* uiRuntimeContext = g_pViewMgr;

  result = g_pDiplomacyTurnStateManager->AreAtWar(nationSlot, sourceNation);

  if (result == 0) {
    result = uiRuntimeContext->MakeWarOfferDialog(nationSlot, targetNation, sourceNation, 0x0A);
    if (result != 0) {
      DeclareWarOn(sourceNation, 1, targetNation);
      return true;
    }
  } else {
    result = uiRuntimeContext->MakeWarOfferDialog(nationSlot, targetNation, sourceNation, 0x0B);
    if (result != 0) {
      TMinor* secondaryNationState = g_apSecondaryNationStateSlots[targetNation];
      if (secondaryNationState != 0) {
        short stateValue = secondaryNationState->DecodeOwnerNationSlot();
        if (stateValue != nationSlot) {
          secondaryNationState->ChangeMaster(nationSlot, 1);
        }
      }
    }
  }
  return result != 0;
}

// FUNCTION: IMPERIALISM 0x004e1e40
int TGreatPower::ConsiderWarOfAlliance(int targetNation, int sourceNation, char swapRoles) {
  char accepted = g_pViewMgr->MakeWarOfferDialog(nationSlot, targetNation, sourceNation,
                                                 static_cast<int>(swapRoles) + 0x14);
  if (accepted == 0) {
    if (swapRoles == 0) {
      sourceNation = targetNation;
    }
    g_pDiplomacyTurnStateManager->TerminateAlliance(nationSlot, sourceNation, swapRoles == 0);
  } else if (swapRoles != 0) {
    DeclareWarOn(targetNation, 2, sourceNation);
  } else {
    DeclareWarOn(sourceNation, 2, targetNation);
  }
  return accepted != 0;
}

// FUNCTION: IMPERIALISM 0x004e1f20
void TGreatPower::SelectAndQueueAdvisoryMapMissions(void) {}

// FUNCTION: IMPERIALISM 0x004e1f40
float TGreatPower::GetPeaceThreat(int targetNation) {
  float alliedArmyForSelf = 0.0f;
  float alliedNavyForSelf = 0.0f;
  float alliedArmyForTarget = 0.0f;
  float alliedNavyForTarget = 0.0f;

  int selfArmyScoreValue = static_cast<int>(GetMilitaryPower());
  if (selfArmyScoreValue <= 1) {
    selfArmyScoreValue = 1;
  }
  float selfArmyScore = static_cast<float>(selfArmyScoreValue);

  int selfNavyScoreValue = static_cast<int>(GetTotalNavalForce());
  if (selfNavyScoreValue <= 1) {
    selfNavyScoreValue = 1;
  }
  float selfNavyScore = static_cast<float>(selfNavyScoreValue);

  int nationIndex = 0;
  while (nationIndex < kMajorNationCount) {
    if (g_pDiplomacyTurnStateManager->AreAtWar(nationIndex, nationSlot) &&
        g_pSimMgr->ReallyInTheGame(nationIndex) && nationIndex != targetNation) {
      TGreatPower* allyState = g_apNationStates[nationIndex];
      alliedArmyForSelf += allyState->GetMilitaryPower();
      alliedNavyForSelf += allyState->GetTotalNavalForce();
    }
    ++nationIndex;
  }

  nationIndex = 0;
  while (nationIndex < kMajorNationCount) {
    if (g_pDiplomacyTurnStateManager->AreAtWar(nationIndex, targetNation) &&
        g_pSimMgr->ReallyInTheGame(nationIndex) && nationIndex != nationSlot) {
      TGreatPower* allyState = g_apNationStates[nationIndex];
      alliedArmyForTarget += allyState->GetMilitaryPower();
      alliedNavyForTarget += allyState->GetTotalNavalForce();
    }
    ++nationIndex;
  }

  bool borderLinked =
      g_pGlobalMapState->AreNationsBorderLinked(targetNation, static_cast<int>(nationSlot));

  TGreatPower* targetState = g_apNationStates[targetNation];
  if (borderLinked != 0) {
    float targetArmyScore = targetState->GetMilitaryPower();
    float numerator = selfArmyScore + alliedArmyForSelf * (-g_Compute_Advisory_Peer_LookupTable);
    float denominator =
        targetArmyScore + alliedArmyForTarget * (-g_Compute_Advisory_Peer_LookupTable);
    return numerator / denominator;
  }

  float targetNavyScore = targetState->GetTotalNavalForce();
  float numerator = selfNavyScore + alliedNavyForSelf * (-g_Compute_Advisory_Peer_LookupTable);
  float denominator =
      targetNavyScore + alliedNavyForTarget * (-g_Compute_Advisory_Peer_LookupTable);
  return numerator / denominator;
}

// FUNCTION: IMPERIALISM 0x004e2190
void TGreatPower::ReplaceObsoleteMissions(void) {}

// FUNCTION: IMPERIALISM 0x004e21b0
void TGreatPower::ChangeMaster(int targetNationSlot, int mode) {
  CString sharedStringScope;

  TCountry::ChangeMaster(targetNationSlot, mode);

  TGreatPower* targetNation = g_apNationStates[targetNationSlot];
  if (targetNation->pendingActionStatus.byAction[9] < '3') {
    targetNation->SetNationPendingActionStateAndPayload(9, nationSlot);
  }
}

// FUNCTION: IMPERIALISM 0x004e2270
void TGreatPower::LoseProvince(int regionId) {
  ownedRegionList->Delete(regionId);
  KillUnitsIn(regionId);
}

// FUNCTION: IMPERIALISM 0x004e22b0
void TGreatPower::AddProvince(int regionId) {
  ownedRegionList->InsertLast(regionId);
  if (ownedRegionList->GetSize() >= 9) {
    signed char pressureHigh = pendingActionStatus.byAction[6];
    pressureHigh = pressureHigh >= 0x33;
    if (pressureHigh != 0) {
      signed char gateHigh = pendingActionStatus.byAction[12];
      gateHigh = gateHigh >= 0x33;
      if (gateHigh == 0) {
        SetNationPendingActionStateAndPayload(0x0C, -1);
      }
    }
  }
}

// FUNCTION: IMPERIALISM 0x004e2330
void TGreatPower::NewStatusFor(int targetNationSlot, int policyCode) {
  const int kPolicyDefensivePact = 500;
  const int kPolicyTradeAgreement = 200;

  short targetNation = targetNationSlot;
  if (policyCode == kPolicyDefensivePact || policyCode != kPolicyTradeAgreement) {
    tradePolicyByNation[targetNation] = 100;
  } else {
    TCountry* terrainDescriptor = g_apTerrainTypeDescriptorTable[targetNation];
    short encodedNationSlot = terrainDescriptor->encodedNationSlot;
    short resolvedNation;
    if (encodedNationSlot >= 200) {
      resolvedNation = static_cast<short>(encodedNationSlot - 200);
    } else if (encodedNationSlot >= 100) {
      resolvedNation = static_cast<short>(encodedNationSlot - 100);
    } else {
      resolvedNation = terrainDescriptor->nationSlot;
    }
    tradePolicyByNation[targetNation] = tradePolicyByNation[resolvedNation];
  }

  diplomacyGrantByNation[targetNation] = -1;

  if (policyCode == kPolicyDefensivePact) {
    TDiplomacyMgr* diplomacyManager = g_pDiplomacyTurnStateManager;
    diplomacyPolicyByNation[targetNation] = -1;
    g_pDiplomacyTurnStateManager->SetNationPairDiplomacyRelationCodeFinal(
        nationSlot, targetNation, kDiplomacyRelationshipPeace);
    StopBeingEnemiesWith(targetNation);
    return;
  }

  if (policyCode != kPolicyTradeAgreement) {
    SetEnemy(targetNation);
    return;
  }

  if (enemyFlags[targetNation] == 0) {
    TCountry* terrainDescriptor = g_apTerrainTypeDescriptorTable[targetNation];
    short encodedNationSlot = terrainDescriptor->encodedNationSlot;
    short resolvedNation;
    if (encodedNationSlot >= 200) {
      resolvedNation = static_cast<short>(encodedNationSlot - 200);
    } else if (encodedNationSlot >= 100) {
      resolvedNation = static_cast<short>(encodedNationSlot - 100);
    } else {
      resolvedNation = terrainDescriptor->nationSlot;
    }
    if (enemyFlags[resolvedNation] == 0) {
      TDiplomacyMgr* diplomacyManager = g_pDiplomacyTurnStateManager;
      if (!g_pDiplomacyTurnStateManager->AreAtWar(nationSlot, resolvedNation)) {
        StopBeingEnemiesWith(targetNation);
        return;
      }
    }
  }

  SetEnemy(targetNation);
}

// FUNCTION: IMPERIALISM 0x004e2500
void TGreatPower::KillUnitsIn(int ownerClass) {
  TMapMgr* globalMapState = g_pGlobalMapState;
  TSortedList* trackedList = trackedObjectList;
  for (int index = trackedList->GetCount(); index != 0; --index) {
    TUnit* order = static_cast<TUnit*>(trackedList->GetEntryByOrdinal(index));
    short orderCityRecord = globalMapState->terrainStateTable[order->tileIndex].cityRecordIndex;
    if (orderCityRecord == ownerClass) {
      order->Vaporize();
      order->Free();
    }
  }

  TSortedList* unitList = militaryUnitList;
  for (int unitIndex = unitList->GetCount(); unitIndex != 0; --unitIndex) {
    TUnit* unit = static_cast<TUnit*>(unitList->GetEntryByOrdinal(unitIndex));
    if (unit->tileIndex == -1) {
      unit->Free();
    }
  }
}

// FUNCTION: IMPERIALISM 0x004e25c0
void TGreatPower::AddColony(int targetNation) {
  SetTradePolicyTo(static_cast<NationSlot>(targetNation), kTradePolicyNormal);
  SetGrantPolicyTo(targetNation, -1);
  for (int nation = 0; nation < kNationSlotCount; ++nation) {
    if (g_pDiplomacyTurnStateManager->AreAtWar(nationSlot, nation)) {
      TellColoniesAboutNewEnemy(nation);
    }
  }
}

// FUNCTION: IMPERIALISM 0x004e2630
void TGreatPower::TellColoniesAboutNewEnemy(int targetNationSlot) {
  int minorNationSlot = kMajorNationCount; // minors occupy slots 7..22
  int tableIndex = 0;
  while (tableIndex < 16) {
    if (g_apTerrainTypeDescriptorTable[7 + tableIndex] != 0) {
      TMinor* auxRuntimeState = g_apNationAuxRuntimeStateSlots[tableIndex];
      if (auxRuntimeState->IsColonyOf(nationSlot) &&
          !g_pDiplomacyTurnStateManager->AreAtWar(minorNationSlot, targetNationSlot)) {
        g_pDiplomacyTurnStateManager->SetTreatyStatus(minorNationSlot, targetNationSlot,
                                                      kDiplomacyRelationshipWar, 0);
        if (targetNationSlot < kMajorNationCount && g_pSimMgr->ReallyInTheGame(targetNationSlot)) {
          TGreatPower* targetState = g_apNationStates[targetNationSlot];
          if (targetState->diplomacyEligibility == 0) {
            targetState->AddNoticeFrom(minorNationSlot, kDiplomacyProposalDeclareWar);
          }
        }
        auxRuntimeState->KillEnemyCiviliansIn(-1);
        auxRuntimeState->KillBoycottedForeignCompanies();
      }
    }
    ++tableIndex;
    ++minorNationSlot;
  }
}

// FUNCTION: IMPERIALISM 0x004e2720
void TGreatPower::TellColoniesAboutNewPeace(int targetNationSlot) {
  int minorNationSlot = kMajorNationCount; // minors occupy slots 7..22
  int tableIndex = 0;
  while (tableIndex < 16) {
    if (g_apTerrainTypeDescriptorTable[7 + tableIndex] != 0) {
      TMinor* auxRuntimeState = g_apNationAuxRuntimeStateSlots[tableIndex];
      if (auxRuntimeState->IsColonyOf(nationSlot)) {
        g_pDiplomacyTurnStateManager->SetNationPairDiplomacyRelationCodeFinal(
            minorNationSlot, targetNationSlot, kDiplomacyRelationshipPeace);
        if (colonyBoycottFlags[targetNationSlot] == 0) {
          auxRuntimeState->SetTradePolicyTo(static_cast<NationSlot>(targetNationSlot),
                                            kTradePolicyNormal);
        }
      }
    }
    ++tableIndex;
    ++minorNationSlot;
  }
}

// FUNCTION: IMPERIALISM 0x004e27b0
void TGreatPower::TellColoniesAboutNewTreaty(int targetNationSlot,
                                             DiplomacyRelationship relationship) {
  if (static_cast<DiplomacyRelationshipStorage>(relationship) == kDiplomacyRelationshipWar) {
    TellColoniesAboutNewEnemy(targetNationSlot);
    return;
  }

  TellColoniesAboutNewPeace(targetNationSlot);
}

// FUNCTION: IMPERIALISM 0x004e27f0
void TGreatPower::DeclareWarOn(int targetNationSlot, int transitionMode, int sourceNationSlot) {
  g_pDiplomacyTurnStateManager->AddDeclarationOfWar(nationSlot, targetNationSlot);

  short proposalCode = transitionMode;
  if ((proposalCode != 1) && (proposalCode != kDiplomacyProposalJoinEmpireWithWarEntanglements)) {
    return;
  }

  TMinor* secondaryNationState = g_apSecondaryNationStateSlots[sourceNationSlot];
  if (secondaryNationState == 0) {
    return;
  }

  short selectedSlot = secondaryNationState->DecodeOwnerNationSlot();

  if (selectedSlot == nationSlot) {
    return;
  }

  secondaryNationState->ChangeMaster(nationSlot, 1);
}

// FUNCTION: IMPERIALISM 0x004e2880
int TGreatPower::ClassifyNationProductionTierVsPeers(void) {
  if (city == 0) {
    return 0;
  }
  float sampleCount = 0.0f;
  float productionSum = 0.0f;
  float productionSquares = 0.0f;
  int slot = 0;
  TGreatPower** nationCursor = g_apNationStates;
  do {
    if (g_pSimMgr->ReallyInTheGame(slot)) {
      TCity* peerMgr = (*nationCursor != 0) ? (*nationCursor)->city : 0;
      if (peerMgr != 0) {
        int production = 4;
        for (int buildingSlot = 0; buildingSlot < 7; ++buildingSlot) {
          peerMgr = (*nationCursor != 0) ? (*nationCursor)->city : 0;
          production +=
              static_cast<short>(peerMgr->GetBuildingType(static_cast<short>(buildingSlot)));
        }
        sampleCount -= (-1.0f);
        productionSum = static_cast<float>(production) + productionSum;
        productionSquares = static_cast<float>(production * production) + productionSquares;
      }
    }
    ++nationCursor;
    ++slot;
  } while (nationCursor < g_apNationStates + kMajorNationCount);
  if (sampleCount < 2.0f) {
    return 2;
  }
  float mean = productionSum / sampleCount;
  float deviation = static_cast<float>(
      sqrt(((mean * mean * sampleCount - (mean * productionSum + mean * productionSum)) +
            productionSquares) /
           (sampleCount - 1.0f)));
  int ownProduction = 4;
  for (int buildingSlot = 0; buildingSlot < 7; ++buildingSlot) {
    ownProduction += static_cast<short>(city->GetBuildingType(static_cast<short>(buildingSlot)));
  }
  float ownScore = static_cast<float>(ownProduction);
  if (mean - deviation * (-2.0f) < ownScore) {
    return 4;
  }
  if (deviation + mean < ownScore) {
    return 3;
  }
  if (mean - deviation <= ownScore) {
    return 2;
  }
  if (mean - (deviation + deviation) <= ownScore) {
    return 1;
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x004e2b00
void TGreatPower::AnnounceLater(short orderKind, short payload, short flags) {
  short turnTick = 0;
  TSimMgr* simMgr = g_pSimMgr;
  if (simMgr != 0) {
    turnTick = simMgr->GetEconomicTurn();
  }

  TurnOrderDispatchPacket packet;
  packet.turnTick = turnTick;
  packet.orderKind = orderKind;
  packet.payload = payload;
  packet.flags = flags;

  TPtrList* turnSummaryQueue = this->turnSummaryQueue;
  if (turnSummaryQueue != 0) {
    turnSummaryQueue->Insert(&packet);
  }
}

// FUNCTION: IMPERIALISM 0x004e2b70
void TGreatPower::BuildGreatPowerTurnMessageSummaryAndDispatch(void) {
  CString countText;
  CString messageText;
  CString entryText;
  short totalGrantValue = 0;
  bool anyPreviousTurnEntry = false;
  short previousTurn = g_pSimMgr->GetEconomicTurn() - 1;

  if (turnSummaryQueue->GetSize() > 0) {
    g_pSimMgr->GetString(0x2749, 9, &messageText);
    for (int index = 1; index <= turnSummaryQueue->GetSize(); ++index) {
      TurnOrderDispatchPacket* entry = static_cast<TurnOrderDispatchPacket*>(
          turnSummaryQueue->GetPtrListEntryByOneBasedIndex(index));
      if (entry->turnTick != previousTurn) {
        continue;
      }
      anyPreviousTurnEntry = true;
      messageText += '\r';
      messageText += s_szTurnSummaryIndent;
      countText.Format(g_szDecimalFormat, entry->flags);
      switch (entry->orderKind) {
      case 1: {
        short grantCount = entry->flags;
        totalGrantValue += TShip::GetTypeCargoHold(entry->payload) * grantCount;
        if (grantCount > 1) {
          g_pSimMgr->GetString(0x271a, entry->payload, &entryText);
        } else {
          g_pSimMgr->GetString(0x2716, entry->payload, &entryText);
        }
        break;
      }
      case 0:
        if (entry->flags > 1) {
          g_pSimMgr->GetString(0x271a, entry->payload, &entryText);
        } else {
          g_pSimMgr->GetString(0x2716, entry->payload, &entryText);
        }
        break;
      case 2:
        if (entry->flags > 1) {
          g_pSimMgr->GetString(0x2748, entry->payload, &entryText);
        } else {
          g_pSimMgr->GetString(0x2718, entry->payload, &entryText);
        }
        break;
      case 3:
        if (entry->flags > 1) {
          BuildUiMessageTextFromBracketTemplate(g_pSimMgr, &entryText, 0x2747, 1, 0x2717,
                                                entry->payload);
        } else {
          short payload = entry->payload;
          if (payload == 0x2508) {
            g_pSimMgr->GetString(0x2744, 2, &entryText);
          } else if (payload == 0x1b || payload == 0x1c || payload == 0x1d) {
            g_pSimMgr->GetString(0x2744, 0, &entryText);
          } else {
            BuildUiMessageTextFromBracketTemplate(g_pSimMgr, &entryText, 0x2747, 0, 0x2717,
                                                  payload);
          }
        }
        break;
      }
      messageText += countText + s_szSpaceSeparator + entryText;
    }

    if (totalGrantValue != 0) {
      CString aidText;
      CString capacityText;
      CString aidTemplate;
      capacityText.Format(g_szDecimalFormat, merchantCapacity);
      g_pSimMgr->GetString(0x2739, 1, &aidTemplate);
      scanBracketExpressions(g_pSimMgr, &aidText, static_cast<LPCSTR>(aidTemplate),
                             static_cast<LPCSTR>(capacityText));
      messageText += '\r';
      messageText += '\r';
      messageText += aidText;
    }

    if (anyPreviousTurnEntry) {
      g_pSfxPlaybackSystem->PlaySoundEffect(0xbcb, 0, 1);
      g_pViewMgr->ModalMessage(messageText, g_ptGreatPowerModalMessage, 2, 0);
    }
  }
}

// FUNCTION: IMPERIALISM 0x004e3060
int TGreatPower::ComputeNationNavyOrderWeightedMovementScore() {
  int navyWeightByType[14];
  navyWeightByType[0] = 0;
  navyWeightByType[1] = 0;
  navyWeightByType[2] = 0;
  navyWeightByType[3] = 0x96;
  navyWeightByType[4] = 0x12c;
  navyWeightByType[5] = 0;
  navyWeightByType[6] = 0;
  navyWeightByType[7] = 0xc8;
  navyWeightByType[8] = 0x190;
  navyWeightByType[9] = 0x28a;
  navyWeightByType[10] = 0;
  navyWeightByType[11] = 0x1c2;
  navyWeightByType[12] = 0x5dc;
  navyWeightByType[13] = 0x4b0;
  int score = 0;
  CIterator iter(militaryUnitList);
  for (void* item = iter.Reset(); iter.More(); item = iter.Advance()) {
    TMilitaryUnit* unit = static_cast<TMilitaryUnit*>(item);
    if (unit->GetCategory() > EncodeArmyUnitCategory(kArmyUnitCategoryMilitia)) {
      score += g_anWeightedNeighborUnitScoreByType[unit->orderType] *
               (static_cast<short>(unit->experiencePercent / 100) + 10) / 10;
    }
  }
  for (TShip* node = TShip::GetFirst(); node != 0; node = node->next) {
    if (node->nation != nationSlot) {
      continue;
    }
    score += navyWeightByType[node->type] * (static_cast<short>(node->experience / 100) + 10) / 10;
  }
  return score;
}

// Average bilateral relation-standing score against every other live descriptor slot.
// FUNCTION: IMPERIALISM 0x004e3220
int TGreatPower::GetDiplomacyScore() {
  TDiplomacyMgr* diplomacy = g_pDiplomacyTurnStateManager;
  int sum = 0;
  int count = 0;
  for (int i = 0; i < kTerrainTypeDescriptorTableCount; i++) {
    if (g_apTerrainTypeDescriptorTable[i] == 0) {
      continue;
    }
    if (i == nationSlot) {
      continue;
    }
    sum += diplomacy->relationStandingScores[nationSlot * kNationSlotCount + static_cast<short>(i)];
    count++;
  }
  return sum / count;
}

// FUNCTION: IMPERIALISM 0x004e32a0
void TGreatPower::GenerateGameScore() {
  int seasonPercentTable[5] = {10, 15, 20, 25, 30};

  TLaborPool* baseline = city->productionSummary->baselineSlots;
  gameScoreRows[kGameScoreLabor] =
      baseline->lowSkillCount + (baseline->mediumSkillCount + baseline->highSkillCount * 2) * 2;
  gameScoreRows[kGameScoreTransport] = transportCapacity;

  gameScoreRows[kGameScoreIndustry] = 0;
  for (int buildingSlot = 0; buildingSlot < 6; ++buildingSlot) {
    gameScoreRows[kGameScoreIndustry] += city->GetBuildingType(static_cast<short>(buildingSlot));
  }

  gameScoreRows[kGameScoreProvinces] = ownedRegionList->GetSize();
  for (int minorSlot = 0; minorSlot < kMinorNationCount; ++minorSlot) {
    TMinor* candidate = g_apNationAuxRuntimeStateSlots[minorSlot];
    if (candidate->IsColonyOf(nationSlot)) {
      gameScoreRows[kGameScoreProvinces] += candidate->ownedRegionList->GetSize();
    }
  }
  gameScoreRows[kGameScoreProvinces] *= 10;

  int militaryOrderCostSum = 0;
  CIterator unitIter(militaryUnitList);
  for (TMilitaryUnit* unit = static_cast<TMilitaryUnit*>(unitIter.Reset()); unitIter.More();
       unit = static_cast<TMilitaryUnit*>(unitIter.Advance())) {
    militaryOrderCostSum += g_aUnitOrderCostProfileByAbilityId[unit->orderType][2];
  }
  gameScoreRows[kGameScoreMilitary] = militaryOrderCostSum;

  gameScoreRows[kGameScoreNavy] = GetArmsInNavy();

  TDiplomacyMgr* diplomacy = g_pDiplomacyTurnStateManager;
  int relationSum = 0;
  int relationCount = 0;
  for (int otherSlot = 0; otherSlot < kTerrainTypeDescriptorTableCount; otherSlot++) {
    if (g_apTerrainTypeDescriptorTable[otherSlot] == 0) {
      continue;
    }
    if (otherSlot == nationSlot) {
      continue;
    }
    relationSum +=
        diplomacy
            ->relationStandingScores[nationSlot * kNationSlotCount + static_cast<short>(otherSlot)];
    relationCount++;
  }
  gameScoreRows[kGameScoreDiplomacy] = relationSum / relationCount;

  gameScoreRows[kGameScoreMerchantMarine] = merchantCapacity;
  int currentQuarter = g_pSimMgr->economicTurn / 4;
  gameScoreRows[kGameScoreYear] = (100 - currentQuarter) * 10;

  gameScoreRows[kGameScoreSubtotal] = 0;
  int* summaryFields = gameScoreRows;
  for (int fieldIndex = 0; fieldIndex < 9; ++fieldIndex) {
    gameScoreRows[kGameScoreSubtotal] += summaryFields[fieldIndex];
  }

  gameScoreRows[kGameScoreDifficultyPercent] = seasonPercentTable[g_pSimMgr->difficultyLevel];
  gameScoreRows[kGameScoreTotal] =
      gameScoreRows[kGameScoreSubtotal] * gameScoreRows[kGameScoreDifficultyPercent] / 10;
}

// FUNCTION: IMPERIALISM 0x004e3560
void TGreatPower::PayForMilitary() {
  int maintenanceMultiplier =
      static_cast<unsigned short>(g_pTechMgr->activePrerequisitePair.primaryTechId) |
      (static_cast<unsigned int>(
           static_cast<unsigned short>(g_pTechMgr->activePrerequisitePair.secondaryTechId))
       << 16);
  int militaryUnitCost = 0;
  CIterator unitIter(militaryUnitList);
  for (TMilitaryUnit* unit = static_cast<TMilitaryUnit*>(unitIter.Reset()); unitIter.More();
       unit = static_cast<TMilitaryUnit*>(unitIter.Advance())) {
    militaryUnitCost += g_aUnitOrderCostProfileByAbilityId[unit->orderType][2];
  }

  int charge = (militaryUnitCost + GetArmsInNavy()) * maintenanceMultiplier;
  militaryExpenses = charge;
  treasuryValue -= charge;
}

// FUNCTION: IMPERIALISM 0x004e3620
int TGreatPower::SumDiplomacyGrantEntriesMaskedToValueBits() {
  int total = 0;
  for (int i = 0; i < 0x17; ++i) {
    unsigned short entry = diplomacyGrantByNation[i];
    if (entry != 0xffff) {
      total += entry & 0x3fff;
    }
  }
  return total;
}

// FUNCTION: IMPERIALISM 0x004e8750
float TGreatPower::ComputeAdvisoryMapNodeScoreFactorByCaseMetric(int metricCase, int cityIndex,
                                                                 TZone* zone,
                                                                 int selectedNationSlot) {
  float result;
  switch (metricCase) {
  case 1: {
    float sum = 0.0f;
    int slot;
    for (slot = 0; slot < kMajorNationCount; ++slot) {
      if (g_pSimMgr->ReallyInTheGame(static_cast<short>(slot))) {
        sum += g_apNationStates[slot]->GetMilitaryPower();
        if (slot == selectedNationSlot) {
          result = g_apNationStates[slot]->GetMilitaryPower();
        }
      }
    }
    if (result == g_Compute_Advisory_Zero) {
      result = 1.0f;
    }
    result = static_cast<float>(g_pSimMgr->GetNumGPs() * result - g_Compute_Advisory_MinusSix);
    return (sum - g_Compute_Advisory_MinusSix) / result;
  }
  case 2: {
    float sum = 0.0f;
    int slot;
    for (slot = 0; slot < kMajorNationCount; ++slot) {
      if (g_pSimMgr->ReallyInTheGame(static_cast<short>(slot))) {
        sum += g_apNationStates[slot]->GetTotalNavalForce();
        if (slot == selectedNationSlot) {
          result = g_apNationStates[slot]->GetTotalNavalForce();
        }
      }
    }
    if (result == g_Compute_Advisory_Zero) {
      result = 1.0f;
    }
    result = static_cast<float>(g_pSimMgr->GetNumGPs() * result - g_Compute_Advisory_MinusSix);
    return (sum - g_Compute_Advisory_MinusSix) / result;
  }
  case 3: {
    int ownedRegionCount =
        g_apTerrainTypeDescriptorTable[selectedNationSlot]->ownedRegionList->GetSize();
    result = static_cast<float>(
        g_apTerrainTypeDescriptorTable[selectedNationSlot]->GetLandForceIn(cityIndex) *
        ownedRegionCount);
    return (g_apTerrainTypeDescriptorTable[selectedNationSlot]->GetTotalLandForce() -
            g_Compute_Advisory_MinusHundred) /
           (result - g_Compute_Advisory_Map_Value);
  }
  case 4: {
    if (selectedNationSlot >= kMajorNationCount) {
      return g_Compute_Advisory_Zero;
    }
    TGreatPower* nation = g_apNationStates[selectedNationSlot];
    result = static_cast<float>(nation->GetNavalForceIn(zone) *
                                nation->CountMapActionContextNodesWithNationBit());
    return (g_apNationStates[selectedNationSlot]->SumNavyOrderPriorityForNation() -
            g_Compute_Advisory_MinusSix) /
           (result - g_Compute_Advisory_MinusSixFloat);
  }
  case 5:
    return g_Compute_Advisory_Hundred /
           g_pDiplomacyTurnStateManager
               ->relationStandingScores[nationSlot * kNationSlotCount +
                                        static_cast<short>(selectedNationSlot)];
  case 6: {
    const Province* record = &g_pGlobalMapState->cityScoreTable[cityIndex];
    result = static_cast<float>(record->cityScoreValue) / g_pGlobalMapState->cityScoreTotal;
    short claimantTag =
        g_pGlobalMapState->cityScoreTable[static_cast<short>(cityIndex)].formerOwnerNationCode;
    if (claimantTag == nationSlot) {
      short ownerTag = record->ownerNationCode;
      if (ownerTag != nationSlot && g_pDiplomacyTurnStateManager->AreAtWar(nationSlot, ownerTag)) {
        return result * g_Compute_Advisory_OnePointFive;
      }
    }
    break;
  }
  case 7:
    return static_cast<float>(zone->GetStrategicValue()) /
           g_pActiveMapOrderContext->GetAverageSeaZoneValue();
  }
  return result;
}
// FUNCTION: IMPERIALISM 0x004e8c20
float TGreatPower::ComputeAdvisoryMapNodeCompositeScore(int cityRecordIndex, int mode) {
  return ComputeAdvisoryMapNodeCompositeScoreByMode(cityRecordIndex, mode, -1);
}

// FUNCTION: IMPERIALISM 0x004e8c50
float TGreatPower::ComputeAdvisoryMapNodeCompositeScoreByMode(int cityRecordIndex, int mode,
                                                              int linkCityRecordIndex) {
  int ownerTag = g_pGlobalMapState->cityScoreTable[cityRecordIndex].ownerNationCode;
  if (g_pDiplomacyTurnStateManager->IsGreatPower(ownerTag)) {
    if (mode == 0) {
      float f1 = ComputeAdvisoryMapNodeScoreFactorByCaseMetric(1, cityRecordIndex, 0, ownerTag);
      float f3 = ComputeAdvisoryMapNodeScoreFactorByCaseMetric(3, cityRecordIndex, 0, ownerTag);
      float f5 = ComputeAdvisoryMapNodeScoreFactorByCaseMetric(5, cityRecordIndex, 0, ownerTag);
      float score = ComputeAdvisoryMapNodeScoreFactorByCaseMetric(6, cityRecordIndex, 0, ownerTag) *
                    f5 * f3 * f1 * f1;
      return score * score;
    }
    if (mode == 1) {
      int linkOwnerTag = g_pGlobalMapState->cityScoreTable[linkCityRecordIndex].ownerNationCode;
      if (linkOwnerTag != ownerTag) {
        return g_Compute_Advisory_Zero;
      }
      float f1 = ComputeAdvisoryMapNodeScoreFactorByCaseMetric(1, cityRecordIndex, 0, ownerTag);
      float f3 = ComputeAdvisoryMapNodeScoreFactorByCaseMetric(3, cityRecordIndex, 0, ownerTag);
      float f5 = ComputeAdvisoryMapNodeScoreFactorByCaseMetric(5, cityRecordIndex, 0, ownerTag);
      float f6 = ComputeAdvisoryMapNodeScoreFactorByCaseMetric(6, cityRecordIndex, 0, ownerTag);
      float score =
          ComputeAdvisoryMapNodeScoreFactorByCaseMetric(3, linkCityRecordIndex, 0, linkOwnerTag) *
          f6 * f5 * f3 * f1;
      return score * score;
    }
    TZone* zone = g_pActiveMapOrderContext->GetSeaZoneAdjacentTo(cityRecordIndex);
    float f1 = ComputeAdvisoryMapNodeScoreFactorByCaseMetric(1, cityRecordIndex, 0, ownerTag);
    float f2 = ComputeAdvisoryMapNodeScoreFactorByCaseMetric(2, cityRecordIndex, 0, ownerTag);
    float f3 = ComputeAdvisoryMapNodeScoreFactorByCaseMetric(3, cityRecordIndex, 0, ownerTag);
    float f4 = ComputeAdvisoryMapNodeScoreFactorByCaseMetric(4, cityRecordIndex, zone, ownerTag);
    float f5 = ComputeAdvisoryMapNodeScoreFactorByCaseMetric(5, cityRecordIndex, 0, ownerTag);
    float f6 = ComputeAdvisoryMapNodeScoreFactorByCaseMetric(6, cityRecordIndex, 0, ownerTag);
    return ComputeAdvisoryMapNodeScoreFactorByCaseMetric(7, cityRecordIndex, zone, ownerTag) * f6 *
           f4 * f5 * f2 * f3 * f1;
  }
  if (mode == 0) {
    float f3 = ComputeAdvisoryMapNodeScoreFactorByCaseMetric(3, cityRecordIndex, 0, ownerTag);
    float f5 = ComputeAdvisoryMapNodeScoreFactorByCaseMetric(5, cityRecordIndex, 0, ownerTag);
    return ComputeAdvisoryMapNodeScoreFactorByCaseMetric(6, cityRecordIndex, 0, ownerTag) * f5 * f3;
  }
  if (mode == 1) {
    int linkOwnerTag = g_pGlobalMapState->cityScoreTable[linkCityRecordIndex].ownerNationCode;
    if (linkOwnerTag != ownerTag) {
      return g_Compute_Advisory_Zero;
    }
    float f1 = ComputeAdvisoryMapNodeScoreFactorByCaseMetric(1, cityRecordIndex, 0, ownerTag);
    float f3 = ComputeAdvisoryMapNodeScoreFactorByCaseMetric(3, cityRecordIndex, 0, ownerTag);
    float f5 = ComputeAdvisoryMapNodeScoreFactorByCaseMetric(5, cityRecordIndex, 0, ownerTag);
    float f6 = ComputeAdvisoryMapNodeScoreFactorByCaseMetric(6, cityRecordIndex, 0, ownerTag);
    return ComputeAdvisoryMapNodeScoreFactorByCaseMetric(3, linkCityRecordIndex, 0, linkOwnerTag) *
           f6 * f5 * f3 * f1;
  }
  TZone* zone = g_pActiveMapOrderContext->GetSeaZoneAdjacentTo(cityRecordIndex);
  float f1 = ComputeAdvisoryMapNodeScoreFactorByCaseMetric(1, cityRecordIndex, 0, ownerTag);
  float f3 = ComputeAdvisoryMapNodeScoreFactorByCaseMetric(3, cityRecordIndex, 0, ownerTag);
  float f5 = ComputeAdvisoryMapNodeScoreFactorByCaseMetric(5, cityRecordIndex, 0, ownerTag);
  float f6 = ComputeAdvisoryMapNodeScoreFactorByCaseMetric(6, cityRecordIndex, 0, ownerTag);
  return ComputeAdvisoryMapNodeScoreFactorByCaseMetric(7, cityRecordIndex, zone, ownerTag) * f6 *
         f5 * f3 * f1;
}

// FUNCTION: IMPERIALISM 0x004e9060
float TGreatPower::ComputeMapActionContextCompositeScoreForNation(TZone* zone) {
  unsigned char* candidateFlags = enemyFlags;
  int activeCandidateCount = 0;
  int selectedCandidateIndex = 0;
  float compositeScore = 0.0f;
  int i;

  for (i = 0; i < 0x17; ++i) {
    if (candidateFlags[i] != 0) {
      ++activeCandidateCount;
    }
  }

  if (activeCandidateCount == 0) {
    TSortedByRelationshipList* relationshipList = new TSortedByRelationshipList();
    relationshipList->ISortedByRelationshipList();
    g_pDiplomacyTurnStateManager->BuildRelationshipList(nationSlot, 1, relationshipList);
    selectedCandidateIndex =
        *static_cast<short*>(relationshipList->GetPtrListEntryByOneBasedIndex(1));
    if (relationshipList != 0) {
      relationshipList->FreeList();
    }
  } else if (activeCandidateCount == 1) {
    // The count guarantees that this scan finds a candidate before reaching the bound.
    while (selectedCandidateIndex < 0x17) {
      if (candidateFlags[selectedCandidateIndex] != 0) {
        break;
      }
      ++selectedCandidateIndex;
    }
  } else {
    short navyPriorities[7] = {0, 0, 0, 0, 0, 0, 0};
    for (i = 0; i < kMajorNationCount; ++i) {
      if (candidateFlags[i] != 0) {
        navyPriorities[i] = static_cast<short>(g_apNationStates[i]->GetNavalForceIn(zone));
      }
    }

    int maxPriority = 0;
    for (i = 0; i < 7; ++i) {
      if (navyPriorities[i] > maxPriority) {
        maxPriority = navyPriorities[i];
        selectedCandidateIndex = i;
      }
    }
    if (maxPriority == 0) {
      compositeScore = 1.0f;
    }
  }

  if (compositeScore == g_Compute_Advisory_Zero) {
    float f2 = ComputeAdvisoryMapNodeScoreFactorByCaseMetric(2, -1, zone, selectedCandidateIndex);
    float f4 = ComputeAdvisoryMapNodeScoreFactorByCaseMetric(4, -1, zone, selectedCandidateIndex);
    float f5 = ComputeAdvisoryMapNodeScoreFactorByCaseMetric(5, -1, zone, selectedCandidateIndex);
    float f7 = ComputeAdvisoryMapNodeScoreFactorByCaseMetric(7, -1, zone, selectedCandidateIndex);
    compositeScore = f5 * f7 * f2 * f4;
  }

  return compositeScore;
}

// FUNCTION: IMPERIALISM 0x005b7f50
char __stdcall IsSpecialNationInteractionResource(short resourceIndex) {
  if (resourceIndex >= 0xD && resourceIndex <= 0x10) {
    return 1;
  }
  return 0;
}
