#include "game/TCityInteriorMinister.h"

#include <stdlib.h>
#include <string.h>

#include "game/TAutoGreatPower.h"
#include "game/CIterator.h"
#include "game/TCity.h"
#include "game/TCivUnit.h"
#include "game/TDiplomacyMgr.h"
#include "game/TForeignMinister.h"
#include "game/TFuzzySet.h"
#include "game/TGreatPower.h"
#include "game/TItemOrder.h"
#include "game/TList.h"
#include "game/TLongintList.h"
#include "game/TMapMgr.h"
#include "game/TShortintList.h"
#include "game/TSimMgr.h"
#include "game/TSortedList.h"
#include "game/TTechMgr.h"
#include "game/TTown.h"
#include "game/TUnit.h"
#include "game/TUnitOrder.h"
#include "game/TViewMgr.h"
#include "game/global_data_tables.h"
#include "game/mfc.h"
#include "game/ui_invalidation_guard.h"

short __stdcall TraceDescendingTileScoreGradientToSource(short startTile, char* scoreMap,
                                                         short* previousTileOut);

// FUNCTION: IMPERIALISM 0x004be000
void InsertScoredTileCandidateWithRandomTieBreak(float score, short tileIndex,
                                                 float* candidateScores, short* candidateTiles,
                                                 int capacity) {
  int insertionIndex = -1;
  for (int index = 0; index < capacity && insertionIndex < 0; ++index) {
    if (score > candidateScores[index] || (score == candidateScores[index] && (rand() & 1) != 0)) {
      insertionIndex = index;
    }
  }
  if (insertionIndex >= 0) {
    for (int shiftIndex = capacity - 1; shiftIndex > insertionIndex; --shiftIndex) {
      candidateScores[shiftIndex] = candidateScores[shiftIndex - 1];
      candidateTiles[shiftIndex] = candidateTiles[shiftIndex - 1];
    }
    candidateScores[insertionIndex] = score;
    candidateTiles[insertionIndex] = tileIndex;
  }
}

// FUNCTION: IMPERIALISM 0x004be6f0
float TCityInteriorMinister::GetAiDevelopmentResourceBudgetScale(int* resourcePools) {
  (void)resourcePools;
  return g_AiDevelopmentResourceBudgetScale_00650758;
}
// SYNTHETIC: IMPERIALISM 0x004be710
// TCityInteriorMinister::CreateObject

// NOTE: The city-policy virtual run (slots 0x58-0xd4) — production rebalancing, command
// queueing, home-tile selection, neighbor-bucket rebuilds — is promoted here as a real
// virtual override layout owning the original addresses (previously return-0 autogen
// stubs / orphan leaves). Bodies are honest partial ports to be enriched later; the slot
// ownership is what drives vtable matching. Methods are listed in ascending-address order
// (marker hygiene), which differs from slot order.

// FUNCTION: IMPERIALISM 0x004be7b0
short TCityInteriorMinister::InteriorSlot1D(int arg) {
  return orderTypeTable12A[arg];
}

// FUNCTION: IMPERIALISM 0x004be7d0
short TCityInteriorMinister::InteriorSlot1E(int arg) {
  return orderTypeTable158[arg];
}

// FUNCTION: IMPERIALISM 0x004be7f0
void TCityInteriorMinister::InteriorSlot1F(int arg) {
  orderTypeTable158[arg] = 0;
}

// SYNTHETIC: IMPERIALISM 0x004be820
// TCityInteriorMinister::GetRuntimeClass

IMPLEMENT_DYNCREATE(TCityInteriorMinister, TInteriorMinister)

// FUNCTION: IMPERIALISM 0x004be840
TCityInteriorMinister::TCityInteriorMinister() : TInteriorMinister() {
  orderList18c = 0;
  capabilityFlag14 = 1;
  capabilityFlag16 = 1;
}

// SYNTHETIC: IMPERIALISM 0x004be880
// TCityInteriorMinister::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x004be8d0
void TCityInteriorMinister::InitializeCityInteriorState(TGreatPower* owner) {
  InitializeBaseOrderArray(owner);

  field10 = 0;
  field12 = 0;
  trailingTable[0] = 0;
  trailingTable[1] = 0;
  trailingTable[2] = 0;
  trailingTable[3] = 0;
  trailingTable[4] = 0;
  trailingTable[5] = 0;
  trailingTable[6] = 0;
  field32 = 0;
  field36 = -1;
  field38 = -1;
  field3a = 50;

  list28 = new TLongintList();
  list2c = new TLongintList();
  field30 = 1;

  orderList18c = new TList();
  if (orderList18c == 0) {
    MessageBoxA(0, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUCityMinister_006964B0, 0x288);
  }

  FillLists();

  field3c = -1;
  field3e = 0;

  for (short i = 0; i < 23; ++i) {
    orderTypeTableFC[i] = 0;
    orderTypeTable12A[i] = 0;
    orderTypeTable158[i] = 0;
  }
  for (short j = 0; j < 60; ++j) {
    orderMetricTable40[j] = 0;
  }
  fieldB8 = 0;
  for (short k = 0; k < 16; ++k) {
    orderShortTableBA[k] = 0;
    orderShortTableDC[k] = 0;
  }

  field34 = 0;
  fieldDA = 0;
  field186 = 0;

  list190 = new TLongintList();

  cityPolicyFuzzySet = new TFuzzySet();
  cityPolicyFuzzySet->Clear();
  cityPolicyFuzzySet->AllocateAndAppendRecord(0xccbebc20, 0xc7c35000, 0xc69c4000, 0xc61c4000);
  cityPolicyFuzzySet->AllocateAndAppendRecord(0xc66a6000, 0xc59c4000, 0xc59c4000, 0x447a0000);
  cityPolicyFuzzySet->AllocateAndAppendRecord(0, 0x459c4000, 0x461c4000, 0x466a6000);
  cityPolicyFuzzySet->AllocateAndAppendRecord(0x461c4000, 0x469c4000, 0x49742400, 0x4e6e6b28);

  field1c2 = 0;
}

// FUNCTION: IMPERIALISM 0x004becd0
void TCityInteriorMinister::Free() {
  if (list28 != 0) {
    list28->Free();
  }
  list28 = 0;
  if (list2c != 0) {
    list2c->Free();
  }
  list2c = 0;
  if (cityPolicyFuzzySet != 0) {
    cityPolicyFuzzySet->Free();
  }
  if (orderList18c != 0) {
    orderList18c->FreePayloadsAndDestroy();
  }
  if (list190 != 0) {
    list190->Free();
  }
  list190 = 0;
  TMinister::Free();
}

// FUNCTION: IMPERIALISM 0x004bed60
void TCityInteriorMinister::FillLists() {
  list28->InsertLast(16);
  list28->InsertLast(15);
  list28->InsertLast(13);
  list28->InsertLast(9);
  list28->InsertLast(11);
  list28->InsertLast(8);

  list2c->InsertLast(2);
  list2c->InsertLast(4);
  list2c->InsertLast(0);
  list2c->InsertLast(3);
  list2c->InsertLast(5);
  list2c->InsertLast(1);
  list2c->InsertLast(6);
}

// FUNCTION: IMPERIALISM 0x004bee20
short TCityInteriorMinister::GetRankingCriterionForGP(short nationSlot) {
  (void)nationSlot;
  return 0;
}

// FUNCTION: IMPERIALISM 0x004beeb0
void TCityInteriorMinister::InteriorSlot1A(short orderKind) {
  if (field32 == 0) {
    field32 = static_cast<short>((orderKind == 2) + 1);
  }
}

// FUNCTION: IMPERIALISM 0x004beee0
void TCityInteriorMinister::IndustryOrder(short industrySlot) {
  list190->InsertLast(static_cast<long>(industrySlot) + 30);
}

// FUNCTION: IMPERIALISM 0x004bef10
void TCityInteriorMinister::VTableSlot2D(short arg) {
  field36 = arg;
}

// FUNCTION: IMPERIALISM 0x004bef30
void TCityInteriorMinister::InteriorSlot1C(short arg) {
  list190->InsertLast(arg);
}

// FUNCTION: IMPERIALISM 0x004bef60
void TCityInteriorMinister::WriteTo(TStream* stream) {
  (void)stream;
}

// FUNCTION: IMPERIALISM 0x004bf390
void TCityInteriorMinister::ReadFrom(TStream* stream) {
  (void)stream;
}

// FUNCTION: IMPERIALISM 0x004bf770
void TCityInteriorMinister::FillOrders() {
  TCity* city;
  if (ownerContextAt04 != 0) {
    city = ownerContextAt04->city;
  } else {
    city = 0;
  }

  for (int needIndex = 0; needIndex < 23; ++needIndex) {
    ownerContextAt04->UpdateNeedTargetAndAccumulateOverCap(static_cast<short>(needIndex), 0);
  }

  RebalanceCityOrderAllocationTargets(city);
  city->EndCityPhase();

  for (short orderSlot = 7; orderSlot < 61; ++orderSlot) {
    if (city->orderSlotsE4[orderSlot] != 0) {
      static_cast<TProductionOrder*>(city->orderSlotsE4[orderSlot])->SetQuantity(0);
    }
  }

  ProcessCityOrderStateTickAndApplyCapabilitySelection();
  RebalanceCitySupportAndLaborAllocations();
  ChooseAndMarkNextCityProductionCommand();
  ComputeCityProductionCommandLimitsFromBuildingOutputs();
  RebuildCityOrderCommandAvailabilityAndPriorityCycle();
  CityMinisterSlot45();

  memset(orderShortTableBA, 0, sizeof(orderShortTableBA));
  for (short itemSlot = 0; itemSlot < 23; ++itemSlot) {
    if (itemSlot == 7) {
      continue;
    }
    if (city->orderSlotsE4[itemSlot] != 0) {
      TItemOrder* itemOrder = static_cast<TItemOrder*>(city->orderSlotsE4[itemSlot]);
      itemOrder->AssertValid();
      orderShortTableBA[itemOrder->productionSlot] += itemOrder->quantityField04;
    }
  }

  EvaluateCityShortagesAndNotifyForeignMinister(city);
}

// FUNCTION: IMPERIALISM 0x004bf8a0
undefined TCityInteriorMinister::EvaluateCityShortagesAndNotifyForeignMinister(TCity* city) {
  if (orderMetricTable40[0] != 0 || orderMetricTable40[1] != 0) {
    bool roll = (rand() % 100) >= 75;
    ownerContextAt04->foreignMinister->PleaseBuy(0, roll);
  }

  for (short i = 2; i <= 6; ++i) {
    short delta = orderMetricTable40[i];
    if (delta != 0) {
      ownerContextAt04->foreignMinister->PleaseBuy(i, delta);
    }
  }

  short localB;
  unsigned short localA;
  city->productionSummary1d8->GetRecentStormImpactMetrics(&localB, &localA);

  short resultCode;
  short magnitude;

  if (localB != 0 || localA != 0) {
    resultCode = 7;
    magnitude = static_cast<short>(localA + localB);
  } else if (city->cityStockSteelCC == 0) {
    resultCode = 11;
    magnitude = 4;
  } else if (city->cityStockLumberC8 == 0) {
    resultCode = 9;
    magnitude = 4;
  } else {
    resultCode = -1;
    magnitude = 0;

    short popHalfNeed = city->productionSummary1d8->populationCount08 / 2;
    if (city->cityStockCannedFoodC4 < popHalfNeed) {
      resultCode = 7;
      magnitude = city->productionSummary1d8->populationCount08 - city->cityStockCannedFoodC4;
      if (magnitude > 6) {
        magnitude = 6;
      }
    }
  }

  if (resultCode != -1) {
    ownerContextAt04->foreignMinister->SetInteriorMinisterBid(resultCode, magnitude);
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x004bfa50
undefined TCityInteriorMinister::GetTEventHandlerClassNamePointer_22(TCity* city, int* arg2) {
  if (city->lowProductionFlag7c != 0 && city->lowStockFlag7d == 0) {
    QueueCityProductionCommand17Or18FromSupportRatio(city, arg2);
  } else if (city->lowProductionFlag7c == 0 && city->lowStockFlag7d != 0) {
    DistributeCityProductionCommandBudgetAndQueueOrders(city, arg2);
  }

  if (field3e != 0) {
    QueueCityProductionCommand33FromAccumulatedDeficit(city, arg2);
  }
  if (field32 != 0) {
    QueueCityProductionCommand2BIfMissingAndResetValue(reinterpret_cast<int>(city), arg2);
  }
  if (field36 > -1) {
    QueueSingleCityProductionCommandFromField36(city, arg2);
  }
  if (field38 > -1) {
    QueueSingleCityProductionCommandFromField38(city, arg2);
  }

  return QueueCityProductionRebalanceCommandsByThresholds(city, arg2);
}

// FUNCTION: IMPERIALISM 0x004bfb20
undefined TCityInteriorMinister::QueueCityProductionRebalanceCommandsByThresholds(TCity*, int*) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004bff60
void TCityInteriorMinister::NoOpProductionCommandHook24(int, int) {}

// FUNCTION: IMPERIALISM 0x004bff80
undefined TCityInteriorMinister::QueueCityProductionCommand33FromAccumulatedDeficit(TCity*, int*) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004c0090
undefined TCityInteriorMinister::DistributeCityProductionCommandBudgetAndQueueOrders(TCity*,
                                                                                     void*) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004c02c0
undefined TCityInteriorMinister::QueueCityProductionCommand17Or18FromSupportRatio(void*, int*) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004c04e0
undefined TCityInteriorMinister::QueueRandomCityProductionCommand19To1C(void*, void*) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004c05a0
undefined TCityInteriorMinister::QueueCityProductionCommand2BIfMissingAndResetValue(int, int*) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004c0690
undefined TCityInteriorMinister::QueueSingleCityProductionCommandFromField36(void*, void*) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004c0730
undefined TCityInteriorMinister::QueueSingleCityProductionCommandFromField38(void*, void*) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004c07d0
undefined
TCityInteriorMinister::DistributeCityProductionAcrossOrderTemplatesAndBackfillDeficits(TCity*) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004c0d90
void TCityInteriorMinister::MakeNewCity(TCity* city) {
  (void)city;
  if (ownerContextAt04->diplomacyEligibilityA0 == 0) {
    ownerContextAt04->treasuryValue10 = 10000;
    orderMetricTable40[53] = 2;
    orderMetricTable40[55] = 2;
    orderMetricTable40[57] = 2;
    orderMetricTable40[54] = 1;
  }
}

// FUNCTION: IMPERIALISM 0x004c0de0
undefined TCityInteriorMinister::SetForeignMinisterReadyFlag14_2e(short, short, short) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004c0e50
undefined TCityInteriorMinister::ReconcileCityProductionQueueAgainstTargetsAndAdjustOrders(int*,
                                                                                           int) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004c11c0
int TCityInteriorMinister::SelectBestSecondaryHomeTileByFrogCityScore() {
  short nationSlot = ownerContextAt04->nationSlot;
  TTown* candidateTown = new TTown();
  candidateTown->InitializeTownMarker("Bleah", 0, 1, nationSlot);

  int bestScore = -1;
  int bestTileIndex = -1;
  int tileIndex = 0;
  do {
    TTerrainStateRecordView* tile = &g_pGlobalMapState->terrainStateTable[tileIndex];
    if (static_cast<short>(tile->ownerNationTag04) == nationSlot &&
        g_pGlobalMapState->IsValidSecondaryNationHomeTileCandidate(static_cast<short>(tileIndex))) {
      short terrainType = tile->terrainType00;
      if (terrainType == 0 || terrainType == 7 || terrainType == 1 || terrainType == 6) {
        candidateTown->tileIndex14 = static_cast<short>(tileIndex);
        candidateTown->CalculateCityResources();

        short resource17 = candidateTown->resourceYieldByType[17];
        short clamped17;
        if (resource17 < 0) {
          clamped17 = 0;
        } else if (resource17 > 6) {
          clamped17 = 6;
        } else {
          clamped17 = resource17;
        }

        short resource18 = candidateTown->resourceYieldByType[18];
        short clamped18;
        if (resource18 < 0) {
          clamped18 = 0;
        } else if (resource18 > 2) {
          clamped18 = 2;
        } else {
          clamped18 = resource18;
        }

        short resource17Surplus = static_cast<short>(resource17 - 6);
        if (resource17Surplus < 0) {
          resource17Surplus = 0;
        } else if (resource17Surplus > 3) {
          resource17Surplus = 3;
        }

        short resource18Surplus = static_cast<short>(resource18 * 2 - 4);
        if (resource18Surplus < 0) {
          resource18Surplus = 0;
        } else if (resource18Surplus > 4) {
          resource18Surplus = 4;
        }

        short industrialBonus = static_cast<short>(
            (candidateTown->resourceYieldByType[19] + candidateTown->resourceYieldByType[20]) * 2);
        if (industrialBonus < 0) {
          industrialBonus = 0;
        } else if (industrialBonus > 4) {
          industrialBonus = 4;
        }

        short rawMaterialBonus = static_cast<short>(candidateTown->resourceYieldByType[2] * 2);
        if (rawMaterialBonus < 0) {
          rawMaterialBonus = 0;
        } else if (rawMaterialBonus > 12) {
          rawMaterialBonus = 12;
        }

        int score = (candidateTown->resourceYieldByType[0] + candidateTown->resourceYieldByType[1] +
                     candidateTown->resourceYieldByType[22]) *
                        3 +
                    candidateTown->resourceYieldByType[3] + candidateTown->resourceYieldByType[4] +
                    rawMaterialBonus + clamped17 * 1000 + clamped18 * 1000 + resource17Surplus +
                    resource18Surplus + industrialBonus;
        if ((tile->activeFlags1c & 1) != 0) {
          score = 32000;
        }
        if (static_cast<short>(bestScore) < score) {
          bestScore = score;
          bestTileIndex = tileIndex;
        }
      }
    }
    ++tileIndex;
  } while (static_cast<short>(tileIndex) < 0x1950);

  candidateTown->Free();
  if (static_cast<short>(bestTileIndex) == -1) {
    CString message;
    g_pSimMgr->GetString(0x2737, 0x35, &message);
    g_pUiRuntimeContext->ModalMessage(message, g_ptCityInteriorMinisterModalMessage, 2, 0);
  }
  return static_cast<short>(bestTileIndex);
}

// FUNCTION: IMPERIALISM 0x004c1510
void TCityInteriorMinister::ProcessUnitOrders() {
  TSortedList* trackedOrders = ownerContextAt04->trackedObjectList;
  ownerContextAt04->DispatchTrackedOrderSlot2CCallbacks();

  int ownedTileCount = 0;
  short nationSlot = ownerContextAt04->nationSlot;
  int tileIndex;
  for (tileIndex = 0; tileIndex < 0x1950; ++tileIndex) {
    if (g_pGlobalMapState->terrainStateTable[static_cast<short>(tileIndex)].ownerNationTag04 ==
        nationSlot) {
      ++ownedTileCount;
    }
  }

  TShortintList ownedTiles;
  ownedTiles.values = static_cast<short*>(realloc(0, ownedTileCount * sizeof(short)));
  ownedTiles.capacity = ownedTileCount;
  for (tileIndex = 0; tileIndex < 0x1950; ++tileIndex) {
    if (g_pGlobalMapState->terrainStateTable[static_cast<short>(tileIndex)].ownerNationTag04 ==
        nationSlot) {
      ownedTiles.InsertLast(static_cast<short>(tileIndex));
    }
  }

  char* primaryDistanceMap = CreateSeaDistanceMap(&ownedTiles);
  char* secondaryDistanceMap = BuildFrogCityDistanceMapFromReachableSeaCandidates(&ownedTiles);
  SeekResources(&ownedTiles, primaryDistanceMap);
  if (field3c == -1) {
    SeekLostTowns(primaryDistanceMap, secondaryDistanceMap);
  }

  short selectedOrderType = 0;
  while (field3c == -1 && selectedOrderType != -1) {
    selectedOrderType = -1;
    for (short orderType = 0; orderType < 23; ++orderType) {
      if (((orderType >= 0 && orderType <= 6) || (orderType >= 17 && orderType <= 22)) &&
          orderTypeTableFC[orderType] != 0 &&
          (selectedOrderType < 0 ||
           orderTypeTableFC[selectedOrderType] < orderTypeTableFC[orderType])) {
        selectedOrderType = orderType;
      }
    }

    if (selectedOrderType != -1) {
      StartRailheadProject(selectedOrderType, &ownedTiles, primaryDistanceMap,
                           secondaryDistanceMap);
      if (field3c == -1) {
        orderTypeTableFC[selectedOrderType] = 0;
      }
    }
  }

  if (field3c == -1) {
    DispatchBuilders();
  } else if (g_pGlobalMapState->terrainStateTable[field3c].ownerNationTag04 != nationSlot) {
    field3c = -1;
  } else {
    bool hasBuilderOrder = false;
    TUnit* availableBuilderOrder = 0;
    int orderCount = trackedOrders->GetCount();
    for (int ordinal = 1; ordinal <= orderCount && availableBuilderOrder == 0; ++ordinal) {
      TUnit* order = static_cast<TUnit*>(trackedOrders->GetEntryByOrdinal(ordinal));
      if (order->orderType == 4) {
        hasBuilderOrder = true;
        if (order->field_8 == 0) {
          availableBuilderOrder = order;
        }
      }
    }
    if (!hasBuilderOrder) {
      VTableSlot2D(4);
    }
    if (availableBuilderOrder != 0) {
      ContinueRailheadProject(availableBuilderOrder, primaryDistanceMap, secondaryDistanceMap);
    }
  }

  RebuildMapTileNeighborBucketsForInteriorMinister();
  AutoAssignProspectingOrdersByTileHeuristics();
  delete secondaryDistanceMap;
  delete primaryDistanceMap;
}

// FUNCTION: IMPERIALISM 0x004c1990
void TCityInteriorMinister::DispatchBuilders() {
  TSortedList* trackedOrders = ownerContextAt04->trackedObjectList;
  TUnit* builderOrder = 0;
  int orderCount = trackedOrders->GetCount();
  for (int ordinal = 1; ordinal <= orderCount && builderOrder == 0; ++ordinal) {
    TUnit* order = static_cast<TUnit*>(trackedOrders->GetEntryByOrdinal(ordinal));
    if (order->orderType == 4 && order->field_8 == 0) {
      builderOrder = order;
    }
  }

  if (builderOrder != 0) {
    int cityRecordIndex = ComputeBestNationTileDevelopmentScore(ownerContextAt04->nationSlot);
    if (cityRecordIndex != -1) {
      TGlobalMapCityScoreRecord* cityRecord = &g_pGlobalMapState->cityScoreTable[cityRecordIndex];
      short cityTileIndex = cityRecord->cityTileIndex04;
      TCivUnit* tileOrder =
          g_pGlobalMapState->terrainStateTable[cityTileIndex].firstCivilianOrder20;
      if ((tileOrder == 0 || tileOrder == builderOrder) &&
          g_awEngineerFortBuildCostByLevel[cityRecord->fortLevel03] <=
              ownerContextAt04->treasuryValue10) {
        builderOrder->VTableSlot10(cityTileIndex);
        builderOrder->SetOrderModeSlot34(12, cityTileIndex);
      }
    }
  }
}

// FUNCTION: IMPERIALISM 0x004c1ac0
void TCityInteriorMinister::RebuildMapTileNeighborBucketsForInteriorMinister() {
  RequestMissingCivilianOrderTypes();

  TShortintList candidateTiles;
  TSortedList* towns = ownerContextAt04->townMarkerList;
  int townCount = towns->GetCount();
  for (int ordinal = 1; ordinal <= townCount; ++ordinal) {
    TTown* town = static_cast<TTown*>(towns->GetEntryByOrdinal(ordinal));
    candidateTiles.InsertLast(town->tileIndex14);
    short regionSubtype =
        g_pGlobalMapState->terrainStateTable[town->tileIndex14].regionSubtypeTag05;
    for (short direction = 0; direction < 6; ++direction) {
      short neighbor =
          TMapMgr::GetWrappedHexNeighborTileIndexByDirection(town->tileIndex14, direction);
      if (neighbor != -1 &&
          g_pGlobalMapState->terrainStateTable[neighbor].regionSubtypeTag05 == regionSubtype &&
          static_cast<short>(g_pGlobalMapState->terrainStateTable[neighbor].ownerNationTag04) ==
              ownerContextAt04->nationSlot) {
        candidateTiles.InsertLast(neighbor);
      }
    }
  }

  if (field3c != -1) {
    candidateTiles.InsertLast(field3c);
    for (short direction = 0; direction < 6; ++direction) {
      short neighbor = TMapMgr::GetWrappedHexNeighborTileIndexByDirection(field3c, direction);
      if (neighbor != -1 &&
          static_cast<short>(g_pGlobalMapState->terrainStateTable[neighbor].ownerNationTag04) ==
              ownerContextAt04->nationSlot) {
        candidateTiles.InsertLast(neighbor);
      }
    }
  }

  for (short tileIndex = 0; tileIndex < 0x1950; ++tileIndex) {
    if (static_cast<short>(
            g_pGlobalMapState->terrainStateTable[tileIndex].secondaryOwnerNationTag18) ==
        ownerContextAt04->nationSlot) {
      candidateTiles.InsertLast(tileIndex);
    }
  }

  TSortedList* trackedOrders = ownerContextAt04->trackedObjectList;
  int orderCount = trackedOrders->GetCount();
  for (int orderOrdinal = 1; orderOrdinal <= orderCount; ++orderOrdinal) {
    TUnit* order = static_cast<TUnit*>(trackedOrders->GetEntryByOrdinal(orderOrdinal));
    if (order->orderType == 4 || order->field_8 != 0) {
      continue;
    }
    char useHighNibble = order->orderType == 0 || order->orderType == 8;
    bool assigned = false;
    for (unsigned int candidateOrdinal = 0; candidateOrdinal < candidateTiles.count && !assigned;
         ++candidateOrdinal) {
      short tileIndex = candidateTiles.values[candidateOrdinal];
      if (g_pGlobalMapState->TileHasCivilianOrderOfTypeAndField8(tileIndex, order->orderType, 10)) {
        continue;
      }
      TTerrainStateRecordView* tile = &g_pGlobalMapState->terrainStateTable[tileIndex];
      if (g_abGateFlagQualifies[tile->gateFlag] == 0) {
        continue;
      }
      for (short edge = 0; edge < 2; ++edge) {
        short resourceType = tile->resourceTypeByEdge[edge];
        if (resourceType != -1 &&
            g_anResourceTypeRequiredOrderType[resourceType] == order->orderType &&
            (g_abResourceTypeAlwaysQualifies[resourceType] != 0 ||
             static_cast<short>(tile->ownerNationTag04) == ownerContextAt04->nationSlot)) {
          short availableClass = g_pGlobalMapState->FindMaxResourceCapabilityValueForTile(
              tileIndex, useHighNibble, ownerContextAt04->nationSlot);
          char currentClass =
              g_pGlobalMapState->GetTileCivilianWorkOrderCostClassNibble(tileIndex, useHighNibble);
          if (availableClass > currentClass) {
            order->VTableSlot10(tileIndex);
            order->SetOrderModeSlot34(10, tileIndex);
            int cost = currentClass == 0 ? 0 : g_adwCivilianWorkOrderCostByClass[currentClass - 1];
            ownerContextAt04->AddToTreasury(-cost);
            assigned = true;
          }
        }
      }
    }
  }
}

// FUNCTION: IMPERIALISM 0x004c2010
void TCityInteriorMinister::RequestMissingCivilianOrderTypes() {
  bool hasOrderType[9];
  memset(hasOrderType, 0, sizeof(hasOrderType));
  TSortedList* trackedOrders = ownerContextAt04->trackedObjectList;
  int orderCount = trackedOrders->GetCount();
  for (int ordinal = 1; ordinal <= orderCount; ++ordinal) {
    TUnit* order = static_cast<TUnit*>(trackedOrders->GetEntryByOrdinal(ordinal));
    hasOrderType[order->orderType] = true;
  }
  hasOrderType[1] = true;
  hasOrderType[7] = true;

  short nationSlot = ownerContextAt04->nationSlot;
  for (short orderType = 8; orderType >= 0; --orderType) {
    if (g_pCityOrderCapabilityState->capRowsD467[nationSlot].flags[orderType] != 0 &&
        !hasOrderType[orderType]) {
      bool needed = false;
      for (short resourceType = 0; resourceType < 23; ++resourceType) {
        if (g_anResourceTypeRequiredOrderType[resourceType] == orderType &&
            civilianOrderDemandByResourceType194[resourceType] != 0) {
          needed = true;
        }
      }
      if (needed) {
        VTableSlot2D(orderType);
      }
    }
  }
}

// FUNCTION: IMPERIALISM 0x004c2120
void TCityInteriorMinister::AutoAssignProspectingOrdersByTileHeuristics() {
  if (g_pSimMgr->GetEconomicTurn() < 4) {
    return;
  }

  short nationSlot = ownerContextAt04->nationSlot;
  float relationScale[23];
  memset(relationScale, 0, sizeof(relationScale));
  for (short minorNation = 7; minorNation < 23; ++minorNation) {
    if (!g_pDiplomacyTurnStateManager->HasAnyWarRelationForNation(minorNation)) {
      float strongestStanding = 0.1f;
      for (short majorNation = 0; majorNation < 7; ++majorNation) {
        if (majorNation != nationSlot &&
            g_pDiplomacyTurnStateManager
                    ->relationStandingScoreMatrix79c[majorNation * 23 + minorNation] >
                strongestStanding) {
          strongestStanding = static_cast<float>(
              g_pDiplomacyTurnStateManager
                  ->relationStandingScoreMatrix79c[majorNation * 23 + minorNation]);
        }
      }
      relationScale[minorNation] =
          static_cast<float>(g_pDiplomacyTurnStateManager
                                 ->relationStandingScoreMatrix79c[nationSlot * 23 + minorNation]) /
          strongestStanding;
    }
  }

  int prospectingOrderCount = 0;
  int developerOrderCount = 0;
  TSortedList* trackedOrders = ownerContextAt04->trackedObjectList;
  int orderCount = trackedOrders->GetCount();
  for (int ordinal = 1; ordinal <= orderCount; ++ordinal) {
    TUnit* order = static_cast<TUnit*>(trackedOrders->GetEntryByOrdinal(ordinal));
    if (order->field_8 == 0) {
      if (order->orderType == 1) {
        ++prospectingOrderCount;
      } else if (order->orderType == 7) {
        ++developerOrderCount;
      }
    }
  }

  int affordableDeveloperCount = ownerContextAt04->ComputeAvailableDiplomacyBudget() / 2000;
  if (affordableDeveloperCount < 0) {
    affordableDeveloperCount = 0;
  }
  if (affordableDeveloperCount < developerOrderCount) {
    developerOrderCount = affordableDeveloperCount;
  }

  short* prospectingTiles = prospectingOrderCount == 0 ? 0 : new short[prospectingOrderCount];
  float* prospectingScores = prospectingOrderCount == 0 ? 0 : new float[prospectingOrderCount];
  for (int index = 0; index < prospectingOrderCount; ++index) {
    prospectingTiles[index] = -1;
    prospectingScores[index] = 0.0f;
  }
  short* developerTiles = developerOrderCount == 0 ? 0 : new short[developerOrderCount];
  float* developerScores = developerOrderCount == 0 ? 0 : new float[developerOrderCount];
  for (int developerInitIndex = 0; developerInitIndex < developerOrderCount; ++developerInitIndex) {
    developerTiles[developerInitIndex] = -1;
    developerScores[developerInitIndex] = 0.0f;
  }

  int resourceWeights[23];
  memset(resourceWeights, 0, sizeof(resourceWeights));
  resourceWeights[0] = orderTypeTable12A[0] + 1;
  resourceWeights[1] = orderTypeTable12A[1] + 1;
  resourceWeights[2] = orderTypeTable12A[2];
  resourceWeights[3] = orderTypeTable12A[3] + 5;
  resourceWeights[4] = orderTypeTable12A[4] + 5;
  bool hasOilProspecting =
      g_pCityOrderCapabilityState->orderCapRows277[nationSlot].techStatusByTechId[19] == 2;
  if (hasOilProspecting) {
    resourceWeights[6] = orderTypeTable12A[6] + 10;
  }

  char prospectableTerrain[8] = {0, 0, 1, 1, 0, 0, 0, 0};
  if (hasOilProspecting) {
    prospectableTerrain[4] = 1;
    prospectableTerrain[6] = 1;
  }

  for (short tileIndex = 0; tileIndex < 0x1950; ++tileIndex) {
    TTerrainStateRecordView* tile = &g_pGlobalMapState->terrainStateTable[tileIndex];
    short minorNation = static_cast<short>(tile->ownerNationTag04);
    if (minorNation <= 6 || minorNation >= 23) {
      continue;
    }
    TCountry* minor = g_apTerrainTypeDescriptorTable[minorNation];
    if (minor->encodedNationSlot != -1 && !minor->IsEncodedNationSlotMinus200Equal(nationSlot)) {
      continue;
    }
    if (g_abGateFlagQualifies[tile->gateFlag] == 0 ||
        g_pDiplomacyTurnStateManager->LookupOrderCompatibilityMatrixValue(nationSlot,
                                                                          minorNation) != 2 ||
        tile->secondaryOwnerNationTag18 != -1) {
      continue;
    }

    bool hasActiveProspecting = false;
    if (prospectableTerrain[tile->terrainType00] != 0) {
      for (TCivUnit* order = tile->firstCivilianOrder20; order != 0;
           order = static_cast<TCivUnit*>(order->nextOnTile)) {
        if (order->field_8 == 13 && order->remainingTurns24 == 8) {
          hasActiveProspecting = true;
        }
      }
      bool developmentBlocked = (tile->pendingDevelopmentFlag0d & (1 << nationSlot)) != 0 ||
                                (g_pGlobalMapState->field24 != 0 &&
                                 (tile->terrainType00 == 2 || tile->terrainType00 == 3 ||
                                  tile->terrainType00 == 4 || tile->terrainType00 == 6));
      if (!hasActiveProspecting && !developmentBlocked && prospectingOrderCount != 0 &&
          relationScale[minorNation] != 0.0f) {
        InsertScoredTileCandidateWithRandomTieBreak(relationScale[minorNation], tileIndex,
                                                    prospectingScores, prospectingTiles,
                                                    prospectingOrderCount);
      }
    }

    if (developerOrderCount != 0) {
      float score = 0.0f;
      for (short edge = 0; edge < 2; ++edge) {
        short resourceType = tile->resourceTypeByEdge[edge];
        if (resourceType != -1) {
          score += static_cast<float>(resourceWeights[resourceType]);
        }
      }
      score *= relationScale[minorNation];
      if (score != 0.0f) {
        InsertScoredTileCandidateWithRandomTieBreak(score, tileIndex, developerScores,
                                                    developerTiles, developerOrderCount);
      }
    }
  }

  int prospectingIndex = 0;
  int developerIndex = 0;
  for (int assignmentOrdinal = 1; assignmentOrdinal <= orderCount; ++assignmentOrdinal) {
    TUnit* order = static_cast<TUnit*>(trackedOrders->GetEntryByOrdinal(assignmentOrdinal));
    if (order->field_8 != 0) {
      continue;
    }
    if (order->orderType == 1 && prospectingIndex < prospectingOrderCount &&
        prospectingScores[prospectingIndex] != 0.0f) {
      short tileIndex = prospectingTiles[prospectingIndex++];
      order->SetOrderModeSlot34(8, tileIndex);
      order->VTableSlot10(tileIndex);
    } else if (order->orderType == 7 && developerIndex < developerOrderCount &&
               developerScores[developerIndex] != 0.0f) {
      short tileIndex = developerTiles[developerIndex++];
      order->SetOrderModeSlot34(13, tileIndex);
      order->VTableSlot10(tileIndex);
      ownerContextAt04->treasuryValue10 -=
          g_pGlobalMapState->CalculateDeveloperTilePurchaseCost(tileIndex);
    }
  }

  delete[] developerTiles;
  delete[] developerScores;
  delete[] prospectingTiles;
  delete[] prospectingScores;
}

// FUNCTION: IMPERIALISM 0x004c2a30
void TCityInteriorMinister::AutoAssignProspectingOrdersFromSeedTileNeighbors() {
  short nationSlot = ownerContextAt04->nationSlot;
  TSortedList* towns = ownerContextAt04->townMarkerList;
  int townCount = towns->GetCount();
  for (int townOrdinal = 1; townOrdinal <= townCount; ++townOrdinal) {
    TTown* town = static_cast<TTown*>(towns->GetEntryByOrdinal(townOrdinal));
    short regionSubtype =
        g_pGlobalMapState->terrainStateTable[town->tileIndex14].regionSubtypeTag05;
    for (short direction = 0; direction <= 6; ++direction) {
      short tileIndex = town->tileIndex14;
      if (direction < 6) {
        tileIndex =
            TMapMgr::GetWrappedHexNeighborTileIndexByDirection(town->tileIndex14, direction);
      }
      if (tileIndex == -1) {
        continue;
      }
      TTerrainStateRecordView* tile = &g_pGlobalMapState->terrainStateTable[tileIndex];
      if (static_cast<short>(tile->ownerNationTag04) != nationSlot ||
          tile->regionSubtypeTag05 != regionSubtype) {
        continue;
      }

      char currentClass = g_pGlobalMapState->GetTileCivilianWorkOrderCostClassNibble(tileIndex, 1);
      if (!g_pGlobalMapState->CheckTileProspectingDiscoveryCandidate(tileIndex) ||
          g_pGlobalMapState->TileHasCivilianOrderOfType(tileIndex, 0)) {
        continue;
      }
      short availableClass =
          g_pGlobalMapState->FindMaxResourceCapabilityValueForTile(tileIndex, 1, nationSlot);
      if (currentClass >= availableClass) {
        continue;
      }

      TUnit* idleProspector = 0;
      bool hasProspector = false;
      TSortedList* trackedOrders = ownerContextAt04->trackedObjectList;
      int orderCount = trackedOrders->GetCount();
      for (int orderOrdinal = 1; orderOrdinal <= orderCount && idleProspector == 0;
           ++orderOrdinal) {
        TUnit* order = static_cast<TUnit*>(trackedOrders->GetEntryByOrdinal(orderOrdinal));
        if (order->orderType == 0) {
          hasProspector = true;
          if (order->field_8 == 0) {
            idleProspector = order;
          }
        }
      }

      if (idleProspector != 0) {
        idleProspector->VTableSlot10(tileIndex);
        idleProspector->SetOrderModeSlot34(10, tileIndex);
      } else if (!hasProspector) {
        TCity* city = ownerContextAt04->city;
        bool shouldRequestProspector = true;
        if (city->buildOrderSlots[9]->quantityField04 == 0) {
          int pendingCount = city->trackedOrderList270->GetCount();
          for (int pendingOrdinal = 1; pendingOrdinal < pendingCount; ++pendingOrdinal) {
            TUnit* pendingOrder =
                static_cast<TUnit*>(city->trackedOrderList270->GetEntryByOrdinal(pendingOrdinal));
            if (pendingOrder->orderType == 0x22) {
              shouldRequestProspector = false;
            }
          }
        } else {
          shouldRequestProspector = false;
        }
        if (shouldRequestProspector) {
          VTableSlot2D(0);
        }
      }
    }
  }
}

// FUNCTION: IMPERIALISM 0x004c2d50
void TCityInteriorMinister::SeekLostTowns(char* primaryDistanceMap, char* secondaryDistanceMap) {
  CIterator townIterator(ownerContextAt04->townMarkerList);
  TTown* town = static_cast<TTown*>(townIterator.Reset());
  while (townIterator.More()) {
    if (town->transportLinkedFlag4c == 0 && (primaryDistanceMap[town->tileIndex14] < 12 ||
                                             (secondaryDistanceMap[town->tileIndex14] < 8 &&
                                              secondaryDistanceMap[town->tileIndex14] > 2))) {
      field3c = town->tileIndex14;
      return;
    }
    town = static_cast<TTown*>(townIterator.Advance());
  }
}

// FUNCTION: IMPERIALISM 0x004c2e10
void TCityInteriorMinister::ContinueRailheadProject(TUnit* builderOrder, char* primaryDistanceMap,
                                                    char* secondaryDistanceMap) {
  char primaryDistance = primaryDistanceMap[field3c];
  if ((primaryDistance == 0 || primaryDistance > 9) &&
      !g_pGlobalMapState->CanBuildPortAtTile(field3c)) {
    if (secondaryDistanceMap[field3c] < 3) {
      field3c = -1;
      return;
    }
    short previousTile;
    short sourceTile =
        TraceDescendingTileScoreGradientToSource(field3c, secondaryDistanceMap, &previousTile);
    if (g_pGlobalMapState->GetTileUnitEntryByOwner(sourceTile, ownerContextAt04->nationSlot) == 0) {
      builderOrder->VTableSlot10(sourceTile);
      builderOrder->SetOrderModeSlot34(7, sourceTile);
    }
    return;
  }

  if (primaryDistance != 1 && (!g_pGlobalMapState->CanBuildPortAtTile(field3c) ||
                               (primaryDistance != 0 && primaryDistance <= 6))) {
    short previousTile;
    short sourceTile =
        TraceDescendingTileScoreGradientToSource(field3c, primaryDistanceMap, &previousTile);
    unsigned short sourceFlags = g_pGlobalMapState->terrainStateTable[sourceTile].activeFlags1c;
    if ((sourceFlags & 4) != 0 && (sourceFlags & 0x10) == 0) {
      builderOrder->VTableSlot10(sourceTile);
      builderOrder->SetOrderModeSlot34(6, sourceTile);
    } else {
      builderOrder->VTableSlot10(previousTile);
      builderOrder->SetOrderModeSlot34(5, sourceTile);
    }
    return;
  }

  builderOrder->VTableSlot10(field3c);
  builderOrder->SetOrderModeSlot34(primaryDistance == 1 ? 6 : 7, field3c);

  TTown* projectedTown = new TTown();
  projectedTown->InitializeTownMarker(g_szEmptyString, field3c, primaryDistance != 1,
                                      ownerContextAt04->nationSlot);
  projectedTown->CalculateCityResources();
  for (short resourceType = 0; resourceType < 23; ++resourceType) {
    if (((resourceType >= 0 && resourceType <= 6) || (resourceType >= 17 && resourceType <= 22)) &&
        projectedTown->resourceYieldByType[resourceType] != 0) {
      orderTypeTableFC[resourceType] = 0;
    }
  }
  projectedTown->Free();
  field3c = -1;
}

// FUNCTION: IMPERIALISM 0x004c30b0
short __stdcall TraceDescendingTileScoreGradientToSource(short startTile, char* scoreMap,
                                                         short* previousTileOut) {
  short currentTile = startTile;
  short previousTile = startTile;
  short score = static_cast<signed char>(scoreMap[currentTile]);
  while (score != 1) {
    short direction = -1;
    if (currentTile != -1) {
      short desiredScore = static_cast<short>(score - 1);
      direction = 0;
      do {
        short neighbor = TMapMgr::GetWrappedHexNeighborTileIndexByDirection(currentTile, direction);
        if (neighbor != -1) {
          score = static_cast<signed char>(scoreMap[neighbor]);
        }
        ++direction;
      } while (score != desiredScore && direction < 6);
      --direction;
      previousTile = currentTile;
    }
    currentTile = TMapMgr::GetWrappedHexNeighborTileIndexByDirection(currentTile, direction);
  }
  *previousTileOut = previousTile;
  return currentTile;
}

// FUNCTION: IMPERIALISM 0x004c3170
void TCityInteriorMinister::StartRailheadProject(short resourceType, TShortintList* ownedTiles,
                                                 char* primaryDistanceMap,
                                                 char* secondaryDistanceMap) {
  TTown* projectedTown = new TTown();
  projectedTown->InitializeTownMarker("Bleah", 0, 1, ownerContextAt04->nationSlot);
  TLongintList* candidateTiles = new TLongintList();

  for (unsigned int ownedTileOrdinal = 0; ownedTileOrdinal < ownedTiles->count;
       ++ownedTileOrdinal) {
    short tileIndex = ownedTiles->values[ownedTileOrdinal];
    TTerrainStateRecordView* tile = &g_pGlobalMapState->terrainStateTable[tileIndex];
    if (tile->regionSubtypeTag05 != -1 ||
        !((primaryDistanceMap[tileIndex] > 0 && primaryDistanceMap[tileIndex] < 9) ||
          g_pGlobalMapState->CanBuildPortAtTile(tileIndex) ||
          (secondaryDistanceMap[tileIndex] > 2 && secondaryDistanceMap[tileIndex] < 6))) {
      continue;
    }

    bool hasConnectedNeighbor = false;
    short neighbors[6];
    TMapMgr::ComputeHexNeighborTileIndices(tileIndex, neighbors,
                                           g_pGlobalMapState->hexNeighborWrapHorizontally20);
    for (short direction = 0; direction < 6; ++direction) {
      if (neighbors[direction] != -1 &&
          (g_pGlobalMapState->terrainStateTable[neighbors[direction]].activeFlags1c & 0x10) != 0) {
        hasConnectedNeighbor = true;
      }
    }
    if (!hasConnectedNeighbor) {
      projectedTown->tileIndex14 = tileIndex;
      projectedTown->CalculateCityResources();
      if (projectedTown->resourceYieldByType[resourceType] != 0) {
        candidateTiles->InsertLast(tileIndex);
      }
    }
  }

  int candidateCount = candidateTiles->GetSize();
  if (candidateCount != 0) {
    short bestScore = -1;
    short bestTile = -1;
    for (int candidateOrdinal = 1; candidateOrdinal <= candidateCount; ++candidateOrdinal) {
      short tileIndex = static_cast<short>(candidateTiles->At(candidateOrdinal));
      short score = EvaluateResources(tileIndex);
      if (score > bestScore) {
        bestScore = score;
        bestTile = tileIndex;
      }
    }
    field3c = bestTile;
  }
  projectedTown->Free();
  candidateTiles->Free();
}

// FUNCTION: IMPERIALISM 0x004c3490
short TCityInteriorMinister::EvaluateResources(short tileIndex) {
  TCity* city = ownerContextAt04 == 0 ? 0 : ownerContextAt04->city;
  TTown* candidateTown = new TTown();
  candidateTown->InitializeTownMarker("Bleah", tileIndex, 1, ownerContextAt04->nationSlot);
  short* citySummary = city->GetCitySummaryRecordSlot74();
  candidateTown->CalculateCityResources();

  short score = 0;
  for (short resourceType = 0; resourceType < 7; ++resourceType) {
    score = static_cast<short>(score + candidateTown->resourceYieldByType[resourceType] *
                                           orderTypeTableFC[resourceType]);
  }

  short shortage = static_cast<short>(citySummary[17] - ownerContextAt04->needCurrentByType[17]);
  if (shortage > 0) {
    score = static_cast<short>(score + candidateTown->resourceYieldByType[17] * shortage);
  }
  shortage = static_cast<short>(citySummary[18] - ownerContextAt04->needCurrentByType[18]);
  if (shortage > 0) {
    score = static_cast<short>(score + candidateTown->resourceYieldByType[18] * shortage);
  }
  shortage = static_cast<short>(citySummary[20] - ownerContextAt04->needCurrentByType[20] -
                                ownerContextAt04->needCurrentByType[19]);
  if (shortage > 0) {
    score = static_cast<short>(
        score + (candidateTown->resourceYieldByType[20] + candidateTown->resourceYieldByType[21]) *
                    shortage);
  }
  if (candidateTown->transportLinkedFlag4c != 0) {
    score = static_cast<short>((score * 3) / 2);
  }
  candidateTown->Free();
  return score;
}

// FUNCTION: IMPERIALISM 0x004c3620
int TCityInteriorMinister::ScoreResource(int amount, int, int scorePerUnit) {
  return amount * scorePerUnit;
}

// FUNCTION: IMPERIALISM 0x004c3640
char* TCityInteriorMinister::CreateSeaDistanceMap(TShortintList* ownedTiles) {
  short nationSlot = ownerContextAt04->nationSlot;
  char allowedTerrain[8];
  allowedTerrain[0] = 1;
  allowedTerrain[1] = 1;
  allowedTerrain[2] =
      g_pCityOrderCapabilityState->orderCapRows277[nationSlot].techStatusByTechId[12] == 2;
  allowedTerrain[3] =
      g_pCityOrderCapabilityState->orderCapRows277[nationSlot].techStatusByTechId[23] == 2;
  allowedTerrain[4] =
      g_pCityOrderCapabilityState->orderCapRows277[nationSlot].techStatusByTechId[6] == 2;
  allowedTerrain[5] = 0;
  allowedTerrain[6] = 1;
  allowedTerrain[7] = 1;

  char* distanceMap = new char[0x1950];
  memset(distanceMap, 0, 0x1950);
  char* transportMap = 0;
  ownerContextAt04->BuildTransportLinkedInfluenceMap(&transportMap);

  int remaining = ownedTiles->count;
  unsigned int ordinal;
  for (ordinal = 0; ordinal < ownedTiles->count; ++ordinal) {
    short tileIndex = ownedTiles->values[ordinal];
    if (transportMap[tileIndex] != 0) {
      distanceMap[tileIndex] = 1;
      --remaining;
    }
  }
  delete[] transportMap;

  while (remaining != 0) {
    short previousRemaining = static_cast<short>(remaining);
    for (ordinal = 0; ordinal < ownedTiles->count; ++ordinal) {
      short tileIndex = ownedTiles->values[ordinal];
      short terrainType = g_pGlobalMapState->terrainStateTable[tileIndex].terrainType00;
      if (distanceMap[tileIndex] == 0 && allowedTerrain[terrainType] != 0) {
        short neighbors[6];
        TMapMgr::ComputeHexNeighborTileIndices(tileIndex, neighbors,
                                               g_pGlobalMapState->hexNeighborWrapHorizontally20);
        char bestNeighborDistance = 0;
        for (short direction = 0; direction < 6; ++direction) {
          char neighborDistance =
              neighbors[direction] == -1 ? 0 : distanceMap[neighbors[direction]];
          if (neighborDistance != 0 &&
              (bestNeighborDistance == 0 || neighborDistance < bestNeighborDistance)) {
            bestNeighborDistance = neighborDistance;
          }
        }
        if (bestNeighborDistance != 0) {
          distanceMap[tileIndex] = static_cast<char>(bestNeighborDistance + 1);
          --remaining;
        }
      }
    }
    if (previousRemaining == remaining) {
      remaining = 0;
    }
  }
  return distanceMap;
}

// FUNCTION: IMPERIALISM 0x004c3910
char* TCityInteriorMinister::BuildFrogCityDistanceMapFromReachableSeaCandidates(
    TShortintList* ownedTiles) {
  short nationSlot = ownerContextAt04->nationSlot;
  char allowedTerrain[8];
  allowedTerrain[0] = 1;
  allowedTerrain[1] = 1;
  allowedTerrain[2] =
      g_pCityOrderCapabilityState->orderCapRows277[nationSlot].techStatusByTechId[11] == 2;
  allowedTerrain[3] =
      g_pCityOrderCapabilityState->orderCapRows277[nationSlot].techStatusByTechId[19] == 2;
  allowedTerrain[4] =
      g_pCityOrderCapabilityState->orderCapRows277[nationSlot].techStatusByTechId[5] == 2;
  allowedTerrain[5] = 0;
  allowedTerrain[6] = 1;
  allowedTerrain[7] = 1;

  char* distanceMap = new char[0x1950];
  memset(distanceMap, 0, 0x1950);
  int remaining = ownedTiles->count;
  unsigned int ordinal;
  for (ordinal = 0; ordinal < ownedTiles->count; ++ordinal) {
    short tileIndex = ownedTiles->values[ordinal];
    TTerrainStateRecordView* tile = &g_pGlobalMapState->terrainStateTable[tileIndex];
    if (tile->regionSubtypeTag05 == -1 && allowedTerrain[tile->terrainType00] != 0 &&
        g_pGlobalMapState->HasReachableSeaTileOutsideActiveType3Or4DiplomaticMask(tileIndex)) {
      distanceMap[tileIndex] = 1;
      --remaining;
    }
  }

  while (remaining != 0) {
    short previousRemaining = static_cast<short>(remaining);
    for (ordinal = 0; ordinal < ownedTiles->count; ++ordinal) {
      short tileIndex = ownedTiles->values[ordinal];
      short terrainType = g_pGlobalMapState->terrainStateTable[tileIndex].terrainType00;
      if (distanceMap[tileIndex] == 0 && allowedTerrain[terrainType] != 0) {
        short neighbors[6];
        TMapMgr::ComputeHexNeighborTileIndices(tileIndex, neighbors,
                                               g_pGlobalMapState->hexNeighborWrapHorizontally20);
        char bestNeighborDistance = 0;
        for (short direction = 0; direction < 6; ++direction) {
          char neighborDistance =
              neighbors[direction] == -1 ? 0 : distanceMap[neighbors[direction]];
          if (neighborDistance != 0 &&
              (bestNeighborDistance == 0 || neighborDistance < bestNeighborDistance)) {
            bestNeighborDistance = neighborDistance;
          }
        }
        if (bestNeighborDistance != 0) {
          distanceMap[tileIndex] = static_cast<char>(bestNeighborDistance + 1);
          --remaining;
        }
      }
    }
    if (previousRemaining == remaining) {
      remaining = 0;
    }
  }
  return distanceMap;
}

// FUNCTION: IMPERIALISM 0x004c3c00
void TCityInteriorMinister::RebalanceCityOrderAllocationTargets(TCity* city) {
  short* citySummary = city->GetCitySummaryRecordSlot74();
  short unfilled = 0;
  short allocated = RequestResource(17, citySummary[17], 7);
  if (allocated < citySummary[17]) {
    unfilled = static_cast<short>(citySummary[17] - allocated);
  }
  allocated = RequestResource(18, citySummary[18], 7);
  if (allocated < citySummary[18]) {
    unfilled = static_cast<short>(unfilled + citySummary[18] - allocated);
  }
  short firstAllocation = RequestResource(19, citySummary[20], 1);
  if (firstAllocation < citySummary[20]) {
    short secondAllocation = RequestResource(20, citySummary[20], 7);
    if (firstAllocation + secondAllocation < citySummary[20]) {
      unfilled =
          static_cast<short>(unfilled + citySummary[20] - firstAllocation - secondAllocation);
    }
  }

  if (unfilled != 0) {
    unfilled = static_cast<short>(unfilled - RequestResource(17, unfilled, 9));
    if (unfilled != 0) {
      unfilled = static_cast<short>(unfilled - RequestResource(18, unfilled, 9));
    }
    if (unfilled != 0) {
      unfilled = static_cast<short>(unfilled - RequestResource(20, unfilled, 9));
    }
    if (unfilled != 0) {
      RequestResource(19, unfilled, 9);
    }
  }

  RequestResource(22, ownerContextAt04->needCurrentByType[22], 1);
  for (short resourceType = 7; resourceType < 17; ++resourceType) {
    RequestResource(resourceType,
                    static_cast<short>(citySummary[resourceType] +
                                       ownerContextAt04->needCurrentByType[resourceType]),
                    1);
  }
}

// FUNCTION: IMPERIALISM 0x004c3d60
undefined TCityInteriorMinister::ProcessCityOrderStateTickAndApplyCapabilitySelection() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004c40c0
undefined TCityInteriorMinister::RebalanceCitySupportAndLaborAllocations() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004c4370
undefined TCityInteriorMinister::ChooseAndMarkNextCityProductionCommand() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004c4690
undefined TCityInteriorMinister::ComputeCityProductionCommandLimitsFromBuildingOutputs() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004c4840
undefined TCityInteriorMinister::RebuildCityOrderCommandAvailabilityAndPriorityCycle() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004c49f0
undefined TCityInteriorMinister::UpdateMinisterProductionMetricsForResourceIndex() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004c4d40
undefined TCityInteriorMinister::CityMinisterSlot44() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004c4e60
undefined TCityInteriorMinister::CityMinisterSlot45() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004c4f90
int TCityInteriorMinister::GetAverageDevelopmentOrderAllocation() {
  short total = 0;
  for (int index = 0; index < 16; ++index) {
    total = static_cast<short>(total + orderShortTableBA[index]);
  }
  return total / 10;
}

// FUNCTION: IMPERIALISM 0x004c4fe0
short TCityInteriorMinister::RequestResource(short resourceType, short requestedAmount,
                                             short flags) {
  TGreatPower* owner = ownerContextAt04;
  TCity* city = owner == 0 ? 0 : owner->city;
  short remaining = requestedAmount;
  short* cityStock = &city->cityStockCottonB6;
  if ((flags & 8) == 0) {
    if (cityStock[resourceType] >= requestedAmount) {
      return requestedAmount;
    }
    remaining = static_cast<short>(requestedAmount - cityStock[resourceType]);
  }

  short availableCapacity = static_cast<short>(owner->needCapA6 - owner->needsOverCapFlag);
  short currentTarget = owner->needTargetByType[resourceType];
  short availableSupply =
      static_cast<short>(owner->needCurrentByType[resourceType] - currentTarget);
  if (availableSupply > remaining) {
    availableSupply = remaining;
  }

  short unavailableSupply = 0;
  if (availableSupply > availableCapacity) {
    unavailableSupply = static_cast<short>(availableSupply - availableCapacity);
    if ((flags & 1) != 0) {
      orderMetricTable40[51] = static_cast<short>(orderMetricTable40[51] + unavailableSupply);
    }
    owner->UpdateNeedTargetAndAccumulateOverCap(
        resourceType, static_cast<short>(currentTarget + availableCapacity));
    if (resourceType == 22) {
      owner->treasuryValue10 += availableCapacity * 200;
    } else if (resourceType == 21) {
      owner->treasuryValue10 += availableCapacity * 500;
    } else {
      cityStock[resourceType] = static_cast<short>(cityStock[resourceType] + availableCapacity);
      city->VerifyStocks();
    }
    remaining = static_cast<short>(remaining - availableCapacity);
  } else {
    owner->UpdateNeedTargetAndAccumulateOverCap(
        resourceType, static_cast<short>(currentTarget + availableSupply));
    if (resourceType == 22) {
      owner->treasuryValue10 += availableSupply * 500;
    } else {
      cityStock[resourceType] = static_cast<short>(cityStock[resourceType] + availableSupply);
      city->VerifyStocks();
    }
    remaining = static_cast<short>(remaining - availableSupply);
  }

  if (remaining == 0) {
    return requestedAmount;
  }
  if ((flags & 2) != 0) {
    short shortfall = static_cast<short>(remaining - unavailableSupply);
    if (shortfall > 0) {
      orderMetricTable40[resourceType] =
          static_cast<short>(orderMetricTable40[resourceType] + shortfall);
    }
  }
  return static_cast<short>(requestedAmount - remaining);
}

// FUNCTION: IMPERIALISM 0x004c5240
undefined TCityInteriorMinister::SeekResources(TShortintList*, char*) {
  return 0;
}

TCityInteriorMinister::~TCityInteriorMinister() {}
