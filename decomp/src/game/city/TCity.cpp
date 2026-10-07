#include "game/city/TCity.h"
#include "game/resource_domain_types.h"
#include "game/navy_order.h"

#include <stdlib.h>

#include "game/nation/TGreatPower.h"
#include "game/city/TCapacityOrder.h"
#include "game/tactical_ui/TCityTask.h"
#include "game/city/TExpansionOrder.h"
#include "game/core/stream_byteswap.h"
#include "game/city/TFoodProcessingOrder.h"
#include "game/city/TItemOrder.h"
#include "game/city/TOrItemOrder.h"
#include "game/city/TPopGrowthOrder.h"
#include "game/city/TPowerPlantOrder.h"
#include "game/city/TProductionOrder.h"
#include "game/city/TShipOrder.h"
#include "game/tactical_ui/TShipBuildingTask.h"
#include "game/ui_core/TSortedList.h"
#include "game/tactical_ui/TTaskList.h"
#include "game/city/TTrainingOrder.h"
#include "game/city/TTown.h"
#include "game/city/TUnitOrder.h"
#include "game/ui_core/TViewMgr.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/ui_core/TPtrList.h"
#include "game/globals/global_types.h"
#include "game/globals/city_globals.h"
#include "game/globals/navy_globals.h"
#include "game/globals/shared_globals.h"
#include "game/mfc.h"
#include "game/gfx/ui_invalidation_guard.h"
#include "game/navy/TShip.h"
#include "game/core/TStream.h"
#include "game/tactical_ui/TTechMgr.h"
#include "game/nation_stream_serialization.h"

static const char kUCityCppPath[] = "D:\\Ambit\\Cross\\UCity.cpp";
static const unsigned int kAddrClassDescTCity = 0x0064f338;

IMPLEMENT_DYNCREATE(TCity, TObject)

// FUNCTION: IMPERIALISM 0x004b24b0
TCity::TCity() {
  homeTownMarker = 0;
  trackedOrderList = 0;
  eventQueue = 0;
  for (int productionSlot = 0; productionSlot < 16; ++productionSlot) {
    productionOrderTable[productionSlot] = 0;
    productionAccum[productionSlot] = 0;
    productionFlags[productionSlot] = 0;
  }
  populationGrowthPenaltyTicks = 0;
  foodSubstitutionCount = 0;
  starvationPopulationLoss = 0;
}

// FUNCTION: IMPERIALISM 0x004b2550
TCity::~TCity() {}

// FUNCTION: IMPERIALISM 0x004b2570
void TCity::ICity(TGreatPower* ownerNation) {
  this->ownerNation = ownerNation;
  powerPlantUpgradeQueuedFlag = false;
  memset(reservedByType, 0, sizeof(reservedByType));
  memset(stockByType, 0, sizeof(stockByType));
  memset(unmetResourceRetryCount, 0,
         sizeof(unmetResourceRetryCount) + sizeof(consumedProductionInputByType));

  for (int productionSlot = 0; productionSlot < 16; ++productionSlot) {
    productionAccum[productionSlot] =
        static_cast<short>(productionAccum[productionSlot] - productionOrderTable[productionSlot]);
    productionOrderTable[productionSlot] = 0;
    productionFlags[productionSlot] = 0;
    buildingWindowX[productionSlot] = 0;
    buildingWindowY[productionSlot] = 0;
  }

  int regionCount = ownerNation->ownedRegionList->GetSize();
  int regionsPerCapacity = ownerNation->pendingActionStatus.byAction[9] >= '3' ? 3 : 4;
  short capacity = regionCount / regionsPerCapacity;
  productionAccum[15] = capacity > 1 ? capacity : 1;

  if (g_pSimMgr->difficultyLevel < kDifficultyNormal && ownerNation->diplomacyEligibility != 0) {
    static const short kInitialProductionBySlot[6] = {2, 1, 2, 1, 2, 1};
    for (int productionSlot = 0; productionSlot < 6; ++productionSlot) {
      short initialProduction = kInitialProductionBySlot[productionSlot];
      productionAccum[productionSlot] =
          static_cast<short>(productionAccum[productionSlot] +
                             (initialProduction - productionOrderTable[productionSlot]));
      productionOrderTable[productionSlot] = initialProduction;
    }
  }

  lowProductionFlag = false;
  lowStockFlag = false;
  serializedState = 0;
  powerAvailable = 0;

  productionSummary = new TPopulationMgr();
  productionSummary->IPopulationMgr(this);
  memset(orderSlots, 0, 244);

  TItemOrder* itemOrder = new TItemOrder();
  itemOrder->IItemOrder(this, 0x0b, 4, 3, 2);
  orderSlots[11] = itemOrder;

  itemOrder = new TItemOrder();
  itemOrder->IItemOrder(this, 0x0f, 0x0b, -1, 3);
  orderSlots[15] = itemOrder;

  itemOrder = new TItemOrder();
  itemOrder->IItemOrder(this, 0x10, 0x0b, -1, 3);
  orderSlots[16] = itemOrder;

  itemOrder = new TItemOrder();
  itemOrder->IItemOrder(this, 9, 2, -1, 4);
  orderSlots[9] = itemOrder;

  itemOrder = new TItemOrder();
  itemOrder->IItemOrder(this, 10, 2, -1, 4);
  orderSlots[10] = itemOrder;

  itemOrder = new TItemOrder();
  itemOrder->IItemOrder(this, 0x0c, 6, -1, 6);
  orderSlots[12] = itemOrder;

  itemOrder = new TItemOrder();
  itemOrder->IItemOrder(this, 0x0d, 8, -1, 1);
  orderSlots[13] = itemOrder;

  itemOrder = new TItemOrder();
  itemOrder->IItemOrder(this, 0x0e, 9, -1, 5);
  orderSlots[14] = itemOrder;

  TOrItemOrder* orItemOrder = new TOrItemOrder();
  orItemOrder->IOrItemOrder(this, 8, 1, 0, 0);
  orderSlots[8] = orItemOrder;

  int profileIndex;
  for (profileIndex = 0; profileIndex < 9; ++profileIndex) {
    short* profile = g_aInitialCityRecruitmentOrderProfiles[profileIndex];
    TUnitOrder* unitOrder = new TUnitOrder();
    unitOrder->IUnitOrder(this, profile[0], profile[1], profile[2], profile[3], profile[4],
                          profile[5], profile[6], 0);
    buildOrderSlots[9 + profileIndex] = unitOrder;
  }

  TUnitOrder* unitOrder = new TUnitOrder();
  unitOrder->IUnitOrder(this, 0x18, 0x10, 2, -1, 0, 5000, 4, 1);
  buildOrderSlots[7] = unitOrder;

  for (profileIndex = 1; profileIndex <= 7; ++profileIndex) {
    short* profile = g_aUnitOrderCostProfileByAbilityId[profileIndex];
    unitOrder = new TUnitOrder();
    unitOrder->IUnitOrder(this, profile[0], profile[1], profile[2], profile[3], profile[4],
                          profile[5], profile[6], 1);
    buildOrderSlots[profileIndex - 1] = unitOrder;
  }

  TPowerPlantOrder* powerPlantOrder = new TPowerPlantOrder();
  powerPlantOrder->IPowerPlantOrder(this);
  trailingOrderSlots[1] = powerPlantOrder;

  TFoodProcessingOrder* foodOrder = new TFoodProcessingOrder();
  foodOrder->IFoodProcessingOrder(this);
  orderSlots[7] = foodOrder;

  TTrainingOrder* trainingOrder = new TTrainingOrder();
  trainingOrder->ITrainingOrder(this, 1);
  orderSlots[23] = trainingOrder;

  trainingOrder = new TTrainingOrder();
  trainingOrder->ITrainingOrder(this, 2);
  orderSlots[24] = trainingOrder;

  for (int shipSlot = 0; shipSlot < 8; ++shipSlot) {
    TShipOrder* shipOrder = new TShipOrder();
    shipOrder->IProductionOrder(this, 0);
    shipOrderSlots[shipSlot] = shipOrder;
  }
  shipOrderSlots[0]->resourceTypeIndex = 1;
  shipOrderSlots[1]->resourceTypeIndex = 2;
  shipOrderSlots[4]->resourceTypeIndex = 3;
  shipOrderSlots[5]->resourceTypeIndex = 4;

  for (int expansionSlot = 0; expansionSlot < 7; ++expansionSlot) {
    TExpansionOrder* expansionOrder = new TExpansionOrder();
    expansionOrder->IExpansionOrder(this, static_cast<short>(expansionSlot), 9, 0x0b, 0x0e);
    trailingOrderSlots[2 + expansionSlot] = expansionOrder;
  }

  TCapacityOrder* capacityOrder = new TCapacityOrder();
  capacityOrder->ICapacityOrder(this, 0x0e, 9, 0x0b, 0x0e);
  trailingOrderSlots[0] = capacityOrder;

  TPopGrowthOrder* populationGrowthOrder = new TPopGrowthOrder();
  populationGrowthOrder->IPopGrowthOrder(this);
  trailingOrderSlots[9] = populationGrowthOrder;

  trackedOrderList = new TTaskList();
  trackedOrderList->ITaskList();
  eventQueue = new TPtrList();
  eventQueue->recordSize = 4;

  cityPhaseCounter = 0;
  memset(militaryRecruitCountByKind, 0, sizeof(militaryRecruitCountByKind));
  memset(civilianRecruitCountByKind, 0, sizeof(civilianRecruitCountByKind));
  memset(orderCountByType, 0, sizeof(orderCountByType));
  rollingItemProductionScore = 0;
}

// FUNCTION: IMPERIALISM 0x004b30a0
void TCity::ReadFrom(TStream* stream) {
  int productionSlotCount = 16;
  int orderSlotCount = 61;
  if (g_nSaveFormatVersion < 0x13) {
    productionSlotCount = 15;
    orderSlotCount = 60;
  }

  TObject::ReadFrom(stream);
  stream->ReadBytes(&powerPlantUpgradeQueuedFlag, 1);
  stream->ReadBytes(&lowProductionFlag, 1);
  stream->ReadBytes(&lowStockFlag, 1);
  stream->ReadBytes(productionFlags, productionSlotCount);
  stream->ReadBytes(&foodSubstitutionCount, 2);
  stream->ReadBytes(&starvationPopulationLoss, 2);
  stream->ReadBytes(&serializedState, 2);
  stream->ReadBytes(&cityPhaseCounter, 2);
  stream->ReadBytes(&powerAvailable, 2);
  stream->ReadBytes(militaryRecruitCountByKind, sizeof(militaryRecruitCountByKind));
  SwapShortArrayBytes(militaryRecruitCountByKind, kMilitaryUnitKindCount);
  stream->ReadBytes(civilianRecruitCountByKind, sizeof(civilianRecruitCountByKind));
  SwapShortArrayBytes(civilianRecruitCountByKind, kCivilianUnitKindCount);
  stream->ReadBytes(orderCountByType, sizeof(orderCountByType));
  SwapShortArrayBytes(orderCountByType, 14);
  stream->ReadBytes(stockByType, sizeof(stockByType));
  SwapShortArrayBytes(stockByType, kResourceKindCount);
  stream->ReadBytes(productionOrderTable, productionSlotCount * 2);
  SwapShortArrayBytes(productionOrderTable, productionSlotCount);
  stream->ReadBytes(productionAccum, productionSlotCount * 2);
  SwapShortArrayBytes(productionAccum, productionSlotCount);
  stream->ReadBytes(unmetResourceRetryCount, sizeof(unmetResourceRetryCount));
  SwapShortArrayBytes(unmetResourceRetryCount, 23);
  stream->ReadBytes(reservedByType, sizeof(reservedByType));
  SwapShortArrayBytes(reservedByType, 23);
  stream->ReadBytes(buildingWindowX, productionSlotCount * 2);
  SwapShortArrayBytes(buildingWindowX, productionSlotCount);
  stream->ReadBytes(buildingWindowY, productionSlotCount * 2);
  SwapShortArrayBytes(buildingWindowY, productionSlotCount);
  stream->ReadBytes(consumedProductionInputByType, sizeof(consumedProductionInputByType));
  SwapShortArrayBytes(consumedProductionInputByType, 23);

  if (g_nSaveFormatVersion > 0x27) {
    stream->ReadBytes(&rollingItemProductionScore, 4);
  } else {
    rollingItemProductionScore = 0;
  }

  productionSummary->ReadFrom(stream);
  TProductionOrder** orderCursor = orderSlots;
  for (int orderSlot = 0; orderSlot < orderSlotCount; ++orderSlot) {
    if (*orderCursor != 0) {
      (*orderCursor)->ReadFrom(stream);
    }
    ++orderCursor;
  }

  int oldTaskCount = trackedOrderList->GetCount();
  for (int oldTaskOrdinal = 1; oldTaskOrdinal <= oldTaskCount; ++oldTaskOrdinal) {
    TObject* oldTask = static_cast<TObject*>(trackedOrderList->GetEntryByOrdinal(1));
    trackedOrderList->RemoveAtOrdinal(1);
    if (oldTask != 0) {
      oldTask->Free();
    }
  }
  trackedOrderList->ReadFrom(stream);

  int taskCount;
  stream->ReadBytes(&taskCount, 4);
  for (int taskOrdinal = 1; taskOrdinal <= taskCount; ++taskOrdinal) {
    unsigned char taskKind;
    stream->ReadBytes(&taskKind, 1);
    TCityTask* task;
    if (taskKind == 1) {
      task = new TCityTask();
      task->ICityTask(0, this, 0);
      task->ReadFrom(stream);
    } else {
      TShipBuildingTask* shipTask = new TShipBuildingTask();
      shipTask->IShipBuildingTask(0, this, 0);
      shipTask->ReadFrom(stream);
      task = shipTask;
    }
    trackedOrderList->AddTask(task);
  }
  eventQueue->ReadFrom(stream);
}

// FUNCTION: IMPERIALISM 0x004b35d0
void TCity::WriteTo(TStream* stream) {
  TObject::WriteTo(stream);
  stream->WriteBytes(&powerPlantUpgradeQueuedFlag, 1);
  stream->WriteBytes(&lowProductionFlag, 1);
  stream->WriteBytes(&lowStockFlag, 1);
  stream->WriteBytes(productionFlags, sizeof(productionFlags));
  stream->WriteBytes(&foodSubstitutionCount, 2);
  stream->WriteBytes(&starvationPopulationLoss, 2);
  stream->WriteBytes(&serializedState, 2);
  stream->WriteBytes(&cityPhaseCounter, 2);
  stream->WriteBytes(&powerAvailable, 2);
  WriteShortArrayElems(stream, militaryRecruitCountByKind, kMilitaryUnitKindCount);
  WriteShortArrayElems(stream, civilianRecruitCountByKind, kCivilianUnitKindCount);
  WriteShortArrayElems(stream, orderCountByType, 14);
  WriteShortArrayElems(stream, stockByType, kResourceKindCount);
  WriteShortArrayElems(stream, productionOrderTable, 16);
  WriteShortArrayElems(stream, productionAccum, 16);
  WriteShortArrayElems(stream, unmetResourceRetryCount, 23);
  WriteShortArrayElems(stream, reservedByType, 23);

  for (int productionSlot = 0; productionSlot < 16; ++productionSlot) {
    short value = buildingWindowX[productionSlot];
    SwapFirstTwoBytesInBuffer(&value);
    stream->WriteBytes(&value, 2);
  }
  for (int accumulatedProductionSlot = 0; accumulatedProductionSlot < 16;
       ++accumulatedProductionSlot) {
    short value = buildingWindowY[accumulatedProductionSlot];
    SwapFirstTwoBytesInBuffer(&value);
    stream->WriteBytes(&value, 2);
  }
  WriteByteSwappedShortArrayToStream(stream, consumedProductionInputByType, 0x17);

  stream->WriteBytes(&rollingItemProductionScore, 4);
  productionSummary->WriteTo(stream);
  TProductionOrder** orderCursor = orderSlots;
  for (int orderSlot = 0; orderSlot < 61; ++orderSlot) {
    if (*orderCursor != 0) {
      (*orderCursor)->WriteTo(stream);
    }
    ++orderCursor;
  }

  trackedOrderList->WriteTo(stream);
  int taskCount = trackedOrderList->GetCount();
  stream->WriteBytes(&taskCount, 4);
  for (int taskOrdinal = 1; taskOrdinal <= taskCount; ++taskOrdinal) {
    TObject* task = static_cast<TObject*>(trackedOrderList->GetEntryByOrdinal(taskOrdinal));
    task->WriteTo(stream);
  }
  eventQueue->WriteTo(stream);
}

// FUNCTION: IMPERIALISM 0x004b3a60
void TCity::Free() {
  if (productionSummary != 0) {
    productionSummary->Free();
  }
  productionSummary = 0;
  TProductionOrder** orderSlot = orderSlots;
  for (int remaining = 0; remaining < 61; ++remaining) {
    if (*orderSlot != 0) {
      (*orderSlot)->Free();
    }
    *orderSlot = 0;
    ++orderSlot;
  }
  if (trackedOrderList != 0) {
    trackedOrderList->FreeList();
  }
  trackedOrderList = 0;
  if (eventQueue != 0) {
    eventQueue->FreeList();
  }
  eventQueue = 0;
  delete this;
}

// FUNCTION: IMPERIALISM 0x004b3b20
void TCity::SetSelectedTownMarker(TTown* townMarker) {
  homeTownMarker = townMarker;
}

// FUNCTION: IMPERIALISM 0x004b3b40
void TCity::EndCityPhase() {
  int i;
  ++cityPhaseCounter;
  VerifyStocks();

  if (ownerNation->diplomacyEligibility == 0) {
    for (i = 0; i < kResourceKindCount; ++i) {
      stockByType[i] = static_cast<short>(stockByType[i] + reservedByType[i]);
    }
  }
  VerifyStocks();

  for (i = 0; i < kResourceKindCount; ++i) {
    stockByType[i] = static_cast<short>(stockByType[i] + consumedProductionInputByType[i]);
    consumedProductionInputByType[i] = 0;
  }

  int previousProductionScore = rollingItemProductionScore;
  rollingItemProductionScore = 0;
  for (i = 0; i < 25; ++i) {
    if (orderSlots[i] != 0) {
      orderSlots[i]->Produce();
    }
  }
  rollingItemProductionScore = (previousProductionScore * 9) / 10 + rollingItemProductionScore * 10;

  for (i = 9; i < 18; ++i) {
    if (buildOrderSlots[i] != 0) {
      buildOrderSlots[i]->Produce();
    }
  }

  for (i = 0; i < 10; ++i) {
    if (trailingOrderSlots[i] != 0) {
      trailingOrderSlots[i]->Produce();
    }
  }

  if (powerPlantUpgradeQueuedFlag) {
    powerPlantUpgradeQueuedFlag = false;
    productionAccum[11] =
        static_cast<short>(productionAccum[0x0b] + (999 - productionOrderTable[11]));
    productionOrderTable[11] = 999;
  }

  for (i = 0; i < kResourceKindCount; ++i) {
    if (stockByType[i] > 9999) {
      stockByType[i] = 9999;
    }
  }

  powerAvailable = 0;
  productionSummary->StartProductionPhase();
  trailingOrderSlots[1]->Restock();

  for (i = 8; i < 17; ++i) {
    orderSlots[i]->Restock();
  }

  short capacity;
  if (ownerNation->pendingActionStatus.byAction[9] >= '3') {
    int regionCapacity = ownerNation->ownedRegionList->GetSize() / 3;
    if (regionCapacity > 1) {
      capacity = static_cast<short>(ownerNation->ownedRegionList->GetSize() / 3);
    } else {
      capacity = 1;
    }
  } else {
    int regionCapacity = ownerNation->ownedRegionList->GetSize() / 4;
    if (regionCapacity > 1) {
      capacity = static_cast<short>(ownerNation->ownedRegionList->GetSize() / 4);
    } else {
      capacity = 1;
    }
  }
  productionAccum[15] = capacity;
  productionAccum[14] = productionOrderTable[14];
  g_pViewMgr->UpdateCityScreen();
}

// FUNCTION: IMPERIALISM 0x004b3de0
void TCity::PredictedNeeds() {
  lowStockFlag = productionSummary->strength >= 2;
  short shortageCount = 3;
  if (productionAccum[4] > 0) {
    shortageCount = 2;
  }
  if (productionAccum[2] > 0) {
    --shortageCount;
  }
  if (productionAccum[0] > 0) {
    --shortageCount;
  }
  lowProductionFlag = shortageCount < 2;
  ownerNation->UpdateCountryStockpile(stockByType);
}

// FUNCTION: IMPERIALISM 0x004b3e70
void TCity::ProduceUnits() {
  int i;
  for (i = 0; i < 8; ++i) {
    if (shipOrderSlots[i] != 0) {
      CString scratch;
      short pendingCount = shipOrderSlots[i]->quantity;
      short tileId = shipOrderSlots[i]->resourceTypeIndex;
      if (pendingCount != 0) {
        if (TShip::GetTypeFirepower(tileId) == 0) {
          ownerNation->AnnounceLater(1, tileId, pendingCount);
        } else {
          ownerNation->AnnounceLater(0, tileId, pendingCount);
        }
      }
    }
  }

  for (i = 0; i < 18; ++i) {
    if (buildOrderSlots[i] != 0) {
      buildOrderSlots[i]->Produce();
    }
  }

  for (i = 0; i < 8; ++i) {
    if (shipOrderSlots[i] != 0) {
      shipOrderSlots[i]->Produce();
    }
  }
}

// FUNCTION: IMPERIALISM 0x004b3fb0
void TCity::AddPurchasedItems(short* needVector) {
  int i;
  for (i = kResourceCotton; i <= kResourceOil; ++i) {
    stockByType[i] = static_cast<short>(stockByType[i] + needVector[i]);
  }
  for (i = kResourceFood; i < kResourceClothing; ++i) {
    stockByType[i] = static_cast<short>(stockByType[i] + needVector[i]);
  }
  for (i = kResourceClothing; i <= kResourceArms; ++i) {
    stockByType[i] = static_cast<short>(stockByType[i] + needVector[i]);
  }
}

// FUNCTION: IMPERIALISM 0x004b4040
void TCity::AddTransportedItems(short* amounts) {
  for (int i = 0; i < kResourceKindCount; ++i) {
    stockByType[i] = static_cast<short>(stockByType[i] + amounts[i]);
  }
  stockByType[kResourceGold] = 0;
  stockByType[kResourceGems] = 0;
}

// FUNCTION: IMPERIALISM 0x004b4090
void TCity::AddTransportedItems() {
  for (int i = 0; i < kResourceKindCount; ++i) {
    stockByType[i] = static_cast<short>(stockByType[i] + ownerNation->needTargetByType[i]);
  }
  stockByType[kResourceGold] = 0;
  stockByType[kResourceGems] = 0;
}

// FUNCTION: IMPERIALISM 0x004b40e0
short TCity::DirectTransport(short needIndex, short amount) {
  TGreatPower* owner = ownerNation;
  short surplus =
      static_cast<short>(owner->needCurrentByType[needIndex] - owner->needTargetByType[needIndex]);
  if (surplus < amount) {
    amount = surplus;
  }
  if (static_cast<short>(owner->transportCapacity - owner->reservedTransportCapacity) < amount) {
    amount = static_cast<short>(owner->transportCapacity - owner->reservedTransportCapacity);
  }
  stockByType[needIndex] = static_cast<short>(stockByType[needIndex] + amount);
  ownerNation->UpdateNeedTargetAndAccumulateOverCap(
      needIndex, static_cast<short>(owner->needTargetByType[needIndex] + amount));
  return amount;
}

// FUNCTION: IMPERIALISM 0x004b4180
void TCity::VerifyStocks() {
  for (int i = 0; i < kResourceKindCount; ++i) {
    if (stockByType[i] < 0) {
      bool dispatchGate = ownerNation->IsRemote();
      if ((!dispatchGate || g_pSimMgr->multiplayerSessionRole != kSessionRoleClient) &&
          !g_Sanitize_City_Counter_Value) {
        ReportAssertionFailure("D:\\Ambit\\Cross\\UCity.cpp", 0x47f);
      }
      stockByType[i] = 0;
    }
  }
}

// FUNCTION: IMPERIALISM 0x004b4210
void TCity::MouseTrap() {}

// FUNCTION: IMPERIALISM 0x004b4230
int TCity::GetRollingStock() {
  if (ownerNation != 0) {
    return ownerNation->transportCapacity;
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x004b4260
void TCity::SetRollingStock(short value) {
  ownerNation->transportCapacity = value;
}

// FUNCTION: IMPERIALISM 0x004b4290
int TCity::GetMerchantMarineDeciSpeed() {
  int weightedSum = 0;
  int totalCount = 0;
  for (int type = 0; type < 14; ++type) {
    short count = orderCountByType[type];
    weightedSum += TShip::GetTypeSailingSpeed(type) * count;
    totalCount += count;
  }
  if (totalCount != 0) {
    return (weightedSum * 10) / totalCount;
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x004b4310
int TCity::GetMerchantMarineAverageCargoHold() {
  int weightedSum = 0;
  int totalCount = 0;
  for (int type = 0; type < 14; ++type) {
    short count = orderCountByType[type];
    weightedSum += TShip::GetTypeCargoHold(type) * count;
    totalCount += count;
  }
  if (totalCount != 0) {
    return (weightedSum * 10 + totalCount / 2) / totalCount;
  }
  return 1;
}

// FUNCTION: IMPERIALISM 0x004b4390
int TCity::PickRandomMerchantVictims(short maxWeight, short* outCounts) {
  int allocatedWeight = 0;
  short remaining = 0;
  for (int type = 0; type < 14; ++type) {
    if (TShip::GetTypeFirepower(static_cast<short>(type)) == 0) {
      remaining += orderCountByType[type];
    }
  }
  while (remaining > 0 && static_cast<short>(allocatedWeight) < maxWeight) {
    int roll = rand() % remaining + 1;
    int type = 0;
    for (;;) {
      if (TShip::GetTypeFirepower(static_cast<short>(type)) == 0) {
        roll -= orderCountByType[type];
        if (roll < 1) {
          break;
        }
      }
      ++type;
    }
    short weight = TShip::GetTypeCargoHold(static_cast<short>(type));
    if (maxWeight < weight &&
        TShip::GetTypeCargoHold(static_cast<short>(type)) - 1 < rand() % maxWeight) {
      break;
    }
    outCounts[type] = static_cast<short>(outCounts[type] + 1);
    orderCountByType[type] = static_cast<short>(orderCountByType[type] - 1);
    allocatedWeight += TShip::GetTypeCargoHold(static_cast<short>(type));
    --remaining;
  }
  return (static_cast<short>(allocatedWeight) >= maxWeight) ? maxWeight : allocatedWeight;
}

// FUNCTION: IMPERIALISM 0x004b44d0
short* TCity::GetUnmetNeeds() {
  short* summary = productionSummary->PredictedNeeds();
  for (short resourceType = 0; resourceType < kResourceKindCount; ++resourceType) {
    short remaining = summary[resourceType];
    if (remaining != 0) {
      remaining -= reservedByType[resourceType];
      summary[resourceType] = remaining;
      if (resourceType == kResourceLivestock) {
        summary[20] = static_cast<short>(remaining - reservedByType[kResourceFish]);
      }
      if (summary[resourceType] < 0) {
        summary[resourceType] = 0;
      }
    }
  }
  return summary;
}

// FUNCTION: IMPERIALISM 0x004b4540
void TCity::AddTransportRequest(short low, short high) {
  int packed = (static_cast<unsigned short>(high) << 16) | static_cast<unsigned short>(low);
  eventQueue->Insert(&packed);
}

// FUNCTION: IMPERIALISM 0x004b4580
void TCity::MakeTown(short selectedResourceType) {
  if (ownerNation->townMarkerList == 0) {
    FailNilPointerWithAssert(kUCityCppPath, 0x53a);
  }

  TTown* town = new TTown();
  if (town == 0) {
    FailNilPointerWithAssert(kUCityCppPath, 0x53c);
  }
  town->ITown("Altown", 0, false, ownerNation->nationSlot);
  town->Free();
  ownerNation->CountResourceYields();
  ownerNation->treasuryValue = ownerNation->treasuryValue;
}

// FUNCTION: IMPERIALISM 0x004b46c0
void TCity::TransferTransportRequests() {
  eventQueue->InvokePtrListResetHook();
}

// FUNCTION: IMPERIALISM 0x004b46e0
short TCity::GetMaxBuildingCapacity(int buildingSlot) {
  if (buildingSlot == 0xf) {
    TGreatPower* owner = ownerNation;
    if (owner->pendingActionStatus.byAction[9] < 0x33) {
      if (owner->ownedRegionList->GetSize() / 4 > 1) {
        return owner->ownedRegionList->GetSize() / 4;
      }
    } else if (owner->ownedRegionList->GetSize() / 3 > 1) {
      return owner->ownedRegionList->GetSize() / 3;
    }
    return 1;
  }
  short capacity = productionOrderTable[buildingSlot];
  switch (buildingSlot) {
  case 0:
  case 2:
  case 4:
  case 6:
    if (capacity == 0) {
      return 2;
    }
    if (capacity == 2) {
      return 4;
    }
    if (capacity == 4) {
      return 8;
    }
    return capacity + 8;
  case 1:
  case 3:
  case 5:
    if (capacity == 0) {
      return 1;
    }
    if (capacity == 1) {
      return 2;
    }
    if (capacity == 2) {
      return 4;
    }
    return capacity + 4;
  default:
    return capacity + 1;
  }
}

// FUNCTION: IMPERIALISM 0x004b48a0
char TCity::GetNextBuildingLevel(int buildingSlot) {
  short capacity = GetMaxBuildingCapacity(buildingSlot);
  short slot = buildingSlot;
  if (slot == 1 || slot == 3 || slot == 5) {
    if (capacity < 4) {
      return 1;
    }
    if (capacity < 8) {
      return 2;
    }
    return (capacity > 0x0f) + 3;
  }
  if (capacity < 8) {
    return 1;
  }
  if (capacity < 0x10) {
    return 2;
  }
  return (capacity > 0x1f) + 3;
}

// FUNCTION: IMPERIALISM 0x004b4940
short TCity::GetNextBuildingType(short buildingSlot) {
  short result = 0;
  short buildingType;
  if (buildingSlot == 0x0f) {
    bool usesThreeRegionsPerLevel = ownerNation->pendingActionStatus.byAction[9] >= '3';
    if (usesThreeRegionsPerLevel) {
      int regionCapacity = ownerNation->ownedRegionList->GetSize() / 3;
      if (regionCapacity > 1) {
        buildingType = static_cast<short>(ownerNation->ownedRegionList->GetSize() / 3);
      } else {
        buildingType = 1;
      }
    } else {
      int regionCapacity = ownerNation->ownedRegionList->GetSize() / 4;
      if (regionCapacity > 1) {
        buildingType = static_cast<short>(ownerNation->ownedRegionList->GetSize() / 4);
      } else {
        buildingType = 1;
      }
    }
  } else {
    buildingType = productionOrderTable[buildingSlot];
  }

  switch (buildingSlot) {
  case 0:
  case 2:
  case 4:
    if (buildingType == 0) {
      break;
    }
    if (buildingType < 0x10) {
      result = 1;
      return result;
    }
    result = static_cast<short>((buildingType >= 0x20) + 2);
    return result;

  case 1:
  case 3:
  case 5:
    if (buildingType == 0) {
      break;
    }
    if (buildingType < 8) {
      result = 1;
      return result;
    }
    result = static_cast<short>((buildingType >= 0x10) + 2);
    return result;

  case 6:
  case 0x0b:
    result = static_cast<short>(buildingType != 0);
    return result;

  case 7: {
    short nationSlot = g_pSimMgr->GetPlayerCountry();
    result = static_cast<short>(
        (g_pTechMgr->techStatusRows[nationSlot].techStatusByTechId[15] == 2) + 1);
    return result;
  }

  case 8:
    if (ownerNation->pendingActionStatus.byAction[12] == '3') {
      result = 3;
      return result;
    }
    result = static_cast<short>((ownerNation->pendingActionStatus.byAction[6] == '3') + 1);
    return result;

  case 10: {
    signed char status = ownerNation->pendingActionStatus.byAction[7];
    if (status < '3') {
      result = 1;
      return result;
    }
    result = static_cast<short>((status != '3') + 2);
    return result;
  }

  case 0x0e: {
    bool thresholdReached = ownerNation->pendingActionStatus.byAction[8] >= '3';
    result = static_cast<short>(thresholdReached + 1);
    return result;
  }

  case 0x0f: {
    bool thresholdReached = ownerNation->pendingActionStatus.byAction[9] >= '3';
    result = static_cast<short>(thresholdReached + 1);
    return result;
  }

  default:
    break;
  }
  return result;
}

// FUNCTION: IMPERIALISM 0x004b4c80
void TCity::SetBuildingWindowState(short productionSlot, bool flag, short current, short accum) {
  productionFlags[productionSlot] = flag;
  buildingWindowX[productionSlot] = current;
  buildingWindowY[productionSlot] = accum;
}

// FUNCTION: IMPERIALISM 0x004b4cc0
char TCity::GetBuildingWindowState(short productionSlot, short* outCurrent, short* outAccum) {
  *outCurrent = buildingWindowX[productionSlot];
  *outAccum = buildingWindowY[productionSlot];
  return productionFlags[productionSlot];
}

// FUNCTION: IMPERIALISM 0x004b4d00
short TCity::IsCapacityCenter(short resourceSlot) {
  if (resourceSlot != 0 && resourceSlot != 1 && resourceSlot != 2 && resourceSlot != 3 &&
      resourceSlot != 4 && resourceSlot != 5 && resourceSlot != 6 && resourceSlot != 0x0b) {
    return 0;
  }
  return 1;
}

// FUNCTION: IMPERIALISM 0x004b4d50
void TCity::BuildPowerPlant(bool enableUpgrade) {
  if (enableUpgrade && !powerPlantUpgradeQueuedFlag) {
    ownerNation->AddToTreasury(-5000);
    powerPlantUpgradeQueuedFlag = true;
    return;
  }

  if (powerPlantUpgradeQueuedFlag && !enableUpgrade) {
    ownerNation->AddToTreasury(5000);
    powerPlantUpgradeQueuedFlag = false;
  }
}

// FUNCTION: IMPERIALISM 0x004b4dc0
int TCity::GetBuildingType(short buildingSlot) {
  if (buildingSlot != 0xf) {
    return productionOrderTable[buildingSlot];
  }
  TGreatPower* owner = ownerNation;
  if (owner->pendingActionStatus.byAction[9] < 0x33) {
    if (owner->ownedRegionList->GetSize() / 4 > 1) {
      return ownerNation->ownedRegionList->GetSize() / 4;
    }
  } else {
    if (owner->ownedRegionList->GetSize() / 3 > 1) {
      return ownerNation->ownedRegionList->GetSize() / 3;
    }
  }
  return 1;
}
