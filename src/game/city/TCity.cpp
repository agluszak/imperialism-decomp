#include "game/TCity.h"
#include "game/navy_order.h"

#include <stdlib.h>

#include "game/TGreatPower.h"
#include "game/TCapacityOrder.h"
#include "game/TCityTask.h"
#include "game/TExpansionOrder.h"
#include "game/TFoodProcessingOrder.h"
#include "game/TItemOrder.h"
#include "game/TOrItemOrder.h"
#include "game/TPopGrowthOrder.h"
#include "game/TPowerPlantOrder.h"
#include "game/TProductionOrder.h"
#include "game/TShipOrder.h"
#include "game/TShipBuildingTask.h"
#include "game/TSortedList.h"
#include "game/TTrainingOrder.h"
#include "game/TTown.h"
#include "game/TUnitOrder.h"
#include "game/TViewMgr.h"
#include "game/TSimMgr.h"
#include "game/TPtrList.h"
#include "game/globals/prelude.h"
#include "game/globals/city_globals.h"
#include "game/globals/shared_globals.h"
#include "game/mfc.h"
#include "game/ui_invalidation_guard.h"
#include "game/TShip.h" // GetResourceDescriptorWeightWord0ByType
#include "game/TStream.h"
#include "game/TTechMgr.h"
#include "game/nation_stream_serialization.h"

static const char kUCityCppPath[] = "D:\\Ambit\\Cross\\UCity.cpp";
static const unsigned int kAddrClassDescTCity = 0x0064f338;
// SYNTHETIC: IMPERIALISM 0x004b2410
// TCity::CreateObject

// SYNTHETIC: IMPERIALISM 0x004b2490
// TCity::GetRuntimeClass

IMPLEMENT_DYNCREATE(TCity, TObject)

// FUNCTION: IMPERIALISM 0x004b24b0
TCity::TCity() {
  selectedOrderB0 = 0;
  trackedOrderList270 = 0;
  eventQueue274 = 0;
  for (int productionSlot = 0; productionSlot < 0x10; ++productionSlot) {
    productionOrderTable1dc[productionSlot] = 0;
    productionAccum1fc[productionSlot] = 0;
    productionFlags21c[productionSlot] = 0;
  }
  populationGrowthPenaltyTicks26c = 0;
  foodSubstitutionCount06 = 0;
  starvationPopulationLoss08 = 0;
}

// SYNTHETIC: IMPERIALISM 0x004b2520
// TCity::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x004b2550
TCity::~TCity() {}

// FUNCTION: IMPERIALISM 0x004b2570
void TCity::InitializeCityProductionState(TGreatPower* ownerNation) {
  ownerNationAc = ownerNation;
  powerPlantUpgradeQueuedFlag04 = 0;
  memset(reservedByType7e, 0, sizeof(reservedByType7e));
  memset(&cityStockCottonB6, 0, sizeof(short) * 0x17);
  memset(unmetResourceRetryCount278, 0,
         sizeof(unmetResourceRetryCount278) + sizeof(consumedProductionInputByType2a6));

  for (int productionSlot = 0; productionSlot < 0x10; ++productionSlot) {
    productionAccum1fc[productionSlot] = static_cast<short>(
        productionAccum1fc[productionSlot] - productionOrderTable1dc[productionSlot]);
    productionOrderTable1dc[productionSlot] = 0;
    productionFlags21c[productionSlot] = 0;
    production22c[productionSlot] = 0;
    production24c[productionSlot] = 0;
  }

  int regionCount = ownerNation->ownedRegionList->GetSize();
  int regionsPerCapacity = ownerNation->field8d1 >= '3' ? 3 : 4;
  short capacity = static_cast<short>(regionCount / regionsPerCapacity);
  productionAccum1fc[0x0f] = capacity > 1 ? capacity : 1;

  if (g_pSimMgr->difficultyLevel < 2 && ownerNation->diplomacyEligibilityA0 != 0) {
    static const short kInitialProductionBySlot[6] = {2, 1, 2, 1, 2, 1};
    for (int productionSlot = 0; productionSlot < 6; ++productionSlot) {
      short initialProduction = kInitialProductionBySlot[productionSlot];
      productionAccum1fc[productionSlot] =
          static_cast<short>(productionAccum1fc[productionSlot] +
                             (initialProduction - productionOrderTable1dc[productionSlot]));
      productionOrderTable1dc[productionSlot] = initialProduction;
    }
  }

  lowProductionFlag7c = 0;
  lowStockFlag7d = 0;
  serializedState0a = 0;
  powerAvailableB4 = 0;

  productionSummary1d8 = new TPopulationMgr();
  productionSummary1d8->InitializePopulationState(this);
  memset(orderSlotsE4, 0, sizeof(orderSlotsE4));

  TItemOrder* itemOrder = new TItemOrder();
  itemOrder->InitializeItemOrderContext(this, 0x0b, 4, 3, 2);
  orderSlotsE4[0x0b] = itemOrder;

  itemOrder = new TItemOrder();
  itemOrder->InitializeItemOrderContext(this, 0x0f, 0x0b, -1, 3);
  orderSlotsE4[0x0f] = itemOrder;

  itemOrder = new TItemOrder();
  itemOrder->InitializeItemOrderContext(this, 0x10, 0x0b, -1, 3);
  orderSlotsE4[0x10] = itemOrder;

  itemOrder = new TItemOrder();
  itemOrder->InitializeItemOrderContext(this, 9, 2, -1, 4);
  orderSlotsE4[9] = itemOrder;

  itemOrder = new TItemOrder();
  itemOrder->InitializeItemOrderContext(this, 10, 2, -1, 4);
  orderSlotsE4[10] = itemOrder;

  itemOrder = new TItemOrder();
  itemOrder->InitializeItemOrderContext(this, 0x0c, 6, -1, 6);
  orderSlotsE4[0x0c] = itemOrder;

  itemOrder = new TItemOrder();
  itemOrder->InitializeItemOrderContext(this, 0x0d, 8, -1, 1);
  orderSlotsE4[0x0d] = itemOrder;

  itemOrder = new TItemOrder();
  itemOrder->InitializeItemOrderContext(this, 0x0e, 9, -1, 5);
  orderSlotsE4[0x0e] = itemOrder;

  TOrItemOrder* orItemOrder = new TOrItemOrder();
  orItemOrder->IOrItemOrder(this, 8, 1, 0, 0);
  orderSlotsE4[8] = orItemOrder;

  int profileIndex;
  for (profileIndex = 0; profileIndex < 9; ++profileIndex) {
    short* profile = g_aInitialCityRecruitmentOrderProfiles[profileIndex];
    TUnitOrder* unitOrder = new TUnitOrder();
    unitOrder->InitializeCityRecruitmentOrderContext(this, profile[0], profile[1], profile[2],
                                                     profile[3], profile[4], profile[5], profile[6],
                                                     0);
    orderSlotsE4[0x22 + profileIndex] = unitOrder;
  }

  TUnitOrder* unitOrder = new TUnitOrder();
  unitOrder->InitializeCityRecruitmentOrderContext(this, 0x18, 0x10, 2, -1, 0, 5000, 4, 1);
  orderSlotsE4[0x20] = unitOrder;

  for (profileIndex = 1; profileIndex <= 7; ++profileIndex) {
    short* profile = g_aUnitOrderCostProfileByAbilityId[profileIndex];
    unitOrder = new TUnitOrder();
    unitOrder->InitializeCityRecruitmentOrderContext(this, profile[0], profile[1], profile[2],
                                                     profile[3], profile[4], profile[5], profile[6],
                                                     1);
    orderSlotsE4[0x18 + profileIndex] = unitOrder;
  }

  TPowerPlantOrder* powerPlantOrder = new TPowerPlantOrder();
  powerPlantOrder->IPowerPlantOrder(this);
  orderSlotsE4[0x34] = powerPlantOrder;

  TFoodProcessingOrder* foodOrder = new TFoodProcessingOrder();
  foodOrder->IFoodProcessingOrder(this);
  orderSlotsE4[7] = foodOrder;

  TTrainingOrder* trainingOrder = new TTrainingOrder();
  trainingOrder->ITrainingOrder(this, 1);
  orderSlotsE4[0x17] = trainingOrder;

  trainingOrder = new TTrainingOrder();
  trainingOrder->ITrainingOrder(this, 2);
  orderSlotsE4[0x18] = trainingOrder;

  for (int shipSlot = 0; shipSlot < 8; ++shipSlot) {
    TShipOrder* shipOrder = new TShipOrder();
    shipOrder->IProductionOrder(this, 0);
    orderSlotsE4[0x2b + shipSlot] = shipOrder;
  }
  shipOrderSlots[0]->resourceTypeIndex48 = 1;
  shipOrderSlots[1]->resourceTypeIndex48 = 2;
  shipOrderSlots[4]->resourceTypeIndex48 = 3;
  shipOrderSlots[5]->resourceTypeIndex48 = 4;

  for (int expansionSlot = 0; expansionSlot < 7; ++expansionSlot) {
    TExpansionOrder* expansionOrder = new TExpansionOrder();
    expansionOrder->IExpansionOrder(this, static_cast<short>(expansionSlot), 9, 0x0b, 0x0e);
    orderSlotsE4[0x35 + expansionSlot] = expansionOrder;
  }

  TCapacityOrder* capacityOrder = new TCapacityOrder();
  capacityOrder->ICapacityOrder(this, 0x0e, 9, 0x0b, 0x0e);
  orderSlotsE4[0x33] = capacityOrder;

  TPopGrowthOrder* populationGrowthOrder = new TPopGrowthOrder();
  populationGrowthOrder->IPopGrowthOrder(this);
  orderSlotsE4[0x3c] = populationGrowthOrder;

  trackedOrderList270 = new TSortedList();
  eventQueue274 = new TPtrList();
  eventQueue274->recordSize14 = 4;

  cityPhaseCounter0c = 0;
  memset(cityMetricsBlock0E, 0, sizeof(cityMetricsBlock0E));
  memset(cityMetricsBlock4A, 0, sizeof(cityMetricsBlock4A));
  memset(orderCountByType5c, 0, sizeof(orderCountByType5c));
  rollingItemProductionScore78 = 0;
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
  stream->ReadBytes(&powerPlantUpgradeQueuedFlag04, 1);
  stream->ReadBytes(&lowProductionFlag7c, 1);
  stream->ReadBytes(&lowStockFlag7d, 1);
  stream->ReadBytes(productionFlags21c, productionSlotCount);
  stream->ReadBytes(&foodSubstitutionCount06, 2);
  stream->ReadBytes(&starvationPopulationLoss08, 2);
  stream->ReadBytes(&serializedState0a, 2);
  stream->ReadBytes(&cityPhaseCounter0c, 2);
  stream->ReadBytes(&powerAvailableB4, 2);
  stream->ReadBytes(cityMetricsBlock0E, sizeof(cityMetricsBlock0E));
  SwapShortArrayBytes(cityMetricsBlock0E, 0x1e);
  stream->ReadBytes(cityMetricsBlock4A, sizeof(cityMetricsBlock4A));
  SwapShortArrayBytes(cityMetricsBlock4A, 9);
  stream->ReadBytes(orderCountByType5c, sizeof(orderCountByType5c));
  SwapShortArrayBytes(orderCountByType5c, 0x0e);
  stream->ReadBytes(&cityStockCottonB6, sizeof(short) * 0x17);
  SwapShortArrayBytes(&cityStockCottonB6, 0x17);
  stream->ReadBytes(productionOrderTable1dc, productionSlotCount * 2);
  SwapShortArrayBytes(productionOrderTable1dc, productionSlotCount);
  stream->ReadBytes(productionAccum1fc, productionSlotCount * 2);
  SwapShortArrayBytes(productionAccum1fc, productionSlotCount);
  stream->ReadBytes(unmetResourceRetryCount278, sizeof(unmetResourceRetryCount278));
  SwapShortArrayBytes(unmetResourceRetryCount278, 0x17);
  stream->ReadBytes(reservedByType7e, sizeof(reservedByType7e));
  SwapShortArrayBytes(reservedByType7e, 0x17);
  stream->ReadBytes(production22c, productionSlotCount * 2);
  SwapShortArrayBytes(production22c, productionSlotCount);
  stream->ReadBytes(production24c, productionSlotCount * 2);
  SwapShortArrayBytes(production24c, productionSlotCount);
  stream->ReadBytes(consumedProductionInputByType2a6, sizeof(consumedProductionInputByType2a6));
  SwapShortArrayBytes(consumedProductionInputByType2a6, 0x17);

  if (g_nSaveFormatVersion > 0x27) {
    stream->ReadBytes(&rollingItemProductionScore78, 4);
  } else {
    rollingItemProductionScore78 = 0;
  }

  productionSummary1d8->ReadFrom(stream);
  for (int orderSlot = 0; orderSlot < orderSlotCount; ++orderSlot) {
    TObject* order = static_cast<TObject*>(orderSlotsE4[orderSlot]);
    if (order != 0) {
      order->ReadFrom(stream);
    }
  }

  int oldTaskCount = trackedOrderList270->GetCount();
  for (int oldTaskOrdinal = 1; oldTaskOrdinal <= oldTaskCount; ++oldTaskOrdinal) {
    TObject* oldTask = static_cast<TObject*>(trackedOrderList270->GetEntryByOrdinal(1));
    trackedOrderList270->RemoveAtOrdinal(1);
    if (oldTask != 0) {
      oldTask->Free();
    }
  }
  trackedOrderList270->ReadFrom(stream);

  int taskCount;
  stream->ReadBytes(&taskCount, 4);
  for (int taskOrdinal = 1; taskOrdinal <= taskCount; ++taskOrdinal) {
    unsigned char taskKind;
    stream->ReadBytes(&taskKind, 1);
    TCityTask* task;
    if (taskKind == 1) {
      task = new TCityTask();
      task->InitializeCityProductionQueueCommand(0, this, 0);
      task->ReadFrom(stream);
    } else {
      TShipBuildingTask* shipTask = new TShipBuildingTask();
      shipTask->InitializeShipProductionQueueTask(0, this, 0);
      shipTask->ReadFrom(stream);
      task = shipTask;
    }
    trackedOrderList270->AddTail(task);
  }
  eventQueue274->ReadFrom(stream);
}

// FUNCTION: IMPERIALISM 0x004b35d0
void TCity::WriteTo(TStream* stream) {
  TObject::WriteTo(stream);
  stream->WriteBytesSlot78(&powerPlantUpgradeQueuedFlag04, 1);
  stream->WriteBytesSlot78(&lowProductionFlag7c, 1);
  stream->WriteBytesSlot78(&lowStockFlag7d, 1);
  stream->WriteBytesSlot78(productionFlags21c, sizeof(productionFlags21c));
  stream->WriteBytesSlot78(&foodSubstitutionCount06, 2);
  stream->WriteBytesSlot78(&starvationPopulationLoss08, 2);
  stream->WriteBytesSlot78(&serializedState0a, 2);
  stream->WriteBytesSlot78(&cityPhaseCounter0c, 2);
  stream->WriteBytesSlot78(&powerAvailableB4, 2);
  WriteShortArrayElems(stream, cityMetricsBlock0E, 0x1e);
  WriteShortArrayElems(stream, cityMetricsBlock4A, 9);
  WriteShortArrayElems(stream, orderCountByType5c, 0x0e);
  WriteShortArrayElems(stream, &cityStockCottonB6, 0x17);
  WriteShortArrayElems(stream, productionOrderTable1dc, 0x10);
  WriteShortArrayElems(stream, productionAccum1fc, 0x10);
  WriteShortArrayElems(stream, unmetResourceRetryCount278, 0x17);
  WriteShortArrayElems(stream, reservedByType7e, 0x17);

  for (int productionSlot = 0; productionSlot < 0x10; ++productionSlot) {
    short value = production22c[productionSlot];
    SwapFirstTwoBytesInBuffer(reinterpret_cast<unsigned char*>(&value));
    stream->WriteBytesSlot78(&value, 2);
  }
  for (int accumulatedProductionSlot = 0; accumulatedProductionSlot < 0x10;
       ++accumulatedProductionSlot) {
    short value = production24c[accumulatedProductionSlot];
    SwapFirstTwoBytesInBuffer(reinterpret_cast<unsigned char*>(&value));
    stream->WriteBytesSlot78(&value, 2);
  }
  WriteWordArrayToOutputCallbackLE(stream, consumedProductionInputByType2a6, 0x17);

  stream->WriteBytesSlot78(&rollingItemProductionScore78, 4);
  productionSummary1d8->WriteTo(stream);
  for (int orderSlot = 0; orderSlot < 0x3d; ++orderSlot) {
    TObject* order = static_cast<TObject*>(orderSlotsE4[orderSlot]);
    if (order != 0) {
      order->WriteTo(stream);
    }
  }

  trackedOrderList270->WriteTo(stream);
  int taskCount = trackedOrderList270->GetCount();
  stream->WriteBytesSlot78(&taskCount, 4);
  for (int taskOrdinal = 1; taskOrdinal <= taskCount; ++taskOrdinal) {
    TObject* task = static_cast<TObject*>(trackedOrderList270->GetEntryByOrdinal(taskOrdinal));
    task->WriteTo(stream);
  }
  eventQueue274->WriteTo(stream);
}

// FUNCTION: IMPERIALISM 0x004b3a60
void TCity::Free() {
  if (this->productionSummary1d8 != 0) {
    this->productionSummary1d8->Free();
  }
  this->productionSummary1d8 = 0;
  // Real disassembly (0x004b3a60) walks the whole 0x3d-slot payload table as a
  // single flat loop, not four per-band loops: every slot's runtime object
  // (TProductionOrder-family orders, TShipOrder, TUnitOrder) derives from
  // TObject and shares Free() at the same vtable slot (0x07), so the original
  // dispatches polymorphically through one uniform TObject* loop rather than
  // one loop per typed band. Keeping the bands separately typed in the union
  // (for callers that need the real element type) while restoring this loop's
  // shape via the flat void*/TObject* view.
  TObject** orderSlot = reinterpret_cast<TObject**>(this->orderSlotsE4);
  int remaining = 0x3d;
  do {
    if (*orderSlot != 0) {
      (*orderSlot)->Free();
    }
    *orderSlot = 0;
    ++orderSlot;
    --remaining;
  } while (remaining != 0);
  if (this->trackedOrderList270 != 0) {
    this->trackedOrderList270->FreePayloadsAndDestroy();
  }
  this->trackedOrderList270 = 0;
  if (this->eventQueue274 != 0) {
    this->eventQueue274->ReleasePtrList();
  }
  this->eventQueue274 = 0;
  delete this;
}

// FUNCTION: IMPERIALISM 0x004b3b20
void TCity::SetSelectedTownMarker(void* order) {
  this->selectedOrderB0 = order;
}

// FUNCTION: IMPERIALISM 0x004b3b40
void TCity::EndCityPhase() {
  ++cityPhaseCounter0c;
  VerifyStocks();

  if (ownerNationAc->diplomacyEligibilityA0 == 0) {
    short* stock = &cityStockCottonB6;
    int remaining = 0x17;
    do {
      *stock = static_cast<short>(*stock + stock[-0x1c]);
      ++stock;
      --remaining;
    } while (remaining != 0);
  }
  VerifyStocks();

  short* consumedInput = consumedProductionInputByType2a6;
  int remaining = 0x17;
  do {
    consumedInput[-0xf8] = static_cast<short>(consumedInput[-0xf8] + *consumedInput);
    *consumedInput = 0;
    ++consumedInput;
    --remaining;
  } while (remaining != 0);

  int previousProductionScore = rollingItemProductionScore78;
  rollingItemProductionScore78 = 0;
  TProductionOrder** order = orderSlotsE4;
  remaining = 0x19;
  do {
    if (*order != 0) {
      (*order)->Produce();
    }
    ++order;
    --remaining;
  } while (remaining != 0);
  rollingItemProductionScore78 =
      (previousProductionScore * 9) / 10 + rollingItemProductionScore78 * 10;

  order = orderSlotsE4 + 0x22;
  remaining = 9;
  do {
    if (*order != 0) {
      (*order)->Produce();
    }
    ++order;
    --remaining;
  } while (remaining != 0);

  order = orderSlotsE4 + 0x33;
  remaining = 10;
  do {
    if (*order != 0) {
      (*order)->Produce();
    }
    ++order;
    --remaining;
  } while (remaining != 0);

  if (powerPlantUpgradeQueuedFlag04 != 0) {
    powerPlantUpgradeQueuedFlag04 = 0;
    productionAccum1fc[0x0b] =
        static_cast<short>(productionAccum1fc[0x0b] + (999 - productionOrderTable1dc[0x0b]));
    productionOrderTable1dc[0x0b] = 999;
  }

  short* stock = &cityStockCottonB6;
  remaining = 0x17;
  do {
    if (*stock > 9999) {
      *stock = 9999;
    }
    ++stock;
    --remaining;
  } while (remaining != 0);

  powerAvailableB4 = 0;
  productionSummary1d8->StartProductionPhase();
  orderSlotsE4[0x34]->Restock();

  order = orderSlotsE4 + 8;
  remaining = 9;
  do {
    (*order)->Restock();
    ++order;
    --remaining;
  } while (remaining != 0);

  short capacity;
  if (ownerNationAc->field8d1 >= '3') {
    int regionCapacity = ownerNationAc->ownedRegionList->GetSize() / 3;
    if (regionCapacity > 1) {
      capacity = static_cast<short>(ownerNationAc->ownedRegionList->GetSize() / 3);
    } else {
      capacity = 1;
    }
  } else {
    int regionCapacity = ownerNationAc->ownedRegionList->GetSize() / 4;
    if (regionCapacity > 1) {
      capacity = static_cast<short>(ownerNationAc->ownedRegionList->GetSize() / 4);
    } else {
      capacity = 1;
    }
  }
  productionAccum1fc[0x0f] = capacity;
  productionAccum1fc[0x0e] = productionOrderTable1dc[0x0e];
  g_pUiRuntimeContext->RefreshCityProductionUi();
}

// FUNCTION: IMPERIALISM 0x004b3de0
void TCity::PredictedNeeds() {
  if (this->productionSummary1d8->strength < 2) {
    this->lowStockFlag7d = 0;
  } else {
    this->lowStockFlag7d = 1;
  }
  short shortageCount = 3;
  if (this->productionAccum1fc[4] > 0) {
    shortageCount = 2;
  }
  if (this->productionAccum1fc[2] > 0) {
    shortageCount = static_cast<short>(shortageCount - 1);
  }
  if (this->productionAccum1fc[0] > 0) {
    shortageCount = static_cast<short>(shortageCount - 1);
  }
  if (shortageCount < 2) {
    this->lowProductionFlag7c = 1;
  } else {
    this->lowProductionFlag7c = 0;
  }
  this->ownerNationAc->AbsorbCityNeedVectorSlotFC(&this->cityStockCottonB6);
}

// FUNCTION: IMPERIALISM 0x004b3e70
void TCity::ProduceUnits() {
  TShipOrder** shipCursor = this->shipOrderSlots;
  int remaining = 8;
  do {
    TShipOrder* shipOrder = *shipCursor;
    if (shipOrder != 0) {
      // The original constructs a scratch CString here that it never reads; it exists
      // only to bracket the loop body in an EH frame (ctor + dtor each iteration).
      CString scratch;
      short pendingCount = shipOrder->quantityField04;
      short tileId = shipOrder->resourceTypeIndex48;
      if (pendingCount != 0) {
        short blockFlag = GetResourceTypeRandomDrawBlockFlag(tileId);
        if (blockFlag == 0) {
          this->ownerNationAc->DispatchTurnOrderActionSlotB0(1, tileId, pendingCount);
        } else {
          this->ownerNationAc->DispatchTurnOrderActionSlotB0(0, tileId, pendingCount);
        }
      }
    }
    ++shipCursor;
    --remaining;
  } while (remaining != 0);

  TUnitOrder** buildCursor = this->buildOrderSlots;
  int buildRemaining = 0x12;
  do {
    if (*buildCursor != 0) {
      (*buildCursor)->Produce();
    }
    ++buildCursor;
    --buildRemaining;
  } while (buildRemaining != 0);

  shipCursor = this->shipOrderSlots;
  remaining = 8;
  do {
    if (*shipCursor != 0) {
      (*shipCursor)->Produce();
    }
    ++shipCursor;
    --remaining;
  } while (remaining != 0);
}

// FUNCTION: IMPERIALISM 0x004b3fb0
void TCity::AddPurchasedItems(short* needVector) {
  short* needCursor = &this->cityStockCottonB6;
  int count = 7;
  short* sourceCursor = needVector;
  do {
    *needCursor = static_cast<short>(*needCursor + *sourceCursor);
    ++sourceCursor;
    ++needCursor;
    --count;
  } while (count != 0);
  sourceCursor = needVector + 7;
  needCursor = &this->cityStockCannedFoodC4;
  count = 6;
  do {
    *needCursor = static_cast<short>(*needCursor + *sourceCursor);
    ++sourceCursor;
    ++needCursor;
    --count;
  } while (count != 0);
  needCursor = &this->cityStockClothingD0;
  sourceCursor = needVector + 0x0d;
  count = 4;
  do {
    *needCursor = static_cast<short>(*needCursor + *sourceCursor);
    ++sourceCursor;
    ++needCursor;
    --count;
  } while (count != 0);
}

// FUNCTION: IMPERIALISM 0x004b4040
void TCity::AddTransportedItems(short* amounts) {
  short* needCursor = &this->cityStockCottonB6;
  int count = 0x17;
  do {
    short amount = *amounts;
    ++amounts;
    *needCursor = static_cast<short>(*needCursor + amount);
    ++needCursor;
    --count;
  } while (count != 0);
  this->cityStockGoldE2 = 0;
  this->cityStockGemsE0 = 0;
}

// FUNCTION: IMPERIALISM 0x004b4090
void TCity::AddTransportedItems() {
  int count = 0x17;
  short* needCursor = &this->cityStockCottonB6;
  short* targetCursor = this->ownerNationAc->needTargetByType;
  do {
    *needCursor = static_cast<short>(*needCursor + *targetCursor);
    --count;
    ++needCursor;
    ++targetCursor;
  } while (count != 0);
  this->cityStockGoldE2 = 0;
  this->cityStockGemsE0 = 0;
}

// FUNCTION: IMPERIALISM 0x004b40e0
short TCity::DirectTransport(short needIndex, short amount) {
  TGreatPower* owner = this->ownerNationAc;
  short surplus =
      static_cast<short>(owner->needCurrentByType[needIndex] - owner->needTargetByType[needIndex]);
  if (surplus < amount) {
    amount = surplus;
  }
  if (static_cast<short>(owner->needCapA6 - owner->needsOverCapFlag) < amount) {
    amount = static_cast<short>(owner->needCapA6 - owner->needsOverCapFlag);
  }
  this->CityStockByType(needIndex) = static_cast<short>(this->CityStockByType(needIndex) + amount);
  this->ownerNationAc->UpdateNeedTargetAndAccumulateOverCap(
      needIndex, static_cast<short>(owner->needTargetByType[needIndex] + amount));
  return amount;
}

// FUNCTION: IMPERIALISM 0x004b4180
void TCity::VerifyStocks() {
  int count = 0x17;
  short* needCursor = &this->cityStockCottonB6;
  do {
    if (*needCursor < 0) {
      bool dispatchGate = this->ownerNationAc->IsRemote();
      if ((dispatchGate == 0 || g_pSimMgr->difficultyLevel != 2) &&
          g_Sanitize_City_Counter_Value_006A24D4 == 0) {
        TemporarilyClearAndRestoreUiInvalidationFlag();
      }
      *needCursor = 0;
    }
    ++needCursor;
    --count;
  } while (count != 0);
}

// FUNCTION: IMPERIALISM 0x004b4210
void TCity::MouseTrap() {}

// FUNCTION: IMPERIALISM 0x004b4230
int TCity::GetOwnerNeedCapA6() {
  if (this->ownerNationAc != 0) {
    return this->ownerNationAc->needCapA6;
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x004b4260
void TCity::SetOwnerNeedCapA6(short value) {
  this->ownerNationAc->needCapA6 = value;
}

// FUNCTION: IMPERIALISM 0x004b4290
int TCity::ComputeAverageWeightWord1TimesTenFromResourceCounts() {
  int weightedSum = 0;
  int totalCount = 0;
  for (int type = 0; type < 0xe; ++type) {
    short count = orderCountByType5c[type];
    weightedSum += GetResourceDescriptorWeightWord1ByType(static_cast<short>(type)) * count;
    totalCount += count;
  }
  if (totalCount != 0) {
    return (weightedSum * 10) / totalCount;
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x004b4310
int TCity::ComputeAverageWeightWord0TimesTenFromResourceCounts() {
  int weightedSum = 0;
  int totalCount = 0;
  for (int type = 0; type < 0xe; ++type) {
    short count = orderCountByType5c[type];
    weightedSum += GetResourceDescriptorWeightWord0ByType(static_cast<short>(type)) * count;
    totalCount += count;
  }
  if (totalCount != 0) {
    return (totalCount / 2 + weightedSum * 10) / totalCount;
  }
  return 1;
}

// FUNCTION: IMPERIALISM 0x004b4390
int TCity::AllocateRandomResourceCountsWithinWeightBudget(short maxWeight, short* outCounts) {
  int allocatedWeight = 0;
  short remaining = 0;
  for (int type = 0; type < 0xe; ++type) {
    if (GetResourceTypeRandomDrawBlockFlag(static_cast<short>(type)) == 0) {
      remaining = static_cast<short>(remaining + orderCountByType5c[type]);
    }
  }
  while (remaining > 0 && static_cast<short>(allocatedWeight) < maxWeight) {
    int roll = static_cast<int>(rand()) % remaining + 1;
    int type = 0;
    for (;;) {
      if (GetResourceTypeRandomDrawBlockFlag(static_cast<short>(type)) == 0) {
        roll -= orderCountByType5c[type];
        if (roll < 1) {
          break;
        }
      }
      ++type;
    }
    short weight = GetResourceDescriptorWeightWord0ByType(static_cast<short>(type));
    if (maxWeight < weight && GetResourceDescriptorWeightWord0ByType(static_cast<short>(type)) - 1 <
                                  static_cast<int>(rand()) % maxWeight) {
      break;
    }
    outCounts[type] = static_cast<short>(outCounts[type] + 1);
    orderCountByType5c[type] = static_cast<short>(orderCountByType5c[type] - 1);
    allocatedWeight += GetResourceDescriptorWeightWord0ByType(static_cast<short>(type));
    remaining = static_cast<short>(remaining - 1);
  }
  return (static_cast<short>(allocatedWeight) >= maxWeight) ? maxWeight : allocatedWeight;
}

// FUNCTION: IMPERIALISM 0x004b44d0
short* TCity::GetCitySummaryRecordSlot74() {
  short* summary = this->productionSummary1d8->PredictedNeeds();
  for (short resourceType = 0; resourceType < 0x17; ++resourceType) {
    short remaining = summary[resourceType];
    if (remaining != 0) {
      remaining = static_cast<short>(remaining - this->reservedByType7e[resourceType]);
      summary[resourceType] = remaining;
      if (resourceType == 0x14) {
        summary[0x14] = static_cast<short>(remaining - this->reservedByType7e[0x13]);
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
  this->eventQueue274->InsertCopiedRecordSortedByComparator(&packed);
}

// FUNCTION: IMPERIALISM 0x004b4580
void TCity::MakeTown(short selectedResourceType) {
  (void)selectedResourceType;
  if (ownerNationAc->townMarkerList == 0) {
    FailNilPointerWithAssert(kUCityCppPath, 0x53a);
  }

  TTown* town = new TTown();
  if (town == 0) {
    FailNilPointerWithAssert(kUCityCppPath, 0x53c);
  }
  town->InitializeTownMarker("Altown", 0, 0, ownerNationAc->nationSlot);
  town->Free();
  ownerNationAc->RebuildNationResourceYieldCountersAndDevelopmentTargets();
  ownerNationAc->treasuryValue10 = ownerNationAc->treasuryValue10;
}

// FUNCTION: IMPERIALISM 0x004b46c0
void TCity::TransferTransportRequests(void*) {
  this->eventQueue274->InvokePtrListResetHook();
}

// FUNCTION: IMPERIALISM 0x004b46e0
short TCity::GetMaxBuildingCapacity(int buildingSlot) {
  if (buildingSlot == 0xf) {
    TGreatPower* owner = this->ownerNationAc;
    int regionCount = owner->ownedRegionList->GetSize();
    if (static_cast<signed char>(owner->serializedStatusFlags[9]) < 0x33) {
      if (regionCount / 4 > 1) {
        return static_cast<short>(regionCount / 4);
      }
    } else if (regionCount / 3 > 1) {
      return static_cast<short>(regionCount / 3);
    }
    return 1;
  }
  short capacity = this->productionOrderTable1dc[buildingSlot];
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
    return static_cast<short>(capacity + 8);
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
    return static_cast<short>(capacity + 4);
  default:
    return static_cast<short>(capacity + 1);
  }
}

// FUNCTION: IMPERIALISM 0x004b48a0
char TCity::GetNextBuildingLevel(int buildingSlot) {
  short capacity = this->GetMaxBuildingCapacity(buildingSlot);
  short slot = static_cast<short>(buildingSlot);
  if (slot == 1 || slot == 3 || slot == 5) {
    if (capacity < 4) {
      return 1;
    }
    if (capacity < 8) {
      return 2;
    }
    return static_cast<char>((0x0f < capacity) + 3);
  }
  if (capacity < 8) {
    return 1;
  }
  if (capacity < 0x10) {
    return 2;
  }
  return static_cast<char>((0x1f < capacity) + 3);
}

// FUNCTION: IMPERIALISM 0x004b4940
short TCity::GetNextBuildingType(short buildingSlot) {
  short result = 0;
  short buildingType;
  if (buildingSlot == 0x0f) {
    unsigned char usesThreeRegionsPerLevel = ownerNationAc->field8d1 >= '3';
    if (usesThreeRegionsPerLevel != 0) {
      int regionCapacity = ownerNationAc->ownedRegionList->GetSize() / 3;
      if (regionCapacity > 1) {
        buildingType = static_cast<short>(ownerNationAc->ownedRegionList->GetSize() / 3);
      } else {
        buildingType = 1;
      }
    } else {
      int regionCapacity = ownerNationAc->ownedRegionList->GetSize() / 4;
      if (regionCapacity > 1) {
        buildingType = static_cast<short>(ownerNationAc->ownedRegionList->GetSize() / 4);
      } else {
        buildingType = 1;
      }
    }
  } else {
    buildingType = productionOrderTable1dc[buildingSlot];
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
    short nationSlot = g_pSimMgr->GetActiveNationId();
    result = static_cast<short>(
        (g_pCityOrderCapabilityState->orderCapRows277[nationSlot].techStatusByTechId[0x0f] == 2) +
        1);
    return result;
  }

  case 8:
    if (ownerNationAc->expansionEventGate == '3') {
      result = 3;
      return result;
    }
    result = static_cast<short>((ownerNationAc->serializedStatusFlags[6] == '3') + 1);
    return result;

  case 10: {
    signed char status = ownerNationAc->serializedStatusFlags[7];
    if (status < '3') {
      result = 1;
      return result;
    }
    result = static_cast<short>((status != '3') + 2);
    return result;
  }

  case 0x0e: {
    unsigned char thresholdReached = ownerNationAc->expansionAlertCounter >= '3';
    result = static_cast<short>((thresholdReached != 0) + 1);
    return result;
  }

  case 0x0f: {
    unsigned char thresholdReached = ownerNationAc->field8d1 >= '3';
    result = static_cast<short>((thresholdReached != 0) + 1);
    return result;
  }

  default:
    break;
  }
  return result;
}

// FUNCTION: IMPERIALISM 0x004b4c80
void TCity::SetBuildingWindowState(short productionSlot, char flag, short current, short accum) {
  this->productionFlags21c[productionSlot] = flag;
  this->production22c[productionSlot] = current;
  this->production24c[productionSlot] = accum;
}

// FUNCTION: IMPERIALISM 0x004b4cc0
char TCity::GetBuildingWindowState(short productionSlot, short* outCurrent, short* outAccum) {
  *outCurrent = this->production22c[productionSlot];
  *outAccum = this->production24c[productionSlot];
  return static_cast<char>(this->productionFlags21c[productionSlot]);
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
void TCity::BuildPowerPlant(char enableUpgrade) {
  (void)enableUpgrade;
}

// FUNCTION: IMPERIALISM 0x004b4dc0
int TCity::GetBuildingType(short buildingSlot) {
  if (buildingSlot != 0xf) {
    return this->productionOrderTable1dc[buildingSlot];
  }
  TGreatPower* owner = this->ownerNationAc;
  if (static_cast<signed char>(owner->serializedStatusFlags[9]) < 0x33) {
    if (owner->ownedRegionList->GetSize() / 4 > 1) {
      return this->ownerNationAc->ownedRegionList->GetSize() / 4;
    }
  } else {
    if (owner->ownedRegionList->GetSize() / 3 > 1) {
      return this->ownerNationAc->ownedRegionList->GetSize() / 3;
    }
  }
  return 1;
}
