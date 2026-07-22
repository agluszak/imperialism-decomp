#include "game/TCityInteriorMinister.h"

#include <stdlib.h>
#include <string.h>

#include "game/TAutoGreatPower.h"
#include "game/CIterator.h"
#include "game/TCity.h"
#include "game/TCityTask.h"
#include "game/TCivUnit.h"
#include "game/TDiplomacyMgr.h"
#include "game/TForeignMinister.h"
#include "game/TFuzzySet.h"
#include "game/TGreatPower.h"
#include "game/TItemOrder.h"
#include "game/TLaborPool.h"
#include "game/TList.h"
#include "game/TLongintList.h"
#include "game/TMapMgr.h"
#include "game/TMilitaryUnit.h"
#include "game/TPopulationMgr.h"
#include "game/TPtrList.h"
#include "game/TShortintList.h"
#include "game/TShipBuildingTask.h"
#include "game/TSimMgr.h"
#include "game/TSortedList.h"
#include "game/TTask.h"
#include "game/TTaskList.h"
#include "game/TTechMgr.h"
#include "game/TTown.h"
#include "game/TUnit.h"
#include "game/TUnitOrder.h"
#include "game/TViewMgr.h"
#include "game/global_data_tables.h"
#include "game/mfc.h"
#include "game/nation_stream_serialization.h"
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
  pendingShipType32 = 0;
  pendingRecruitmentCommandIndex36 = -1;
  pendingUnitCommandIndex38 = -1;
  resource15ProductionPercent3a = 50;

  list28 = new TLongintList();
  list2c = new TLongintList();
  nextProductionBuildingOrdinal30 = 1;

  orderList18c = new TList();
  if (orderList18c == 0) {
    MessageBoxA(0, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUCityMinister_006964B0, 0x288);
  }

  FillLists();

  field3c = -1;
  accumulatedUnmetNeed3e = 0;

  for (short i = 0; i < 23; ++i) {
    orderTypeTableFC[i] = 0;
    orderTypeTable12A[i] = 0;
    orderTypeTable158[i] = 0;
  }
  for (short j = 0; j < 61; ++j) {
    orderMetricTable40[j] = 0;
  }
  for (short k = 0; k < 16; ++k) {
    orderShortTableBA[k] = 0;
    orderShortTableDC[k] = 0;
  }

  field34 = 0;
  deferredLaborShortfallDA = 0;
  temporarilyReservedShipArms186 = 0;

  list190 = new TLongintList();

  cityPolicyFuzzySet = new TFuzzySet();
  cityPolicyFuzzySet->Clear();
  cityPolicyFuzzySet->AllocateAndAppendRecord(0xccbebc20, 0xc7c35000, 0xc69c4000, 0xc61c4000);
  cityPolicyFuzzySet->AllocateAndAppendRecord(0xc66a6000, 0xc59c4000, 0xc59c4000, 0x447a0000);
  cityPolicyFuzzySet->AllocateAndAppendRecord(0, 0x459c4000, 0x461c4000, 0x466a6000);
  cityPolicyFuzzySet->AllocateAndAppendRecord(0x461c4000, 0x469c4000, 0x49742400, 0x4e6e6b28);

  temporaryFurnitureSubstituteLumber1c2 = 0;
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
  if (pendingShipType32 == 0) {
    pendingShipType32 = static_cast<short>((orderKind == 2) + 1);
  }
}

// FUNCTION: IMPERIALISM 0x004beee0
void TCityInteriorMinister::IndustryOrder(short industrySlot) {
  list190->InsertLast(static_cast<long>(industrySlot) + 30);
}

// FUNCTION: IMPERIALISM 0x004bef10
void TCityInteriorMinister::SelectRecruitmentProductionCommand(short commandIndex) {
  pendingRecruitmentCommandIndex36 = commandIndex;
}

// FUNCTION: IMPERIALISM 0x004bef30
void TCityInteriorMinister::InteriorSlot1C(short arg) {
  list190->InsertLast(arg);
}

// FUNCTION: IMPERIALISM 0x004bef60
void TCityInteriorMinister::WriteTo(TStream* stream) {
  TMinister::WriteTo(stream);
  stream->WriteBytesSlot78(&field10, 2);
  stream->WriteBytesSlot78(&field12, 2);
  stream->WriteBytesSlot78(&capabilityFlag14, 2);
  stream->WriteBytesSlot78(&capabilityFlag16, 2);
  WriteShortArrayElems(stream, trailingTable, 7);
  stream->WriteBytesSlot78(&nextProductionBuildingOrdinal30, 2);
  stream->WriteBytesSlot78(&pendingShipType32, 2);
  stream->WriteBytesSlot78(&field34, 2);
  stream->WriteBytesSlot78(&pendingRecruitmentCommandIndex36, 2);
  stream->WriteBytesSlot78(&pendingUnitCommandIndex38, 2);
  stream->WriteBytesSlot78(&resource15ProductionPercent3a, 2);
  stream->WriteBytesSlot78(&field3c, 2);
  stream->WriteBytesSlot78(&accumulatedUnmetNeed3e, 2);
  WriteShortArrayElems(stream, orderMetricTable40, 61);
  stream->WriteBytesSlot78(&deferredLaborShortfallDA, 2);
  WriteShortArrayElems(stream, orderShortTableDC, 16);
  WriteShortArrayElems(stream, orderTypeTableFC, 23);
  WriteShortArrayElems(stream, orderTypeTable12A, 23);
  WriteShortArrayElems(stream, orderTypeTable158, 23);
  stream->WriteBytesSlot78(&temporarilyReservedShipArms186, 2);

  {
    list28->NoOpWriteTo(stream);
    int entryCount = list28->GetSize();
    stream->WriteBytesSlot78(&entryCount, 4);
    for (int ordinal = 1; ordinal <= entryCount; ++ordinal) {
      int entryValue = list28->At(ordinal);
      stream->WriteBytesSlot78(&entryValue, 4);
    }
  }

  {
    list2c->NoOpWriteTo(stream);
    int entryCount = list2c->GetSize();
    stream->WriteBytesSlot78(&entryCount, 4);
    for (int ordinal = 1; ordinal <= entryCount; ++ordinal) {
      int entryValue = list2c->At(ordinal);
      stream->WriteBytesSlot78(&entryValue, 4);
    }
  }

  {
    list190->NoOpWriteTo(stream);
    int entryCount = list190->GetSize();
    stream->WriteBytesSlot78(&entryCount, 4);
    for (int ordinal = 1; ordinal <= entryCount; ++ordinal) {
      int entryValue = list190->At(ordinal);
      stream->WriteBytesSlot78(&entryValue, 4);
    }
  }

  {
    short* demandCursor = civilianOrderDemandByResourceType194;
    int remaining = 23;
    do {
      short element = *demandCursor;
      unsigned char* elementBytes = reinterpret_cast<unsigned char*>(&element);
      unsigned char low = elementBytes[0];
      elementBytes[0] = elementBytes[1];
      elementBytes[1] = low;
      stream->WriteBytesSlot78(&element, 2);
      ++demandCursor;
      --remaining;
    } while (remaining != 0);
  }
}

// FUNCTION: IMPERIALISM 0x004bf390
void TCityInteriorMinister::ReadFrom(TStream* stream) {
  int shortTableCount = 16;
  int metricCount = 61;
  if (g_nSaveFormatVersion < 0x13) {
    shortTableCount = 15;
    metricCount = 60;
  }

  TMinister::ReadFrom(stream);
  stream->ReadBytes(&field10, 2);
  stream->ReadBytes(&field12, 2);
  stream->ReadBytes(&capabilityFlag14, 2);
  stream->ReadBytes(&capabilityFlag16, 2);
  stream->ReadBytes(trailingTable, sizeof(trailingTable));
  SwapShortArrayBytes(trailingTable, 7);
  stream->ReadBytes(&nextProductionBuildingOrdinal30, 2);
  stream->ReadBytes(&pendingShipType32, 2);
  stream->ReadBytes(&field34, 2);
  stream->ReadBytes(&pendingRecruitmentCommandIndex36, 2);
  stream->ReadBytes(&pendingUnitCommandIndex38, 2);
  stream->ReadBytes(&resource15ProductionPercent3a, 2);
  stream->ReadBytes(&field3c, 2);
  stream->ReadBytes(&accumulatedUnmetNeed3e, 2);
  stream->ReadBytes(orderMetricTable40, metricCount * 2);
  SwapShortArrayBytes(orderMetricTable40, metricCount);
  stream->ReadBytes(&deferredLaborShortfallDA, 2);
  stream->ReadBytes(orderShortTableDC, shortTableCount * 2);
  SwapShortArrayBytes(orderShortTableDC, shortTableCount);
  stream->ReadBytes(orderTypeTableFC, sizeof(orderTypeTableFC));
  SwapShortArrayBytes(orderTypeTableFC, 23);
  stream->ReadBytes(orderTypeTable12A, sizeof(orderTypeTable12A));
  SwapShortArrayBytes(orderTypeTable12A, 23);
  stream->ReadBytes(orderTypeTable158, sizeof(orderTypeTable158));
  SwapShortArrayBytes(orderTypeTable158, 23);
  stream->ReadBytes(&temporarilyReservedShipArms186, 2);
  {
    if (list28->GetSize() != 0) {
      list28->RemoveAll();
    }
    list28->NoOpReadFrom(stream);
    int entryCount;
    stream->ReadBytes(&entryCount, 4);
    for (int ordinal = 1; ordinal <= entryCount; ++ordinal) {
      int entryValue;
      stream->ReadBytes(&entryValue, 4);
      list28->InsertLast(entryValue);
    }
  }

  {
    if (list2c->GetSize() != 0) {
      list2c->RemoveAll();
    }
    list2c->NoOpReadFrom(stream);
    int entryCount;
    stream->ReadBytes(&entryCount, 4);
    for (int ordinal = 1; ordinal <= entryCount; ++ordinal) {
      int entryValue;
      stream->ReadBytes(&entryValue, 4);
      list2c->InsertLast(entryValue);
    }
  }

  {
    if (list190->GetSize() != 0) {
      list190->RemoveAll();
    }
    list190->NoOpReadFrom(stream);
    int entryCount;
    stream->ReadBytes(&entryCount, 4);
    for (int ordinal = 1; ordinal <= entryCount; ++ordinal) {
      int entryValue;
      stream->ReadBytes(&entryValue, 4);
      list190->InsertLast(entryValue);
    }
  }
  if (g_nSaveFormatVersion > 0x13) {
    stream->ReadBytes(civilianOrderDemandByResourceType194,
                      sizeof(civilianOrderDemandByResourceType194));
    SwapShortArrayBytes(civilianOrderDemandByResourceType194, 23);
  }
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
  FillRemainingNeedCapacityAndReducePowerPlantOrder();

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
void TCityInteriorMinister::QueueCityProductionPolicyCommands(TCity* city,
                                                              TTaskList* commandQueue) {
  if (city->lowProductionFlag7c != 0 && city->lowStockFlag7d == 0) {
    QueueCityProductionCommand17Or18FromSupportRatio(city, commandQueue);
  } else if (city->lowProductionFlag7c == 0 && city->lowStockFlag7d != 0) {
    DistributeCityProductionCommandBudgetAndQueueOrders(city, commandQueue);
  }

  if (accumulatedUnmetNeed3e != 0) {
    QueueCityProductionCommand33FromAccumulatedDeficit(city, commandQueue);
  }
  if (pendingShipType32 != 0) {
    QueueShipProductionCommandIfMissing(city, commandQueue);
  }
  if (pendingRecruitmentCommandIndex36 > -1) {
    QueuePendingRecruitmentProductionCommand(city, commandQueue);
  }
  if (pendingUnitCommandIndex38 > -1) {
    QueuePendingUnitProductionCommand(city, commandQueue);
  }

  QueueCityProductionRebalanceCommandsByThresholds(city, commandQueue);
}

// FUNCTION: IMPERIALISM 0x004bfb20
void TCityInteriorMinister::QueueCityProductionRebalanceCommandsByThresholds(
    TCity* city, TTaskList* commandQueue) {
  short amount;
  TCityTask* task;

  if (city->cityStockCottonB6 > 14 || city->cityStockWoolB8 > 14) {
    amount = static_cast<short>(
        (ownerContextAt04->needCurrentByType[1] + ownerContextAt04->needCurrentByType[0]) / 2 -
        city->GetBuildingType(0));
    if (amount > 0 && commandQueue->ContainsTask(0x35) == 0) {
      task = new TCityTask();
      task->InitializeCityProductionQueueCommand(0x35, city, amount);
      commandQueue->AddTail(task);
    }
  }

  if (city->cityStockCoalBC > 14 && city->cityStockIronBE > 14) {
    amount = static_cast<short>(ownerContextAt04->needCurrentByType[3] - city->GetBuildingType(2));
    if (amount > 0 && commandQueue->ContainsTask(0x37) == 0) {
      task = new TCityTask();
      task->InitializeCityProductionQueueCommand(0x37, city, amount);
      commandQueue->AddTail(task);
    }
  }

  if (city->cityStockTimberBA > 14) {
    amount =
        static_cast<short>(ownerContextAt04->needCurrentByType[2] / 2 - city->GetBuildingType(4));
    if (amount > 0 && commandQueue->ContainsTask(0x39) == 0) {
      task = new TCityTask();
      task->InitializeCityProductionQueueCommand(0x39, city, amount);
      commandQueue->AddTail(task);
    }
  }

  if (city->cityStockFabricC6 > 14) {
    amount = static_cast<short>(city->GetBuildingType(0) / 2 - city->GetBuildingType(1));
    if (amount > 0 && commandQueue->ContainsTask(0x36) == 0) {
      task = new TCityTask();
      task->InitializeCityProductionQueueCommand(0x36, city, amount);
      commandQueue->AddTail(task);
    }
  }

  if (city->cityStockSteelCC > 14) {
    amount = static_cast<short>(city->GetBuildingType(2) / 2 - city->GetBuildingType(3));
    if (amount > 0 && commandQueue->ContainsTask(0x38) == 0) {
      task = new TCityTask();
      task->InitializeCityProductionQueueCommand(0x38, city, amount);
      commandQueue->AddTail(task);
    }
  }

  if (city->cityStockLumberC8 > 14) {
    amount = static_cast<short>(city->GetBuildingType(4) / 2 - city->GetBuildingType(5));
    if (amount > 0 && commandQueue->ContainsTask(0x3a) == 0) {
      task = new TCityTask();
      task->InitializeCityProductionQueueCommand(0x3a, city, amount);
      commandQueue->AddTail(task);
    }
  }
}

// FUNCTION: IMPERIALISM 0x004bff60
void TCityInteriorMinister::NoOpProductionCommandHook24(int, int) {}

// FUNCTION: IMPERIALISM 0x004bff80
void TCityInteriorMinister::QueueCityProductionCommand33FromAccumulatedDeficit(
    TCity* city, TTaskList* commandQueue) {
  short needCap = ownerContextAt04 != 0 ? ownerContextAt04->needCapA6 : 0;
  if (commandQueue->ContainsTask(0x33) != 0) {
    return;
  }

  short totalCurrentNeed = 0;
  for (short resource = 0; resource < 0x17; ++resource) {
    totalCurrentNeed =
        static_cast<short>(totalCurrentNeed + ownerContextAt04->needCurrentByType[resource]);
  }

  short amount = accumulatedUnmetNeed3e;
  if (needCap + amount > totalCurrentNeed) {
    amount = static_cast<short>(totalCurrentNeed - needCap);
  }
  if (amount > 0) {
    TCityTask* task = new TCityTask();
    task->InitializeCityProductionQueueCommand(0x33, city, amount);
    commandQueue->AddTail(task);
  }
}

// FUNCTION: IMPERIALISM 0x004c0090
void TCityInteriorMinister::DistributeCityProductionCommandBudgetAndQueueOrders(
    TCity* city, TTaskList* commandQueue) {
  short totalProduction = 0;
  for (short initialBuildingSlot = 0; initialBuildingSlot <= 6; ++initialBuildingSlot) {
    totalProduction =
        static_cast<short>(totalProduction + city->GetBuildingType(initialBuildingSlot));
  }
  short commandBudget = static_cast<short>(totalProduction * 20 / 100);
  if (commandBudget < 2) {
    commandBudget = 2;
  }

  short selectedOrdinal = nextProductionBuildingOrdinal30;
  short lastOrdinal = static_cast<short>(list2c->GetSize());
  short commandCounts[7] = {0, 0, 0, 0, 0, 0, 0};
  while (commandBudget != 0) {
    short selectedBuildingSlot = static_cast<short>(list2c->At(selectedOrdinal));
    bool qualifies = false;
    if (selectedBuildingSlot == 0 || selectedBuildingSlot == 2 || selectedBuildingSlot == 4) {
      qualifies = true;
    } else if (selectedBuildingSlot == 1 || selectedBuildingSlot == 3 ||
               selectedBuildingSlot == 5) {
      qualifies = city->GetBuildingType(selectedBuildingSlot) <
                  city->GetBuildingType(static_cast<short>(selectedBuildingSlot - 1)) / 2;
    }
    if (qualifies) {
      ++commandCounts[selectedBuildingSlot];
      --commandBudget;
    }
    if (selectedOrdinal == lastOrdinal) {
      selectedOrdinal = 1;
    } else {
      ++selectedOrdinal;
    }
  }
  nextProductionBuildingOrdinal30 = selectedOrdinal;

  for (short queuedBuildingSlot = 0; queuedBuildingSlot <= 6; ++queuedBuildingSlot) {
    if (commandCounts[queuedBuildingSlot] != 0) {
      TCityTask* task = new TCityTask();
      task->InitializeCityProductionQueueCommand(static_cast<short>(queuedBuildingSlot + 0x35),
                                                 city, commandCounts[queuedBuildingSlot]);
      commandQueue->AddTail(task);
    }
  }
}

// FUNCTION: IMPERIALISM 0x004c02c0
void TCityInteriorMinister::QueueCityProductionCommand17Or18FromSupportRatio(
    TCity* city, TTaskList* commandQueue) {
  TLaborPool* labor = city->productionSummary1d8->baselineSlots10;
  short mediumSkill = labor->mediumSkillCount06;
  short lowSkill = labor->lowSkillCount04;
  short highSkill = labor->highSkillCount08;

  for (int ordinal = 1; ordinal <= commandQueue->GetCount(); ++ordinal) {
    TTask* task = static_cast<TTask*>(commandQueue->GetEntryByOrdinal(ordinal));
    if (task->citySlotIndex == 0x17 || task->citySlotIndex == 0x18) {
      return;
    }
  }

  short supportCycle = static_cast<short>((mediumSkill + highSkill) % 10);
  short amount = static_cast<short>((lowSkill + mediumSkill + highSkill) * 20 / 100);
  if (amount < 1) {
    amount = 1;
  }

  short command;
  if ((supportCycle == 9 && mediumSkill != 0) || lowSkill < 1) {
    if (mediumSkill < 1) {
      return;
    }
    if (amount > mediumSkill) {
      amount = mediumSkill;
    }
    command = 0x18;
  } else {
    if (amount > lowSkill) {
      amount = lowSkill;
    }
    if (amount + supportCycle > 9 && supportCycle != 9) {
      amount = static_cast<short>(9 - supportCycle);
    }
    command = 0x17;
  }

  TCityTask* task = new TCityTask();
  task->InitializeCityProductionQueueCommand(command, city, amount);
  commandQueue->AddTail(task);
}

// FUNCTION: IMPERIALISM 0x004c04e0
void TCityInteriorMinister::QueueRandomCityProductionCommand19To1C(TCity* city,
                                                                   TTaskList* commandQueue) {
  short command = static_cast<short>(rand() % 4 + 0x19);
  TCityTask* task = new TCityTask();
  task->InitializeCityProductionQueueCommand(command, city, 1);
  commandQueue->AddTail(task);
}

// FUNCTION: IMPERIALISM 0x004c05a0
void TCityInteriorMinister::QueueShipProductionCommandIfMissing(TCity* city,
                                                                TTaskList* commandQueue) {
  for (int ordinal = 1; ordinal <= commandQueue->GetCount(); ++ordinal) {
    TTask* task = static_cast<TTask*>(commandQueue->GetEntryByOrdinal(ordinal));
    if (task->citySlotIndex == 0x2b) {
      return;
    }
  }

  TShipBuildingTask* task = new TShipBuildingTask();
  task->InitializeShipProductionQueueTask(0x2b, city, pendingShipType32);
  commandQueue->AddTail(task);
  pendingShipType32 = 0;
}

// FUNCTION: IMPERIALISM 0x004c0690
void TCityInteriorMinister::QueuePendingRecruitmentProductionCommand(TCity* city,
                                                                     TTaskList* commandQueue) {
  short command = static_cast<short>(pendingRecruitmentCommandIndex36 + 0x22);
  TCityTask* task = new TCityTask();
  task->InitializeCityProductionQueueCommand(command, city, 1);
  commandQueue->AddTail(task);
  pendingRecruitmentCommandIndex36 = -1;
}

// FUNCTION: IMPERIALISM 0x004c0730
void TCityInteriorMinister::QueuePendingUnitProductionCommand(TCity* city,
                                                              TTaskList* commandQueue) {
  short command = static_cast<short>(pendingUnitCommandIndex38 + 0x19);
  TCityTask* task = new TCityTask();
  task->InitializeCityProductionQueueCommand(command, city, 1);
  commandQueue->AddTail(task);
  pendingUnitCommandIndex38 = -1;
}

// FUNCTION: IMPERIALISM 0x004c07d0
void TCityInteriorMinister::DistributeCityProductionAcrossOrderTemplatesAndBackfillDeficits(
    TCity* city) {
  accumulatedUnmetNeed3e = 0;

  int orderOrdinal = 1;
  while (city->productionSummary1d8->strength > 1 && orderOrdinal <= list28->GetSize()) {
    short orderSlot = static_cast<short>(list28->At(orderOrdinal));
    TItemOrder* order = static_cast<TItemOrder*>(city->orderSlotsE4[orderSlot]);
    order->AssertValid();

    short maxOrder = order->MaxOrder();
    city->DirectTransport(order->resourceTypeIndex48, city->GetBuildingType(order->productionSlot));

    if (order->field40 == 0) {
      if (order->resourceTypeIndex48 != 8) {
        OrderSheet orderSheet;
        order->FillOrderSheet(&orderSheet, city->productionAccum1fc[order->productionSlot]);

        short resourceCount = 0;
        short totalRequested = 0;
        for (short countedResource = 0; countedResource < 0x17; ++countedResource) {
          short requested = orderSheet.ForResourceCode(countedResource);
          if (requested != 0) {
            ++resourceCount;
            totalRequested = static_cast<short>(totalRequested + requested);
          }
        }

        short needHeadroom =
            static_cast<short>(ownerContextAt04->needCapA6 - ownerContextAt04->needsOverCapFlag);
        if (needHeadroom < totalRequested) {
          totalRequested = needHeadroom;
        }
        short transportShare = static_cast<short>(totalRequested / resourceCount);

        for (short requestedResource = 0; requestedResource < 0x17; ++requestedResource) {
          short requested = orderSheet.ForResourceCode(requestedResource);
          if (requested != 0) {
            short transported = city->DirectTransport(requestedResource, transportShare);
            short deficit = static_cast<short>(requested - transported);
            if (deficit > 0) {
              city->AddTransportRequest(requestedResource, deficit);
              short availableNeed =
                  static_cast<short>(ownerContextAt04->needCurrentByType[requestedResource] -
                                     ownerContextAt04->needTargetByType[requestedResource]);
              if ((requestedResource >= 0 && requestedResource <= 6) ||
                  (requestedResource >= 0x11 && requestedResource <= 0x16)) {
                short countedDeficit = availableNeed;
                if (countedDeficit > deficit) {
                  countedDeficit = deficit;
                }
                if (countedDeficit > 0) {
                  accumulatedUnmetNeed3e =
                      static_cast<short>(accumulatedUnmetNeed3e + countedDeficit);
                }
                if (countedDeficit < deficit) {
                  ++city->unmetResourceRetryCount278[requestedResource];
                }
              }
            }
          }
        }
      } else {
        short requested =
            static_cast<short>((city->productionAccum1fc[order->productionSlot] - maxOrder) * 2);
        short primaryResource;
        short secondaryResource;
        if (rand() % 100 < 50) {
          primaryResource = 0;
          secondaryResource = 1;
        } else {
          primaryResource = 1;
          secondaryResource = 0;
        }

        short transported = city->DirectTransport(primaryResource, requested);
        if (transported < requested) {
          transported = static_cast<short>(
              transported + city->DirectTransport(secondaryResource,
                                                  static_cast<short>(requested - transported)));
        }
        if (transported < requested) {
          city->AddTransportRequest(primaryResource, static_cast<short>(requested - transported));
          short availableNeed =
              static_cast<short>(ownerContextAt04->needCurrentByType[primaryResource] -
                                 ownerContextAt04->needTargetByType[primaryResource] +
                                 ownerContextAt04->needCurrentByType[secondaryResource] -
                                 ownerContextAt04->needTargetByType[secondaryResource]);
          if (availableNeed > 0) {
            accumulatedUnmetNeed3e = static_cast<short>(accumulatedUnmetNeed3e + availableNeed);
          }
          if (availableNeed < requested) {
            ++city->unmetResourceRetryCount278[1];
          }
        }
      }

      maxOrder = order->MaxOrder();
    }

    if (order->resourceTypeIndex48 == 0x0f) {
      maxOrder = static_cast<short>(resource15ProductionPercent3a * maxOrder / 100);
    }
    order->SetQuantity(maxOrder);
    ++orderOrdinal;
  }

  short needHeadroom =
      static_cast<short>(ownerContextAt04->needCapA6 - ownerContextAt04->needsOverCapFlag);
  if (city->cityStockHorsesC0 < 5) {
    needHeadroom = static_cast<short>(
        needHeadroom - city->DirectTransport(5, ownerContextAt04->needCurrentByType[5]));
  }

  short lateResourceTotal = 0;
  for (short lateResource = 0x11; lateResource <= 0x14; ++lateResource) {
    short available = static_cast<short>(ownerContextAt04->needCurrentByType[lateResource] -
                                         ownerContextAt04->needTargetByType[lateResource]);
    if (lateResourceTotal + available > 20) {
      available = static_cast<short>(20 - lateResourceTotal);
    }
    if (available > 0) {
      lateResourceTotal =
          static_cast<short>(lateResourceTotal + city->DirectTransport(lateResource, available));
    }
  }

  short previousHeadroom = 0;
  while (needHeadroom > 0 && previousHeadroom != needHeadroom) {
    previousHeadroom = needHeadroom;
    for (int ordinal = 1; ordinal <= list28->GetSize() && needHeadroom != 0; ++ordinal) {
      short orderSlot = static_cast<short>(list28->At(ordinal));
      TItemOrder* order = static_cast<TItemOrder*>(city->orderSlotsE4[orderSlot]);
      order->AssertValid();
      OrderSheet orderSheet;
      order->FillOrderSheet(&orderSheet, city->GetBuildingType(order->productionSlot));
      for (short sheetResource = 0; sheetResource < 0x17; ++sheetResource) {
        needHeadroom = static_cast<short>(
            needHeadroom -
            city->DirectTransport(sheetResource, orderSheet.ForResourceCode(sheetResource)));
      }
    }
  }

  previousHeadroom = 0;
  while (needHeadroom > 0 && previousHeadroom != needHeadroom) {
    previousHeadroom = needHeadroom;
    for (short fallbackResource = 0; fallbackResource < 0x17; ++fallbackResource) {
      needHeadroom = static_cast<short>(needHeadroom - city->DirectTransport(fallbackResource, 1));
    }
  }
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
short TCityInteriorMinister::RaiseNeedTargetWithinAvailableSurplus(short resourceType,
                                                                   short requestedAmount,
                                                                   short allocationLimit) {
  TGreatPower* owner = ownerContextAt04;
  short availableSurplus = static_cast<short>(owner->needCurrentByType[resourceType] -
                                              owner->needTargetByType[resourceType]);
  short allocated = requestedAmount;
  if (availableSurplus < allocated) {
    allocated = availableSurplus;
  }
  if (allocationLimit < allocated) {
    allocated = allocationLimit;
  }
  owner->UpdateNeedTargetAndAccumulateOverCap(
      resourceType, static_cast<short>(owner->needTargetByType[resourceType] + allocated));
  return allocated;
}

// FUNCTION: IMPERIALISM 0x004c0e50
short TCityInteriorMinister::RebuildNeedTargetsAndQueueProductionShortfalls(
    TCity* city, TTaskList* commandQueue) {
  TGreatPower* owner = ownerContextAt04;
  short* citySummary = city->GetCitySummaryRecordSlot74();
  short remainingNeedCapacity = owner != 0 ? owner->needCapA6 : 0;

  for (short resourceType = 0; resourceType < 23; ++resourceType) {
    owner->UpdateNeedTargetAndAccumulateOverCap(resourceType, 0);
  }

  short allocated =
      RaiseNeedTargetWithinAvailableSurplus(17, citySummary[17], remainingNeedCapacity);
  remainingNeedCapacity = static_cast<short>(remainingNeedCapacity - allocated);
  if (allocated < citySummary[17]) {
    city->AddTransportRequest(17, static_cast<short>(citySummary[17] - allocated));
    if (remainingNeedCapacity != 0) {
      ++city->unmetResourceRetryCount278[17];
    }
  }

  allocated = RaiseNeedTargetWithinAvailableSurplus(18, citySummary[18], remainingNeedCapacity);
  remainingNeedCapacity = static_cast<short>(remainingNeedCapacity - allocated);
  if (allocated < citySummary[18]) {
    city->AddTransportRequest(18, static_cast<short>(citySummary[18] - allocated));
    if (remainingNeedCapacity != 0) {
      ++city->unmetResourceRetryCount278[18];
    }
  }

  short remainingIndustrialNeed = citySummary[20];
  allocated =
      RaiseNeedTargetWithinAvailableSurplus(20, remainingIndustrialNeed, remainingNeedCapacity);
  remainingNeedCapacity = static_cast<short>(remainingNeedCapacity - allocated);
  remainingIndustrialNeed = static_cast<short>(remainingIndustrialNeed - allocated);
  allocated =
      RaiseNeedTargetWithinAvailableSurplus(19, remainingIndustrialNeed, remainingNeedCapacity);
  remainingNeedCapacity = static_cast<short>(remainingNeedCapacity - allocated);
  if (allocated < remainingIndustrialNeed) {
    remainingIndustrialNeed = static_cast<short>(remainingIndustrialNeed - allocated);
    city->AddTransportRequest(20, remainingIndustrialNeed);
    if (remainingNeedCapacity != 0) {
      ++city->unmetResourceRetryCount278[20];
    }
  }

  for (short inputResourceType = 13; inputResourceType < 17; ++inputResourceType) {
    short amount = city->CityStockByType(inputResourceType);
    if (amount > citySummary[inputResourceType]) {
      amount = citySummary[inputResourceType];
    }
    if (city->CityStockByType(inputResourceType) < citySummary[inputResourceType]) {
      TCityTask* task = new TCityTask();
      task->InitializeCityProductionQueueCommand(
          inputResourceType, city,
          static_cast<short>(citySummary[inputResourceType] -
                             city->CityStockByType(inputResourceType)));
      commandQueue->AddTail(task);
    }
    city->CityStockByType(inputResourceType) =
        static_cast<short>(city->CityStockByType(inputResourceType) - amount);
    city->VerifyStocks();
    city->consumedProductionInputByType2a6[inputResourceType] = amount;
  }

  int requestOrdinal = 1;
  while (requestOrdinal <= city->eventQueue274->GetSize()) {
    TCityTransportRequest* request = static_cast<TCityTransportRequest*>(
        city->eventQueue274->GetPtrListEntryByOneBasedIndex(requestOrdinal));
    allocated = RaiseNeedTargetWithinAvailableSurplus(
        request->resourceType, request->requestedAmount, remainingNeedCapacity);
    remainingNeedCapacity = static_cast<short>(remainingNeedCapacity - allocated);
    if (allocated < request->requestedAmount && remainingNeedCapacity > 0) {
      request->requestedAmount = static_cast<short>(request->requestedAmount - allocated);
      ++requestOrdinal;
    } else {
      city->eventQueue274->RemovePtrListEntryByOneBasedIndexAndFree(requestOrdinal);
    }
  }

  allocated = RaiseNeedTargetWithinAvailableSurplus(22, owner->needCurrentByType[22],
                                                    remainingNeedCapacity);
  remainingNeedCapacity = static_cast<short>(remainingNeedCapacity - allocated);
  owner->ApplyNationResourceNeedTargetsToOrderState();
  owner->needsOverCapFlag = static_cast<short>(owner->needCapA6 - remainingNeedCapacity);
  city->TransferTransportRequests();
  return remainingNeedCapacity;
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
      StrategicTerrainKind terrainKind = tile->GetTerrainKind();
      if (terrainKind == kStrategicTerrainPlains || terrainKind == kStrategicTerrainFarmland ||
          terrainKind == kStrategicTerrainForest || terrainKind == kStrategicTerrainDesert) {
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
      SelectRecruitmentProductionCommand(4);
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
      Province* cityRecord = &g_pGlobalMapState->cityScoreTable[cityRecordIndex];
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
        SelectRecruitmentProductionCommand(orderType);
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

  char prospectableTerrain[kStrategicTerrainCount] = {0, 0, 1, 1, 0, 0, 0, 0};
  if (hasOilProspecting) {
    prospectableTerrain[kStrategicTerrainSwamp] = 1;
    prospectableTerrain[kStrategicTerrainDesert] = 1;
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
    if (prospectableTerrain[tile->GetTerrainKind()] != 0) {
      for (TCivUnit* order = tile->firstCivilianOrder20; order != 0;
           order = static_cast<TCivUnit*>(order->nextOnTile)) {
        if (order->field_8 == 13 && order->remainingTurns24 == 8) {
          hasActiveProspecting = true;
        }
      }
      bool developmentBlocked = (tile->pendingDevelopmentFlag0d & (1 << nationSlot)) != 0 ||
                                (g_pGlobalMapState->field24 != 0 &&
                                 (tile->GetTerrainKind() == kStrategicTerrainHills ||
                                  tile->GetTerrainKind() == kStrategicTerrainMountain ||
                                  tile->GetTerrainKind() == kStrategicTerrainSwamp ||
                                  tile->GetTerrainKind() == kStrategicTerrainDesert));
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
          SelectRecruitmentProductionCommand(0);
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
  char allowedTerrain[kStrategicTerrainCount];
  allowedTerrain[kStrategicTerrainPlains] = 1;
  allowedTerrain[kStrategicTerrainForest] = 1;
  allowedTerrain[kStrategicTerrainHills] =
      g_pCityOrderCapabilityState->orderCapRows277[nationSlot].techStatusByTechId[12] == 2;
  allowedTerrain[kStrategicTerrainMountain] =
      g_pCityOrderCapabilityState->orderCapRows277[nationSlot].techStatusByTechId[23] == 2;
  allowedTerrain[kStrategicTerrainSwamp] =
      g_pCityOrderCapabilityState->orderCapRows277[nationSlot].techStatusByTechId[6] == 2;
  allowedTerrain[kStrategicTerrainWater] = 0;
  allowedTerrain[kStrategicTerrainDesert] = 1;
  allowedTerrain[kStrategicTerrainFarmland] = 1;

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
      StrategicTerrainKind terrainKind =
          g_pGlobalMapState->terrainStateTable[tileIndex].GetTerrainKind();
      if (distanceMap[tileIndex] == 0 && allowedTerrain[terrainKind] != 0) {
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
  char allowedTerrain[kStrategicTerrainCount];
  allowedTerrain[kStrategicTerrainPlains] = 1;
  allowedTerrain[kStrategicTerrainForest] = 1;
  allowedTerrain[kStrategicTerrainHills] =
      g_pCityOrderCapabilityState->orderCapRows277[nationSlot].techStatusByTechId[11] == 2;
  allowedTerrain[kStrategicTerrainMountain] =
      g_pCityOrderCapabilityState->orderCapRows277[nationSlot].techStatusByTechId[19] == 2;
  allowedTerrain[kStrategicTerrainSwamp] =
      g_pCityOrderCapabilityState->orderCapRows277[nationSlot].techStatusByTechId[5] == 2;
  allowedTerrain[kStrategicTerrainWater] = 0;
  allowedTerrain[kStrategicTerrainDesert] = 1;
  allowedTerrain[kStrategicTerrainFarmland] = 1;

  char* distanceMap = new char[0x1950];
  memset(distanceMap, 0, 0x1950);
  int remaining = ownedTiles->count;
  unsigned int ordinal;
  for (ordinal = 0; ordinal < ownedTiles->count; ++ordinal) {
    short tileIndex = ownedTiles->values[ordinal];
    TTerrainStateRecordView* tile = &g_pGlobalMapState->terrainStateTable[tileIndex];
    if (tile->regionSubtypeTag05 == -1 && allowedTerrain[tile->GetTerrainKind()] != 0 &&
        g_pGlobalMapState->HasReachableSeaTileOutsideActiveType3Or4DiplomaticMask(tileIndex)) {
      distanceMap[tileIndex] = 1;
      --remaining;
    }
  }

  while (remaining != 0) {
    short previousRemaining = static_cast<short>(remaining);
    for (ordinal = 0; ordinal < ownedTiles->count; ++ordinal) {
      short tileIndex = ownedTiles->values[ordinal];
      StrategicTerrainKind terrainKind =
          g_pGlobalMapState->terrainStateTable[tileIndex].GetTerrainKind();
      if (distanceMap[tileIndex] == 0 && allowedTerrain[terrainKind] != 0) {
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
void TCityInteriorMinister::ProcessCityOrderStateTickAndApplyCapabilitySelection() {
  TCity* city = ownerContextAt04->city;
  bool recruitmentAllowed = true;
  if (city->productionSummary1d8->populationCount08 < 7) {
    if (LowSkillLaborShortfall() == 0) {
      LowSkillLaborShortfall() = 2;
    }
    recruitmentAllowed = false;
  }

  int treasuryThresholdByDifficulty[5] = {-20000, -40000, -60000, -80000, -100000};
  int treasuryThreshold = -80000;
  if (g_pSimMgr->scenarioMapIndexPlusOne == 0) {
    treasuryThreshold = treasuryThresholdByDifficulty[g_pSimMgr->difficultyLevel];
  }
  if (ownerContextAt04->treasuryValue10 < treasuryThreshold) {
    return;
  }

  if (pendingRecruitmentCommandIndex36 != -1 && recruitmentAllowed) {
    short orderSlot = static_cast<short>(pendingRecruitmentCommandIndex36 + 0x22);
    orderMetricTable40[orderSlot] = 1;
    UpdateMinisterProductionMetricsForResourceIndex(orderSlot);
    pendingRecruitmentCommandIndex36 = -1;
  }

  if (g_pSimMgr->economicTurn == 0) {
    pendingShipType32 = 2;
  }
  if (pendingShipType32 != 0) {
    short shipOrderSlot = -1;
    for (short shipSlotIndex = 0x2b; shipSlotIndex <= 0x32 && shipOrderSlot == -1;
         ++shipSlotIndex) {
      TProductionOrder* order = static_cast<TProductionOrder*>(city->orderSlotsE4[shipSlotIndex]);
      if (order->resourceTypeIndex48 == pendingShipType32) {
        shipOrderSlot = shipSlotIndex;
      }
    }
    if (shipOrderSlot != -1) {
      orderMetricTable40[shipOrderSlot] = 1;
      pendingShipType32 = 0;
    }
  }

  city->cityStockArmsD6 =
      static_cast<short>(city->cityStockArmsD6 + temporarilyReservedShipArms186);
  city->VerifyStocks();
  temporarilyReservedShipArms186 = 0;

  if (list190->GetSize() > 0 && g_pSimMgr->economicTurn / 4 > 3) {
    for (int ordinal = 1; ordinal <= list190->GetSize(); ++ordinal) {
      short requestedCapability = static_cast<short>(list190->At(ordinal));
      short matchedOrderSlot = -1;
      if (requestedCapability < 0x1e) {
        if (TryApplyCityOrderCapabilitySelectionBySlot(requestedCapability)) {
          continue;
        }
        if (recruitmentAllowed) {
          for (short recruitmentSlotIndex = 0x19;
               recruitmentSlotIndex <= 0x20 && matchedOrderSlot == -1; ++recruitmentSlotIndex) {
            TProductionOrder* order =
                static_cast<TProductionOrder*>(city->orderSlotsE4[recruitmentSlotIndex]);
            if (order->resourceTypeIndex48 == requestedCapability) {
              matchedOrderSlot = recruitmentSlotIndex;
            }
          }
        }
      } else {
        requestedCapability = static_cast<short>(requestedCapability - 0x1e);
        for (short shipRequestSlotIndex = 0x2b;
             shipRequestSlotIndex <= 0x32 && matchedOrderSlot == -1; ++shipRequestSlotIndex) {
          TProductionOrder* order =
              static_cast<TProductionOrder*>(city->orderSlotsE4[shipRequestSlotIndex]);
          if (order->resourceTypeIndex48 == requestedCapability) {
            matchedOrderSlot = shipRequestSlotIndex;
          }
        }
      }
      if (matchedOrderSlot != -1) {
        orderMetricTable40[matchedOrderSlot] = 1;
        UpdateMinisterProductionMetricsForResourceIndex(matchedOrderSlot);
        orderMetricTable40[matchedOrderSlot] = 0;
      }
    }
    list190->RemoveAll();
  }

  for (short navyMetricSlot = 0x2b; navyMetricSlot <= 0x32; ++navyMetricSlot) {
    if (orderMetricTable40[navyMetricSlot] != 0) {
      UpdateMinisterProductionMetricsForResourceIndex(navyMetricSlot);
    }
  }
  if (recruitmentAllowed) {
    for (short recruitmentMetricSlot = 0x19; recruitmentMetricSlot <= 0x21;
         ++recruitmentMetricSlot) {
      if (orderMetricTable40[recruitmentMetricSlot] != 0) {
        UpdateMinisterProductionMetricsForResourceIndex(recruitmentMetricSlot);
      }
    }
  }
}

// FUNCTION: IMPERIALISM 0x004c40c0
void TCityInteriorMinister::RebalanceCitySupportAndLaborAllocations() {
  short totalOrders = 0;
  for (short orderSlot = 0; orderSlot < 16; ++orderSlot) {
    totalOrders = static_cast<short>(totalOrders + orderShortTableBA[orderSlot]);
  }
  short targetLabor = static_cast<short>(totalOrders / 20 + 2);
  TCity* city = ownerContextAt04->city;
  short savedMediumLaborOrder = orderMetricTable40[23];
  short savedHighLaborOrder = orderMetricTable40[24];
  short lowSkillLabor = city->productionSummary1d8->baselineSlots10->lowSkillCount04;
  short mediumSkillLabor = city->productionSummary1d8->baselineSlots10->mediumSkillCount06;
  orderMetricTable40[23] = 0;
  orderMetricTable40[24] = 0;

  short availableSupport = static_cast<short>(city->GetBuildingType(15));
  if (deferredLaborShortfallDA == 0) {
    if (lowSkillLabor < targetLabor) {
      LowSkillLaborShortfall() = static_cast<short>(targetLabor - lowSkillLabor);
      if (LowSkillLaborShortfall() > availableSupport) {
        LowSkillLaborShortfall() = availableSupport;
      }
      availableSupport = static_cast<short>(availableSupport - LowSkillLaborShortfall());
    }
    if (mediumSkillLabor < targetLabor) {
      orderMetricTable40[23] = static_cast<short>(targetLabor - mediumSkillLabor);
      if (orderMetricTable40[23] > availableSupport) {
        orderMetricTable40[23] = availableSupport;
      }
    }
  } else {
    while (availableSupport > 0) {
      if (lowSkillLabor - savedMediumLaborOrder > targetLabor) {
        ++orderMetricTable40[23];
        --lowSkillLabor;
      } else if (mediumSkillLabor - savedHighLaborOrder > targetLabor) {
        ++orderMetricTable40[24];
        --mediumSkillLabor;
      } else {
        ++LowSkillLaborShortfall();
      }
      --availableSupport;
    }
    deferredLaborShortfallDA = 0;
  }
  orderMetricTable40[23] = static_cast<short>(orderMetricTable40[23] + savedMediumLaborOrder);
  orderMetricTable40[24] = static_cast<short>(orderMetricTable40[24] + savedHighLaborOrder);

  UpdateMinisterProductionMetricsForResourceIndex(23);
  UpdateMinisterProductionMetricsForResourceIndex(24);
  UpdateMinisterProductionMetricsForResourceIndex(60);
  orderMetricTable40[23] = 0;
  orderMetricTable40[24] = 0;

  short clothingConsumed = city->cityStockClothingD0;
  if (clothingConsumed > 2) {
    clothingConsumed = 2;
  }
  short furnitureConsumed = city->cityStockFurnitureD2;
  if (furnitureConsumed > 2) {
    furnitureConsumed = 2;
  }
  city->cityStockClothingD0 = static_cast<short>(city->cityStockClothingD0 - clothingConsumed);
  city->VerifyStocks();
  city->consumedProductionInputByType2a6[13] = clothingConsumed;
  city->cityStockFurnitureD2 = static_cast<short>(city->cityStockFurnitureD2 - furnitureConsumed);
  city->VerifyStocks();
  city->consumedProductionInputByType2a6[14] = furnitureConsumed;
  if (furnitureConsumed == 0 && city->cityStockLumberC8 > 1) {
    city->cityStockLumberC8 = static_cast<short>(city->cityStockLumberC8 - 2);
    city->VerifyStocks();
    temporaryFurnitureSubstituteLumber1c2 = 2;
  }
  if (LowSkillLaborShortfall() > 4) {
    LowSkillLaborShortfall() = 4;
  }
}

// FUNCTION: IMPERIALISM 0x004c4370
void TCityInteriorMinister::ChooseAndMarkNextCityProductionCommand() {
  TCity* city = ownerContextAt04->city;
  short nationSlot = ownerContextAt04->nationSlot;
  bool hasOilTechnology =
      g_pCityOrderCapabilityState->orderCapRows277[nationSlot].techStatusByTechId[19] == 2;

  if (orderMetricTable40[0x33] != 0) {
    UpdateMinisterProductionMetricsForResourceIndex(0x33);
    orderMetricTable40[0x33] = 0;
  }
  if (hasOilTechnology && city->GetBuildingType(11) == 0) {
    city->BuildPowerPlant(1);
  }

  short priorityOrder[7] = {0, 1, 2, 3, 4, 5, 6};
  if (!hasOilTechnology) {
    orderShortTableDC[6] = -1;
  }
  for (short destination = 0; destination < 6; ++destination) {
    short best = destination;
    for (short candidate = static_cast<short>(destination + 1); candidate < 7; ++candidate) {
      short candidateScore = orderShortTableDC[priorityOrder[candidate]];
      short bestScore = orderShortTableDC[priorityOrder[best]];
      if (candidateScore > bestScore || (candidateScore == bestScore && (rand() & 1) != 0)) {
        best = candidate;
      }
    }
    short saved = priorityOrder[destination];
    priorityOrder[destination] = priorityOrder[best];
    priorityOrder[best] = saved;
  }

  short commandSlot;
  if (orderShortTableDC[priorityOrder[0]] == 0 && (g_pSimMgr->GetEconomicTurn() & 1) != 0) {
    short choice = static_cast<short>(rand() % (hasOilTechnology ? 4 : 3));
    if (choice == 3) {
      commandSlot = 0x3b;
    } else {
      float upgradeRatio = static_cast<float>(city->GetBuildingType(choice)) /
                           static_cast<float>(city->GetBuildingType(choice + 1));
      if (upgradeRatio <= g_cityProductionUpgradeRatioThreshold_00696450[choice]) {
        commandSlot = static_cast<short>(choice + 0x35);
      } else {
        commandSlot = static_cast<short>(choice + 0x36);
      }
    }
    short buildingSlot = static_cast<short>(commandSlot - 0x35);
    if (orderShortTableBA[buildingSlot] + 2 < city->GetBuildingType(buildingSlot)) {
      commandSlot = 0;
    }
  } else {
    short selectedBuildingSlot = priorityOrder[0];
    if ((selectedBuildingSlot & 1) != 0 &&
        city->GetBuildingType(selectedBuildingSlot) >=
            city->GetBuildingType(static_cast<short>(selectedBuildingSlot - 1))) {
      --selectedBuildingSlot;
    }
    commandSlot = static_cast<short>(selectedBuildingSlot + 0x35);
  }

  if (commandSlot != 0) {
    orderMetricTable40[commandSlot] = 1;
  }
  for (short orderSlot = 0x35; orderSlot <= 0x3b; ++orderSlot) {
    if (orderMetricTable40[orderSlot] != 0) {
      UpdateMinisterProductionMetricsForResourceIndex(orderSlot);
      if (orderMetricTable40[orderSlot] < 2) {
        orderShortTableDC[orderSlot - 0x35] = 0;
      }
    }
  }
}

// FUNCTION: IMPERIALISM 0x004c4690
void TCityInteriorMinister::ComputeCityProductionCommandLimitsFromBuildingOutputs() {
  TCity* city = ownerContextAt04->city;
  orderMetricTable40[9] = static_cast<short>(city->GetBuildingType(4) + 1);
  orderMetricTable40[8] = static_cast<short>(city->GetBuildingType(0) + 1);
  orderMetricTable40[11] = static_cast<short>(city->GetBuildingType(2) + 1);
  if (city->cityStockPaperCA < 3 && orderMetricTable40[10] == 0) {
    orderMetricTable40[10] = 1;
  }

  if (g_pSimMgr->GetEconomicTurn() > 2) {
    int policyBand = cityPolicyFuzzySet->SelectWeightedMemberIndex(
        static_cast<float>(ownerContextAt04->treasuryValue10));
    short reserve = g_cityProductionReserveByPolicyBand_00696400[policyBand];
    short quantity = static_cast<short>((city->cityStockLumberC8 - reserve) / 2);
    if (quantity > 0) {
      short capacity = static_cast<short>(city->GetBuildingType(5) + 1);
      if (quantity > capacity) {
        quantity = capacity;
      }
      orderMetricTable40[14] = quantity;
    }
    quantity = static_cast<short>((city->cityStockFabricC6 - reserve) / 2);
    if (quantity > 0) {
      short capacity = static_cast<short>(city->GetBuildingType(1) + 1);
      if (quantity > capacity) {
        quantity = capacity;
      }
      orderMetricTable40[13] = quantity;
    }
    quantity = static_cast<short>((city->cityStockSteelCC - reserve) / 2);
    if (quantity > 0) {
      short capacity = static_cast<short>(city->GetBuildingType(3) + 1);
      if (quantity > capacity) {
        quantity = capacity;
      }
      if (orderMetricTable40[16] != 0) {
        orderMetricTable40[16] = quantity;
        return;
      }
      short averageAllocation = 0;
      for (short orderSlot = 0; orderSlot < 16; ++orderSlot) {
        averageAllocation = static_cast<short>(averageAllocation + orderShortTableBA[orderSlot]);
      }
      averageAllocation = static_cast<short>(averageAllocation / 20);
      orderMetricTable40[16] = averageAllocation;
      orderMetricTable40[15] = static_cast<short>(quantity - averageAllocation);
    }
  }
}

// FUNCTION: IMPERIALISM 0x004c4840
void TCityInteriorMinister::RebuildCityOrderCommandAvailabilityAndPriorityCycle() {
  TCity* city = ownerContextAt04->city;
  city->cityStockLumberC8 =
      static_cast<short>(city->cityStockLumberC8 + temporaryFurnitureSubstituteLumber1c2);
  city->VerifyStocks();

  switch (g_pSimMgr->GetEconomicTurn() % 3) {
  case 0:
    UpdateMinisterProductionMetricsForResourceIndex(16);
    UpdateMinisterProductionMetricsForResourceIndex(15);
    UpdateMinisterProductionMetricsForResourceIndex(13);
    UpdateMinisterProductionMetricsForResourceIndex(14);
    break;
  case 1:
    UpdateMinisterProductionMetricsForResourceIndex(13);
    UpdateMinisterProductionMetricsForResourceIndex(14);
    UpdateMinisterProductionMetricsForResourceIndex(16);
    UpdateMinisterProductionMetricsForResourceIndex(15);
    break;
  default:
    UpdateMinisterProductionMetricsForResourceIndex(14);
    UpdateMinisterProductionMetricsForResourceIndex(13);
    UpdateMinisterProductionMetricsForResourceIndex(16);
    UpdateMinisterProductionMetricsForResourceIndex(15);
    break;
  }

  short nationSlot = ownerContextAt04->nationSlot;
  if (g_pCityOrderCapabilityState->orderCapRows277[nationSlot].techStatusByTechId[19] == 2) {
    UpdateMinisterProductionMetricsForResourceIndex(12);
  }
  UpdateMinisterProductionMetricsForResourceIndex(7);
  bool supportReady = LowSkillLaborShortfall() > 0 && orderMetricTable40[13] > 0;
  if (supportReady) {
    UpdateMinisterProductionMetricsForResourceIndex(8);
  }
  UpdateMinisterProductionMetricsForResourceIndex(10);
  if (city->cityStockLumberC8 < city->cityStockSteelCC) {
    UpdateMinisterProductionMetricsForResourceIndex(9);
    UpdateMinisterProductionMetricsForResourceIndex(11);
  } else {
    UpdateMinisterProductionMetricsForResourceIndex(11);
    UpdateMinisterProductionMetricsForResourceIndex(9);
  }
  if (!supportReady) {
    UpdateMinisterProductionMetricsForResourceIndex(8);
  }
}

// FUNCTION: IMPERIALISM 0x004c49f0
void TCityInteriorMinister::UpdateMinisterProductionMetricsForResourceIndex(short orderSlot) {
  TCity* city = ownerContextAt04->city;
  TPopulationMgr* population = city->productionSummary1d8;
  TProductionOrder* order = static_cast<TProductionOrder*>(city->orderSlotsE4[orderSlot]);

  if (orderSlot < 23 && orderSlot != 7) {
    order->AssertValid();
    TItemOrder* itemOrder = static_cast<TItemOrder*>(order);
    short buildingLevel = static_cast<short>(city->GetBuildingType(itemOrder->productionSlot));
    short productionLimit = static_cast<short>(buildingLevel * 2 + 2);
    if (orderMetricTable40[orderSlot] > productionLimit) {
      orderMetricTable40[orderSlot] = productionLimit;
    }
  }
  if (orderMetricTable40[7] > LowSkillLaborShortfall()) {
    orderMetricTable40[7] = LowSkillLaborShortfall();
  }

  short requestedQuantity = orderMetricTable40[orderSlot];
  OrderSheet orderSheet;
  order->FillOrderSheet(&orderSheet, requestedQuantity);

  short laborShortfall = 0;
  short availableLabor = RaisePowerPlantOrderToReachLaborTarget(orderSheet.ForResourceCode(61));
  if (availableLabor < orderSheet.ForResourceCode(61)) {
    laborShortfall = static_cast<short>(orderSheet.ForResourceCode(61) - availableLabor);
    requestedQuantity = static_cast<short>(availableLabor / 2);
    order->FillOrderSheet(&orderSheet, requestedQuantity);
  }

  if (orderSlot != 8) {
    for (short resourceType = 0; resourceType < 23; ++resourceType) {
      short resourceNeed = orderSheet.ForResourceCode(resourceType);
      if (resourceNeed != 0) {
        RequestResource(resourceType, resourceNeed, 7);
      }
    }
  } else {
    short basicMaterialNeed = static_cast<short>(orderSheet.ForResourceCode(0) * 2);
    RequestResource(0, basicMaterialNeed, 7);
    short basicMaterialStock = static_cast<short>(city->cityStockCottonB6 + city->cityStockWoolB8);
    if (basicMaterialStock < basicMaterialNeed) {
      RequestResource(1, static_cast<short>(basicMaterialNeed - basicMaterialStock), 7);
    }
  }

  TLaborPool* laborPool = population->baselineSlots10;
  if (orderSheet.ForResourceCode(60) > laborPool->lowSkillCount04) {
    LowSkillLaborShortfall() =
        static_cast<short>(orderSheet.ForResourceCode(60) - laborPool->lowSkillCount04);
  }
  if (orderSheet.ForResourceCode(23) > laborPool->mediumSkillCount06) {
    orderMetricTable40[23] =
        static_cast<short>(orderSheet.ForResourceCode(23) - laborPool->mediumSkillCount06);
  }
  if (orderSheet.ForResourceCode(24) > laborPool->highSkillCount08) {
    orderMetricTable40[24] =
        static_cast<short>(orderSheet.ForResourceCode(24) - laborPool->highSkillCount08);
  }

  short maximumQuantity = order->MaxOrder();
  if (maximumQuantity < requestedQuantity) {
    laborShortfall = 0;
    if (orderSlot >= 7 && orderSlot <= 16 && orderSlot != 7) {
      order->AssertValid();
      if (order->field40 == 2) {
        TItemOrder* itemOrder = static_cast<TItemOrder*>(order);
        orderShortTableDC[itemOrder->productionSlot] = static_cast<short>(
            orderShortTableDC[itemOrder->productionSlot] + requestedQuantity - maximumQuantity);
      }
    } else if (orderSlot >= 0x2b && orderSlot <= 0x32) {
      short armsRecovered = g_industryActionCostWeightResCode10[order->resourceTypeIndex48];
      if (armsRecovered > city->cityStockArmsD6) {
        armsRecovered = city->cityStockArmsD6;
      }
      city->cityStockArmsD6 = static_cast<short>(city->cityStockArmsD6 - armsRecovered);
      city->VerifyStocks();
      temporarilyReservedShipArms186 =
          static_cast<short>(temporarilyReservedShipArms186 + armsRecovered);
    }
    requestedQuantity = maximumQuantity;
  }

  order->SetQuantity(requestedQuantity);
  if (laborShortfall > 0) {
    deferredLaborShortfallDA = static_cast<short>(deferredLaborShortfallDA + laborShortfall);
  }
  orderMetricTable40[orderSlot] =
      static_cast<short>(orderMetricTable40[orderSlot] - requestedQuantity);
  if (orderMetricTable40[orderSlot] < 0) {
    orderMetricTable40[orderSlot] = 0;
  }
}

// FUNCTION: IMPERIALISM 0x004c4d40
short TCityInteriorMinister::RaisePowerPlantOrderToReachLaborTarget(short targetLabor) {
  TCity* city = ownerContextAt04->city;
  short currentLabor = city->productionSummary1d8->strength;
  if (currentLabor < targetLabor) {
    short nationSlot = ownerContextAt04->nationSlot;
    if (g_pCityOrderCapabilityState->orderCapRows277[nationSlot].techStatusByTechId[19] != 2) {
      return currentLabor;
    }
    TProductionOrder* powerPlantOrder = static_cast<TProductionOrder*>(city->orderSlotsE4[0x34]);
    short increment = static_cast<short>(((targetLabor - currentLabor) / 6 + 1) * 6);
    short currentQuantity = powerPlantOrder->quantityField04;
    short maximumQuantity = powerPlantOrder->MaxOrder();
    if (maximumQuantity < currentQuantity + increment) {
      orderMetricTable40[12] = static_cast<short>(orderMetricTable40[12] + currentQuantity -
                                                  maximumQuantity + increment);
      increment = static_cast<short>(maximumQuantity - currentQuantity);
    }
    powerPlantOrder->SetQuantity(static_cast<short>(currentQuantity + increment));
    currentLabor = city->productionSummary1d8->strength;
    if (currentLabor < targetLabor) {
      return currentLabor;
    }
  }
  return targetLabor;
}

// FUNCTION: IMPERIALISM 0x004c4e60
void TCityInteriorMinister::FillRemainingNeedCapacityAndReducePowerPlantOrder() {
  TCity* city = ownerContextAt04->city;
  if (city->cityStockHorsesC0 < 5) {
    RequestResource(5, static_cast<short>(5 - city->cityStockHorsesC0), 8);
  }

  short remainingNeedCapacity =
      static_cast<short>(ownerContextAt04->needCapA6 - ownerContextAt04->needsOverCapFlag);
  short previousNeedCapacity = -1;
  while (remainingNeedCapacity > 0 && previousNeedCapacity != remainingNeedCapacity) {
    previousNeedCapacity = remainingNeedCapacity;
    for (short resourceType = 0; resourceType < 23; ++resourceType) {
      remainingNeedCapacity =
          static_cast<short>(remainingNeedCapacity - RequestResource(resourceType, 1, 8));
    }
  }

  short availablePower = city->productionSummary1d8->strength;
  if (availablePower > city->powerAvailableB4) {
    availablePower = city->powerAvailableB4;
  }
  short powerGroups = static_cast<short>(availablePower / 6);
  if (powerGroups > 0) {
    TProductionOrder* powerPlantOrder = static_cast<TProductionOrder*>(city->orderSlotsE4[0x34]);
    powerPlantOrder->SetQuantity(
        static_cast<short>(powerPlantOrder->quantityField04 - powerGroups * 6));
  }
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

// FUNCTION: IMPERIALISM 0x004c56e0
bool TCityInteriorMinister::TryApplyCityOrderCapabilitySelectionBySlot(short capabilitySlot) {
  CIterator unitCursor(ownerContextAt04->militaryUnitList44);
  TMilitaryUnit* unit = static_cast<TMilitaryUnit*>(unitCursor.Reset());
  while (unitCursor.More()) {
    if (unit->ResolveEraCapabilityFallbackSlot() == capabilitySlot) {
      if (unit->ApplyEraCapabilityCostAndSetSelection()) {
        return true;
      }
      short candidateSlot;
      short armsCost;
      short cashCost;
      short fuelCost;
      unit->GetEraCapabilityFallbackCosts(&candidateSlot, &armsCost, &cashCost, &fuelCost);
      RequestResource(16, armsCost, 7);
      RequestResource(12, fuelCost, 7);
      return false;
    }
    unit = static_cast<TMilitaryUnit*>(unitCursor.Advance());
  }

  short actionCategory = GetCityActionCategoryCodeBySlot(capabilitySlot);
  if (actionCategory == 8 || actionCategory == 9) {
    return false;
  }

  unit = static_cast<TMilitaryUnit*>(unitCursor.Reset());
  while (unitCursor.More()) {
    if (g_cityActionCapabilityGroupBySlot_00650670[unit->orderType] ==
            g_cityActionCapabilityGroupBySlot_00650670[capabilitySlot] &&
        unit->GetUnitMovementClassId() != 0 && unit->ResolveEraCapabilityFallbackSlot() != -1) {
      if (unit->ApplyEraCapabilityCostAndSetSelection()) {
        return true;
      }
      short candidateSlot;
      short armsCost;
      short cashCost;
      short fuelCost;
      unit->GetEraCapabilityFallbackCosts(&candidateSlot, &armsCost, &cashCost, &fuelCost);
      RequestResource(16, armsCost, 7);
      RequestResource(12, fuelCost, 7);
      return false;
    }
    unit = static_cast<TMilitaryUnit*>(unitCursor.Advance());
  }
  return false;
}

TCityInteriorMinister::~TCityInteriorMinister() {}
