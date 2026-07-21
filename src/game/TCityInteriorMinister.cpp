#include "game/TCityInteriorMinister.h"

#include <stdlib.h>

#include "game/TCity.h"
#include "game/TForeignMinister.h"
#include "game/TFuzzySet.h"
#include "game/TGreatPower.h"
#include "game/TList.h"
#include "game/TLongintList.h"
#include "game/global_data_tables.h"
#include "game/mfc.h"
#include "game/ui_invalidation_guard.h"

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

  CityInteriorSlot20();

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
void TCityInteriorMinister::Free() {}

// FUNCTION: IMPERIALISM 0x004bed60
void TCityInteriorMinister::CityInteriorSlot20() {}

// FUNCTION: IMPERIALISM 0x004bee20
short TCityInteriorMinister::DispatchNationStateEventCode10(short nationSlot) {
  (void)nationSlot;
  return 0;
}

// FUNCTION: IMPERIALISM 0x004beeb0
void TCityInteriorMinister::InteriorSlot1A(short) {}

// FUNCTION: IMPERIALISM 0x004beee0
void TCityInteriorMinister::InteriorSlot1B(short) {}

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
void TCityInteriorMinister::Call54() {}

// FUNCTION: IMPERIALISM 0x004bf8a0
undefined TCityInteriorMinister::EvaluateCityShortagesAndNotifyForeignMinister(TCity* city) {
  if (orderMetricTable40[0] != 0 || orderMetricTable40[1] != 0) {
    bool roll = (rand() % 100) >= 75;
    ownerContextAt04->foreignMinister->AddToForeignMinisterCounterAtIndex(0, roll);
  }

  for (short i = 2; i <= 6; ++i) {
    short delta = orderMetricTable40[i];
    if (delta != 0) {
      ownerContextAt04->foreignMinister->AddToForeignMinisterCounterAtIndex(i, delta);
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

    short popHalfNeed = city->productionSummary1d8->fieldAt8 / 2;
    if (city->cityStockCannedFoodC4 < popHalfNeed) {
      resultCode = 7;
      magnitude = city->productionSummary1d8->fieldAt8 - city->cityStockCannedFoodC4;
      if (magnitude > 6) {
        magnitude = 6;
      }
    }
  }

  if (resultCode != -1) {
    ownerContextAt04->foreignMinister->SetForeignMinisterPrimaryAndSecondaryTargets(resultCode,
                                                                                    magnitude);
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
    QueueCityProductionCommand33FromAccumulatedDeficit(reinterpret_cast<int*>(city),
                                                       reinterpret_cast<int>(arg2));
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
undefined TCityInteriorMinister::QueueCityProductionCommand33FromAccumulatedDeficit(int*, int) {
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
void TCityInteriorMinister::NoOpForeignMinisterUtilityStub(void* receiver) {
  (void)receiver;
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
int TCityInteriorMinister::GetHomeCityRecordIndexSlotC0() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004c1510
void TCityInteriorMinister::CallD4() {}

// FUNCTION: IMPERIALISM 0x004c1ac0
undefined TCityInteriorMinister::RebuildMapTileNeighborBucketsForInteriorMinister() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004c2010
undefined TCityInteriorMinister::GetTEventHandlerClassNamePointer_32() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004c2120
undefined TCityInteriorMinister::AutoAssignProspectingOrdersByTileHeuristics() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004c2a30
undefined TCityInteriorMinister::AutoAssignProspectingOrdersFromSeedTileNeighbors() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004c2d50
undefined TCityInteriorMinister::IterateLinkedListCursorEntries_004c2d50(int, int) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004c2e10
undefined TCityInteriorMinister::HandleFrogCityTileSelectionAndDispatchOrders(int*, int, int) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004c3170
undefined TCityInteriorMinister::SelectBestFrogCityTileFromCandidateSet(short, int, int, int) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004c3490
undefined TCityInteriorMinister::ComputeFrogCityCandidateScoreFromNationNeeds(int) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004c3620
undefined TCityInteriorMinister::GetTEventHandlerClassNamePointer_3a(int, int, int) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004c3640
undefined TCityInteriorMinister::BuildFrogCityDistanceMapFromPrimarySeedSet(int) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004c3910
undefined TCityInteriorMinister::BuildFrogCityDistanceMapFromReachableSeaCandidates(int) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004c3c00
undefined TCityInteriorMinister::RebalanceCityOrderAllocationTargets(int*) {
  return 0;
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
undefined TCityInteriorMinister::CityMinisterSlot46() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004c5240
undefined TCityInteriorMinister::BuildFrogCityTerrainCountsAndOverlayStats() {
  return 0;
}

TCityInteriorMinister::~TCityInteriorMinister() {}
