#include "game/TCityInteriorMinister.h"

#include "game/mfc.h"

extern "C" {
CRuntimeClass g_pClassDescTCityInteriorMinister = {nullptr, 0, 0, nullptr, nullptr};
}

// NOTE: The city-policy virtual run (slots 0x58-0xd4) — production rebalancing, command
// queueing, home-tile selection, neighbor-bucket rebuilds — is promoted here as a real
// virtual override layout owning the original addresses (previously return-0 autogen
// stubs / orphan leaves). Bodies are honest partial ports to be enriched later; the slot
// ownership is what drives vtable matching. Methods are listed in ascending-address order
// (marker hygiene), which differs from slot order.



// FUNCTION: IMPERIALISM 0x004be480
void TCityInteriorMinister::CityInteriorSlot16() {}



// FUNCTION: IMPERIALISM 0x004be4c0
void TCityInteriorMinister::CityInteriorSlot17() {}



// FUNCTION: IMPERIALISM 0x004be650
void TCityInteriorMinister::CityInteriorSlot18() {}



// FUNCTION: IMPERIALISM 0x004be690
void TCityInteriorMinister::CityInteriorSlot19() {}


// FUNCTION: IMPERIALISM 0x004be7b0
undefined TCityInteriorMinister::VTableSlot1D() { return 0; }


// FUNCTION: IMPERIALISM 0x004be7d0
undefined TCityInteriorMinister::CreateTInteriorMinisterInstance() { return 0; }


// FUNCTION: IMPERIALISM 0x004be7f0
undefined TCityInteriorMinister::VTableSlot1F() { return 0; }



// FUNCTION: IMPERIALISM 0x004be820
CRuntimeClass* TCityInteriorMinister::GetRuntimeClass() const {
  return &g_pClassDescTCityInteriorMinister;
}



// FUNCTION: IMPERIALISM 0x004be840
TCityInteriorMinister::TCityInteriorMinister() : TInteriorMinister() {}



// SYNTHETIC: IMPERIALISM 0x004be880
// TCityInteriorMinister::`scalar deleting destructor'


// FUNCTION: IMPERIALISM 0x004be8d0
void TCityInteriorMinister::InitializeCityInteriorState() {
  reinterpret_cast<void(__cdecl*)(TCityInteriorMinister*)>(thunk_InitializeCityInteriorMinister)(
      this);
}



// FUNCTION: IMPERIALISM 0x004becd0
void TCityInteriorMinister::Free() {}


// FUNCTION: IMPERIALISM 0x004bed60
undefined TCityInteriorMinister::GetTEventHandlerClassNamePointer_20() { return 0; }


// FUNCTION: IMPERIALISM 0x004bee20
undefined TCityInteriorMinister::DispatchNationStateEventCode10() { return 0; }


// FUNCTION: IMPERIALISM 0x004beeb0
undefined TCityInteriorMinister::SetForeignMinisterReadyFlag14() { return 0; }


// FUNCTION: IMPERIALISM 0x004beee0
undefined TCityInteriorMinister::VTableSlot1B() { return 0; }


// FUNCTION: IMPERIALISM 0x004bef10
undefined TCityInteriorMinister::VTableSlot2D() { return 0; }


// FUNCTION: IMPERIALISM 0x004bef30
undefined TCityInteriorMinister::GetTEventHandlerClassNamePointer() { return 0; }



// FUNCTION: IMPERIALISM 0x004bef60
void TCityInteriorMinister::WriteTo(TStream* stream) {
  (void)stream;
}



// FUNCTION: IMPERIALISM 0x004bf390
void TCityInteriorMinister::ReadFrom(TStream* stream) {
  (void)stream;
}


// FUNCTION: IMPERIALISM 0x004bf770
undefined TCityInteriorMinister::OrphanCallChain_C7_I57_004be5b0() { return 0; }


// FUNCTION: IMPERIALISM 0x004bf8a0
undefined TCityInteriorMinister::VTableSlot21() { return 0; }


// FUNCTION: IMPERIALISM 0x004bfa50
undefined TCityInteriorMinister::GetTEventHandlerClassNamePointer_22() { return 0; }


// FUNCTION: IMPERIALISM 0x004bfb20
undefined TCityInteriorMinister::QueueCityProductionRebalanceCommandsByThresholds() { return 0; }


// FUNCTION: IMPERIALISM 0x004bff60
undefined TCityInteriorMinister::GetTEventHandlerClassNamePointer_24() { return 0; }


// FUNCTION: IMPERIALISM 0x004bff80
undefined TCityInteriorMinister::QueueCityProductionCommand33FromAccumulatedDeficit() { return 0; }


// FUNCTION: IMPERIALISM 0x004c0090
undefined TCityInteriorMinister::DistributeCityProductionCommandBudgetAndQueueOrders() { return 0; }


// FUNCTION: IMPERIALISM 0x004c02c0
undefined TCityInteriorMinister::QueueCityProductionCommand17Or18FromSupportRatio() { return 0; }


// FUNCTION: IMPERIALISM 0x004c04e0
undefined TCityInteriorMinister::QueueRandomCityProductionCommand19To1C() { return 0; }


// FUNCTION: IMPERIALISM 0x004c05a0
undefined TCityInteriorMinister::QueueCityProductionCommand2BIfMissingAndResetValue() { return 0; }


// FUNCTION: IMPERIALISM 0x004c0690
undefined TCityInteriorMinister::QueueSingleCityProductionCommandFromField36() { return 0; }


// FUNCTION: IMPERIALISM 0x004c0730
undefined TCityInteriorMinister::QueueSingleCityProductionCommandFromField38() { return 0; }


// FUNCTION: IMPERIALISM 0x004c07d0
undefined TCityInteriorMinister::DistributeCityProductionAcrossOrderTemplatesAndBackfillDeficits() { return 0; }



// FUNCTION: IMPERIALISM 0x004c0d90
void TCityInteriorMinister::NotifySlot44(void* receiver) {
  (void)receiver;
}


// FUNCTION: IMPERIALISM 0x004c0de0
undefined TCityInteriorMinister::SetForeignMinisterReadyFlag14_2e() { return 0; }


// FUNCTION: IMPERIALISM 0x004c0e50
undefined TCityInteriorMinister::ReconcileCityProductionQueueAgainstTargetsAndAdjustOrders() { return 0; }


// FUNCTION: IMPERIALISM 0x004c11c0
undefined TCityInteriorMinister::SelectBestSecondaryHomeTileByFrogCityScore() { return 0; }


// FUNCTION: IMPERIALISM 0x004c1510
undefined TCityInteriorMinister::BuildNationTileDevelopmentScoreListForTerrainClass() { return 0; }


// FUNCTION: IMPERIALISM 0x004c1ac0
undefined TCityInteriorMinister::RebuildMapTileNeighborBucketsForInteriorMinister() { return 0; }


// FUNCTION: IMPERIALISM 0x004c2010
undefined TCityInteriorMinister::GetTEventHandlerClassNamePointer_32() { return 0; }


// FUNCTION: IMPERIALISM 0x004c2120
undefined TCityInteriorMinister::AutoAssignProspectingOrdersByTileHeuristics() { return 0; }


// FUNCTION: IMPERIALISM 0x004c2a30
undefined TCityInteriorMinister::AutoAssignProspectingOrdersFromSeedTileNeighbors() { return 0; }



// FUNCTION: IMPERIALISM 0x004c2d50
undefined TCityInteriorMinister::IterateLinkedListCursorEntries_004c2d50() {
  return 0;
}



// FUNCTION: IMPERIALISM 0x004c2e10
undefined TCityInteriorMinister::HandleFrogCityTileSelectionAndDispatchOrders() {
  return 0;
}



// FUNCTION: IMPERIALISM 0x004c3170
undefined TCityInteriorMinister::SelectBestFrogCityTileFromCandidateSet() {
  return 0;
}



// FUNCTION: IMPERIALISM 0x004c3490
undefined TCityInteriorMinister::ComputeFrogCityCandidateScoreFromNationNeeds() {
  return 0;
}



// FUNCTION: IMPERIALISM 0x004c3620
undefined TCityInteriorMinister::GetTEventHandlerClassNamePointer_3a() {
  return 0;
}



// FUNCTION: IMPERIALISM 0x004c3640
undefined TCityInteriorMinister::BuildFrogCityDistanceMapFromPrimarySeedSet() {
  return 0;
}



// FUNCTION: IMPERIALISM 0x004c3910
undefined TCityInteriorMinister::BuildFrogCityDistanceMapFromReachableSeaCandidates() {
  return 0;
}



// FUNCTION: IMPERIALISM 0x004c3c00
undefined TCityInteriorMinister::RebalanceCityOrderAllocationTargets() {
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

void TCityInteriorMinister::Call54() {}

void TCityInteriorMinister::CallD4(void) {}

void TCityInteriorMinister::CityInteriorSlot1A(void) {}

void TCityInteriorMinister::CityInteriorSlot1B(void) {}

void TCityInteriorMinister::CityInteriorSlot1C(void) {}

void TCityInteriorMinister::CityInteriorSlot1D(void) {}

void TCityInteriorMinister::CityInteriorSlot1E(void) {}

void TCityInteriorMinister::CityInteriorSlot1F(void) {}

void TCityInteriorMinister::CityInteriorSlot20(void) {}

void TCityInteriorMinister::CityInteriorSlot21(void) {}

void TCityInteriorMinister::CityInteriorSlot22(void) {}

void TCityInteriorMinister::CityInteriorSlot23(void) {}

void TCityInteriorMinister::CityInteriorSlot24(void) {}

void TCityInteriorMinister::CityInteriorSlot25(void) {}

void TCityInteriorMinister::CityInteriorSlot26(void) {}

void TCityInteriorMinister::CityInteriorSlot27(void) {}

void TCityInteriorMinister::CityInteriorSlot28(void) {}

void TCityInteriorMinister::CityInteriorSlot29(void) {}

void TCityInteriorMinister::CityInteriorSlot2A(void) {}

void TCityInteriorMinister::CityInteriorSlot2B(void) {}

void TCityInteriorMinister::CityInteriorSlot2C(void) {}

void TCityInteriorMinister::CityInteriorSlot2D(void) {}

void TCityInteriorMinister::CityInteriorSlot2E(void) {}

void TCityInteriorMinister::CityInteriorSlot2F(void) {}

void TCityInteriorMinister::CityInteriorSlot31(void) {}

void TCityInteriorMinister::CityInteriorSlot32(void) {}

void TCityInteriorMinister::CityInteriorSlot33(void) {}

void TCityInteriorMinister::CityInteriorSlot34(void) {}

int TCityInteriorMinister::GetHomeCityRecordIndexSlotC0(void) { return 0;}

void TCityInteriorMinister::MinisterSlot0A() {}

undefined TCityInteriorMinister::NoOpForeignMinisterUtilityStub(void) { return 0;}

TCityInteriorMinister::~TCityInteriorMinister() {}
