#include "game/TCityInteriorMinister.h"

#include "game/mfc.h"

// NOTE: The city-policy virtual run (slots 0x58-0xd4) — production rebalancing, command
// queueing, home-tile selection, neighbor-bucket rebuilds — is promoted here as a real
// virtual override layout owning the original addresses (previously return-0 autogen
// stubs / orphan leaves). Bodies are honest partial ports to be enriched later; the slot
// ownership is what drives vtable matching. Methods are listed in ascending-address order
// (marker hygiene), which differs from slot order.

// FUNCTION: IMPERIALISM 0x004be7b0
short TCityInteriorMinister::InteriorSlot1D(int arg) {
  return *reinterpret_cast<short*>(reinterpret_cast<char*>(this) + 0x12a + arg * 2);
}

// FUNCTION: IMPERIALISM 0x004be7d0
short TCityInteriorMinister::InteriorSlot1E(int arg) {
  return *reinterpret_cast<short*>(reinterpret_cast<char*>(this) + 0x158 + arg * 2);
}

// FUNCTION: IMPERIALISM 0x004be7f0
void TCityInteriorMinister::InteriorSlot1F(int arg) {
  *reinterpret_cast<short*>(reinterpret_cast<char*>(this) + 0x158 + arg * 2) = 0;
}
// SYNTHETIC: IMPERIALISM 0x004be710
// TCityInteriorMinister::CreateObject

// SYNTHETIC: IMPERIALISM 0x004be820
// TCityInteriorMinister::GetRuntimeClass

IMPLEMENT_DYNCREATE(TCityInteriorMinister, TInteriorMinister)

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
undefined TCityInteriorMinister::VTableSlot2D(short) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004bef30
void TCityInteriorMinister::InteriorSlot1C(short) {}

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
undefined TCityInteriorMinister::VTableSlot21(int) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004bfa50
undefined TCityInteriorMinister::GetTEventHandlerClassNamePointer_22(int, int) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004bfb20
undefined TCityInteriorMinister::QueueCityProductionRebalanceCommandsByThresholds(TCity*, int*) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004bff60
undefined TCityInteriorMinister::GetTEventHandlerClassNamePointer_24(int, int) {
  return 0;
}

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

// FUNCTION: IMPERIALISM 0x004c4fe0
undefined TCityInteriorMinister::CityMinisterSlot46() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004c5240
undefined TCityInteriorMinister::BuildFrogCityTerrainCountsAndOverlayStats() {
  return 0;
}

TCityInteriorMinister::~TCityInteriorMinister() {}
