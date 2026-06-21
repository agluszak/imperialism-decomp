#include "game/TRemoteMinor.h"

#include <new>

static const unsigned int kAddrClassDescTRemoteMinor = 0x0065b020;

// FUNCTION: IMPERIALISM 0x004e6040
undefined TRemoteMinor::ReassignTileObjectOwnerAndNotifyForSelectedCells() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004e6150
undefined TRemoteMinor::ReassignUnitOrdersForCountryTargetChange() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004e6520
undefined TRemoteMinor::RelinkTileUnitsToCountryOrderManager() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x00541c10
void* TRemoteMinor::AllocateAndConstructTRemoteMinor() {
  return new TRemoteMinor();
}

// FUNCTION: IMPERIALISM 0x00541c90
char TRemoteMinor::ShouldDispatchImmediatelySlot28(void) {
  // Remote minors always take the immediate-dispatch path (orig RET 1).
  return 1;
}

// FUNCTION: IMPERIALISM 0x00541cb0
void TRemoteMinor::ApplyIndexedResourceDeltaAndAdjustNationTotals(int resourceIndex, int delta,
                                                                  int multiplier) {
  // Intentional minor-nation no-op: orig body is RET with no work (OrphanRetStub_00541cb0).
  (void)resourceIndex;
  (void)delta;
  (void)multiplier;
}

// SYNTHETIC: IMPERIALISM 0x00541cd0
// TRemoteMinor::`scalar deleting destructor'
TRemoteMinor::~TRemoteMinor() {}

TRemoteMinor::TRemoteMinor() : TMinor() {}

// FUNCTION: IMPERIALISM 0x00541d70
CRuntimeClass* TRemoteMinor::GetRuntimeClass() const {
  return reinterpret_cast<CRuntimeClass*>(kAddrClassDescTRemoteMinor);
}

void* TRemoteMinor::GetTRemoteMinorClassNamePointer() {
  return reinterpret_cast<void*>(kAddrClassDescTRemoteMinor);
}

// FUNCTION: IMPERIALISM 0x00541d90
void TRemoteMinor::NoOpNationSelectedRegionAndMapCellLabelHook(int arg1, int arg2) {
  // Remote override: stores selected region and updates the map-cell label (orig
  // SetNationSelectedRegionAndMapCellLabelAlt). Stub pending full CString/map hook port.
  (void)arg1;
  (void)arg2;
}

void TRemoteMinor::AssertValid() const {}

void TRemoteMinor::Dump(CDumpContext &) {}

TObject* TRemoteMinor::ShallowFree() { return 0; }

undefined TRemoteMinor::InvokeObjectVtableMethod24() { return 0; }

void TRemoteMinor::Serialize(CArchive& archive) {}

char TRemoteMinor::ReturnFalseNationStateCapabilityFlag98() {
  return 0;
}

char TRemoteMinor::ReturnFalseNationStateCapabilityFlag9C() {
  return 0;
}

void TRemoteMinor::Free() {}

undefined TRemoteMinor::SelectCandidateTilesWithLowGroundUnitCount_0b() { return 0; }

undefined TRemoteMinor::OrphanLeaf_NoCall_Ins06_004d87b0_0a() { return 0; }

undefined TRemoteMinor::SeedRecruitAndNavyOrdersForEligibleCoastalCities() { return 0; }

undefined TRemoteMinor::CreateAndDispatchMilitaryRecruitOrderForNationSlot() { return 0; }

undefined TRemoteMinor::AddToNationMetricAtField10() { return 0; }

void TRemoteMinor::ApplyJoinEmpireModeForTargetNation(int targetNationSlot,int mode) {}

undefined TRemoteMinor::IsDiplomacyTargetClassCode200Match() { return 0; }

undefined TRemoteMinor::SetNationPercentFieldByModeAndDescriptorLinks() { return 0; }

undefined TRemoteMinor::OrphanRetStub_004d7e90() { return 0; }

undefined TRemoteMinor::OrphanLeaf_NoCall_Ins02_004d7f00() { return 0; }

undefined TRemoteMinor::PopulateSelectableEntryFlavorTextAndOrdinals() { return 0; }

undefined TRemoteMinor::OrphanLeaf_NoCall_Ins06_004d87b0_10() { return 0; }

undefined TRemoteMinor::SelectCandidateTilesWithLowGroundUnitCount_11() { return 0; }

undefined TRemoteMinor::DeserializeDiplomacyNationStateFromStream() { return 0; }

undefined TRemoteMinor::SerializeDiplomacyNationStateToStream() { return 0; }

undefined TRemoteMinor::IsPolicyCodeInSpecialNationPolicySet() { return 0; }

undefined TRemoteMinor::OrphanLeaf_NoCall_Ins02_004d7ee0() { return 0; }

undefined TRemoteMinor::OrphanLeaf_NoCall_Ins02_004d7f20() { return 0; }

undefined TRemoteMinor::OrphanLeaf_NoCall_Ins02_004d7f40() { return 0; }

undefined TRemoteMinor::RebuildDiplomacyEconomicPressureFromMapState() { return 0; }

undefined TRemoteMinor::Helper_Uses_GenerateThreadLocalRandom15_At004e4bd0() { return 0; }

undefined TRemoteMinor::IsDiplomacyPolicyAllowedForTargetClassState() { return 0; }

undefined TRemoteMinor::ReturnFalseNationStateActionStub() { return 0; }

undefined TRemoteMinor::SetNationTradePolicyValueForTargetAndNotify() { return 0; }

undefined TRemoteMinor::CanInitiateJoinEmpireProposalToTarget() { return 0; }

undefined TRemoteMinor::ResolveAndApplyDiplomacyPolicyTransition() { return 0; }

undefined TRemoteMinor::TriggerNationWarTransitionHandlersIfNeeded() { return 0; }

undefined TRemoteMinor::ProcessTurnEventNationStateTransitionAndDiplomacy() { return 0; }

void TRemoteMinor::HandleNetworkPortConstructionOrder(int nNationId) {}

undefined TRemoteMinor::ApplyNationStateCode200AndQueueEvent1B() { return 0; }

undefined TRemoteMinor::ApplyJoinEmpireMode2FinalizeNationNameState() { return 0; }

undefined TRemoteMinor::SetNationRowDisplayValueByDiplomacyPredicate() { return 0; }

undefined TRemoteMinor::ClearTileActivityOverlayByProvinceId() { return 0; }

undefined TRemoteMinor::QueueInterNationEvent17ForState300AffectedNations() { return 0; }

undefined TRemoteMinor::ApplyDiplomacyRelationMaskToProvinceLinkedObjects() { return 0; }

undefined TRemoteMinor::RemoveRegionIdFromNationOwnedRegionList() { return 0; }

undefined TRemoteMinor::AddRegionIdToNationOwnedRegionList() { return 0; }

undefined TRemoteMinor::SetNationSelectedRegionAndMapCellLabelAlt() { return 0; }
