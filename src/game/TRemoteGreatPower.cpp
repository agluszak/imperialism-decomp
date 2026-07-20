#include "game/TRemoteGreatPower.h"

// FUNCTION: IMPERIALISM 0x00541840
char TRemoteGreatPower::ShouldDispatchImmediatelySlot28(void) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x00541860
char TRemoteGreatPower::UpdateGreatPowerPressureStateAndDispatchEscalationMessage(void) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x00541880
void TRemoteGreatPower::RefreshGreatPowerRelationPanelsAndDispatchDeltaSummary(void) {}

// FUNCTION: IMPERIALISM 0x005418a0
void TRemoteGreatPower::NotifyCitySlot2C(void) {}

// FUNCTION: IMPERIALISM 0x005418c0
void TRemoteGreatPower::OrphanRetStub_004dcc30(void) {}

// FUNCTION: IMPERIALISM 0x005418e0
void TRemoteGreatPower::OrphanRetStub_005418e0(void) {}

// FUNCTION: IMPERIALISM 0x00541900
void TRemoteGreatPower::SortTrackedOrdersByTypePriority(void) {}

// FUNCTION: IMPERIALISM 0x00541920
void TRemoteGreatPower::ClearDiplomacyState1c6Block(void) {}

// FUNCTION: IMPERIALISM 0x00541940
void TRemoteGreatPower::ClearDiplomacyState1c6ForTarget(short targetSlot) {
  (void)targetSlot;
}

// FUNCTION: IMPERIALISM 0x00541960
void TRemoteGreatPower::BeginTurnDiplomacyPrePassSlot1c8(void) {}

// FUNCTION: IMPERIALISM 0x00541980
void TRemoteGreatPower::ApplyTurnDiplomacyStateSlot1e0(void) {}

// FUNCTION: IMPERIALISM 0x005419a0
void TRemoteGreatPower::ResetNationDiplomacyProposalQueue(void) {}

// FUNCTION: IMPERIALISM 0x005419c0
void TRemoteGreatPower::ReleaseProposalQueueSlot7F(void) {}

// FUNCTION: IMPERIALISM 0x005419e0
void TRemoteGreatPower::ProcessPendingDiplomacyProposalQueue(void) {}

// FUNCTION: IMPERIALISM 0x00541a00
void TRemoteGreatPower::SetCandidateNationFlagAndPortZoneState(int targetNation) {
  (void)targetNation;
}

// FUNCTION: IMPERIALISM 0x00541a20
void TRemoteGreatPower::CallSlotA8(int targetNation) {
  (void)targetNation;
}

// FUNCTION: IMPERIALISM 0x00541a40
void TRemoteGreatPower::RecomputeAiExpansionAndMissionPressureScores(void) {}

// FUNCTION: IMPERIALISM 0x00541a60
void TRemoteGreatPower::RefreshTrackedEntriesAndReplanAiDevelopment(int unused) {
  (void)unused;
}

// SYNTHETIC: IMPERIALISM 0x00541a80
// TRemoteGreatPower::`scalar deleting destructor'
TRemoteGreatPower::~TRemoteGreatPower() {}
// SYNTHETIC: IMPERIALISM 0x005417c0
// TRemoteGreatPower::CreateObject

// SYNTHETIC: IMPERIALISM 0x00541b20
// TRemoteGreatPower::GetRuntimeClass

IMPLEMENT_DYNCREATE(TRemoteGreatPower, TGreatPower)

TRemoteGreatPower::TRemoteGreatPower() {}

// FUNCTION: IMPERIALISM 0x00541b40
void TRemoteGreatPower::NoOpNationSelectedRegionAndMapCellLabelHook(int arg1, int arg2) {
  (void)arg1;
  (void)arg2;
}

// FUNCTION: IMPERIALISM 0x00541be0
void TRemoteGreatPower::DispatchTurnEvent11F8NoPayloadSlot2AC(void) {}
