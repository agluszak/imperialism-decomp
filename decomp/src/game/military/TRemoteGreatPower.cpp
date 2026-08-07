#include "game/military/TRemoteGreatPower.h"

#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"
#include "game/map/TMapMgr.h"
#include "game/ui_screens/TSimMgr.h"

// FUNCTION: IMPERIALISM 0x00541840
bool TRemoteGreatPower::IsRemote(void) const {
  return true;
}

// FUNCTION: IMPERIALISM 0x00541860
char TRemoteGreatPower::UpdateGreatPowerPressureStateAndDispatchEscalationMessage(void) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x00541880
void TRemoteGreatPower::RefreshGreatPowerRelationPanelsAndDispatchDeltaSummary(void) {}

// FUNCTION: IMPERIALISM 0x005418a0
void TRemoteGreatPower::CalculatePotentials(void) {}

// FUNCTION: IMPERIALISM 0x005418c0
void TRemoteGreatPower::FillInteriorMinisterOrders(void) {}

// FUNCTION: IMPERIALISM 0x005418e0
void TRemoteGreatPower::DoMovePhase(void) {}

// FUNCTION: IMPERIALISM 0x00541900
void TRemoteGreatPower::SortTrackedOrdersByTypePriority(void) {}

// FUNCTION: IMPERIALISM 0x00541920
void TRemoteGreatPower::ClearTradeOffers(void) {}

// FUNCTION: IMPERIALISM 0x00541940
void TRemoteGreatPower::ClearTradeOfferForResource(short targetSlot) {
  (void)targetSlot;
}

// FUNCTION: IMPERIALISM 0x00541960
void TRemoteGreatPower::SetDiplomacyPolicies(void) {}

// FUNCTION: IMPERIALISM 0x00541980
void TRemoteGreatPower::FinishDiplomacyPhase(void) {}

// FUNCTION: IMPERIALISM 0x005419a0
void TRemoteGreatPower::InitializeDiplomacyOffers(void) {}

// FUNCTION: IMPERIALISM 0x005419c0
void TRemoteGreatPower::InitializeDiplomacyNotices(void) {}

// FUNCTION: IMPERIALISM 0x005419e0
void TRemoteGreatPower::ReplyToDiplomacyOffers(void) {
  ResetDiplomacyPolicyAndGrantEntriesPreserveRecurringGrants();
}

// FUNCTION: IMPERIALISM 0x00541a00
void TRemoteGreatPower::SetEnemy(int targetNation) {
  (void)targetNation;
}

// FUNCTION: IMPERIALISM 0x00541a20
void TRemoteGreatPower::DeclareWarOnTargetForAlignedMinors(int targetNation) {
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
// FUNCTION: IMPERIALISM 0x00541ab0
TRemoteGreatPower::~TRemoteGreatPower() {}
// SYNTHETIC: IMPERIALISM 0x005417c0
// TRemoteGreatPower::CreateObject

// SYNTHETIC: IMPERIALISM 0x00541b20
// TRemoteGreatPower::GetRuntimeClass

IMPLEMENT_DYNCREATE(TRemoteGreatPower, TGreatPower)

// FUNCTION: IMPERIALISM 0x00541b40
void TRemoteGreatPower::PlopDownCity(short selectedRegion, const char* mapCellLabel) {
  homeTileIndex = selectedRegion;
  CString label(mapCellLabel);
  short cityRecordIndex =
      g_pGlobalMapState->terrainStateTable[static_cast<short>(homeTileIndex)].cityRecordIndex;
  g_pGlobalMapState->SetGlobalMapCellSharedLabel(cityRecordIndex, &label);
}

// FUNCTION: IMPERIALISM 0x00541be0
void TRemoteGreatPower::SorryYouLose(void) {
  g_pSimMgr->RemoveNationSlotAndNotifyPeers(nationSlot);
}
