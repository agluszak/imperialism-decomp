#include "game/TDiplomacyTurnStateManager.h"

// FUNCTION: IMPERIALISM 0x004ee6c0
TDiplomacyTurnStateManager*
TDiplomacyTurnStateManager::ConstructTDiplomacyTurnStateManager_Vtbl00654d90() {
  int zero = 0;
  queuedWarTransitionActive794 = zero;
  queuedWarTransitionPending798 = zero;
  proposalDispatchCounter790 = static_cast<short>(zero);
  lastProcessedNationSlot78e = static_cast<short>(-1);
  return this;
}

// Vtable-shape placeholders for slots that are still implemented elsewhere or
// only needed to preserve the native class layout.
void TDiplomacyTurnStateManager::slot_00() {}
void TDiplomacyTurnStateManager::slot_04() {}
void TDiplomacyTurnStateManager::slot_08() {}
void TDiplomacyTurnStateManager::slot_0c() {}
void TDiplomacyTurnStateManager::slot_10() {}
void TDiplomacyTurnStateManager::slot_14() {}
void TDiplomacyTurnStateManager::slot_18() {}
void TDiplomacyTurnStateManager::slot_1c() {}
void TDiplomacyTurnStateManager::slot_20() {}
void TDiplomacyTurnStateManager::slot_24() {}
char TDiplomacyTurnStateManager::HasPolicyWithNationSlot44(int sourceNation,
                                                           int targetNation) {
  return 0;
}
char TDiplomacyTurnStateManager::HasOutdatedWarRelationSlot48(int sourceNation,
                                                              int targetNation) {
  return 0;
}
void TDiplomacyTurnStateManager::slot_30() {}
void TDiplomacyTurnStateManager::slot_34() {}
void TDiplomacyTurnStateManager::slot_38() {}
void TDiplomacyTurnStateManager::slot_3c() {}
void TDiplomacyTurnStateManager::slot_40() {}
void TDiplomacyTurnStateManager::slot_50() {}
void TDiplomacyTurnStateManager::slot_54() {}
void TDiplomacyTurnStateManager::slot_58() {}
char TDiplomacyTurnStateManager::ValidateDiplomacyActionSlot5c(int sourceNation,
                                                               int targetNation,
                                                               int actionCode) {
  return 0;
}
void TDiplomacyTurnStateManager::slot_64() {}
int TDiplomacyTurnStateManager::GetRelationTypeSlot68(int sourceNation, int targetNation) {
  return 0;
}
void TDiplomacyTurnStateManager::slot_6c() {}
short TDiplomacyTurnStateManager::GetRelationTierSlot70(int sourceNation, int targetNation) {
  return 0;
}
void TDiplomacyTurnStateManager::SetRelationCodeSlot74WithMode(int sourceNation,
                                                               int targetNation,
                                                               int relationCode,
                                                               int updateMode) {}
void TDiplomacyTurnStateManager::SetRelationCodeSlot78Final(int sourceNation,
                                                            int targetNation,
                                                            int relationCode) {}
void TDiplomacyTurnStateManager::ApplyRelationCode4Slot7c(int sourceNation,
                                                          int targetNation,
                                                          int updateMode) {}
char TDiplomacyTurnStateManager::HasFlag84ForNationSlot84(int nation) {
  return 0;
}
int TDiplomacyTurnStateManager::CountMajorAllianceRelationsSlot8c(int sourceNation) {
  return 0;
}
int TDiplomacyTurnStateManager::GetNthAlliedMajorNationSlot90(int nthAllianceIndex,
                                                              int sourceNation) {
  return 0;
}
void TDiplomacyTurnStateManager::slot_9c() {}
