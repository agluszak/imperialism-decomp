#include "game/THostGreatPower.h"

#include "game/TStream.h"

// FUNCTION: IMPERIALISM 0x00540f20
char THostGreatPower::ReturnFalseNationStateCapabilityFlag9C(void) {
  return 0;
}

// SYNTHETIC: IMPERIALISM 0x00540f40
// THostGreatPower::`scalar deleting destructor'
THostGreatPower::~THostGreatPower() {}

// FUNCTION: IMPERIALISM 0x00540fe0
CRuntimeClass* THostGreatPower::GetRuntimeClass() const {
  return 0;
}

// FUNCTION: IMPERIALISM 0x00541000
void THostGreatPower::ReadFrom(TStream* stream) {
  (void)stream;
}

// FUNCTION: IMPERIALISM 0x00541040
void THostGreatPower::WriteTo(TStream* stream) {
  (void)stream;
}

// FUNCTION: IMPERIALISM 0x00541080
char THostGreatPower::TryDispatchNationActionViaUiContextOrFallback(int arg1, int arg2, int arg3,
                                                                  int arg4) {
  (void)arg1;
  (void)arg2;
  (void)arg3;
  (void)arg4;
  return 0;
}

// FUNCTION: IMPERIALISM 0x005410f0
void THostGreatPower::ProcessPendingDiplomacyProposalQueue(void) {
}

// FUNCTION: IMPERIALISM 0x00541170
void THostGreatPower::DispatchTurnEvent11F8NoPayloadSlot2AC(void) {
}
