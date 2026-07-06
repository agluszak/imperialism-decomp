#include "game/TGreatPower.h"
#include "game/TSortedByRelationshipList.h"

// FUNCTION: IMPERIALISM 0x004df5a0
void TGreatPower::ReleaseProposalQueueSlot7F(void) {
  this->proposalQueue->ResetPtrListRecordsSlot1C();
}
