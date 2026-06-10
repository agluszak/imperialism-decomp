#include "game/TGreatPower.h"
#include "game/TQueueObject.h"

// FUNCTION: IMPERIALISM 0x004df5a0
#pragma optimize("y", on)
void TGreatPower::ReleaseProposalQueueSlot7F(void) {
  this->proposalQueue->Release1C();
}
#pragma optimize("", on)
