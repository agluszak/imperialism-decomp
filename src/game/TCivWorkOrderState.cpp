#include "game/TCivWorkOrderState.h"

// FUNCTION: IMPERIALISM 0x005c28c0
// Civilian work-order ctor: the inlined base init (TUnitOrderState) sets the
// base fields and MSVC emits the single derived vptr write to 0x0066ee60. No
// derived field init here (remainingTurns24/completionMarker26 are set later by
// InitializeCivWorkOrderState).
TCivWorkOrderState::TCivWorkOrderState() {}

// FUNCTION: IMPERIALISM 0x00404b33
void TCivWorkOrderState::InitializeCivWorkOrderState(int nOrderType, int pOwnerContext,
                                                     int nOrderOwnerNationId) {
  this->RegisterUnitOrderWithOwnerManager(nOrderType, pOwnerContext, nOrderOwnerNationId, 0);
  this->remainingTurns24 = 0;
  this->completionMarker26 = static_cast<short>(-1);
}
#pragma optimize("", on)
