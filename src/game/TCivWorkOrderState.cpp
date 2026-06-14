#include "game/TCivWorkOrderState.h"
#include "game/TUnitOrderState.h"

#if defined(_MSC_VER)
#pragma optimize("y", on)
#endif

// Civilian work-order ctor: the inlined base init (TUnitOrderState) sets the
// base fields and MSVC emits the single derived vptr write to 0x0066ee60. No
// derived field init here (remainingTurns24/completionMarker26 are set later by
// InitializeCivWorkOrderState).
// FUNCTION: IMPERIALISM 0x005c28c0
TCivWorkOrderState::TCivWorkOrderState() {}

// FUNCTION: IMPERIALISM 0x005c2940
void TCivWorkOrderState::InitializeCivWorkOrderState(int nOrderType, int pOwnerContext,
                                                     int nOrderOwnerNationId) {
  this->RegisterUnitOrderWithOwnerManager(static_cast<short>(nOrderType), pOwnerContext,
                                          static_cast<short>(nOrderOwnerNationId), 0);
  this->remainingTurns24 = 0;
  this->completionMarker26 = static_cast<short>(-1);
}

#if defined(_MSC_VER)
#pragma optimize("", on)
#endif
