#include "game/TCivWorkOrderState.h"

// FUNCTION: IMPERIALISM 0x00404b33
void TCivWorkOrderState::thunk_InitializeCivWorkOrderState(int nOrderType, int pOwnerContext,
                                                           int nOrderOwnerNationId) {
  this->InitializeCivWorkOrderState(nOrderType, pOwnerContext, nOrderOwnerNationId);
}

// FUNCTION: IMPERIALISM 0x005c2940
void TCivWorkOrderState::InitializeCivWorkOrderState(int nOrderType, int pOwnerContext,
                                                     int nOrderOwnerNationId) {
  this->thunk_RegisterUnitOrderWithOwnerManager(nOrderType, pOwnerContext, nOrderOwnerNationId, 0);
  this->remainingTurns24 = 0;
  this->completionMarker26 = static_cast<short>(-1);
}
