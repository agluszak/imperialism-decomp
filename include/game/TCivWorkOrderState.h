#pragma once

#include "game/TUnitOrderState.h"

class TCivWorkOrderState : public TUnitOrderState {
public:
  short remainingTurns24;   // 0x24
  short completionMarker26; // 0x26

  void InitializeCivWorkOrderState(int nOrderType, int pOwnerContext, int nOrderOwnerNationId);
  void thunk_InitializeCivWorkOrderState(int nOrderType, int pOwnerContext,
                                         int nOrderOwnerNationId);
};
