#pragma once

#include "game/TGreatPower.h"

// VTABLE: IMPERIALISM 0x00654088
class TAutoGreatPower : public TGreatPower {
public:
  TListObject* autoTrackedListB60;

  TAutoGreatPower();
  static void* GetTAutoGreatPowerClassNamePointer(void);
  void* ConstructTAutoGreatPowerBaseState(void);
  void RecomputeDiplomacyAidBudgetAndResetNeedScoresAndMatrix(void);
  void ReplayQueuedDiplomacyProposalRowsAndProcessQueue(void);
};
