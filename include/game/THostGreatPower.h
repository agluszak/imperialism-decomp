#pragma once

#include "game/TGreatPower.h"
#include "game/mfc.h"

class TStream;

// VTABLE: IMPERIALISM 0x0065b3d0
class THostGreatPower : public TGreatPower {
public:
  DECLARE_DYNCREATE(THostGreatPower)
  ~THostGreatPower() override;

  void WriteTo(TStream* stream) override;
  void ReadFrom(TStream* stream) override;
  char TryDispatchNationActionViaUiContextOrFallback(int arg1, int arg2, int arg3,
                                                     int arg4) override;
  char ReturnFalseNationStateCapabilityFlag9C(void) override;
  void ProcessPendingDiplomacyProposalQueue(void) override;
  void DispatchTurnEvent11F8NoPayloadSlot2AC(void) override;

  THostGreatPower();
};

