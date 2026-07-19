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

  // Original object size is 0x968 (CRuntimeClass m_nObjectSize); the source class ended
  // at 0x964. Trailing 4 byte(s) not yet semantically recovered — declared so sizeof and
  // the recomp's allocation size match the original.
  int field964;
};
