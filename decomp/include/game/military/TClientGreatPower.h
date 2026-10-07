#pragma once

#include "compat.h"

#include "game/nation/TGreatPower.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0065b728
class TClientGreatPower : public TGreatPower {
public:
  DECLARE_DYNCREATE(TClientGreatPower)
  ~TClientGreatPower() override;

  bool IsClient(void) const override;
  bool IsRemote(void) const override;
  void AcceptOffer(short proposalIndex) override;
  void RejectOffer(short proposalQueueIndex) override;
  void ReplyToDiplomacyOffers(void) override;
  int ConsiderWarOfIntervention(int targetNation, int sourceNation) override;
  int ConsiderWarOfAlliance(int targetNation, int sourceNation, char swapRoles) override;
  void SorryYouLose(void) override;

  TClientGreatPower() : TGreatPower() {}
};
ASSERT_SIZE(TClientGreatPower, 0x964);
