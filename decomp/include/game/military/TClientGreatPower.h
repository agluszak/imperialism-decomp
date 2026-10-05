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
  // slot 0x9f — 0x005416b0: client command 0x69 wrapper around slot 0x27c logic.
  int ConsiderWarOfIntervention(int targetNation, int sourceNation) override;
  // slot 0xa0 — 0x005415c0: client command 0x61 wrapper around slot 0x280 logic.
  int ConsiderWarOfAlliance(int targetNation, int sourceNation,
                                             char swapRoles) override;
  void SorryYouLose(void) override;

  TClientGreatPower() : TGreatPower() {}
};
ASSERT_SIZE(TClientGreatPower, 0x964);
