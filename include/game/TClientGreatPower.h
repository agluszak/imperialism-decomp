#pragma once

#include "game/TGreatPower.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0065b728
class TClientGreatPower : public TGreatPower {
public:
  DECLARE_DYNCREATE(TClientGreatPower)
  ~TClientGreatPower() override;

  // slot 0x26 — 0x005412b0
  char IsClient(void) override;
  // slot 0x28 — 0x005412d0
  char IsRemote(void) override;
  // slot 0x7b — 0x005413b0
  void AcceptOffer(short proposalIndex) override;
  // slot 0x7c — 0x00541450
  void RejectOffer(unsigned short proposalQueueIndex) override;
  // slot 0x81 — 0x005414f0
  void ReplyToDiplomacyOffers(void) override;
  // slot 0x9f — 0x005416b0: client command 0x69 wrapper around slot 0x27c logic.
  int CheckTransitionSlot27C(int targetNation, int sourceNation) override;
  // slot 0xa0 — 0x005415c0: client command 0x61 wrapper around slot 0x280 logic.
  int PropagateWarTransitionSlot280(int targetNation, int sourceNation, int mode) override;
  // slot 0xab — 0x00541790
  void SorryYouLose(void) override;

  TClientGreatPower() : TGreatPower() {}
};
