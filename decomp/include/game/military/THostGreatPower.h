#pragma once

#include "compat.h"

#include "game/nation/TGreatPower.h"
#include "game/mfc.h"

class TStream;

// VTABLE: IMPERIALISM 0x0065b3d0
class THostGreatPower : public TGreatPower {
public:
  DECLARE_DYNCREATE(THostGreatPower)
  ~THostGreatPower() override;

  void WriteTo(TStream* stream) override;
  void ReadFrom(TStream* stream) override;
  char ReplyToTradeOffer(NationSlot targetNationSlot, short amount, short price,
                         ResourceKindStorage resourceKind) override;
  bool IsHost(void) const override;
  void ReplyToDiplomacyOffers(void) override;
  void SorryYouLose(void) override;

  THostGreatPower() : nationLostEventDispatched(0) {}

  // +0x964 — serialized from save format 0x3d onward. The host sends the tagged
  // nation-loss event only once, then sets this byte.
  unsigned char nationLostEventDispatched;
  unsigned char pad965[3];
};
ASSERT_SIZE(THostGreatPower, 0x968);
