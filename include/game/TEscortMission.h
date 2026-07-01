#pragma once

#include "game/TNavyMission.h"

// Mac: TEscortMission — navy mission escorting a beachhead landing / convoy.
// VTABLE: IMPERIALISM 0x0065aab0
class TEscortMission : public TNavyMission {
  DECLARE_SERIAL(TEscortMission)
public:
  TEscortMission();
  TEscortMission(TZone* targetZone);

  // Slots 0x0c, 0x0e, 0x0f: TMission's own virtuals, overridden here.
  virtual void Call30() override;             // slot 0x0c 0x539a70 -- reset dispatch flag, copy target context id
  virtual void ResetValue0CToZero() override; // slot 0x0e 0x539ca0 -- nation-scaled score using primary port context
  virtual void NoOpSlot3C() override;         // slot 0x0f 0x539e70 -- resource weights from eligible-nation navy pressure

  virtual void MissionSlot44() override; // slot 0x11 0x53a290 -- reset beachhead-child flags, dispatch field5 context
  virtual TMission* GetReplacementSlot48() override; // slot 0x12 0x539900 -- passthrough
  virtual char MatchesMissionKeySlot4C(int kind, int key, int mode) override; // slot 0x13 0x53a250

  virtual char ReturnFalseSlot60() override; // slot 0x18 0x539940
  virtual char ReturnFalseSlot64() override; // slot 0x19 0x539920
};

ASSERT_SIZE(TEscortMission, 0x3c);
