#pragma once

#include "game/TNavyMission.h"

class TAttackProvinceMission;

// Mac: TBeachheadMission — navy-mission child of TInvadeMission; ferries/
// escorts an amphibious landing at a target coastal zone and reports back to
// its owning TInvadeMission via parentMission3c.
// VTABLE: IMPERIALISM 0x0065ab88
class TBeachheadMission : public TNavyMission {
  DECLARE_SERIAL(TBeachheadMission)
public:
  TAttackProvinceMission* parentMission3c; // +0x3c owning TInvadeMission (typed as its base)

  TBeachheadMission();
  TBeachheadMission(TZone* targetZone, TAttackProvinceMission* parentMission);

  // Slots 0x0c-0x0f: TMission's own virtuals, overridden here (TNavyMission
  // leaves them at TMission's defaults).
  virtual void Call30() override;             // slot 0x0c 0x5387f0 -- port-zone-context score recompute
  virtual void SetStateByte8To2() override;   // slot 0x0d 0x538fe0 -- state update from target navy similarity
  virtual void ResetValue0CToZero() override; // slot 0x0e 0x539290 -- port-zone-context average score
  virtual void NoOpSlot3C() override;         // slot 0x0f 0x53a500 -- resource weights from navy context

  virtual TMission* GetReplacementSlot48() override; // slot 0x12 0x538900 -- validates terrain coverage / refreshes target
  virtual char MatchesMissionKeySlot4C(int kind, int key, int mode) override; // slot 0x13 0x53a7b0

  virtual int ReturnZeroSlot58() override;   // slot 0x16 0x53a920 -- returns parentMission3c (not `this`)
  virtual char ReturnFalseSlot60() override; // slot 0x18 0x53a3b0
  virtual char ReturnFalseSlot64() override; // slot 0x19 0x53a390

  virtual char ReturnFalseSlot98() override; // slot 0x26 0x53a940 -- clears blockade-port child order links if ready

  virtual void NoOpSlot9C() override; // slot 0x27 0x53a800 -- try-queue province order from context message
  virtual void RefreshMissionPortZoneContextForNation() override; // slot 0x28 0x539780
};

ASSERT_SIZE(TBeachheadMission, 0x40);
