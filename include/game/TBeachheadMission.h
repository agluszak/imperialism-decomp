#pragma once

#include "game/TControlSeaZoneMission.h"

class TAttackProvinceMission;

// Mac: TBeachheadMission — navy-mission child of TInvadeMission; ferries/
// escorts an amphibious landing at a target coastal zone and reports back to
// its owning TInvadeMission via parentMission3c.
//
// Real base is TControlSeaZoneMission (confirmed via the RTTI CRuntimeClass
// ancestry: TBeachheadMission -> TControlSeaZoneMission -> TNavyMission ->
// TMission -> TObject -> CObject), not TNavyMission directly. Slots 0x0c-0x0f,
// 0x12, and 0x28 below are NOT overridden here -- they're inherited unchanged
// from TControlSeaZoneMission (previously mis-modeled as a same-address
// "COMDAT fold" between sibling classes; it's plain inheritance).
// VTABLE: IMPERIALISM 0x0065ab88
class TBeachheadMission : public TControlSeaZoneMission {
  DECLARE_SERIAL(TBeachheadMission)
public:
  TAttackProvinceMission* parentMission3c; // +0x3c owning TInvadeMission (typed as its base)

  TBeachheadMission();
  TBeachheadMission(TZone* targetZone, TAttackProvinceMission* parentMission);

  virtual char MatchesMissionKeySlot4C(int kind, int key, int mode) override; // slot 0x13 0x53a7b0

  virtual int
  ReturnZeroSlot58() override; // slot 0x16 0x53a920 -- returns parentMission3c (not `this`)
  virtual char ReturnFalseSlot60() override; // slot 0x18 0x53a3b0
  virtual char ReturnFalseSlot64() override; // slot 0x19 0x53a390

  virtual char ReturnFalseSlot98()
      override; // slot 0x26 0x53a940 -- clears blockade-port child order links if ready

  virtual void
  NoOpSlot9C() override; // slot 0x27 0x53a800 -- try-queue province order from context message

  // slot 0x0f 0x53a500 -- resource weights from navy context (own override; not shared)
  virtual void NoOpSlot3C() override;
};

ASSERT_SIZE(TBeachheadMission, 0x40);
