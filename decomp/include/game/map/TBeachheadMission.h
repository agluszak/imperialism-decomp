#pragma once

#include "game/map/TControlSeaZoneMission.h"

class TInvadeMission;

// VTABLE: IMPERIALISM 0x0065ab88
class TBeachheadMission : public TControlSeaZoneMission {
  DECLARE_SERIAL(TBeachheadMission)
public:
  TInvadeMission* parentMission; // +0x3c owning composite invade mission

  TBeachheadMission() : TControlSeaZoneMission(), parentMission(nullptr) {}

  TBeachheadMission(TZone* targetZone, TInvadeMission* parentMission);
  virtual ~TBeachheadMission() override;

  virtual bool Matches(eMissionType missionType, int key,
                       TZone* zoneContext) const override; // slot 0x13 0x53a7b0

  virtual TMission*
  GetArmyMission() override; // slot 0x16 0x53a920 -- returns parentMission (not `this`)
  virtual bool IsDefensiveSeaZoneMission() const override; // slot 0x18 0x53a3b0
  virtual bool IsHospitalMission() const override;         // slot 0x19 0x53a390

  virtual bool SmokeEmIfYouGotEm()
      override; // slot 0x26 0x53a940 -- clears blockade-port child order links if ready

  virtual void GiveActionOrders(TTaskForce* mapOrderEntry)
      override; // slot 0x27 0x53a800 -- try-queue province order from context message

  // slot 0x0f 0x53a500 -- resource weights from navy context (own override; not shared)
  virtual void CalculateNeeds() override;
};

ASSERT_SIZE(TBeachheadMission, 0x40);
