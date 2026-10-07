#pragma once

#include "game/map/TControlSeaZoneMission.h"

class TInvadeMission;

// VTABLE: IMPERIALISM 0x0065ab88
class TBeachheadMission : public TControlSeaZoneMission {
  DECLARE_SERIAL(TBeachheadMission)
public:
  TInvadeMission* parentMission; // +0x3c owning composite invade mission

  TBeachheadMission() : parentMission(NULL) {}

  TBeachheadMission(TZone* targetZone, TInvadeMission* parentMission);
  virtual ~TBeachheadMission() override;

  virtual bool Matches(eMissionType missionType, int key, TZone* zoneContext) const override;

  virtual TMission* GetArmyMission() override; // returns parentMission (not `this`)
  virtual bool IsDefensiveSeaZoneMission() const override;
  virtual bool IsHospitalMission() const override;

  virtual bool SmokeEmIfYouGotEm() override; // clears blockade-port child order links if ready

  virtual void GiveActionOrders(
      TTaskForce* mapOrderEntry) override; // try-queue province order from context message

  virtual void CalculateNeeds() override;
};

ASSERT_SIZE(TBeachheadMission, 0x40);
