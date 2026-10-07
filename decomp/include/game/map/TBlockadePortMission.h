#pragma once

#include "game/map/TControlSeaZoneMission.h"

class TZone;

// VTABLE: IMPERIALISM 0x0065ac60
class TBlockadePortMission : public TControlSeaZoneMission {
  DECLARE_SERIAL(TBlockadePortMission)
public:
  TZone* portZoneContext; // +0x3c blockade-target port zone (deserialized by node id)

  TBlockadePortMission() : TControlSeaZoneMission(), portZoneContext(NULL) {}

  TBlockadePortMission(TZone* context);
  virtual ~TBlockadePortMission() override;

  virtual void WriteTo(TStream* stream) override;
  virtual void ReadFrom(TStream* stream) override;

  virtual void Initialize() override;
  virtual void SetStateByte8To2() override; // state08 = 3
  virtual void CalculateNeeds() override;   // resource weights from navy context

  virtual TMission* GetReplacement() override; // validate context / refresh child
  virtual bool Matches(eMissionType missionType, int key, TZone* zoneContext) const override;

  virtual bool IsDefensiveSeaZoneMission() const override;
  virtual bool IsHospitalMission() const override;

  virtual void GiveActionOrders(
      TTaskForce* mapOrderEntry) override; // queue map-order type 6 from context pointer
};

ASSERT_SIZE(TBlockadePortMission, 0x40);
