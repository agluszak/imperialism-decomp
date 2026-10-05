#pragma once

#include "game/map/TControlSeaZoneMission.h"

class TZone;

// VTABLE: IMPERIALISM 0x0065ac60
class TBlockadePortMission : public TControlSeaZoneMission {
  DECLARE_SERIAL(TBlockadePortMission)
public:
  TZone* portZoneContext3c; // +0x3c blockade-target port zone (deserialized by node id)

  TBlockadePortMission() : TControlSeaZoneMission(), portZoneContext3c(nullptr) {}

  TBlockadePortMission(TZone* context);
  virtual ~TBlockadePortMission() override;

  virtual void WriteTo(TStream* stream) override;  // slot 0x05 0x53ac60
  virtual void ReadFrom(TStream* stream) override; // slot 0x06 0x53aca0

  virtual void Initialize() override;       // slot 0x0c 0x53ace0
  virtual void SetStateByte8To2() override; // slot 0x0d 0x53ae90 -- state08 = 3
  virtual void
  CalculateNeeds() override; // slot 0x0f 0x53aeb0 -- resource weights from navy context

  virtual TMission*
  GetReplacement() override; // slot 0x12 0x53adf0 -- validate context / refresh child
  virtual bool Matches(eMissionType missionType, int key,
                       TZone* zoneContext) const override; // slot 0x13 0x53ba10

  virtual bool IsDefensiveSeaZoneMission() const override; // slot 0x18 0x53aa70
  virtual bool IsHospitalMission() const override;         // slot 0x19 0x53aa50

  virtual void GiveActionOrders(TTaskForce* mapOrderEntry)
      override; // slot 0x27 0x53ba40 -- queue map-order type 6 from context pointer
};

ASSERT_SIZE(TBlockadePortMission, 0x40);
