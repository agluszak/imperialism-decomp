#pragma once

#include "game/map/TNavyMission.h"

// Mac: TEscortMission — navy mission escorting a beachhead landing / convoy.
// VTABLE: IMPERIALISM 0x0065aab0
class TEscortMission : public TNavyMission {
  DECLARE_SERIAL(TEscortMission)
public:
  virtual ~TEscortMission() override; // slot 0x01 dtor 0x00539990 / ??_G
public:
  TEscortMission() {}

  TEscortMission(TZone* targetZone);

  virtual void Initialize() override;          // reset dispatch flag, copy target context id
  virtual void CalculateImportance() override; // nation-scaled score using primary port context
  virtual void CalculateNeeds() override; // resource weights from eligible-nation navy pressure

  virtual void GiveOrders() override; // reset beachhead-child flags, dispatch field5 context
  virtual TMission* GetReplacement() override; // passthrough
  virtual bool Matches(eMissionType missionType, int key, TZone* zoneContext) const override;

  virtual bool IsDefensiveSeaZoneMission() const override;
  virtual bool IsHospitalMission() const override;
};

ASSERT_SIZE(TEscortMission, 0x3c);
