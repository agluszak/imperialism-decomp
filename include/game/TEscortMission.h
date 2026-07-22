#pragma once

#include "game/TNavyMission.h"

// Mac: TEscortMission — navy mission escorting a beachhead landing / convoy.
// VTABLE: IMPERIALISM 0x0065aab0
class TEscortMission : public TNavyMission {
  DECLARE_SERIAL(TEscortMission)
public:
  virtual ~TEscortMission() override; // slot 0x01 dtor 0x00539990 / ??_G 0x00539960
public:
  TEscortMission();
  TEscortMission(TZone* targetZone);

  // Slots 0x0c, 0x0e, 0x0f: TMission's own virtuals, overridden here.
  virtual void
  Initialize() override; // slot 0x0c 0x539a70 -- reset dispatch flag, copy target context id
  virtual void CalculateImportance()
      override; // slot 0x0e 0x539ca0 -- nation-scaled score using primary port context
  virtual void CalculateNeeds()
      override; // slot 0x0f 0x539e70 -- resource weights from eligible-nation navy pressure

  virtual void GiveOrders()
      override; // slot 0x11 0x53a290 -- reset beachhead-child flags, dispatch field5 context
  virtual TMission* GetReplacementSlot48() override; // slot 0x12 0x539900 -- passthrough
  virtual bool Matches(eMissionType missionType, int key,
                       TZone* zoneContext) const override; // slot 0x13 0x53a250

  virtual bool IsDefensiveSeaZoneMission() const override; // slot 0x18 0x539940
  virtual bool IsHospitalMission() const override;         // slot 0x19 0x539920
};

ASSERT_SIZE(TEscortMission, 0x3c);
