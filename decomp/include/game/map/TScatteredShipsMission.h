#pragma once

#include "game/map/TNavyMission.h"
#include "game/navy/TTaskForce.h"

// Mac: TScatteredShipsMission — navy mission gathering scattered/stray ships.
// VTABLE: IMPERIALISM 0x0065a5a8
class TScatteredShipsMission : public TNavyMission {
  DECLARE_SERIAL(TScatteredShipsMission)
public:
  TScatteredShipsMission() : TNavyMission() {}

  TScatteredShipsMission(TZone* targetZone) : TNavyMission(targetZone) {}
  virtual ~TScatteredShipsMission() override;

  virtual bool IsANoBrainer() const override; // returns true (capability flag)

  virtual void Initialize() override; // reset state/score to default
  virtual void ResetPriority() override;
  virtual void CalculateImportance() override;
  virtual void CalculateNeeds() override; // resource weights from nation navy pressure

  virtual void Reassess() override;            // state-update pipeline
  virtual void GiveOrders() override;          // select context, promote mission order chain
  virtual TMission* GetReplacement() override; // passthrough
  virtual bool Matches(eMissionType missionType, int key, TZone* zoneContext) const override;

  virtual bool IsDefensiveSeaZoneMission() const override; // returns true
  virtual bool IsHospitalMission() const override;         // returns true

  virtual TZone* PickAmassingZone() override; // returns null
};

ASSERT_SIZE(TScatteredShipsMission, 0x3c);
