#pragma once

#include "game/map/TNavyMission.h"
#include "game/navy/TTaskForce.h"

// Mac: TScatteredShipsMission — navy mission gathering scattered/stray ships.
// VTABLE: IMPERIALISM 0x0065a5a8
class TScatteredShipsMission : public TNavyMission {
  DECLARE_SERIAL(TScatteredShipsMission)
public:
  TScatteredShipsMission();
  TScatteredShipsMission(TZone* targetZone);
  virtual ~TScatteredShipsMission() override;

  virtual bool
  IsANoBrainer() const override; // slot 0x0a 0x535680 -- returns true (capability flag)

  // Slots 0x0c-0x0f: TMission's own virtuals, overridden here.
  virtual void Initialize() override;          // slot 0x0c 0x53bb90 -- reset state/score to default
  virtual void SetStateByte8To2() override;    // slot 0x0d 0x53bc00 -- state08 = 3
  virtual void CalculateImportance() override; // slot 0x0e 0x53bc20
  virtual void
  CalculateNeeds() override; // slot 0x0f 0x53bc40 -- resource weights from nation navy pressure

  virtual void Reassess() override; // slot 0x10 0x53bbb0 -- state-update pipeline
  virtual void
  GiveOrders() override; // slot 0x11 0x53bdd0 -- select context, promote mission order chain
  virtual TMission* GetReplacementSlot48() override; // slot 0x12 0x53bbe0 -- passthrough
  virtual bool Matches(eMissionType missionType, int key,
                       TZone* zoneContext) const override; // slot 0x13 0x53bcc0

  virtual bool IsDefensiveSeaZoneMission() const override; // slot 0x18 0x535660 -- returns true
  virtual bool IsHospitalMission() const override;         // slot 0x19 0x535640 -- returns true

  // Unconditionally returns nullptr (xor eax,eax; ret) -- see the TNavyMission base
  // declaration comment for why this slot returns TZone*.
  virtual TZone*
  RefreshMissionPortZoneContextForNation() override; // slot 0x28 0x53bf90 -- returns null
};

ASSERT_SIZE(TScatteredShipsMission, 0x3c);
