#pragma once

#include "game/TNavyMission.h"

// Mac: TControlSeaZoneMission — navy mission that holds/patrols a sea zone.
// Real base of TBeachheadMission and TBlockadePortMission (confirmed via RTTI
// CRuntimeClass ancestry), so several of its overrides below are inherited by
// both unchanged (see the notes in those two classes' files); the addresses
// here are the true, single owning definitions.
// VTABLE: IMPERIALISM 0x0065a740
class TControlSeaZoneMission : public TNavyMission {
  DECLARE_SERIAL(TControlSeaZoneMission)
public:
  virtual ~TControlSeaZoneMission() override; // slot 0x01 dtor 0x00535620 / ??_G 0x005355f0
public:
  TControlSeaZoneMission();
  TControlSeaZoneMission(TZone* targetZone);

  // Slots 0x0c-0x0f: TMission's own virtuals, overridden here.
  virtual void
  Initialize() override; // slot 0x0c 0x5387f0 -- port-zone-context score recompute (shared)
  virtual void
  SetStateByte8To2() override; // slot 0x0d 0x538fe0 -- state update from target navy similarity
  virtual void
  CalculateImportance() override; // slot 0x0e 0x539290 -- port-zone-context average score (shared)
  virtual void
  CalculateNeeds() override; // slot 0x0f 0x5393a0 -- resource weights from allied navy pressure

  virtual TMission* GetReplacementSlot48()
      override; // slot 0x12 0x538900 -- validate terrain coverage / refresh target (shared)
  virtual char Matches(eMissionType missionType, int key,
                       TZone* zoneContext) const override; // slot 0x13 0x539600

  virtual char IsDefensiveSeaZoneMission() const override; // slot 0x18 0x5355d0
  virtual char IsHospitalMission() const override;         // slot 0x19 0x5355b0

  virtual void GiveActionOrders(TTaskForce* mapOrderEntry)
      override; // slot 0x27 0x539640 -- resolve+queue port-zone map order
  // Returns the resolved port-zone context TZone* (GetReplacementSlot48 consumes it,
  // storing the result back into targetZone18 -- confirmed by 0x538900's disassembly,
  // which calls this virtual and assigns EAX into targetZone18); base TNavyMission
  // declares it void, but every known caller of the base slot is this override.
  virtual TZone* RefreshMissionPortZoneContextForNation() override; // slot 0x28 0x539780 (shared)
};

ASSERT_SIZE(TControlSeaZoneMission, 0x3c);
