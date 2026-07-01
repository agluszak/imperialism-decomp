#pragma once

#include "game/TNavyMission.h"

// Mac: TControlSeaZoneMission — navy mission that holds/patrols a sea zone.
// Owner of several port-zone-context helper bodies shared (COMDAT-folded in
// the original binary) with TBeachheadMission and TBlockadePortMission; see
// the `// FUNCTION:` markers below and the callers in those two files.
// VTABLE: IMPERIALISM 0x0065a740
class TControlSeaZoneMission : public TNavyMission {
  DECLARE_SERIAL(TControlSeaZoneMission)
public:
  TControlSeaZoneMission();
  TControlSeaZoneMission(TZone* targetZone);

  // Slots 0x0c-0x0f: TMission's own virtuals, overridden here.
  virtual void Call30() override;             // slot 0x0c 0x5387f0 -- port-zone-context score recompute (shared)
  virtual void SetStateByte8To2() override;   // slot 0x0d 0x538fe0 -- state update from target navy similarity
  virtual void ResetValue0CToZero() override; // slot 0x0e 0x539290 -- port-zone-context average score (shared)
  virtual void NoOpSlot3C() override;         // slot 0x0f 0x5393a0 -- resource weights from allied navy pressure

  virtual TMission* GetReplacementSlot48() override; // slot 0x12 0x538900 -- validate terrain coverage / refresh target (shared)
  virtual char MatchesMissionKeySlot4C(int kind, int key, int mode) override; // slot 0x13 0x539600

  virtual char ReturnFalseSlot60() override; // slot 0x18 0x5355d0
  virtual char ReturnFalseSlot64() override; // slot 0x19 0x5355b0

  virtual void NoOpSlot9C() override; // slot 0x27 0x539640 -- resolve+queue port-zone map order
  virtual void RefreshMissionPortZoneContextForNation() override; // slot 0x28 0x539780 (shared)
};

ASSERT_SIZE(TControlSeaZoneMission, 0x3c);
