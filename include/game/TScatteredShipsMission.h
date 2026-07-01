#pragma once

#include "game/TMapOrderEntry.h"
#include "game/TNavyMission.h"

// Mac: TScatteredShipsMission — navy mission gathering scattered/stray ships.
// VTABLE: IMPERIALISM 0x0065a5a8
class TScatteredShipsMission : public TNavyMission {
  DECLARE_SERIAL(TScatteredShipsMission)
public:
  TScatteredShipsMission();
  TScatteredShipsMission(TZone* targetZone);

  virtual char ReturnFalseSlot28() override; // slot 0x0a 0x535680 -- returns true (capability flag)

  // Slots 0x0c-0x0f: TMission's own virtuals, overridden here.
  virtual void Call30() override;             // slot 0x0c 0x53bb90 -- reset state/score to default
  virtual void SetStateByte8To2() override;   // slot 0x0d 0x53bc00 -- state08 = 3
  virtual void ResetValue0CToZero() override; // slot 0x0e 0x53bc20
  virtual void NoOpSlot3C() override;         // slot 0x0f 0x53bc40 -- resource weights from nation navy pressure

  virtual void RefreshSlot40() override;             // slot 0x10 0x53bbb0 -- state-update pipeline
  virtual void MissionSlot44() override;             // slot 0x11 0x53bdd0 -- select context, promote mission order chain
  virtual TMission* GetReplacementSlot48() override; // slot 0x12 0x53bbe0 -- passthrough
  virtual char MatchesMissionKeySlot4C(int kind, int key, int mode) override; // slot 0x13 0x53bcc0

  virtual char ReturnFalseSlot60() override; // slot 0x18 0x535660 -- returns true
  virtual char ReturnFalseSlot64() override; // slot 0x19 0x535640 -- returns true

  virtual void RefreshMissionPortZoneContextForNation() override; // slot 0x28 0x53bf90 -- returns false

  // Generic child-link-chain flag setter (not a vtable slot; misattributed
  // class prefix in Ghidra, kept per Hard Rule 6). Shared by other navy
  // mission classes walking a TMapOrderChildLinkNode chain.
  static void SetMapOrderEntryChildFlags(TMapOrderChildLinkNode* node, unsigned char flag); // 0x536f70
};

ASSERT_SIZE(TScatteredShipsMission, 0x3c);
