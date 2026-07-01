#pragma once

#include "game/TArmyMission.h"

// Mac: TDefendProvinceMission — army defend-province mission.
// VTABLE: IMPERIALISM 0x0065a680
class TDefendProvinceMission : public TArmyMission {
  DECLARE_SERIAL(TDefendProvinceMission)
public:
  TDefendProvinceMission();

  virtual void Call30() override; // slot 0x0c (TMission) 0x53eff0
  virtual void Free() override;   // slot 0x1c (TObject) 0x53ebe0 -- releases orderListAt18 and deletes self

  virtual char ReturnFalseSlot28() override; // slot 0x28 0x5357b0
  virtual char ReturnFalseSlot64() override; // slot 0x64 0x535790
  virtual void MissionSlot44() override;     // slot 0x44 0x535770 -- propagates target tile to linked units
  virtual TMission* GetReplacementSlot48() override; // slot 0x48 0x53f040
  virtual char MatchesMissionKeySlot4C(int kind, int key, int mode) override; // slot 0x4c 0x53f010

  // These override TMission's own slots 0x0d/0x0e/0x0f (SetStateByte8To2 /
  // ResetValue0CToZero / NoOpSlot3C) with DefendProvinceMission-specific bodies.
  virtual void SetStateByte8To2() override;    // slot 0x34 0x53ecc0 -- updates state by nation target match
  virtual void ResetValue0CToZero() override;  // slot 0x38 0x53ed00 -- computes terrain adjacency score
  virtual void NoOpSlot3C() override;          // slot 0x3c 0x53edf0 -- populates resource weights by diplomacy context

  static float ComputeLocalSupportVectorScore(int nodeContext);
  static float ComputeCrossNationSupportVectorScore(int nodeContext);
};

ASSERT_SIZE(TDefendProvinceMission, 0x30);
