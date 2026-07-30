#pragma once

#include "game/military/TArmyMission.h"

// Mac: TAttackProvinceMission — army mission that masses/attacks a target
// province. Base of TInvadeMission (which adds a TBeachheadMission child).
// VTABLE: IMPERIALISM 0x0065adf8
class TAttackProvinceMission : public TArmyMission {
  DECLARE_SERIAL(TAttackProvinceMission)
public:
  short targetProvince30;   // +0x30 target province/region index (ctor = -1)
  short amassingProvince32; // +0x32 amassing province/region index (ctor = -1)

  TAttackProvinceMission() : TArmyMission(-1) {
    targetProvince30 = -1;
    amassingProvince32 = -1;
  }

  TAttackProvinceMission(short targetProvince, short amassingProvince);
  // Inline so TInvadeMission emits the original direct CObject teardown.
  // FUNCTION: IMPERIALISM 0x0053d7f0
  virtual ~TAttackProvinceMission() override {}

  virtual void WriteTo(TStream* stream) override;  // slot 0x05 0x53d810
  virtual void ReadFrom(TStream* stream) override; // slot 0x06 0x53d850
  virtual void Free() override;                    // slot 0x07 0x53d890

  virtual void
  Initialize() override; // slot 0x0c 0x53e570 -- resolves movement class from target province
  virtual void SetStateByte8To2() override; // slot 0x0d 0x53e180 -- sets state08 = 2 (pending)
  virtual void CalculateImportance()
      override; // slot 0x0e 0x53e1a0 -- terrain adjacency score (shared w/ TInvadeMission)
  virtual void CalculateNeeds()
      override; // slot 0x0f 0x53e290 -- populates requiredEquipageByClass from target province

  virtual void GiveOrders() override;                // slot 0x11 0x53de00
  virtual TMission* GetReplacementSlot48() override; // slot 0x12 0x53e050
  virtual bool Matches(eMissionType missionType, int key,
                       TZone* zoneContext) const override; // slot 0x13 0x53e5b0

  virtual bool IsHospitalMission() const override; // slot 0x19 0x53d6f0

  virtual float
  FitnessOf(TMilitaryUnit* candidateUnit,
            float* referenceVector) override; // slot 0x1e 0x53e500 (shared w/ TInvadeMission)

  virtual char SmokeEmIfYouGotEm() override; // slot 0x26 0x53d950

  // First TAttackProvinceMission-introduced virtual (slot 0x28 / offset 0xa0).
  virtual char TryResolveTargetTerrainClass(); // 0x53db60
};

ASSERT_SIZE(TAttackProvinceMission, 0x34);
