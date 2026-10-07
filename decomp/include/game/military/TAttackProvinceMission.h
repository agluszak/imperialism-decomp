#pragma once

#include "game/military/TArmyMission.h"

// VTABLE: IMPERIALISM 0x0065adf8
class TAttackProvinceMission : public TArmyMission {
  DECLARE_SERIAL(TAttackProvinceMission)
public:
  short targetProvince;   // +0x30 target province/region index (ctor = -1)
  short amassingProvince; // +0x32 amassing province/region index (ctor = -1)

  TAttackProvinceMission() : TArmyMission(-1) {
    this->targetProvince = -1;
    this->amassingProvince = -1;
  }

  TAttackProvinceMission(short targetProvince, short amassingProvince);
  // Inline so TInvadeMission emits the original direct CObject teardown.
  // FUNCTION: IMPERIALISM 0x0053d7f0
  virtual ~TAttackProvinceMission() override {}

  virtual void WriteTo(TStream* stream) override;
  virtual void ReadFrom(TStream* stream) override;
  virtual void Free() override;

  virtual void Initialize() override;          // resolves movement class from target province
  virtual void SetStateByte8To2() override;    // sets state08 = 2 (pending)
  virtual void CalculateImportance() override; // terrain adjacency score (shared w/ TInvadeMission)
  virtual void CalculateNeeds() override; // populates requiredEquipageByClass from target province

  virtual void GiveOrders() override;
  virtual TMission* GetReplacement() override;
  virtual bool Matches(eMissionType missionType, int key, TZone* zoneContext) const override;

  virtual bool IsHospitalMission() const override;

  virtual float
  FitnessOf(TMilitaryUnit* candidateUnit,
            float* referenceVector) override; // slot 0x1e 0x53e500 (shared w/ TInvadeMission)

  virtual bool SmokeEmIfYouGotEm() override;

  // First TAttackProvinceMission-introduced virtual (slot 0x28 / offset 0xa0).
  virtual bool TryResolveTargetTerrainClass();
};

ASSERT_SIZE(TAttackProvinceMission, 0x34);
