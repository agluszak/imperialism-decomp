#pragma once

#include "game/military/TAttackProvinceMission.h"

class TBeachheadMission;

// VTABLE: IMPERIALISM 0x0065aec0
class TInvadeMission : public TAttackProvinceMission {
  DECLARE_SERIAL(TInvadeMission)
public:
  TBeachheadMission* beachhead; // +0x34 owned amphibious-landing child mission

  TInvadeMission() : beachhead(NULL) {}

  TInvadeMission(TZone* beachheadZone, short targetProvince);
  virtual ~TInvadeMission() override;

  float CalculatePriority();

  virtual void WriteTo(TStream* stream) override;
  virtual void ReadFrom(TStream* stream) override;
  virtual void Free() override;

  virtual int AccumulateLack(int* accumulatedLack, bool includeExistingLack) const override;

  virtual void Initialize() override;       // init from nation/target tile
  virtual void SetStateByte8To2() override; // state08 = 2
  virtual void CalculateNeeds() override;   // updates invade+beachhead child state

  virtual void Reassess() override;            // advance composite handlers
  virtual void GiveOrders() override;          // refresh beachhead node / repath
  virtual TMission* GetReplacement() override; // reset target terrain class + refresh
  virtual bool Matches(eMissionType missionType, int key, TZone* zoneContext) const override;

  virtual bool IsArmyMission() const override;
  virtual bool IsNavyMission() const override;

  virtual TMission* GetNavyMission() override; // returns beachhead

  virtual bool IsHospitalMission() const override;

  virtual float IndustrialCostOfNeeds() override;               // composite score with beachhead
  virtual float ValueOf(TMilitaryUnit* candidateUnit) override; // weighted score delta
  virtual float ValueOf(TShip* candidate) override;             // beachhead score if enabled

  using TAttackProvinceMission::AcceptReenforcement;
  virtual void AcceptReenforcement(TShip* ship, bool notify) override;
  using TAttackProvinceMission::RejectConstituent;
  virtual void RejectConstituent(TShip* ship, bool notify) override;
  virtual void ForgetTaskForce(TTaskForce* taskForce) override;
  virtual void Hold(bool value) override;

  virtual bool SmokeEmIfYouGotEm() override; // evaluate beachhead + queue eligible units

  virtual bool TryResolveTargetTerrainClass() override;
};

ASSERT_SIZE(TInvadeMission, 0x38);
