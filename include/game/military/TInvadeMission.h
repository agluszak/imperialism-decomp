#pragma once

#include "game/military/TAttackProvinceMission.h"

class TBeachheadMission;

// Mac: TInvadeMission — TAttackProvinceMission variant that also drives an
// amphibious TBeachheadMission child (beachhead34) when the target province
// is not directly reachable overland.
// VTABLE: IMPERIALISM 0x0065aec0
class TInvadeMission : public TAttackProvinceMission {
  DECLARE_SERIAL(TInvadeMission)
public:
  TBeachheadMission* beachhead34; // +0x34 owned amphibious-landing child mission

  TInvadeMission() : TAttackProvinceMission(), beachhead34(nullptr) {}

  // Mac: TInvadeMission(TZone*, short).
  TInvadeMission(TZone* beachheadZone, short targetProvince);
  virtual ~TInvadeMission() override;

  // Mac: CalculatePriority(). Sums the current army cost, derives remaining
  // city-development resource demand, and returns the larger pressure score.
  float CalculatePriority(); // 0x53f800

  virtual void WriteTo(TStream* stream) override;  // slot 0x05 0x53f640
  virtual void ReadFrom(TStream* stream) override; // slot 0x06 0x53f690
  virtual void Free() override;                    // slot 0x07 0x53f410

  virtual int AccumulateLack(int* accumulatedLack,
                             unsigned char includeExistingLack) const override; // 0x53fc10

  virtual void Initialize() override;       // slot 0x0c 0x53f580 -- init from nation/target tile
  virtual void SetStateByte8To2() override; // slot 0x0d 0x53f5f0 -- state08 = 2
  virtual void
  CalculateNeeds() override; // slot 0x0f 0x53f610 -- updates invade+beachhead child state

  virtual void Reassess() override;   // slot 0x10 0x53f7d0 -- advance composite handlers
  virtual void GiveOrders() override; // slot 0x11 0x53f780 -- refresh beachhead node / repath
  virtual TMission*
  GetReplacementSlot48() override; // slot 0x12 0x53fe10 -- reset target terrain class + refresh
  virtual bool Matches(eMissionType missionType, int key,
                       TZone* zoneContext) const override; // slot 0x13 0x53fbc0

  virtual bool IsArmyMission() const override; // slot 0x14 0x53faa0
  virtual bool IsNavyMission() const override; // slot 0x15 0x53f140

  virtual TMission* GetNavyMission() override; // slot 0x17 0x53f120 -- returns beachhead34

  virtual bool IsHospitalMission() const override; // slot 0x19 0x53f240

  virtual float
  IndustrialCostOfNeeds() override; // slot 0x1b 0x53f1f0 -- composite score with beachhead
  virtual float
  ValueOf(TMilitaryUnit* candidateUnit) override; // slot 0x1c 0x53fac0 -- weighted score delta
  virtual float
  ValueOf(TShip* candidate) override; // slot 0x1d 0x53fb60 -- beachhead score if enabled

  using TAttackProvinceMission::AcceptReenforcement;
  virtual void AcceptReenforcement(TShip* ship,
                                   unsigned char notify) override; // slot 0x21 0x53f190
  using TAttackProvinceMission::RejectConstituent;
  virtual void RejectConstituent(TShip* ship,
                                 unsigned char notify) override; // slot 0x23 0x53f1c0
  virtual void ForgetTaskForce(TTaskForce* taskForce) override;  // slot 0x24 0x53f160
  virtual void Hold(unsigned char value) override;               // slot 0x25 0x53fb90

  virtual char
  SmokeEmIfYouGotEm() override; // slot 0x26 0x53f4e0 -- evaluate beachhead + queue eligible units

  virtual char TryResolveTargetTerrainClass() override; // slot 0x28 0x53fdc0
};

ASSERT_SIZE(TInvadeMission, 0x38);
