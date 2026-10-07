#pragma once

#include "compat.h"
#include "decomp_types.h"
#include "game/mfc.h"
#include "game/nation_domain_types.h"
#include "game/app/TObject.h"

class TZone;
class TMilitaryUnit;
class TShip;
class TTaskForce;
class TSortedList;

enum eMissionType {
  kMissionTypeAttackProvince = 0, // TAttackProvinceMission (direct) / TControlSeaZoneMission
  kMissionTypeAmassProvince = 1,  // TAttackProvinceMission with an amassing province
  kMissionTypeInvadeProvince = 2, // TInvadeMission / TControlSeaZoneMission
  kMissionTypeDefendProvince =
      3,                        // TDefendProvinceMission / TEscortMission / TControlSeaZoneMission
  kMissionTypeBlockadePort = 4, // TBlockadePortMission
  kMissionTypeScatteredShips = 5, // TScatteredShipsMission
};

// VTABLE: IMPERIALISM 0x0065a4e8
class TMission : public TObject {
public:
  NationSlot nationId;   // source-nation id (InitializeMission...)
  short pathMarker;      // path/dispatch marker
  char priority;         // lower is more urgent
  float importanceScore; // cached score/value (ctor = 0.0f)
  unsigned char onHold;
  char requiredForces; // bit 0 army, bit 1 navy
  unsigned char padding12[2];

  TMission();

  // --- MFC CObject prefix slots 0x00-0x04 ---
  DECLARE_SERIAL(TMission)
  // Inline so every mission subclass reproduces the original direct CObject teardown.
  // FUNCTION: IMPERIALISM 0x00535080
  virtual ~TMission() override {}

  // --- TMission's own virtuals, exact vtable slot order ---
  virtual void WriteTo(TStream* stream) override;
  virtual void ReadFrom(TStream* stream) override;
  virtual bool IsANoBrainer() const;
  virtual int AccumulateLack(int* accumulatedLack, bool includeExistingLack) const;
  virtual void Initialize();
  virtual void ResetPriority();
  virtual void CalculateImportance();
  virtual void CalculateNeeds();
  virtual void Reassess();
  virtual void GiveOrders();
  virtual TMission* GetReplacement();
  virtual bool Matches(eMissionType missionType, int key, TZone* zoneContext) const;
  virtual bool IsArmyMission() const;
  virtual bool IsNavyMission() const;
  virtual TMission* GetArmyMission();
  virtual TMission* GetNavyMission();
  virtual bool IsDefensiveSeaZoneMission() const;
  virtual bool IsHospitalMission() const;
  virtual float GetWeightedSatisfaction();
  virtual float IndustrialCostOfNeeds();
  virtual float ValueOf(TShip* candidate);
  virtual float ValueOf(TMilitaryUnit* candidateUnit);
  virtual float FitnessOf(TShip* candidate, float* targetProfile);
  virtual float FitnessOf(TMilitaryUnit* candidateUnit, float* referenceVector);
  virtual void AcceptReenforcement(TShip* ship, bool notify);
  virtual void AcceptReenforcement(TMilitaryUnit* unit, bool notify);
  virtual void RejectConstituent(TShip* ship, bool notify);
  virtual void RejectConstituent(TMilitaryUnit* unit, bool notify);
  virtual void ForgetTaskForce(TTaskForce* taskForce);
  virtual void Hold(bool value);
  virtual bool SmokeEmIfYouGotEm();

  void IMission(NationSlot nationSlot);

  static TMission* CreateMission(NationSlot sourceNation, eMissionType missionKind, int nodeKey,
                                 TZone* zoneContext, int relatedNodeKey);

  static TMission* Find(TSortedList* missions, eMissionType missionType, short key,
                        TZone* zoneContext);
};

ASSERT_SIZE(TMission, 0x14);

short __cdecl CompareByMovementThenEfficiency(void* a, void* b, void* reverseOrder);
