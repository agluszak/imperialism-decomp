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
  NationSlot nationId;   // 0x04 source-nation id (InitializeMission...)
  short pathMarker;      // 0x06 path/dispatch marker (set 0xffff)
  unsigned char state08; // 0x08 lifecycle state byte (ctor = 2)
  unsigned char padding09[3];
  float importanceScore;  // 0x0c cached score/value (ctor = 0.0f)
  unsigned char flag10;   // 0x10 dispatch flag (SetMissionField10FromArgSlot94)
  unsigned char marker11; // 0x11 status byte (ctor = 0xff)
  unsigned char padding12[2];

  TMission();

  // --- MFC CObject prefix slots 0x00-0x04 ---
  DECLARE_SERIAL(TMission)
  // Inline so every mission subclass reproduces the original direct CObject teardown.
  // FUNCTION: IMPERIALISM 0x00535080
  virtual ~TMission() override {}

  // --- TMission's own virtuals, exact vtable slot order ---
  virtual void WriteTo(TStream* stream) override;  // slot 0x05 0x535820
  virtual void ReadFrom(TStream* stream) override; // slot 0x06 0x5358a0
  virtual bool IsANoBrainer() const;               // 0x0a 0x534c00
  virtual int AccumulateLack(int* accumulatedLack,
                             bool includeExistingLack) const; // 0x0b 0x534c20
  virtual void Initialize();                                  // 0x0c 0x534c40
  virtual void SetStateByte8To2();                            // 0x0d 0x534c60
  virtual void CalculateImportance();                         // 0x0e 0x534c80
  virtual void CalculateNeeds();                              // 0x0f 0x534ca0
  virtual void Reassess();                                    // 0x10 0x534cc0
  virtual void GiveOrders();                                  // 0x11 0x534cf0
  virtual TMission* GetReplacement();                         // 0x12 0x534d10
  virtual bool Matches(eMissionType missionType, int key,
                       TZone* zoneContext) const;                  // 0x13 0x534d30
  virtual bool IsArmyMission() const;                              // 0x14 0x534d50
  virtual bool IsNavyMission() const;                              // 0x15 0x534d70
  virtual TMission* GetArmyMission();                              // 0x16 0x534d90
  virtual TMission* GetNavyMission();                              // 0x17 0x534db0
  virtual bool IsDefensiveSeaZoneMission() const;                  // 0x18 0x534dd0
  virtual bool IsHospitalMission() const;                          // 0x19 0x534df0
  virtual float GetWeightedSatisfaction();                         // 0x1a 0x534e10
  virtual float IndustrialCostOfNeeds();                           // 0x1b 0x534e30
  virtual float ValueOf(TShip* candidate);                         // 0x1d 0x534e50
  virtual float ValueOf(TMilitaryUnit* candidateUnit);             // 0x1c 0x534e70
  virtual float FitnessOf(TShip* candidate, float* targetProfile); // 0x1f 0x534e90
  virtual float FitnessOf(TMilitaryUnit* candidateUnit,
                          float* referenceVector);            // 0x1e 0x534eb0
  virtual void AcceptReenforcement(TShip* ship, bool notify); // 0x21 0x534ed0
  virtual void AcceptReenforcement(TMilitaryUnit* unit,
                                   bool notify);            // 0x20 0x534ef0
  virtual void RejectConstituent(TShip* ship, bool notify); // 0x23 0x534f10
  virtual void RejectConstituent(TMilitaryUnit* unit,
                                 bool notify);         // 0x22 0x534f30
  virtual void ForgetTaskForce(TTaskForce* taskForce); // 0x24 0x534f50
  virtual void Hold(bool value);                       // 0x25 0x534f70
  virtual bool SmokeEmIfYouGotEm();                    // 0x26 0x534f90

  void InitializeMissionWithNationIdAndResetPathMarker(NationSlot nationSlot);

  static TMission* CreateMission(NationSlot sourceNation, eMissionType missionKind, int nodeKey,
                                 TZone* zoneContext, int relatedNodeKey);

  static TMission* Find(TSortedList* missions, eMissionType missionType, short key,
                        TZone* zoneContext);
};

ASSERT_SIZE(TMission, 0x14);

short __cdecl CompareMissionOrderEntriesByMovementClassThenEfficiency(void* a, void* b,
                                                                      void* reverseOrder);
