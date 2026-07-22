#pragma once

#include "game/TMission.h"
#include "game/TSortedList.h"

class TMilitaryUnit;

// Army-mission branch base (vtable prefix shares TMission slots 0x00-0x26).
// VTABLE: IMPERIALISM 0x0065ad38
class TArmyMission : public TMission {
  DECLARE_SERIAL(TArmyMission)
public:
  short presentLocation14;
  short padding_16;
  TSortedList* orderListAt18;
  float requiredEquipageByClass[5]; // offset 0x1c

  TArmyMission();
  TArmyMission(int nodeKey);
  virtual ~TArmyMission() override;

  virtual void WriteTo(TStream* stream) override;  // slot 0x05
  virtual void ReadFrom(TStream* stream) override; // slot 0x06
  virtual void
  Free() override; // slot 0x1c (TObject) 0x53c220 -- releases orderListAt18 and deletes self

  virtual char
  IsANoBrainer() const override; // slot 0x28 0x53c1b0 -- army attack/invade capability flag
  virtual int AccumulateLack(int* accumulatedLack, unsigned char includeExistingLack)
      const override; // slot 0x2c 0x53c620 -- accumulates remaining equipage lack, returns total
  virtual TMission* GetReplacementSlot48() override; // slot 0x48 0x53d630
  virtual char
  IsArmyMission() const override; // slot 0x50 0x5356f0 -- army mission capability flag (true)
  virtual TMission* GetArmyMission() override; // slot 0x58 0x535710 -- returns this
  virtual TMission*
  GetNavyMission() override; // slot 0x5c 0x535730 -- army: no navy-selectable mission (null)
  virtual float
  GetWeightedSatisfaction() override; // slot 0x68 0x53ceb0 -- composition alignment score
  virtual float IndustrialCostOfNeeds() override; // slot 0x6c 0x53d3e0 -- dot product score
  virtual float ValueOf(TMilitaryUnit* candidateUnit)
      override; // slot 0x70 0x53d420 -- score delta vs current selection
  virtual float FitnessOf(TMilitaryUnit* candidateUnit, float* referenceVector)
      override; // slot 0x78 0x53d4a0 -- candidate vector distance score
  virtual void AcceptReenforcement(TMilitaryUnit* unit,
                                   unsigned char notify) override; // slot 0x80 0x53c570
  virtual void RejectConstituent(TMilitaryUnit* unit,
                                 unsigned char notify) override; // slot 0x88 0x53c5e0
  virtual char
  SmokeEmIfYouGotEm() override; // slot 0x98 0x53c4f0 -- queue eligible units by movement class

  // First TArmyMission-introduced virtual (TMission abstract slot 0x27 / offset 0x9c).
  // Mac: GetPresentLocation() const. Returns the mission's target province/context id.
  virtual short GetPresentLocation() const; // 0x535750

  // Mac: ProjectEquipage(float*, short, short) const. Accumulates the five-slot
  // unit equipage vector, optionally filtering by the target tile.
  void ProjectEquipage(float* vector, short targetTile, short bypassTileFilter) const; // 0x53c9d0

  // Mac: ProjectSatisfaction(short) const. Scores projected equipage against the
  // mission's requested resource weights.
  float ProjectSatisfaction(short bypassTileFilter) const; // 0x53cac0

  // Adds one unit's contribution directly into `vector` (no accumulation loop): weight-
  // table lookup by clamped IsNotStationedInProvince distance from GetPresentLocation,
  // scaled by GetProvinceUnitOrderWeight, with an explicit sign
  // (true adds, false subtracts) instead of the fixed +1.0 the loop-based accumulators use.
  // 0x53cb50, __thiscall, RET 0xC.
  void AccumulateMissionUnitPriorityContributionWithScaleMode(TMilitaryUnit* unit, float* vector,
                                                              bool scaleMode);

  // Mac: GetWeightedEquipage(float*) const. Builds the distance-weighted five-slot
  // vector for the mission's current unit list.
  void GetWeightedEquipage(float* vector) const; // 0x53cda0

  // Order-vector score including one extra candidate unit contribution
  // (0x53d200 negates the candidate's scale: the "without unit" variant).
  float ComputeArmyMissionScoreDeltaWithCandidateUnit(TMilitaryUnit* candidateUnit); // 0x53d020
  float
  ComputeArmyMissionScoreDeltaWithScaledCandidateUnit(TMilitaryUnit* candidateUnit); // 0x53d200

private:
  // Shared accumulation loop over orderListAt18 (0x53c620 / 0x53ceb0 both repeat
  // this exact per-unit vector-contribution pattern).
  void AccumulateOrderPriorityVector(float* vector) const;
};

ASSERT_SIZE(TArmyMission, 0x30);

// Adds unit's stat contributions (stat indices 0-4, scaled by strength/quality and
// the province order weight) into the five-component priority vector. 0x53cc10,
// __cdecl, shared by the whole mission-scoring family.
void AccumulateUnitOrderPriorityVectorContribution(TMilitaryUnit* unit, float* vector, float scale,
                                                   float weight);
