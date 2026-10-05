#pragma once

#include "game/map/TMission.h"
#include "game/ui_core/TSortedList.h"

class TMilitaryUnit;

// Army-mission branch base (vtable prefix shares TMission slots 0x00-0x26).
// VTABLE: IMPERIALISM 0x0065ad38
class TArmyMission : public TMission {
  DECLARE_SERIAL(TArmyMission)
public:
  short presentLocation;
  short padding_16;
  TSortedList* orderList;
  float requiredEquipageByClass[5]; // offset 0x1c

  TArmyMission(int nodeKey = -1);
  // Inline so concrete army-mission destructors collapse through the empty base chain.
  // FUNCTION: IMPERIALISM 0x0053c200
  virtual ~TArmyMission() override {}

  virtual void WriteTo(TStream* stream) override;  // slot 0x05
  virtual void ReadFrom(TStream* stream) override; // slot 0x06
  virtual void
  Free() override; // slot 0x1c (TObject) 0x53c220 -- releases orderList and deletes self

  virtual bool
  IsANoBrainer() const override; // slot 0x28 0x53c1b0 -- army attack/invade capability flag
  virtual int AccumulateLack(int* accumulatedLack, bool includeExistingLack)
      const override; // slot 0x2c 0x53c620 -- accumulates remaining equipage lack, returns total
  virtual TMission* GetReplacement() override; // slot 0x48 0x53d630
  virtual bool
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
                                   bool notify) override; // slot 0x80 0x53c570
  virtual void RejectConstituent(TMilitaryUnit* unit,
                                 bool notify) override; // slot 0x88 0x53c5e0
  virtual char
  SmokeEmIfYouGotEm() override; // slot 0x98 0x53c4f0 -- queue eligible units by movement class

  virtual short GetPresentLocation() const; // 0x535750

  void ProjectEquipage(float* vector, short targetTile, short bypassTileFilter) const; // 0x53c9d0

  float ProjectSatisfaction(short bypassTileFilter) const; // 0x53cac0

  void AccumulateWeightedUnitEquipage(TMilitaryUnit* unit, float* vector,
                                                              bool scaleMode);

  void GetWeightedEquipage(float* vector) const; // 0x53cda0

  float ComputeArmyMissionScoreDeltaWithCandidateUnit(TMilitaryUnit* candidateUnit); // 0x53d020
  float
  ComputeArmyMissionScoreDeltaWithScaledCandidateUnit(TMilitaryUnit* candidateUnit); // 0x53d200

protected:
  void AccumulateOrderPriorityVector(float* vector) const;

private:
  float ComputeProvinceImportance(short provinceIndex);
};

ASSERT_SIZE(TArmyMission, 0x30);

void AccumulateUnitOrderPriorityVectorContribution(TMilitaryUnit* unit, float* vector, float scale,
                                                   float weight);
