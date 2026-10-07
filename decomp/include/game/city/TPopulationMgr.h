#pragma once

#include "compat.h"

#include "game/app/TObject.h"
#include "game/debug/TLaborPool.h"
#include "game/mfc.h"
#include "game/resource_domain_types.h"

class TStream;

class TCity;

// VTABLE: IMPERIALISM 0x0064f9b0
class TPopulationMgr : public TObject {
public:
  DECLARE_DYNCREATE(TPopulationMgr)
  virtual ~TPopulationMgr() override;
  virtual void WriteTo(TStream* stream) override;
  virtual void ReadFrom(TStream* stream) override;
  virtual void Free() override;
  virtual void Copy(TLaborPool* source, TLaborPool* destination);
  // VC5 emits these overloaded virtuals in reverse declaration order.
  virtual void SetPopulation(short lowSkillCount);
  virtual void SetPopulation(short lowSkillCount, short mediumSkillCount, short highSkillCount);
  virtual void RemovePopulation(short startingSkillBand, short amount);
  virtual void Eat();
  virtual void PretendToEat(short& substitutionCount, short& starvationCount);
  virtual bool Strike();
  virtual void StartProductionPhase();
  virtual float GrowthRate();
  virtual void MakeUnavailable(short skillBand, short amount);
  virtual short* PredictedNeeds();

  void IPopulationMgr(TCity* city);
  void AddUntrained(short count);
  void AddExpert(short count);

  TCity* city;
  short populationCount; // total workers across the three skill bands
  unsigned char pad0a[2];
  float populationCountFloat;
  TLaborPool* baselineSlots;
  TLaborPool* productionSlots;
  TLaborPool* pendingDeltaSlots;
  short strength; // low-stock flag / trade production cap
  short powerPlantOutput;
  short consumptionRotation; // snapshotted by the turn-event-0x2c packet

  short predictedNeedByResource[kResourceKindCount];

  TPopulationMgr() {}
};
ASSERT_SIZE(TPopulationMgr, 0x50);
