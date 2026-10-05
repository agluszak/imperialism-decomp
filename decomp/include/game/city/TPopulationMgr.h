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
  virtual ~TPopulationMgr() override;              // slot 0x01 (scalar deleting destructor)
  virtual void WriteTo(TStream* stream) override;  // slot 0x05 0x4b6850
  virtual void ReadFrom(TStream* stream) override; // slot 0x06 0x4b68f0
  virtual void Free() override;                    // slot 0x07 0x4b6990
  virtual void Copy(TLaborPool* source, TLaborPool* destination); // slot 0x0a 0x4b5d10
  // VC5 emits these overloaded virtuals in reverse declaration order.
  virtual void SetPopulation(short lowSkillCount); // slot 0x0c 0x4b5d50
  virtual void SetPopulation(short lowSkillCount, short mediumSkillCount,
                             short highSkillCount); // slot 0x0b 0x4b5dc0
  virtual void RemovePopulation(short startingSkillBand,
                                short amount); // slot 0x0d 0x4b66a0
  virtual void Eat();                          // slot 0x0e 0x4b5ed0
  virtual void PretendToEat(short& substitutionCount,
                            short& starvationCount); // slot 0x0f 0x4b6260
  virtual char Strike();                             // slot 0x10 0x4b65b0
  virtual void StartProductionPhase(); // slot 0x11 0x4b5e80
  virtual float GrowthRate();          // slot 0x12 0x4b63e0
  virtual void MakeUnavailable(short skillBand,
                               short amount); // slot 0x13 0x4b67e0
  virtual short* PredictedNeeds(); // slot 0x14 0x4b64c0

  void IPopulationMgr(TCity* city);
  void AddUntrained(short count);
  // Mac CodeWarrior oracle: AddExpert(short) -- 0x004b6a30.
  void AddExpert(short count);

  TCity* city04;
  short populationCount; // +0x08 — total workers across the three skill bands
  unsigned char pad0a[2];
  float populationCountFloat;
  TLaborPool* baselineSlots;     // +0x10
  TLaborPool* productionSlots;   // +0x14
  TLaborPool* pendingDeltaSlots; // +0x18
  short strength;                // +0x1c — low-stock flag / trade production cap
  short extraAt1e;               // +0x1e
  short fieldAt20;               // +0x20 — snapshotted by the turn-event-0x2c packet

  short predictedNeedByResource22[kResourceKindCount];

  TPopulationMgr() {}
};
ASSERT_SIZE(TPopulationMgr, 0x50);
