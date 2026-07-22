#pragma once

#include "game/TObject.h"
#include "game/TLaborPool.h"
#include "game/mfc.h"

// Forward declarations for types referenced by generated signatures.
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
  // Mac CodeWarrior oracle: SetPopulation(short, short, short). Seeds the low-,
  // medium-, and high-skill labor-pool counts and refreshes aggregate population metrics.
  virtual void SetPopulation(short lowSkillCount, short mediumSkillCount,
                             short highSkillCount); // slot 0x0b 0x4b5dc0
  // Mac CodeWarrior oracle: RemovePopulation(short, short). The first argument selects
  // the starting skill band (1/2/4); a negative amount adds population to that band.
  virtual void RemovePopulation(short startingSkillBand,
                                short amount); // slot 0x0d 0x4b66a0
  virtual void Eat();                          // slot 0x0e 0x4b5ed0
  virtual void PretendToEat(short& substitutionCount,
                            short& starvationCount); // slot 0x0f 0x4b6260
  virtual char Strike();                             // slot 0x10 0x4b65b0
  // Mac oracle: StartProductionPhase(). Copies the baseline labor pools into the
  // working pool, applies pending deltas and consumption, and refreshes strength.
  virtual void StartProductionPhase(); // slot 0x11 0x4b5e80
  virtual float GrowthRate();          // slot 0x12 0x4b63e0
  virtual void MakeUnavailable(short skillBand,
                               short amount); // slot 0x13 0x4b67e0
  // Mac CodeWarrior oracle: PredictedNeeds(). Rebuilds and returns the per-resource
  // predicted-needs vector stored at +0x22.
  virtual short* PredictedNeeds(); // slot 0x14 0x4b64c0

  // 0x004b5c00: attach this population state to a city and allocate its three
  // labor pools.
  void InitializePopulationState(TCity* city);

  TCity* city04;
  short populationCount08; // +0x08 — total workers across the three skill bands
  unsigned char pad0a[2];
  // +0x0c — snapshotted by the turn-event-0x2c packet. Genuinely float: written via FSTP in
  // SetPopulation (0x4b5dc0), not an int.
  float populationCountFloat0c;
  TLaborPool* baselineSlots10;     // +0x10
  TLaborPool* productionSlots14;   // +0x14
  TLaborPool* pendingDeltaSlots18; // +0x18
  short strength;                  // +0x1c — low-stock flag / trade production cap
  short extraAt1e;                 // +0x1e
  short fieldAt20;                 // +0x20 — snapshotted by the turn-event-0x2c packet

  // +0x22..+0x4f — one predicted requirement per resource type. ReadFrom/WriteTo
  // serialize all 23 shorts as a single persistent block.
  short predictedNeedByResource22[0x17];

  TPopulationMgr();
};
