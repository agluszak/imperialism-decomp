#pragma once

#include "game/TMission.h"
#include "game/TSortedList.h"

// Army-mission branch base (vtable prefix shares TMission slots 0x00-0x26).
// VTABLE: IMPERIALISM 0x0065ad38
class TArmyMission : public TMission {
  DECLARE_SERIAL(TArmyMission)
public:
  short field_14;
  short padding_16;
  TSortedList* orderListAt18;
  float resourceWeights[5]; // offset 0x1c

  TArmyMission();
  TArmyMission(int nodeKey);

  virtual void WriteTo(TStream* stream) override;  // slot 0x05
  virtual void ReadFrom(TStream* stream) override; // slot 0x06
  virtual void Free() override; // slot 0x1c (TObject) 0x53c220 -- releases orderListAt18 and deletes self

  virtual char ReturnFalseSlot28() override;                 // slot 0x28 0x53c1b0 -- army attack/invade capability flag
  virtual int ReturnZeroSlot2C(int* outBuffer, int unused) override; // slot 0x2c 0x53c620 -- builds priority vector, returns total
  virtual TMission* GetReplacementSlot48() override;         // slot 0x48 0x53d630
  virtual char ReturnFalseSlot50() override;                 // slot 0x50 0x5356f0 -- army mission capability flag (true)
  virtual int ReturnZeroSlot58() override;                   // slot 0x58 0x535710
  virtual int ReturnZeroSlot5C() override;                   // slot 0x5c 0x535730 -- army mission capability flag (false)
  virtual float ReturnZeroFloatSlot68() override;            // slot 0x68 0x53ceb0 -- composition alignment score
  virtual float ReturnZeroFloatSlot6C() override;            // slot 0x6c 0x53d3e0 -- dot product score
  virtual float ReturnZeroFloatSlot70(TMission* candidate) override; // slot 0x70 0x53d420 -- score delta vs current selection
  virtual float ReturnZeroFloatSlot78(TMission* candidate, float* referenceVector) override; // slot 0x78 0x53d4a0 -- candidate vector distance score
  virtual void NoOpSlot80(TMission* item, int notify) override; // slot 0x80 0x53c570 -- attach mission as owner and notify
  virtual void NoOpSlot88(TMission* item, int unused) override;  // slot 0x88 0x53c5e0 -- release mission owner link
  virtual char ReturnFalseSlot98() override;                 // slot 0x98 0x53c4f0 -- queue eligible units by movement class

  // First TArmyMission-introduced virtual (TMission abstract slot 0x27 / offset 0x9c).
  virtual short GetMissionTargetContextIdFromField14(); // 0x535750

private:
  // Shared accumulation loop over orderListAt18 (0x53c620 / 0x53ceb0 both repeat
  // this exact per-unit vector-contribution pattern).
  void AccumulateOrderPriorityVector(float* vector);
};

ASSERT_SIZE(TArmyMission, 0x30);
