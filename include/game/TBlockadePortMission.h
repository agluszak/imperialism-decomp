#pragma once

#include "game/TNavyMission.h"

// Mac: TBlockadePortMission — navy mission that blockades an enemy port zone.
// VTABLE: IMPERIALISM 0x0065ac60
class TBlockadePortMission : public TNavyMission {
  DECLARE_SERIAL(TBlockadePortMission)
public:
  // +0x3c: pointer to the port-zone order-context this mission was built
  // from (TMission::ConstructBlockadePortMissionForContext); layout of the
  // pointed-to object is not yet recovered, so it stays untyped.
  void* portZoneContext3c;

  TBlockadePortMission();
  TBlockadePortMission(TZone* targetZone);

  virtual void WriteTo(TStream* stream) override;  // slot 0x05 0x53ac60
  virtual void ReadFrom(TStream* stream) override; // slot 0x06 0x53aca0

  // Slots 0x0c-0x0f: TMission's own virtuals, overridden here.
  virtual void Call30() override;             // slot 0x0c 0x53ace0
  virtual void SetStateByte8To2() override;   // slot 0x0d 0x53ae90 -- state08 = 3
  virtual void ResetValue0CToZero() override; // slot 0x0e 0x539290 -- port-zone-context average score (shared)
  virtual void NoOpSlot3C() override;         // slot 0x0f 0x53aeb0 -- resource weights from navy context

  virtual TMission* GetReplacementSlot48() override; // slot 0x12 0x53adf0 -- validate context / refresh child
  virtual char MatchesMissionKeySlot4C(int kind, int key, int mode) override; // slot 0x13 0x53ba10

  virtual char ReturnFalseSlot60() override; // slot 0x18 0x53aa70
  virtual char ReturnFalseSlot64() override; // slot 0x19 0x53aa50

  virtual void NoOpSlot9C() override; // slot 0x27 0x53ba40 -- queue map-order type 6 from context pointer
  virtual void RefreshMissionPortZoneContextForNation() override; // slot 0x28 0x539780 (shared)
};

ASSERT_SIZE(TBlockadePortMission, 0x40);
