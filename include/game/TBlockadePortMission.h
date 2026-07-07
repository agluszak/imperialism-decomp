#pragma once

#include "game/TControlSeaZoneMission.h"

class TZone;

// Mac: TBlockadePortMission — navy mission that blockades an enemy port zone.
//
// Real base is TControlSeaZoneMission (confirmed via the RTTI CRuntimeClass
// ancestry: TBlockadePortMission -> TControlSeaZoneMission -> TNavyMission ->
// TMission -> TObject -> CObject), not TNavyMission directly. Slots 0x0e and
// 0x28 below are NOT overridden here -- they're inherited unchanged from
// TControlSeaZoneMission (previously mis-modeled as a same-address "COMDAT
// fold" between sibling classes; it's plain inheritance). Slots 0x0c/0x0d/0x12
// genuinely are own overrides with distinct bodies.
// VTABLE: IMPERIALISM 0x0065ac60
class TBlockadePortMission : public TControlSeaZoneMission {
  DECLARE_SERIAL(TBlockadePortMission)
public:
  // +0x3c: pointer to the port-zone order-context this mission was built
  // from (TMission::ConstructBlockadePortMissionForContext); layout of the
  // pointed-to object is not yet recovered, so it stays untyped.
  TZone* portZoneContext3c; // +0x3c blockade-target port zone (deserialized by node id)

  TBlockadePortMission();
  // 0x0053ab50 -- built from a map-order context node (a TZone): derives the
  // target port zone from context->primaryNeighbors[0] and stores the node in
  // portZoneContext3c.
  TBlockadePortMission(TZone* context);

  virtual void WriteTo(TStream* stream) override;  // slot 0x05 0x53ac60
  virtual void ReadFrom(TStream* stream) override; // slot 0x06 0x53aca0

  virtual void Call30() override;           // slot 0x0c 0x53ace0
  virtual void SetStateByte8To2() override; // slot 0x0d 0x53ae90 -- state08 = 3
  virtual void NoOpSlot3C() override; // slot 0x0f 0x53aeb0 -- resource weights from navy context

  virtual TMission*
  GetReplacementSlot48() override; // slot 0x12 0x53adf0 -- validate context / refresh child
  virtual char MatchesMissionKeySlot4C(int kind, int key, int mode) override; // slot 0x13 0x53ba10

  virtual char ReturnFalseSlot60() override; // slot 0x18 0x53aa70
  virtual char ReturnFalseSlot64() override; // slot 0x19 0x53aa50

  virtual void
  NoOpSlot9C() override; // slot 0x27 0x53ba40 -- queue map-order type 6 from context pointer
};

ASSERT_SIZE(TBlockadePortMission, 0x40);
