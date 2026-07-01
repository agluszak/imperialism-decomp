#pragma once

#include "game/TMission.h"

// Army-mission branch base (vtable prefix shares TMission slots 0x00-0x26).
// VTABLE: IMPERIALISM 0x0065ad38
class TArmyMission : public TMission {
  DECLARE_SERIAL(TArmyMission)
public:
  short field_14;
  short padding_16;
  void* orderListAt18;
  float resourceWeights[5]; // offset 0x1c

  TArmyMission();
  TArmyMission(int nodeKey);
  virtual ~TArmyMission() override;

  virtual void WriteTo(TStream* stream) override;  // slot 0x05
  virtual void ReadFrom(TStream* stream) override; // slot 0x06

  virtual void CleanupTArmyMissionAndReleaseChildContext(); // slot 0x27 / offset 0x9c
};

ASSERT_SIZE(TArmyMission, 0x30);
