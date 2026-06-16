#pragma once

#include "game/TMission.h"

// Army-mission branch base (vtable prefix shares TMission slots 0x00-0x26).
// VTABLE: IMPERIALISM 0x0065ad38
class TArmyMission : public TMission {
public:
  // Introduced at +0x18: mission order list (CPtrList-backed, ctor 0x53c0a0).
  void* orderListAt18;
  unsigned char pad1c[0x20 - 0x1C];
};

ASSERT_SIZE(TArmyMission, 0x20);
