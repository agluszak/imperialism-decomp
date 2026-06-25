#pragma once

#include "game/TUberCluster.h"

// Army map-context toolbar cluster (0x8c bytes).
// VTABLE: IMPERIALISM 0x00667ad0
class TArmyToolbar : public TUberCluster {
public:
  int field88;

  TArmyToolbar() : TUberCluster(), field88(0) {}
};

ASSERT_SIZE(TArmyToolbar, 0x8c);
