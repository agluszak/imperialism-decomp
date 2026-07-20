#pragma once

#include "game/TUnitToolbarCluster.h"

struct CRuntimeClass;

// Army map-context toolbar cluster (0x8c bytes).
// VTABLE: IMPERIALISM 0x00667ad0
class TArmyToolbar : public TUnitToolbarCluster {
public:
  int selectedTileIndex;

  TArmyToolbar();
  ~TArmyToolbar() override;

  TArmyToolbar* ConstructTArmyToolbarBaseState();
  DECLARE_DYNCREATE(TArmyToolbar)
  void HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) override;
};

ASSERT_SIZE(TArmyToolbar, 0x8c);
