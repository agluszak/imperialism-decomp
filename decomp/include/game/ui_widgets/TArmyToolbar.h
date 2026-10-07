#pragma once

#include "game/ui_widgets/TUnitToolbarCluster.h"

struct CRuntimeClass;

// Army map-context toolbar cluster (0x8c bytes).
// VTABLE: IMPERIALISM 0x00667ad0
class TArmyToolbar : public TUnitToolbarCluster {
public:
  short selectedProvinceIndex; // -1 clears the toolbar selection

  TArmyToolbar();
  ~TArmyToolbar() override;

  DECLARE_DYNCREATE(TArmyToolbar)
  void DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) override;
  virtual void SetProvince(short provinceIndex);
};

ASSERT_SIZE(TArmyToolbar, 0x8c);
