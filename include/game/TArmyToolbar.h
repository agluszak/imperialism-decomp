#pragma once

#include "game/TUnitToolbarCluster.h"

struct CRuntimeClass;

// Army map-context toolbar cluster (0x8c bytes).
// VTABLE: IMPERIALISM 0x00667ad0
class TArmyToolbar : public TUnitToolbarCluster {
public:
  short selectedProvinceIndex; // +0x88; -1 clears the toolbar selection

  TArmyToolbar();
  ~TArmyToolbar() override;

  DECLARE_DYNCREATE(TArmyToolbar)
  void DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) override;
  // TArmyToolbar's sole slot beyond TUnitToolbarCluster. Recounts the selected
  // province's stationed units into the placards and order-state arrow controls.
  virtual void SetProvince(short provinceIndex); // slot 0x74 0x0058df60
};

ASSERT_SIZE(TArmyToolbar, 0x8c);
