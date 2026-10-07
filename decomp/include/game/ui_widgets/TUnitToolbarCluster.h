#pragma once

#include "compat.h"

#include "game/ui_screens/TUberCluster.h"

struct CRuntimeClass;
// VTABLE: IMPERIALISM 0x00664d38
class TUnitToolbarCluster : public TUberCluster {
public:
  virtual ~TUnitToolbarCluster() override;
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) override;
  virtual void SetCurrentChoice(int childTag) override;
  virtual bool IsTradeControlAtMinimum() override;
  // Source evidence: unreferenced retained COMDAT in retail.
  TUnitToolbarCluster() {}
  DECLARE_DYNCREATE(TUnitToolbarCluster)
};
ASSERT_SIZE(TUnitToolbarCluster, 0x88);
