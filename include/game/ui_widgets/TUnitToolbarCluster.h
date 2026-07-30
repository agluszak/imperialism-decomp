#pragma once

#include "compat.h"

#include "game/ui_screens/TUberCluster.h"

struct CRuntimeClass;
// VTABLE: IMPERIALISM 0x00664d38
class TUnitToolbarCluster : public TUberCluster {
public:
  virtual ~TUnitToolbarCluster() override; // slot 0x01 (scalar deleting destructor)
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler,
                       TEvent* event) override;                      // slot 0x0f 0x00586090
  virtual void SetSelectedChildTagAndRefresh(int childTag) override; // slot 0x72 0x586170
  virtual int IsTradeControlAtMinimum() override;                    // slot 0x73 0x586150
  using TUberCluster::HandleEvent;

  // FUNCTION: IMPERIALISM 0x00586010
  TUnitToolbarCluster() : TUberCluster() {}
  DECLARE_DYNCREATE(TUnitToolbarCluster)
};
ASSERT_SIZE(TUnitToolbarCluster, 0x88);
