#pragma once

#include "compat.h"

#include "game/ui_screens/TUberCluster.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0065d6e0
class TNavyToolbarCluster : public TUberCluster {
public:
  DECLARE_DYNCREATE(TNavyToolbarCluster)
  virtual ~TNavyToolbarCluster() override;
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) override;
  virtual void SetCurrentChoice(int childTag) override;
  virtual bool IsTradeControlAtMinimum() override;

  TNavyToolbarCluster();
};
ASSERT_SIZE(TNavyToolbarCluster, 0x88);
