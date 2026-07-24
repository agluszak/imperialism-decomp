#pragma once

#include "compat.h"

#include "game/ui_screens/TUberCluster.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0065d6e0
class TNavyToolbarCluster : public TUberCluster {
public:
  DECLARE_DYNCREATE(TNavyToolbarCluster)
  virtual ~TNavyToolbarCluster() override; // slot 0x01 (scalar deleting destructor)
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler,
                       TEvent* event) override;                      // slot 0x0f 0x00569550
  virtual void SetSelectedChildTagAndRefresh(int childTag) override; // slot 0x72 0x5696f0
  virtual int IsTradeControlAtMinimum() override;                    // slot 0x73 0x5696d0

  TNavyToolbarCluster();
};
ASSERT_SIZE(TNavyToolbarCluster, 0x88);
