#pragma once

#include "compat.h"

#include "game/ui_screens/TUberCluster.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00663de0
class TTradePolicyCluster : public TUberCluster {
public:
  DECLARE_DYNCREATE(TTradePolicyCluster)
  virtual ~TTradePolicyCluster() override;
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) override;

  TTradePolicyCluster();
};
ASSERT_SIZE(TTradePolicyCluster, 0x88);
