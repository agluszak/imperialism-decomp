#pragma once

#include "compat.h"

#include "game/ui_core/TCluster.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0066b578
class TMapEditCluster : public TCluster {
public:
  DECLARE_DYNCREATE(TMapEditCluster)
  virtual ~TMapEditCluster() override;
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) override;

  // NOOP: verified empty in original 0x005b28b6
  TMapEditCluster() {}
};
ASSERT_SIZE(TMapEditCluster, 0x88);
