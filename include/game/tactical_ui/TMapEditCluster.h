#pragma once

#include "compat.h"

#include "game/ui_core/TCluster.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0066b578
class TMapEditCluster : public TCluster {
public:
  DECLARE_DYNCREATE(TMapEditCluster)
  virtual ~TMapEditCluster() override; // slot 0x01 (scalar deleting destructor)
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler,
                       TEvent* event) override; // slot 0x0f 0x005b2970

  // NOOP: verified empty in original 0x005b28b6 (no standalone TMapEditCluster::TMapEditCluster body exists: CreateObject 0x005b2880 inlines this default ctor, calling the TCluster base ctor directly at that site)
  TMapEditCluster() {}
};
ASSERT_SIZE(TMapEditCluster, 0x88);
