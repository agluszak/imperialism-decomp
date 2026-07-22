#pragma once

#include "game/TCluster.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0066b578
class TMapEditCluster : public TCluster {
public:
  DECLARE_DYNCREATE(TMapEditCluster)
  virtual ~TMapEditCluster() override; // slot 0x01 (scalar deleting destructor)
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler,
                       TEvent* event) override; // slot 0x0f 0x005b2970

  TMapEditCluster();
};
