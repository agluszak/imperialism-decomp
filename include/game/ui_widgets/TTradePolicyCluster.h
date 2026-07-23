#pragma once

#include "game/ui_screens/TUberCluster.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00663de0
class TTradePolicyCluster : public TUberCluster {
public:
  DECLARE_DYNCREATE(TTradePolicyCluster)
  virtual ~TTradePolicyCluster() override; // slot 0x01 (scalar deleting destructor)
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler,
                       TEvent* event) override; // slot 0x0f 0x00584320

  TTradePolicyCluster();
};
