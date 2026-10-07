#pragma once

#include "compat.h"

#include "game/ui_screens/TUberCluster.h"

struct CRuntimeClass;
// VTABLE: IMPERIALISM 0x00665838
class TAmtBarCluster : public TUberCluster {
public:
  virtual ~TAmtBarCluster() override;
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) override;
  virtual void DoPostCreate(int styleSeed) override;
  virtual void SetMoveAmount(short amount);

  TAmtBarCluster() {}
  DECLARE_DYNCREATE(TAmtBarCluster)
};
ASSERT_SIZE(TAmtBarCluster, 0x88);
