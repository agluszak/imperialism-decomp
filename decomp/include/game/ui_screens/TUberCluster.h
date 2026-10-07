#pragma once

#include "compat.h"

#include "game/ui_core/TCluster.h"

struct CRuntimeClass;
// VTABLE: IMPERIALISM 0x65f210
class TUberCluster : public TCluster {
public:
  virtual ~TUberCluster() override;
  virtual bool IsTradeControlAtMinimum();
  TUberCluster();
  DECLARE_DYNCREATE(TUberCluster)
};
ASSERT_SIZE(TUberCluster, 0x88);
