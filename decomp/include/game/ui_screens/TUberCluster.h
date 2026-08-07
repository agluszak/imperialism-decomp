#pragma once

#include "compat.h"

#include "game/ui_core/TCluster.h"

struct CRuntimeClass;
// VTABLE: IMPERIALISM 0x65f210
class TUberCluster : public TCluster {
public:
  virtual ~TUberCluster() override;       // slot 0x01 (scalar deleting destructor)
  virtual char IsTradeControlAtMinimum(); // slot 0x73 0x5714e0
  TUberCluster();
  DECLARE_DYNCREATE(TUberCluster)
};
ASSERT_SIZE(TUberCluster, 0x88);
