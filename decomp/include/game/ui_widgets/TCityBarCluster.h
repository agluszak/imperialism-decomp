#pragma once

#include "compat.h"

#include "game/ui_screens/TUberCluster.h"

struct CRuntimeClass;
class TCity;
// VTABLE: IMPERIALISM 0x00665190
class TCityBarCluster : public TUberCluster {
public:
  virtual ~TCityBarCluster() override;
  virtual void StuffValues(TCity* city);
  TCityBarCluster();
  DECLARE_DYNCREATE(TCityBarCluster)
};
ASSERT_SIZE(TCityBarCluster, 0x88);
