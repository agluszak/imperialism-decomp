#pragma once

#include "compat.h"

#include "game/ui_screens/TUberCluster.h"

struct CRuntimeClass;
class TCity;
// VTABLE: IMPERIALISM 0x00665190
class TCityBarCluster : public TUberCluster {
public:
  virtual ~TCityBarCluster() override;      // slot 0x01 (scalar deleting destructor)
  virtual void ApplyMoveValue(TCity* city); // slot 0x74 0x5866b0
  TCityBarCluster();
  DECLARE_DYNCREATE(TCityBarCluster)
};
ASSERT_SIZE(TCityBarCluster, 0x88);
