#pragma once

#include "compat.h"

#include "game/ui_screens/TUberCluster.h"

struct CRuntimeClass;
// VTABLE: IMPERIALISM 0x00665190
class TCityBarCluster : public TUberCluster {
public:
  virtual ~TCityBarCluster() override;    // slot 0x01 (scalar deleting destructor)
  virtual void ApplyMoveValue(int value); // slot 0x74 0x5866b0
  TCityBarCluster();
  DECLARE_DYNCREATE(TCityBarCluster)

  void UpdateTradeSummaryMetricControlsFromRecord(int recordContext);
};
ASSERT_SIZE(TCityBarCluster, 0x88);
