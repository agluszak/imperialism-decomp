#pragma once

#include "game/TUberCluster.h"

struct CRuntimeClass;
// VTABLE: IMPERIALISM 0x00665190
class TCityBarCluster : public TUberCluster {
public:
  TCityBarCluster();
  CRuntimeClass* GetRuntimeClass() const override;

  static TCityBarCluster* CreateInstance();
  void ApplyMoveValue(int value) override;

  void UpdateTradeSummaryMetricControlsFromRecord(int recordContext);
};
