#pragma once

#include "game/TUberCluster.h"

// VTABLE: IMPERIALISM 0x00665190
struct CRuntimeClass;
class TCityBarCluster : public TUberCluster {
public:
  TCityBarCluster();
  CRuntimeClass* GetRuntimeClass() override;

  static TCityBarCluster* CreateInstance();
  void* DestructAndMaybeFree(int freeSelfFlag);

  // Maybe an Update method
  void UpdateTradeSummaryMetricControlsFromRecord(int recordContext);
};
