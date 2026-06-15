#pragma once

#include "game/TUberCluster.h"

struct CRuntimeClass;
// VTABLE: IMPERIALISM 0x00665190
class TCityBarCluster : public TUberCluster {
public:
  TCityBarCluster();
  CRuntimeClass* GetRuntimeClass() const override;

  static TCityBarCluster* CreateInstance();
  void* DestructAndMaybeFree(int freeSelfFlag);

  // Maybe an Update method
  void UpdateTradeSummaryMetricControlsFromRecord(int recordContext);
};
