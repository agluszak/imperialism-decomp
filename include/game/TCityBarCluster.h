#pragma once

#include "game/TUberCluster.h"

// VTABLE: IMPERIALISM 0x00665190
class TCityBarCluster : public TUberCluster {
public:
  TCityBarCluster();

  static TCityBarCluster* CreateInstance();
  static void* GetClassNamePointer();
  void* DestructAndMaybeFree(int freeSelfFlag);

  // Maybe an Update method
  void UpdateTradeSummaryMetricControlsFromRecord(int recordContext);
};
