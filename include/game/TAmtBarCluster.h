#pragma once

#include "game/TUberCluster.h"

struct CRuntimeClass;
// VTABLE: IMPERIALISM 0x00665838
class TAmtBarCluster : public TUberCluster {
public:
  void HandleTradeMoveStepCommand(int commandId, void* eventArg, int eventExtra);
  short metricSlotAt88;
  short pad_8a;
  short valueAt8c;
  short valueAt8e;
  TAmtBarCluster();
  CRuntimeClass* GetRuntimeClass() override;
  // Destructor is compiler-generated (implicit virtual dtor) from TUberCluster.

  static TAmtBarCluster* CreateInstance();
};
