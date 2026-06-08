#pragma once

#include "game/TUberCluster.h"

// VTABLE: IMPERIALISM 0x00665838
class TAmtBarCluster : public TUberCluster {
public:
  short metricSlotAt88;
  short pad_8a;
  short valueAt8c;
  short valueAt8e;
  TAmtBarCluster();
  // Destructor is compiler-generated (implicit virtual dtor) from TUberCluster.

  static TAmtBarCluster* CreateInstance();
  static void* GetClassNamePointer();

  // We use the original struct name for parameters until we verify the method signature.
  void HandleTradeSellControlCommand(int commandId, void* eventArg, int eventExtra);
};
