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

  static TAmtBarCluster* CreateInstance();
  static void* GetClassNamePointer();
  void* DestructAndMaybeFree(int freeSelfFlag);

  // We use the original struct name for parameters until we verify the method signature.
  void HandleTradeSellControlCommand(int commandId, void* eventArg, int eventExtra);
};
