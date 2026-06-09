#pragma once

#include "game/TControl.h"

// VTABLE: IMPERIALISM 0x64b0c0
class TCluster : public TControl {
public:
  int field84;

  TCluster();

  void DispatchPanelControlEvent(int eventClass, void* eventPayload, int eventFlags);

  // Slots 0x1C4 - 0x1C8 (0x71, 0x72)
  virtual int GetField84();
  virtual void SetControlClassAndRefresh(int classState, int refreshFlag);
};
