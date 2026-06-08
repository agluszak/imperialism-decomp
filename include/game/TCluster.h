#pragma once

#include "game/TControl.h"

// VTABLE: IMPERIALISM 0x64b0c0
class TCluster : public TControl {
public:
  int field84;

  TCluster();

  void DispatchPanelControlEvent(int eventClass, void* eventPayload, int eventFlags);
};
