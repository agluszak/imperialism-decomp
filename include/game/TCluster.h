#pragma once

#include "game/TControl.h"

// VTABLE: IMPERIALISM 0x64b0c0
class TCluster : public TControl {
public:
  int field84;

  TCluster();

  void DispatchPanelControlEvent(int eventClass, void* eventPayload, int eventFlags);

  // Slots 0x1CC - 0x1E0
  virtual void vmethod_0115();
  virtual void ApplyMoveValue(int value);
  virtual void NotifyControlSelectionChange(void* boundEntry);
  virtual char GetControlFlag();
  virtual char GetBoolSlot1DC();
  virtual void DoControlAction();
};
