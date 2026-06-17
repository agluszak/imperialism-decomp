#pragma once

#include "game/TUberCluster.h"

struct CRuntimeClass;
// VTABLE: IMPERIALISM 0x00665838
class TAmtBarCluster : public TUberCluster {
public:
  short metricSlotAt88;
  short pad_8a;
  short valueAt8c;
  short valueAt8e;
  TAmtBarCluster();
  CRuntimeClass* GetRuntimeClass() const override;

  void HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) override;
  void NoOpUiLifecycleHook(int styleSeed) override;
  virtual void ApplyMoveValue(int value) override;

  static TAmtBarCluster* CreateInstance();
};
