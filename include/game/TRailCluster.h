#pragma once

#include "compat.h"
#include "game/TUberCluster.h"

struct CRuntimeClass;
class TAmtBar;

// VTABLE: IMPERIALISM 0x666318
class TRailCluster : public TUberCluster {
public:
  TAmtBar* selectedMetricControl; // 0x88
  short selectedMetricValue;      // 0x8c
  short selectedMetricStep;       // 0x8e

  TRailCluster();
  CRuntimeClass* GetRuntimeClass() const override;

  void HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) override;
  void NoOpUiLifecycleHook(int styleSeed) override;
  virtual void ApplyMoveValue(int value) override;
  virtual int NotifyControlSelectionChange(void* boundEntry, int arg2 = 0) override;
  virtual int GetControlFlag(int arg1 = 0, int arg2 = 0) override;
};

ASSERT_SIZE(TRailCluster, 0x90);

TRailCluster* __cdecl CreateTradeMoveScaledControlPanel(void);
