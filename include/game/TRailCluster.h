#pragma once

#include "game/TUberCluster.h"

class TRailCluster : public TUberCluster {
public:
  struct TAmtBar* selectedMetricControl; // 0x88
  short selectedMetricValue;             // 0x8c
  short selectedMetricStep;              // 0x8e

  TRailCluster();
  virtual ~TRailCluster();

  static TRailCluster* CreateInstance();
  static void* GetClassNamePointer();

  virtual void ApplyMoveValue(int value);
  virtual int NotifyControlSelectionChange(void* boundEntry, int arg2 = 0);
  virtual int GetControlFlag(int arg1 = 0, int arg2 = 0);

  void SelectTradeCommodityPresetBySummaryTagAndInitControls(short recordIndex);
};

ASSERT_SIZE(TRailCluster, 0x90);
