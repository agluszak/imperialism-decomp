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

  virtual int QueryStepValue();
  virtual void vmethod_0013();
  virtual void DispatchEvent(int arg1, void* arg2, int arg3);

  void SelectTradeCommodityPresetBySummaryTagAndInitControls(short recordIndex);
};

ASSERT_SIZE(TRailCluster, 0x90);
