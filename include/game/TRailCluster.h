#pragma once

#include "compat.h"
#include "game/TUberCluster.h"

class TAmtBar;

// VTABLE: IMPERIALISM 0x666318
class TRailCluster : public TUberCluster {
public:
  TAmtBar* selectedMetricControl; // 0x88
  short selectedMetricValue;      // 0x8c
  short selectedMetricStep;       // 0x8e

  TRailCluster();
  virtual ~TRailCluster();

  virtual void ApplyMoveValue(int value);
  virtual int NotifyControlSelectionChange(void* boundEntry, int arg2 = 0);
  virtual int GetControlFlag(int arg1 = 0, int arg2 = 0);

  void SelectTradeCommodityPresetBySummaryTagAndInitControls(short recordIndex);
};

ASSERT_SIZE(TRailCluster, 0x90);

TRailCluster* __cdecl CreateTradeMoveScaledControlPanel(void);
void* __cdecl GetTRailClusterClassNamePointer(void);
