#pragma once

#include "compat.h"
#include "game/TUberCluster.h"

struct CRuntimeClass;
class TAmtBar;

// VTABLE: IMPERIALISM 0x665ed0
class TIndustryCluster : public TUberCluster {
public:
  TAmtBar* selectedMetricControl; // 0x88
  short selectedMetricValue;      // 0x8c
  short selectedMetricStep;       // 0x8e

  TIndustryCluster();
  CRuntimeClass* GetRuntimeClass() override;
  // Destructor is compiler-generated (implicit virtual dtor from TUberCluster).

  virtual void ApplyMoveValue(int value);
  virtual int NotifyControlSelectionChange(void* boundEntry, int arg2 = 0);
  virtual int GetControlFlag(int arg1 = 0, int arg2 = 0);

  void SyncTradeCommoditySelectionWithActiveNationAndInitControls(int styleSeed);
};

ASSERT_SIZE(TIndustryCluster, 0x90);

TIndustryCluster* __cdecl CreateTradeMoveStepControlPanel(void);
