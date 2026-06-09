#pragma once

#include "game/TUberCluster.h"

class TIndustryCluster : public TUberCluster {
public:
  int field_88;
  short field_8c;
  short field_8e;

  TIndustryCluster();
  virtual ~TIndustryCluster();

  static TIndustryCluster* CreateInstance();
  static void* GetClassNamePointer();

  virtual void ApplyMoveValue(int value);
  virtual int NotifyControlSelectionChange(void* boundEntry, int arg2 = 0);
  virtual int GetControlFlag(int arg1 = 0, int arg2 = 0);
};

ASSERT_SIZE(TIndustryCluster, 0x90);
