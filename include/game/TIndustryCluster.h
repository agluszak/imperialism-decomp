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

  virtual void vmethod_0012();
  virtual void vmethod_0013();
  virtual void DispatchEvent(int arg1, void* arg2, int arg3);
};

ASSERT_SIZE(TIndustryCluster, 0x90);
