#pragma once

#include "game/TUberCluster.h"

class TRailCluster : public TUberCluster {
public:
  int field_88;
  short field_8c;
  short field_8e;

  TRailCluster();
  virtual ~TRailCluster();

  static TRailCluster* CreateInstance();
  static void* GetClassNamePointer();

  virtual void vmethod_0012();
  virtual void vmethod_0013();
  virtual void DispatchEvent(int arg1, void* arg2, int arg3);
};

ASSERT_SIZE(TRailCluster, 0x90);
