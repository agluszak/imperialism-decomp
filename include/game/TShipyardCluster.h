#pragma once

#include "game/TUberCluster.h"

class TShipyardCluster : public TUberCluster {
public:
  int field_88;
  short field_8c;
  short field_8e;

  TShipyardCluster();
  virtual ~TShipyardCluster();

  static TShipyardCluster* CreateInstance();
  static void* GetClassNamePointer();

  virtual void ApplyMoveValue(int value);
};

ASSERT_SIZE(TShipyardCluster, 0x90);
