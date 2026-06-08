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

  virtual int QueryStepValue(); // SelectTradeSpecialCommodityAndInitializeControls
  virtual void vmethod_0013(); // RefreshTradeMoveBarAndTurnControl
  virtual void DispatchEvent(int arg1, void* arg2, int arg3); // HandleTradeMoveArrowControlEvent
};

ASSERT_SIZE(TShipyardCluster, 0x90);
