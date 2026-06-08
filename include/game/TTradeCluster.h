#pragma once

#include "game/TUberCluster.h"

class TAmtBar;

extern "C" char g_pClassDescTTradeCluster;

// VTABLE: IMPERIALISM 0x665a70
class TTradeCluster : public TUberCluster {
public:
  short tradeMetricSlot; // 0x88

  TTradeCluster();

  void InitializeTradeSellControlState(unsigned int styleSeed);
  short QueryTradeSellControlQuantity();
  char IsTradeBidControlActionable();
  char IsTradeOfferControlActionable();
  void SetTradeBidSecondaryBitmapState();
  void SetTradeBidControlBitmapState();
  void SetTradeOfferControlBitmapState();
  void SetTradeOfferSecondaryBitmapState();
  char IsTradeSellControlAtMinimum();
  void UpdateTradeSellControlAndBarFromNationMetric(int metricClampMax);
  void SetTradeToolSubcontrolEnabledStateByFlag(unsigned char enabledFlag);
};
