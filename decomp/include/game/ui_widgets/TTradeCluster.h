#include "compat.h"
#pragma once

#include "game/ui_widgets/TAmtBarCluster.h"
#include "game/mfc.h"

class TAmtBar;

struct CRuntimeClass;

// VTABLE: IMPERIALISM 0x665a70
class TTradeCluster : public TAmtBarCluster {
public:
  // FUNCTION: IMPERIALISM 0x00587110
  ~TTradeCluster() override {}
  short tradeMetricSlot; // 0x88

  DECLARE_DYNCREATE(TTradeCluster)
  TTradeCluster();

  void DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) override;

  void DoPostCreate(int styleSeed) override; // 0xdc 0x587130
  virtual bool IsTradeControlAtMinimum() override;
  void SetMoveAmount(short amount) override;
  virtual int GetTradeSellControlValue();
  virtual bool IsSelectionAllowed();
  virtual int IsSellOffer();
  virtual void DoControlAction();
  virtual void ShowBidCard();
  virtual void ShowOfferCard();
  virtual void ShowOfferHandle();
};
ASSERT_SIZE(TTradeCluster, 0x8c);
