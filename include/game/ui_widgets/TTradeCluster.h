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
  // Destructor is compiler-generated (implicit virtual dtor from TAmtBarCluster).

  void DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) override;

  void DoPostCreate(int styleSeed) override; // 0xdc 0x587130
  virtual int IsTradeControlAtMinimum() override;
  void SetMoveAmount(short amount) override;
  virtual int GetTradeSellControlValue();
  virtual unsigned char IsSelectionAllowed();
  virtual int GetBoolSlot1DC();
  virtual void DoControlAction();
  virtual void SetTradeBidControlBitmap();
  virtual void SetTradeOfferControlBitmap();
  virtual void SetTradeOfferSecondaryBitmap();
};
ASSERT_SIZE(TTradeCluster, 0x8c);
