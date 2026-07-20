#include "compat.h"
#pragma once

#include "game/TUberCluster.h"
#include "game/mfc.h"

class TAmtBar;

struct CRuntimeClass;

// VTABLE: IMPERIALISM 0x665a70
class TTradeCluster : public TUberCluster {
public:
  short tradeMetricSlot; // 0x88

  DECLARE_DYNCREATE(TTradeCluster)
  TTradeCluster();
  // Destructor is compiler-generated (implicit virtual dtor from TUberCluster).

  void HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) override;

  void DoPostCreate(int styleSeed) override; // 0xdc 0x587130
  virtual int IsTradeControlAtMinimum() override;
  virtual void ApplyMoveValue(int value);
  virtual int NotifyControlSelectionChange(void* boundEntry, int arg2 = 0);
  virtual int GetControlFlag(int arg1 = 0, int arg2 = 0);
  virtual int GetBoolSlot1DC();
  virtual void DoControlAction();
  virtual void SetTradeBidControlBitmap();
  virtual void SetTradeOfferControlBitmap();
  virtual void SetTradeOfferSecondaryBitmap();
};
