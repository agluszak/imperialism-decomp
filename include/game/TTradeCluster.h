#include "compat.h"
#pragma once

#include "game/TUberCluster.h"

class TAmtBar;

struct CRuntimeClass;
extern "C" CRuntimeClass g_pClassDescTTradeCluster;

// VTABLE: IMPERIALISM 0x665a70
class TTradeCluster : public TUberCluster {
public:
  short tradeMetricSlot; // 0x88

  TTradeCluster();
  CRuntimeClass* GetRuntimeClass() override;
  // Destructor is compiler-generated (implicit virtual dtor from TUberCluster).

  void InitializeTradeSellControlState(unsigned int styleSeed);
  virtual int NotifyControlSelectionChange(void* boundEntry, int arg2 = 0);
  virtual int GetControlFlag(int arg1 = 0, int arg2 = 0);
  virtual int GetBoolSlot1DC();
  virtual void DoControlAction();
  virtual void SetTradeBidControlBitmap();
  virtual void SetTradeOfferControlBitmap();
  virtual void SetTradeOfferSecondaryBitmap();
  virtual int vmethod_0115();
  virtual void ApplyMoveValue(int value);
  void SetTradeToolSubcontrolEnabledStateByFlag(unsigned char enabledFlag);
};
